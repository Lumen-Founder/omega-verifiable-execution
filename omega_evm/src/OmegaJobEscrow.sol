// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "./OmegaSettlement.sol";
import {OVM0Dispute} from "./OVM0Dispute.sol";

/// @title OMEGA verified jobs: an agent-signed intent buys one deterministic OVM-0 computation, and the price is
///  released only for a result that survived the dispute game and meets the intent's condition.
/// @notice Intent -> policy -> execution -> verifiable result -> challenge -> conditional settlement, on one chain:
///  - post(): the agent's EIP-712 signature (plus the owner-registered cosigner's, e.g. the OMEGA kernel's policy key,
///    when one is set) over the job; the owner's on-chain policy (allowed programs and executors, price and window
///    caps, step cap, validity, revocation) is checked and the price is moved from the account's balance into escrow.
///  - reserve(): before claiming, the job's executor stakes bondFor(price) >= price, in the job's token, from its bond
///    balance here. Only claims made after the reservation count for the job, so the stake is at risk before anyone
///    can know whether the claim will be challenged.
///  - the executor runs the program off chain, publishes it in OVM0Inbox and claims the result in OVM0Dispute with a
///    bond; anyone can challenge within the dispute window (OVM0Dispute decides with the one-step referee).
///  - settle(): given a claim that OVM0Dispute has Accepted, made by the job's executor for exactly the job's
///    (program, inputs, maxSteps), after the reservation and before the job's deadline, and not used for another job:
///    if the verified final state halted cleanly (trap 0) and its output meets the condition, the executor is paid;
///    a verified result that fails the condition refunds the account (the outcome is certain, no one has to wait).
///  - slash(): any such claim that OVM0Dispute Rejected moves the stake to the account, until expiresAt, even after the
///    job was settled with another claim. It goes to the account, not to the challenger: the defender of a false claim
///    can win the race to defeat it with its own challenger and so recover its dispute bond, but not this stake.
///  - expire(): a job with no such settlement by deadline + window + 2 * clock + grace (the latest a claim made before
///    the deadline can be finally decided, plus time to call settle or slash) refunds the account; release() (or
///    expire) returns an unslashed stake after that time.
///  Lying for one job then costs the stake whenever it is caught: with q the chance a false claim is defeated, it gains
///  at most (1 - q) * price - q * bondFor(price), negative for every q > price / (price + bond) (q > 1/2 at the floor).
///  The escrow never judges a result itself: correctness comes only from OVM0Dispute, so the same security
///  assumption holds (one honest watcher within the window; the chain is live and not censoring for clock seconds).
contract OmegaJobEscrow {
    enum Cond { CleanHalt, OutputEq, OutputLe, OutputGe }
    enum JobStatus { None, Open, Paid, Refunded }

    struct Account {
        address owner;
        address agent;
        address cosigner;
        bool revoked;
        uint64 validUntil;
        uint64 window;
        uint64 windowStart;
        uint64 maxStepsCap;
        uint128 maxPerJob;
        uint128 maxPerWindow;
        uint128 spentInWindow;
    }

    /// @dev what the agent signs; `key` is the idempotency key (one job per key, ever)
    struct JobReq {
        bytes32 key;
        bytes32 account;
        address executor;
        bytes32 prog;
        bytes32 inputs;
        uint64 maxSteps;
        uint128 price;
        uint8 cond;
        uint64 condArg;
        uint64 deadline; // last moment a claim for this job may be made
    }

    /// @dev One storage slot per job. The job's fields are not stored: records[key] (the EIP-712 struct hash, kept
    ///  anyway for idempotency) commits to all of them, settle/expire take them back as calldata and check that hash,
    ///  and Posted logs them for executors and watchers.
    struct Job {
        JobStatus status;
        uint64 postedAt;
        uint64 claimFloor; // only claims with a larger id were made after the current reservation (after the post before one)
        uint64 claimId; // the claim that settled it (0 for an expiry)
        bool bonded; // the executor's stake bondFor(price) is held for this job
    }

    struct Sig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    bytes32 public constant JOB_TYPEHASH = keccak256(
        "Job(bytes32 key,bytes32 account,address executor,bytes32 prog,bytes32 inputs,uint64 maxSteps,uint128 price,"
        "uint8 cond,uint64 condArg,uint64 deadline)");
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint32 public constant MIN_BOND_BPS = 10_000; // the stake is never below the price

    IERC20 public immutable token;
    OVM0Dispute public immutable dispute;
    uint64 public immutable grace;
    uint32 public immutable bondBps; // stake per job = price * bondBps / 10_000, rounded up
    mapping(bytes32 => Account) public accounts;
    mapping(bytes32 => uint256) public balanceOf; // free (unlocked) balance per account
    mapping(bytes32 => mapping(bytes32 => bool)) public programAllowed;
    mapping(bytes32 => mapping(address => bool)) public executorAllowed;
    mapping(bytes32 => bytes32) public records; // key => EIP-712 struct hash of the job it created
    mapping(bytes32 => Job) internal _jobs;
    mapping(uint256 => bytes32) public claimUsedBy; // dispute claim id => job key it settled or slashed
    mapping(address => uint256) public bondOf; // free (unreserved) stake per executor
    uint256 public locked; // sum of prices of open jobs
    uint256 public bondsHeld; // sum of stakes reserved for jobs

    error NotOwner();
    error AccountTaken();
    error SameKey();
    error BadSignature();
    error BadCosign();
    error KeyReuse();
    error DeadlinePassed();
    error ZeroAmount();
    error BadCondition();
    error MandateRevoked();
    error MandateExpired();
    error ProgramDenied();
    error ExecutorDenied();
    error OverPerJob();
    error OverWindow();
    error TooManySteps();
    error InsufficientBalance();
    error TokenTransferFailed();
    error JobNotOpen();
    error BadJob();
    error ClaimNotAccepted();
    error ClaimMismatch();
    error StaleClaim();
    error LateClaim();
    error ClaimUsed();
    error TooEarly();
    error TooLate();
    error BadBondRatio();
    error NotExecutor();
    error AlreadyBonded();
    error NotBonded();
    error InsufficientBond();
    error ClaimNotRejected();

    event Opened(bytes32 indexed account, address indexed owner);
    event Posted(bytes32 indexed key, bytes32 indexed account, address indexed executor, bytes32 prog, bytes32 inputs,
                 uint64 maxSteps, uint128 price, uint8 cond, uint64 condArg, uint64 deadline);
    event Paid(bytes32 indexed key, uint256 indexed claimId, address indexed executor, uint128 price, uint64 output);
    event Refunded(bytes32 indexed key, uint256 indexed claimId, uint64 output, uint8 trap); // claimId 0: expired
    event Reserved(bytes32 indexed key, address indexed executor, uint256 bond, uint64 claimFloor);
    event Slashed(bytes32 indexed key, uint256 indexed claimId, uint256 bond);
    event Released(bytes32 indexed key, uint256 bond);

    constructor(IERC20 token_, OVM0Dispute dispute_, uint64 grace_, uint32 bondBps_) {
        if (bondBps_ < MIN_BOND_BPS) revert BadBondRatio();
        (token, dispute, grace, bondBps) = (token_, dispute_, grace_, bondBps_);
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("OmegaJobEscrow"), keccak256("1"), block.chainid, address(this)));
    }

    modifier onlyOwner(bytes32 account) {
        if (accounts[account].owner != msg.sender) revert NotOwner();
        _;
    }

    // ---- owner policy ---------------------------------------------------------------------------------------------
    function open(bytes32 account) external {
        if (accounts[account].owner != address(0)) revert AccountTaken();
        accounts[account].owner = msg.sender;
        accounts[account].revoked = true; // nothing runs until setMandate
        emit Opened(account, msg.sender);
    }

    function deposit(bytes32 account, uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        balanceOf[account] += amount;
    }

    /// @notice A new agent key invalidates every unposted signature of the old one; posted jobs are unaffected.
    function setAgent(bytes32 account, address agent) external onlyOwner(account) {
        if (agent != address(0) && agent == accounts[account].cosigner) revert SameKey();
        accounts[account].agent = agent;
    }

    /// @notice address(0) turns the cosign requirement off.
    function setCosigner(bytes32 account, address cosigner) external onlyOwner(account) {
        if (cosigner != address(0) && cosigner == accounts[account].agent) revert SameKey();
        accounts[account].cosigner = cosigner;
    }

    function setMandate(bytes32 account, uint128 maxPerJob, uint128 maxPerWindow, uint64 window, uint64 validUntil,
                        uint64 maxStepsCap) external onlyOwner(account)
    {
        Account storage a = accounts[account];
        a.maxPerJob = maxPerJob;
        a.maxPerWindow = maxPerWindow;
        a.window = window;
        a.validUntil = validUntil;
        a.maxStepsCap = maxStepsCap;
        a.revoked = false;
    }

    function setProgram(bytes32 account, bytes32 prog, bool allowed) external onlyOwner(account) {
        programAllowed[account][prog] = allowed;
    }

    function setExecutor(bytes32 account, address executor, bool allowed) external onlyOwner(account) {
        executorAllowed[account][executor] = allowed;
    }

    function revoke(bytes32 account) external onlyOwner(account) {
        accounts[account].revoked = true;
    }

    /// @notice Only the free balance; prices locked in open jobs come back through settle/expire.
    function withdraw(bytes32 account, address to, uint256 amount) external onlyOwner(account) {
        if (balanceOf[account] < amount) revert InsufficientBalance();
        balanceOf[account] -= amount;
        if (!token.transfer(to, amount)) revert TokenTransferFailed();
    }

    // ---- executor stake ---------------------------------------------------------------------------------------------
    function depositBond(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        bondOf[msg.sender] += amount;
    }

    /// @notice Only the free stake; a reserved one comes back through release/expire (or goes to the account by slash).
    function withdrawBond(address to, uint256 amount) external {
        if (bondOf[msg.sender] < amount) revert InsufficientBond();
        bondOf[msg.sender] -= amount;
        if (!token.transfer(to, amount)) revert TokenTransferFailed();
    }

    function bondFor(uint128 price) public view returns (uint256) {
        return (uint256(price) * bondBps + 9_999) / 10_000;
    }

    // ---- intent -----------------------------------------------------------------------------------------------------
    function digestOf(JobReq calldata r) public view returns (bytes32 structHash, bytes32 digest) {
        structHash = keccak256(abi.encode(JOB_TYPEHASH, r.key, r.account, r.executor, r.prog, r.inputs, r.maxSteps,
                                          r.price, r.cond, r.condArg, r.deadline));
        digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function getJob(bytes32 key) external view returns (Job memory) {
        return _jobs[key];
    }

    /// @return fresh false if this exact job was already posted (idempotent replay; nothing is locked twice)
    /// @param cosig ignored when the account has no cosigner, required otherwise
    function post(JobReq calldata r, Sig calldata agentSig, Sig calldata cosig) external returns (bool fresh) {
        (bytes32 sh, bytes32 digest) = digestOf(r);
        bytes32 prior = records[r.key];
        if (prior != bytes32(0)) {
            if (prior != sh) revert KeyReuse();
            return false;
        }
        if (block.timestamp >= r.deadline) revert DeadlinePassed();
        if (r.price == 0) revert ZeroAmount();
        if (r.cond > uint8(Cond.OutputGe)) revert BadCondition();
        _authorize(accounts[r.account], digest, agentSig, cosig);
        _policy(accounts[r.account], r);
        records[r.key] = sh;
        _open(r);
        return true;
    }

    function _authorize(Account storage a, bytes32 digest, Sig calldata agentSig, Sig calldata cosig) internal view {
        if (a.agent == address(0) || _signer(digest, agentSig) != a.agent) revert BadSignature();
        if (a.cosigner != address(0) && _signer(digest, cosig) != a.cosigner) revert BadCosign();
    }

    function _open(JobReq calldata r) internal {
        balanceOf[r.account] -= r.price;
        locked += r.price;
        _jobs[r.key] = Job(JobStatus.Open, uint64(block.timestamp), uint64(dispute.claims()), 0, false);
        emit Posted(r.key, r.account, r.executor, r.prog, r.inputs, r.maxSteps, r.price, r.cond, r.condArg, r.deadline);
    }

    /// @dev the job `r` describes: reverts unless r hashes to what was posted under r.key (any field changed)
    function _job(JobReq calldata r) internal view returns (Job storage j) {
        (bytes32 sh,) = digestOf(r);
        if (records[r.key] != sh) revert BadJob();
        j = _jobs[r.key];
    }

    function _openJob(JobReq calldata r) internal view returns (Job storage j) {
        j = _job(r);
        if (j.status != JobStatus.Open) revert JobNotOpen();
    }

    function _policy(Account storage a, JobReq calldata r) internal {
        if (a.revoked) revert MandateRevoked();
        if (block.timestamp >= a.validUntil || r.deadline > a.validUntil) revert MandateExpired();
        if (!programAllowed[r.account][r.prog]) revert ProgramDenied();
        if (!executorAllowed[r.account][r.executor]) revert ExecutorDenied();
        if (r.maxSteps > a.maxStepsCap || r.maxSteps > dispute.stepCap()) revert TooManySteps();
        if (r.price > a.maxPerJob) revert OverPerJob();
        if (block.timestamp >= uint256(a.windowStart) + a.window) {
            a.windowStart = uint64(block.timestamp);
            a.spentInWindow = 0;
        }
        if (uint256(a.spentInWindow) + r.price > a.maxPerWindow) revert OverWindow();
        if (balanceOf[r.account] < r.price) revert InsufficientBalance();
        a.spentInWindow += r.price; // a later refund does not give window budget back
    }

    // ---- stake ------------------------------------------------------------------------------------------------------
    /// @notice The job's executor stakes bondFor(price) for an open job before its deadline; claims made before this call
    ///  no longer count for the job. After a slash the executor may stake again and retry until the deadline.
    function reserve(JobReq calldata r) external {
        Job storage j = _openJob(r);
        if (msg.sender != r.executor) revert NotExecutor();
        if (j.bonded) revert AlreadyBonded();
        if (block.timestamp > r.deadline) revert DeadlinePassed();
        uint256 b = bondFor(r.price);
        if (bondOf[msg.sender] < b) revert InsufficientBond();
        bondOf[msg.sender] -= b;
        bondsHeld += b;
        (j.bonded, j.claimFloor) = (true, uint64(dispute.claims()));
        emit Reserved(r.key, msg.sender, b, j.claimFloor);
    }

    /// @notice Anyone may call until expiresAt, with a claim that could have settled the job (see settle) and that
    ///  OVM0Dispute Rejected: the stake goes to the account's free balance. Works after the job was settled with another
    ///  claim too, so a second, honest claim cannot shield a false one.
    function slash(JobReq calldata r, uint256 claimId) external {
        Job storage j = _job(r);
        if (!j.bonded) revert NotBonded();
        if (block.timestamp > expiresAt(r.deadline)) revert TooLate();
        OVM0Dispute.Claim memory c = _claimFor(r, j, claimId);
        if (c.status != OVM0Dispute.ClaimStatus.Rejected) revert ClaimNotRejected();
        claimUsedBy[claimId] = r.key;
        j.bonded = false;
        uint256 b = bondFor(r.price);
        bondsHeld -= b;
        balanceOf[r.account] += b;
        emit Slashed(r.key, claimId, b);
    }

    /// @notice Return an unslashed stake to the executor's free stake once no slash can come (after expiresAt).
    function release(JobReq calldata r) external {
        Job storage j = _job(r);
        if (!j.bonded) revert NotBonded();
        if (block.timestamp <= expiresAt(r.deadline)) revert TooEarly();
        _release(r, j);
    }

    function _release(JobReq calldata r, Job storage j) internal {
        j.bonded = false;
        uint256 b = bondFor(r.price);
        bondsHeld -= b;
        bondOf[r.executor] += b;
        emit Released(r.key, b);
    }

    /// @dev a claim by the job's executor for exactly its computation, made after the current reservation and by the
    ///  deadline, not yet used for any job (its status is the caller's to check)
    function _claimFor(JobReq calldata r, Job storage j, uint256 claimId)
        internal view returns (OVM0Dispute.Claim memory c)
    {
        if (claimId <= j.claimFloor) revert StaleClaim();
        if (claimUsedBy[claimId] != bytes32(0)) revert ClaimUsed();
        c = dispute.getClaim(claimId);
        if (c.defender != r.executor || c.prog != r.prog || c.inputs != r.inputs || c.maxSteps != r.maxSteps) {
            revert ClaimMismatch();
        }
        if (c.deadline - dispute.window() > r.deadline) revert LateClaim(); // claim time = window end - window
    }

    // ---- settlement -------------------------------------------------------------------------------------------------
    /// @notice Anyone may call, with the job exactly as posted (see Posted). Pays the executor or refunds the account
    ///  according to the verified result. The stake stays held until expiresAt (see slash).
    function settle(JobReq calldata r, uint256 claimId) external returns (bool paid) {
        Job storage j = _openJob(r);
        if (!j.bonded) revert NotBonded();
        OVM0Dispute.Claim memory c = _claimFor(r, j, claimId);
        if (c.status != OVM0Dispute.ClaimStatus.Accepted) revert ClaimNotAccepted();
        claimUsedBy[claimId] = r.key;
        j.claimId = uint64(claimId);
        locked -= r.price;
        paid = c.trap == 0 && _meets(r.cond, c.output, r.condArg);
        if (paid) {
            j.status = JobStatus.Paid;
            if (!token.transfer(r.executor, r.price)) revert TokenTransferFailed();
            emit Paid(r.key, claimId, r.executor, r.price, c.output);
        } else {
            j.status = JobStatus.Refunded;
            balanceOf[r.account] += r.price;
            emit Refunded(r.key, claimId, c.output, c.trap);
        }
    }

    /// @notice Refund a job that nobody settled in time (the job exactly as posted), and return an unslashed stake.
    function expire(JobReq calldata r) external {
        Job storage j = _openJob(r);
        if (block.timestamp <= expiresAt(r.deadline)) revert TooEarly();
        j.status = JobStatus.Refunded;
        locked -= r.price;
        balanceOf[r.account] += r.price;
        emit Refunded(r.key, 0, 0, 0);
        if (j.bonded) _release(r, j);
    }

    /// @return the time after which a job with this claim deadline can be expired
    function expiresAt(uint64 deadline) public view returns (uint256) {
        return uint256(deadline) + dispute.window() + 2 * uint256(dispute.clock()) + grace;
    }

    function _meets(uint8 cond, uint64 output, uint64 arg) internal pure returns (bool) {
        if (cond == uint8(Cond.CleanHalt)) return true;
        if (cond == uint8(Cond.OutputEq)) return output == arg;
        if (cond == uint8(Cond.OutputLe)) return output <= arg;
        return output >= arg;
    }

    /// @dev -> recovered signer, or address(0) for malformed / high-s signatures (callers reject a zero key first)
    function _signer(bytes32 digest, Sig calldata g) internal pure returns (address) {
        if (uint256(g.s) > HALF_N || (g.v != 27 && g.v != 28)) return address(0);
        return ecrecover(digest, g.v, g.r, g.s);
    }
}
