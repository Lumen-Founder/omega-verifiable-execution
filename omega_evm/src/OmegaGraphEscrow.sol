// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "./OmegaSettlement.sol";
import {OVM0Dispute} from "./OVM0Dispute.sol";

/// @title OMEGA dependency-graph escrow (W1, docs/adr/ADR-0011): jobs that consume other jobs' unfinal results, with
///  the whole graph's liability reserved up front and payment only once every ancestor is final.
/// @notice A node is one job plus the one claim its executor bound to it. A child names parent jobs of the same account
///  and, through the signed `parents` hash, the exact claims bound to them; its inputs must start with those claims'
///  outputs (the contract recomputes the OVM-0 inputs commitment). So a child can be posted and executed while its
///  parents are still being judged (early execution), but:
///  - settle() pays only when the node's own claim is Accepted and every ancestor is FINAL (no payment before that,
///    so nothing ever has to be clawed back);
///  - every node whose bound claim can still be rejected (CLAIMED) holds a cover stake, reserved by its executor at
///    reserve() next to the usual bond, and the D-rule keeps cover(a) >= L(a) = sum of owed (= comp + ext) over the
///    still-unresolved descendant SET of a (each descendant counted once however many paths reach it): a child is
///    refused (ExposureExceeded, nothing changes) unless every CLAIMED ancestor has room for its owed;
///  - reject() of a false bound claim refunds the price, moves the bond and the cover beyond L(a) to the account and
///    keeps L(a) for the descendants; voidNode() of each descendant refunds its price and pays its comp to its executor
///    (only if its own bound claim was Accepted, else to the account) and its ext to the account, out of one rejected
///    ancestor's cover. The bond and the cover are separate ledgers (bondsHeld, coversHeld).
///  Correctness still comes only from each node's referee (an OVM0Dispute-like contract allowed by the account owner
///  with a grade; a node's grade is the minimum over itself and its ancestors). Assumed of every referee: an Accepted
///  claim never becomes Rejected (A-REF). Not covered: a referee that never decides (the node and its descendants
///  expire, honest executors get no comp), unreported external effects, anything outside this contract.
contract OmegaGraphEscrow {
    enum Cond { CleanHalt, OutputEq, OutputLe, OutputGe }
    enum Status { None, Posted, Claimed, Verified, Final, Rejected, Voided, Expired }

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

    /// @dev what the agent signs; `key` is the idempotency key; `parents` = keccak256(abi.encode(parentKeys,
    ///  parentClaimIds)) for the claims bound to the parents when the agent signed (bytes32(0) for a root)
    struct JobReq {
        bytes32 key;
        bytes32 account;
        address executor;
        address referee;
        bytes32 prog;
        bytes32 inputs;
        uint64 maxSteps;
        uint128 price;
        uint128 comp; // paid to this node's executor if an ancestor is rejected and its own claim was Accepted
        uint128 ext; // declared external exposure, paid to the account if an ancestor is rejected
        uint128 cover; // this node's executor stakes it for its descendants' owed
        uint8 cond;
        uint64 condArg;
        uint64 deadline; // last moment a claim for this job may be made
        bytes32 parents;
    }

    struct Node {
        Status status;
        uint8 grade;
        bool bonded; // bondFor(price) held for this node
        bool coverHeld; // `cover` held for this node's descendants
        uint64 deadline;
        uint64 claimFloor; // only claims with a larger id were made after the reservation
        uint64 claimId; // the bound claim (0: none)
        address referee;
        uint8 cond;
        uint64 condArg;
        address executor;
        uint64 maxSteps;
        bytes32 account;
        bytes32 prog;
        bytes32 inputs;
        uint128 price;
        uint128 comp;
        uint128 ext;
        uint128 cover; // what is held (for a REJECTED node: what is left for its unresolved descendants)
        uint128 liab; // L: owed of the unresolved descendants reserved on this node while it held cover
        uint64 expiry; // fixed at post: deadline + the referee's window + 2 * clock + grace (ADR-0012 D1)
    }

    struct Sig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    bytes32 public constant JOB_TYPEHASH = keccak256(
        "Job(bytes32 key,bytes32 account,address executor,address referee,bytes32 prog,bytes32 inputs,uint64 maxSteps,"
        "uint128 price,uint128 comp,uint128 ext,uint128 cover,uint8 cond,uint64 condArg,uint64 deadline,bytes32 parents)");
    bytes32 private immutable _DOMAIN; // for the deployment chain id; recomputed on any other (a fork), ADR-0012 D12
    uint256 private immutable _CHAIN_ID;
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint32 public constant MIN_BOND_BPS = 10_000;
    uint256 public constant MAX_PARENTS = 8;
    uint256 public constant MAX_ANCESTORS = 32;
    uint256 public constant MAX_INPUTS = 64;
    uint256 public constant REFEREE_GAS = 200_000; // cap on a status read that must not be able to block expiry
    uint256 public constant MAX_REFEREE_DELAY = 90 days; // longest window or clock a referee may report: bounds expiry

    IERC20 public immutable token;
    uint64 public immutable grace;
    uint32 public immutable bondBps;
    mapping(bytes32 => Account) public accounts;
    mapping(bytes32 => uint256) public balanceOf; // free balance per account
    mapping(bytes32 => mapping(bytes32 => bool)) public programAllowed;
    mapping(bytes32 => mapping(address => bool)) public executorAllowed;
    mapping(bytes32 => mapping(address => uint8)) public refereeGrade; // 0: not allowed
    mapping(bytes32 => bytes32) public records; // key => EIP-712 struct hash
    mapping(bytes32 => Node) internal _nodes;
    mapping(bytes32 => bytes32[]) internal _anc; // ancestor set, parents first, fixed at post
    mapping(address => mapping(uint256 => bytes32)) public claimUsedBy; // referee => claim id => node it bound/slashed
    mapping(address => uint256) public bondOf; // free stake (and received comp) per executor
    uint256 public locked; // prices of open nodes
    uint256 public bondsHeld;
    uint256 public coversHeld;
    uint256 private _lock = 1;

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
    error RefereeDenied();
    error OverPerJob();
    error OverWindow();
    error TooManySteps();
    error InsufficientBalance();
    error TokenTransferFailed();
    error BadBondRatio();
    error Reentrancy();
    error TooManyParents();
    error TooManyAncestors();
    error TooManyInputs();
    error UnknownParent();
    error ForeignParent();
    error DuplicateParent();
    error ParentNotBound();
    error ParentRejected();
    error BadParents();
    error BadInputs();
    error AncestorDead();
    error AncestorExpired();
    error ExposureExceeded();
    error WrongStatus();
    error NotExecutor();
    error AlreadyBonded();
    error NotBonded();
    error InsufficientBond();
    error StaleClaim();
    error ClaimUsed();
    error ClaimMismatch();
    error LateClaim();
    error ClaimNotLive();
    error ClaimNotAccepted();
    error ClaimNotRejected();
    error ClaimPending();
    error ClaimRejected();
    error AncestorNotFinal();
    error NoRejectedAncestor();
    error TooEarly();
    error TooLate();
    error ForeignKey();
    error Settleable();
    error AccountNotOpen();
    error BadRefereeDelay();

    event Opened(bytes32 indexed account, address indexed owner);
    event Posted(bytes32 indexed key, bytes32 indexed account, address indexed executor, address referee, bytes32 parents,
                 uint8 grade);
    event Reserved(bytes32 indexed key, uint256 bond, uint256 cover, uint64 claimFloor);
    event Bound(bytes32 indexed key, uint256 indexed claimId);
    event Verified(bytes32 indexed key);
    event Settled(bytes32 indexed key, bool paid, uint256 price);
    event Rejected(bytes32 indexed key, uint256 bond, uint256 surplus);
    event Voided(bytes32 indexed key, bytes32 indexed payer, uint256 comp, bool compToExecutor, uint256 ext);
    event Expired(bytes32 indexed key);
    event Released(bytes32 indexed key, uint256 bond);
    event Slashed(bytes32 indexed key, uint256 indexed claimId, uint256 bond);

    constructor(IERC20 token_, uint64 grace_, uint32 bondBps_) {
        if (bondBps_ < MIN_BOND_BPS) revert BadBondRatio();
        (token, grace, bondBps) = (token_, grace_, bondBps_);
        (_DOMAIN, _CHAIN_ID) = (_domain(), block.chainid);
    }

    function _domain() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("OmegaGraphEscrow"), keccak256("1"), block.chainid, address(this)));
    }

    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == _CHAIN_ID ? _DOMAIN : _domain();
    }

    modifier onlyOwner(bytes32 account) {
        if (accounts[account].owner != msg.sender) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    // ---- owner policy (as OmegaJobEscrow, plus allowed referees with a grade) ------------------------------------
    function open(bytes32 account) external {
        if (accounts[account].owner != address(0)) revert AccountTaken();
        accounts[account].owner = msg.sender;
        accounts[account].revoked = true;
        emit Opened(account, msg.sender);
    }

    /// @notice Into an opened account only: a deposit into an unopened id could be taken by whoever opens it first.
    function deposit(bytes32 account, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (accounts[account].owner == address(0)) revert AccountNotOpen();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        balanceOf[account] += amount;
    }

    function setAgent(bytes32 account, address agent) external onlyOwner(account) {
        if (agent != address(0) && agent == accounts[account].cosigner) revert SameKey();
        accounts[account].agent = agent;
    }

    function setCosigner(bytes32 account, address cosigner) external onlyOwner(account) {
        if (cosigner != address(0) && cosigner == accounts[account].agent) revert SameKey();
        accounts[account].cosigner = cosigner;
    }

    function setMandate(bytes32 account, uint128 maxPerJob, uint128 maxPerWindow, uint64 window, uint64 validUntil,
                        uint64 maxStepsCap) external onlyOwner(account)
    {
        Account storage a = accounts[account];
        (a.maxPerJob, a.maxPerWindow, a.window, a.validUntil, a.maxStepsCap) =
            (maxPerJob, maxPerWindow, window, validUntil, maxStepsCap);
        a.revoked = false;
    }

    function setProgram(bytes32 account, bytes32 prog, bool allowed) external onlyOwner(account) {
        programAllowed[account][prog] = allowed;
    }

    function setExecutor(bytes32 account, address executor, bool allowed) external onlyOwner(account) {
        executorAllowed[account][executor] = allowed;
    }

    /// @notice grade 0 denies the referee for new jobs; posted jobs keep theirs.
    function setReferee(bytes32 account, address referee, uint8 grade) external onlyOwner(account) {
        refereeGrade[account][referee] = grade;
    }

    function revoke(bytes32 account) external onlyOwner(account) {
        accounts[account].revoked = true;
    }

    function withdraw(bytes32 account, address to, uint256 amount) external onlyOwner(account) nonReentrant {
        if (balanceOf[account] < amount) revert InsufficientBalance();
        balanceOf[account] -= amount;
        if (!token.transfer(to, amount)) revert TokenTransferFailed();
    }

    // ---- executor stake -------------------------------------------------------------------------------------------
    function depositBond(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        bondOf[msg.sender] += amount;
    }

    function withdrawBond(address to, uint256 amount) external nonReentrant {
        if (bondOf[msg.sender] < amount) revert InsufficientBond();
        bondOf[msg.sender] -= amount;
        if (!token.transfer(to, amount)) revert TokenTransferFailed();
    }

    function bondFor(uint128 price) public view returns (uint256) {
        return (uint256(price) * bondBps + 9_999) / 10_000;
    }

    // ---- views ----------------------------------------------------------------------------------------------------
    function digestOf(JobReq calldata r) public view returns (bytes32 structHash, bytes32 digest) {
        structHash = keccak256(abi.encode(JOB_TYPEHASH, r));
        digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function getNode(bytes32 key) external view returns (Node memory) {
        return _nodes[key];
    }

    function ancestorsOf(bytes32 key) external view returns (bytes32[] memory) {
        return _anc[key];
    }

    /// @return the time after which the node can be expired (claim deadline + the referee's latest decision + grace),
    ///  fixed at post so that a referee that later fails cannot block expiry (ADR-0012 D1)
    function expiresAt(bytes32 key) public view returns (uint256) {
        return _nodes[key].expiry;
    }

    /// @notice The OVM-0 inputs commitment (omega_compute.evm_step.inputs_commit): leaves keccak(i, x) padded with
    ///  zero words to a power of two, a keccak Merkle root, then keccak(root, n).
    function inputsCommit(uint256[] calldata vals) public pure returns (bytes32) {
        uint256 n = vals.length;
        uint256 size = 1;
        while (size < n) size <<= 1;
        bytes32[] memory lv = new bytes32[](size);
        for (uint256 i; i < n; ++i) lv[i] = keccak256(abi.encode(i, vals[i]));
        for (uint256 w = size; w > 1; w >>= 1) {
            for (uint256 i; i < w / 2; ++i) lv[i] = keccak256(abi.encodePacked(lv[2 * i], lv[2 * i + 1]));
        }
        return keccak256(abi.encode(lv[0], n));
    }

    // ---- post: intent, policy, links, D-rule ----------------------------------------------------------------------
    /// @return fresh false for an idempotent replay of the exact same job (nothing is locked or reserved twice)
    /// @param parentKeys the parent jobs (same account, each with a bound claim); empty for a root
    /// @param inputVals the job's input values; for a child they must start with the parents' bound outputs, in order
    function post(JobReq calldata r, bytes32[] calldata parentKeys, uint256[] calldata inputVals, Sig calldata agentSig,
                  Sig calldata cosig) external nonReentrant returns (bool fresh)
    {
        // the key's first 12 bytes are keccak(account)'s: no other account can take this account's keys (D10)
        if (bytes12(r.key) != bytes12(keccak256(abi.encode(r.account)))) revert ForeignKey();
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
        records[r.key] = sh;
        _create(r, parentKeys, inputVals);
        return true;
    }

    function _authorize(Account storage a, bytes32 digest, Sig calldata agentSig, Sig calldata cosig) internal view {
        if (a.agent == address(0) || _signer(digest, agentSig) != a.agent) revert BadSignature();
        if (a.cosigner != address(0) && _signer(digest, cosig) != a.cosigner) revert BadCosign();
    }

    function _create(JobReq calldata r, bytes32[] calldata parentKeys, uint256[] calldata inputVals) internal {
        uint8 grade = _policy(accounts[r.account], r);
        bytes32[] memory anc;
        (anc, grade) = _links(r, parentKeys, inputVals, grade);
        _reserveLiability(anc, uint256(r.comp) + r.ext);
        _store(r, grade);
        bytes32[] storage stored = _anc[r.key];
        for (uint256 i; i < anc.length; ++i) stored.push(anc[i]);
        balanceOf[r.account] -= r.price;
        locked += r.price;
        emit Posted(r.key, r.account, r.executor, r.referee, r.parents, grade);
    }

    function _policy(Account storage a, JobReq calldata r) internal returns (uint8 grade) {
        if (a.revoked) revert MandateRevoked();
        if (block.timestamp >= a.validUntil || r.deadline > a.validUntil) revert MandateExpired();
        if (!programAllowed[r.account][r.prog]) revert ProgramDenied();
        if (!executorAllowed[r.account][r.executor]) revert ExecutorDenied();
        grade = refereeGrade[r.account][r.referee];
        if (grade == 0) revert RefereeDenied();
        if (r.maxSteps > a.maxStepsCap || r.maxSteps > OVM0Dispute(r.referee).stepCap()) revert TooManySteps();
        if (r.price > a.maxPerJob) revert OverPerJob();
        if (block.timestamp >= uint256(a.windowStart) + a.window) {
            a.windowStart = uint64(block.timestamp);
            a.spentInWindow = 0;
        }
        if (uint256(a.spentInWindow) + r.price > a.maxPerWindow) revert OverWindow();
        if (balanceOf[r.account] < r.price) revert InsufficientBalance();
        a.spentInWindow += r.price;
    }

    /// @dev parents checked one by one, the signed parents hash and inputs checked, -> the ancestor set (parents in
    ///  order, then each parent's stored ancestors, first occurrence kept) and the grade (minimum over the parents)
    function _links(JobReq calldata r, bytes32[] calldata ps, uint256[] calldata vals, uint8 grade)
        internal view returns (bytes32[] memory anc, uint8 g)
    {
        g = grade;
        if (ps.length == 0) {
            if (r.parents != bytes32(0)) revert BadParents();
            return (new bytes32[](0), g);
        }
        if (ps.length > MAX_PARENTS) revert TooManyParents();
        if (vals.length > MAX_INPUTS) revert TooManyInputs();
        if (vals.length < ps.length) revert BadInputs();
        uint256[] memory cids = new uint256[](ps.length);
        anc = new bytes32[](MAX_ANCESTORS);
        uint256 n;
        for (uint256 i; i < ps.length; ++i) {
            for (uint256 j; j < i; ++j) if (ps[j] == ps[i]) revert DuplicateParent();
            uint8 pg;
            (cids[i], pg) = _parent(r.account, ps[i], vals[i]);
            if (pg < g) g = pg;
            n = _add(anc, n, ps[i]);
            bytes32[] storage pa = _anc[ps[i]];
            for (uint256 k; k < pa.length; ++k) n = _add(anc, n, pa[k]);
        }
        if (keccak256(abi.encode(ps, cids)) != r.parents) revert BadParents();
        if (inputsCommit(vals) != r.inputs) revert BadInputs();
        assembly {
            mstore(anc, n)
        }
    }

    function _parent(bytes32 account, bytes32 key, uint256 val) internal view returns (uint256 cid, uint8 grade) {
        Node storage p = _nodes[key];
        if (p.status == Status.None) revert UnknownParent(); // also every future key and the child itself
        if (p.account != account) revert ForeignParent();
        if (p.claimId == 0) revert ParentNotBound();
        OVM0Dispute.Claim memory c = OVM0Dispute(p.referee).getClaim(p.claimId);
        if (c.status == OVM0Dispute.ClaimStatus.Rejected) revert ParentRejected();
        if (val != c.output) revert BadInputs();
        (cid, grade) = (p.claimId, p.grade);
    }

    function _add(bytes32[] memory set, uint256 n, bytes32 k) internal pure returns (uint256) {
        for (uint256 i; i < n; ++i) if (set[i] == k) return n;
        if (n == MAX_ANCESTORS) revert TooManyAncestors();
        set[n] = k;
        return n + 1;
    }

    /// @dev the D-rule, all or nothing: every ancestor alive (status pass first, so the error does not depend on the
    ///  order), then room for `owed` on every CLAIMED ancestor, reserved once per ancestor
    function _reserveLiability(bytes32[] memory anc, uint256 owed) internal {
        for (uint256 i; i < anc.length; ++i) {
            Status s = _nodes[anc[i]].status;
            if (s == Status.Rejected || s == Status.Voided) revert AncestorDead();
            if (s == Status.Expired) revert AncestorExpired();
        }
        for (uint256 i; i < anc.length; ++i) {
            Node storage a = _nodes[anc[i]];
            if (a.status != Status.Claimed) continue; // VERIFIED / FINAL can no longer be rejected (A-REF)
            if (uint256(a.cover) - a.liab < owed) revert ExposureExceeded();
            a.liab += uint128(owed); // <= cover < 2^128
        }
    }

    function _store(JobReq calldata r, uint8 grade) internal {
        Node storage d = _nodes[r.key];
        d.status = Status.Posted;
        d.grade = grade;
        d.deadline = r.deadline;
        d.referee = r.referee;
        d.cond = r.cond;
        d.condArg = r.condArg;
        d.executor = r.executor;
        d.maxSteps = r.maxSteps;
        d.account = r.account;
        d.prog = r.prog;
        d.inputs = r.inputs;
        d.price = r.price;
        d.comp = r.comp;
        d.ext = r.ext;
        d.cover = r.cover;
        OVM0Dispute ref = OVM0Dispute(r.referee);
        (uint256 w, uint256 k) = (ref.window(), ref.clock());
        if (w > MAX_REFEREE_DELAY || k > MAX_REFEREE_DELAY) revert BadRefereeDelay(); // else expire could wait forever
        uint256 e = uint256(r.deadline) + w + 2 * k + grace;
        d.expiry = e > type(uint64).max ? type(uint64).max : uint64(e); // saturate: never wrap into the past (D8)
    }

    // ---- executor: stake, bind ------------------------------------------------------------------------------------
    /// @notice Once per node: the executor stakes bondFor(price) + cover before claiming; claims made before this call
    ///  never count for the node. There is no second reservation (a retry is a new job).
    function reserve(bytes32 key) external nonReentrant {
        Node storage d = _nodes[key];
        if (d.status != Status.Posted) revert WrongStatus();
        if (msg.sender != d.executor) revert NotExecutor();
        if (d.bonded || d.coverHeld) revert AlreadyBonded();
        if (block.timestamp > d.deadline) revert DeadlinePassed();
        uint256 b = bondFor(d.price);
        if (bondOf[msg.sender] < b + d.cover) revert InsufficientBond();
        bondOf[msg.sender] -= b + d.cover;
        bondsHeld += b;
        coversHeld += d.cover;
        (d.bonded, d.coverHeld, d.claimFloor) = (true, true, uint64(OVM0Dispute(d.referee).claims()));
        emit Reserved(key, b, d.cover, d.claimFloor);
    }

    /// @notice The executor fixes the node's result: one of its claims for exactly this computation, made after the
    ///  reservation and by the deadline, unused, not (yet) rejected. Children then bind to this claim.
    function bind(bytes32 key, uint256 claimId) external nonReentrant {
        Node storage d = _nodes[key];
        if (d.status != Status.Posted) revert WrongStatus();
        if (msg.sender != d.executor) revert NotExecutor();
        if (!d.bonded) revert NotBonded();
        OVM0Dispute.ClaimStatus s = _claimFor(d, claimId).status;
        if (s != OVM0Dispute.ClaimStatus.Claimed && s != OVM0Dispute.ClaimStatus.Accepted) revert ClaimNotLive();
        claimUsedBy[d.referee][claimId] = key;
        (d.claimId, d.status) = (uint64(claimId), Status.Claimed);
        emit Bound(key, claimId);
    }

    function _claimFor(Node storage d, uint256 claimId) internal view returns (OVM0Dispute.Claim memory c) {
        if (claimId <= d.claimFloor) revert StaleClaim();
        if (claimId > type(uint64).max) revert ClaimMismatch(); // stored as uint64; never truncated
        if (claimUsedBy[d.referee][claimId] != bytes32(0)) revert ClaimUsed();
        OVM0Dispute ref = OVM0Dispute(d.referee);
        c = ref.getClaim(claimId);
        if (c.defender != d.executor || c.prog != d.prog || c.inputs != d.inputs || c.maxSteps != d.maxSteps) {
            revert ClaimMismatch();
        }
        if (c.deadline - ref.window() > d.deadline) revert LateClaim();
    }

    function _boundStatus(Node storage d) internal view returns (OVM0Dispute.ClaimStatus) {
        return OVM0Dispute(d.referee).getClaim(d.claimId).status;
    }

    /// @dev the bound claim as far as the referee can say: 1 Accepted, 2 Rejected, 0 anything else, including a
    ///  revert, too little return data, a status outside the enum, a word that settle's typed decoder would refuse or a
    ///  call that burns its gas (D1, D9). A plain staticcall with a gas cap: try/catch would not catch an answer that
    ///  fails to decode. Calling such an answer unknown matters: expire must never wait for a settle that cannot run.
    function _acceptedOrUnknown(Node storage d) internal view returns (uint8) {
        (bool ok, bytes memory ret) = d.referee.staticcall{gas: REFEREE_GAS}(
            abi.encodeWithSelector(OVM0Dispute.getClaim.selector, uint256(d.claimId)));
        if (!ok || ret.length < 352) return 0; // the Claim struct is 11 static words
        uint256 st;
        uint256 high;
        assembly {
            let p := add(ret, 32)
            st := mload(add(p, 224)) // word 7: status
            high := or(shr(160, mload(p)), // word 0: defender (address)
                or(shr(64, mload(add(p, 96))), // words 3, 4, 5: maxSteps, n, deadline (uint64)
                or(shr(64, mload(add(p, 128))),
                or(shr(64, mload(add(p, 160))),
                or(shr(32, mload(add(p, 192))), // word 6: open (uint32)
                or(shr(64, mload(add(p, 288))), // word 9: output (uint64)
                shr(8, mload(add(p, 320))))))))) // word 10: trap (uint8)
        }
        if (high != 0) return 0;
        return st == uint256(OVM0Dispute.ClaimStatus.Accepted) ? 1 : st == uint256(OVM0Dispute.ClaimStatus.Rejected)
            ? 2 : 0;
    }

    /// @dev an ancestor is out for good: this node can never be settled
    function _ancestorEnded(bytes32 key) internal view returns (bool) {
        bytes32[] storage anc = _anc[key];
        for (uint256 i; i < anc.length; ++i) {
            Status s = _nodes[anc[i]].status;
            if (s == Status.Rejected || s == Status.Voided || s == Status.Expired) return true;
        }
        return false;
    }

    // ---- verification and settlement ------------------------------------------------------------------------------
    /// @notice Anyone: the bound claim is Accepted, so this node can no longer be rejected and its cover goes back to
    ///  its executor; payment still waits for every ancestor to be final (settle).
    function verify(bytes32 key) external nonReentrant {
        Node storage d = _nodes[key];
        if (d.status != Status.Claimed) revert WrongStatus();
        if (_boundStatus(d) != OVM0Dispute.ClaimStatus.Accepted) revert ClaimNotAccepted();
        d.status = Status.Verified;
        _releaseCover(d);
        emit Verified(key);
    }

    /// @notice Anyone: own claim Accepted and every ancestor FINAL -> FINAL; credits the executor if the result halted
    ///  cleanly and meets the condition, refunds the account otherwise. The bond stays held until expiresAt (slash).
    ///  Payment is a credit (withdrawBond), never a token call: a payee the token refuses (a USDC blacklist) must not
    ///  stop this node and its descendants from settling, because expire refuses a settleable node.
    function settle(bytes32 key) external nonReentrant returns (bool paid) {
        Node storage d = _nodes[key];
        if (d.status != Status.Claimed && d.status != Status.Verified) revert WrongStatus();
        OVM0Dispute.Claim memory c = OVM0Dispute(d.referee).getClaim(d.claimId);
        if (c.status != OVM0Dispute.ClaimStatus.Accepted) revert ClaimNotAccepted();
        bytes32[] storage anc = _anc[key];
        for (uint256 i; i < anc.length; ++i) if (_nodes[anc[i]].status != Status.Final) revert AncestorNotFinal();
        d.status = Status.Final;
        if (d.coverHeld) _releaseCover(d);
        uint256 price = d.price;
        locked -= price;
        paid = c.trap == 0 && _meets(d.cond, c.output, d.condArg);
        emit Settled(key, paid, price);
        if (paid) bondOf[d.executor] += price;
        else balanceOf[d.account] += price;
    }

    // ---- rejection, voiding ---------------------------------------------------------------------------------------
    /// @notice Anyone: the bound claim was Rejected. Refund, bond to the account, cover beyond L to the account, L kept
    ///  for the descendants; this node's own owed is released from every ancestor that reserved it.
    function reject(bytes32 key) external nonReentrant {
        Node storage a = _nodes[key];
        if (a.status != Status.Claimed) revert WrongStatus();
        if (_boundStatus(a) != OVM0Dispute.ClaimStatus.Rejected) revert ClaimNotRejected();
        a.status = Status.Rejected;
        uint256 price = a.price;
        locked -= price;
        uint256 toAccount = price;
        uint256 b;
        if (a.bonded) {
            a.bonded = false;
            b = bondFor(a.price);
            bondsHeld -= b;
        }
        uint256 surplus = uint256(a.cover) - a.liab; // CLAIMED always holds its cover
        a.cover = a.liab;
        coversHeld -= surplus;
        toAccount += b + surplus + _resolve(key, uint256(a.comp) + a.ext, bytes32(0));
        balanceOf[a.account] += toAccount;
        emit Rejected(key, b, surplus);
    }

    /// @notice Anyone, for a node with a REJECTED ancestor: VOIDED, price refunded, comp to its executor if its own
    ///  bound claim was Accepted (else to the account), ext to the account, paid from the first rejected ancestor's
    ///  cover. Waits while its own bound claim is undecided (it may be a lie of its own: then use reject).
    function voidNode(bytes32 key) external nonReentrant {
        Node storage d = _nodes[key];
        Status s = d.status;
        bool honest;
        if (s == Status.Claimed) {
            OVM0Dispute.ClaimStatus cs = _boundStatus(d);
            if (cs == OVM0Dispute.ClaimStatus.Rejected) revert ClaimRejected();
            if (cs != OVM0Dispute.ClaimStatus.Accepted) revert ClaimPending();
            honest = true;
        } else if (s == Status.Verified) {
            honest = true; // Accepted when verified (A-REF)
        } else if (s == Status.Expired) {
            honest = d.claimId != 0 && _acceptedOrUnknown(d) == 1; // a failed referee: comp to the account (D1)
        } else if (s != Status.Posted) {
            revert WrongStatus();
        } else if (d.bonded && block.timestamp <= uint256(d.deadline) + grace) {
            revert ClaimPending(); // staked and may hold an honest claim whose bind is on its way (re-audit 2026-11-03 F5)
        }
        bytes32 payer = _firstRejected(key);
        d.status = Status.Voided;
        uint256 toAccount;
        if (s != Status.Expired) {
            locked -= d.price;
            toAccount = d.price;
        }
        if (d.coverHeld) _releaseCover(d);
        uint256 comp = d.comp;
        toAccount += d.ext + _resolve(key, comp + d.ext, payer);
        if (honest) bondOf[d.executor] += comp;
        else toAccount += comp;
        balanceOf[d.account] += toAccount;
        emit Voided(key, payer, comp, honest, d.ext);
    }

    function _firstRejected(bytes32 key) internal view returns (bytes32) {
        bytes32[] storage anc = _anc[key];
        for (uint256 i; i < anc.length; ++i) if (_nodes[anc[i]].status == Status.Rejected) return anc[i];
        revert NoRejectedAncestor();
    }

    /// @dev x (with `owed`) is resolved: every ancestor still holding cover drops it from L; a rejected one also gives up
    ///  that part of its cover, to the payees if it is `payer` (the caller pays them), else to the account (returned)
    function _resolve(bytes32 x, uint256 owed, bytes32 payer) internal returns (uint256 toAccount) {
        bytes32[] storage anc = _anc[x];
        for (uint256 i; i < anc.length; ++i) {
            Node storage b = _nodes[anc[i]];
            if (!b.coverHeld) continue;
            b.liab -= uint128(owed);
            if (b.status == Status.Rejected) {
                b.cover -= uint128(owed);
                coversHeld -= owed;
                if (anc[i] != payer) toAccount += owed;
            }
        }
    }

    function _releaseCover(Node storage d) internal {
        d.coverHeld = false;
        uint256 c = d.cover;
        coversHeld -= c;
        bondOf[d.executor] += c;
    }

    // ---- expiry, stake release, slash -----------------------------------------------------------------------------
    /// @notice Anyone, after expiresAt, for a node never finally settled: refund, bond and cover back to the executor.
    ///  Refused while the bound claim is Rejected (reject it instead) and while the node can be settled (settle it
    ///  instead, or wait for its ancestors). An EXPIRED node never becomes REJECTED. A referee that cannot be read counts as no decision, so a
    ///  failed referee never locks the funds (ADR-0012 D1, D9).
    function expire(bytes32 key) external nonReentrant {
        Node storage d = _nodes[key];
        Status s = d.status;
        if (s != Status.Posted && s != Status.Claimed && s != Status.Verified) revert WrongStatus();
        if (block.timestamp <= d.expiry) revert TooEarly();
        if (s != Status.Posted) {
            uint8 v = _acceptedOrUnknown(d);
            if (s == Status.Claimed && v == 2) revert ClaimRejected();
            // an accepted result whose ancestors are all final can be paid: anyone may settle it, nobody may expire it
            // instead (that would deny its executor and its children their payment), ADR-0012 D11. The same while an
            // ancestor can still become final: its expiry may be later than this node's (a slower referee), and each
            // ancestor ends by its own expiry at the latest, so this wait is finite (re-audit 2026-11-03 F1)
            if (v == 1 && !_ancestorEnded(key)) revert Settleable();
        }
        d.status = Status.Expired;
        locked -= d.price;
        balanceOf[d.account] += d.price;
        if (d.bonded) _releaseBond(key, d);
        if (d.coverHeld) _releaseCover(d);
        emit Expired(key);
    }

    /// @notice Anyone, after expiresAt: the bond of a FINAL or VOIDED node back to its executor.
    function release(bytes32 key) external nonReentrant {
        Node storage d = _nodes[key];
        if (!d.bonded) revert NotBonded();
        if (d.status != Status.Final && d.status != Status.Voided) revert WrongStatus();
        if (block.timestamp <= d.expiry) revert TooEarly();
        _releaseBond(key, d);
    }

    function _releaseBond(bytes32 key, Node storage d) internal {
        d.bonded = false;
        uint256 b = bondFor(d.price);
        bondsHeld -= b;
        bondOf[d.executor] += b;
        emit Released(key, b);
    }

    /// @notice Anyone, until expiresAt: another (unbound) claim of the executor for this computation, made after the
    ///  reservation, was Rejected -> the bond goes to the account (S-1: an honest claim cannot shield a false one).
    ///  The graph status does not change: only the bound claim decides it.
    function slash(bytes32 key, uint256 claimId) external nonReentrant {
        Node storage d = _nodes[key];
        if (!d.bonded) revert NotBonded();
        if (block.timestamp > d.expiry) revert TooLate();
        if (_claimFor(d, claimId).status != OVM0Dispute.ClaimStatus.Rejected) revert ClaimNotRejected();
        claimUsedBy[d.referee][claimId] = key;
        d.bonded = false;
        uint256 b = bondFor(d.price);
        bondsHeld -= b;
        balanceOf[d.account] += b;
        emit Slashed(key, claimId, b);
    }

    function _meets(uint8 cond, uint64 output, uint64 arg) internal pure returns (bool) {
        if (cond == uint8(Cond.CleanHalt)) return true;
        if (cond == uint8(Cond.OutputEq)) return output == arg;
        if (cond == uint8(Cond.OutputLe)) return output <= arg;
        return output >= arg;
    }

    function _signer(bytes32 digest, Sig calldata g) internal pure returns (address) {
        if (uint256(g.s) > HALF_N || (g.v != 27 && g.v != 28)) return address(0);
        return ecrecover(digest, g.v, g.r, g.s);
    }
}
