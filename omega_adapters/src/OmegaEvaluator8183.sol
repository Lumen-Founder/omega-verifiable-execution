// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @dev the part of an ERC-8183 (Agentic Commerce, Draft) contract this evaluator uses. JobStatus order of the EIP:
///  Open, Funded, Submitted, Completed, Rejected, Expired.
interface IAgenticCommerce {
    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        string description;
        uint256 budget;
        uint256 expiredAt;
        uint8 status;
        address hook;
    }

    function getJob(uint256 jobId) external view returns (Job memory);
    function complete(uint256 jobId, bytes32 reason, bytes calldata optParams) external;
    function reject(uint256 jobId, bytes32 reason, bytes calldata optParams) external;
}

/// @dev OmegaGraphEscrow.getNode's return value, field for field (Status as uint8)
interface IOmegaGraphEscrow {
    struct Node {
        uint8 status;
        uint8 grade;
        bool bonded;
        bool coverHeld;
        uint64 deadline;
        uint64 claimFloor;
        uint64 claimId;
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
        uint128 cover;
        uint128 liab;
        uint64 expiry;
    }

    function getNode(bytes32 key) external view returns (Node memory);
}

/// @dev the claim every referee of the escrow answers (OVM0Dispute.Claim)
interface IReferee {
    struct Claim {
        address defender;
        bytes32 prog;
        bytes32 inputs;
        uint64 maxSteps;
        uint64 n;
        uint64 deadline;
        uint32 open;
        uint8 status;
        bytes32 hN;
        uint64 output;
        uint8 trap;
    }

    function getClaim(uint256 id) external view returns (Claim memory);
}

/// @title An ERC-8183 evaluator that decides by an OMEGA job
/// @notice TESTNET ADAPTER, NOT AUDITED and not one of the eight contracts in the audit scope. ERC-8183 leaves the decision
///  to one evaluator and has no dispute: "a malicious evaluator can complete or reject arbitrarily". This evaluator has no
///  opinion of its own. The client links its 8183 job to one OMEGA job (an escrow node) before the work is submitted;
///  after that anyone may call decide, which completes the 8183 job exactly when OMEGA pays that node's executor (FINAL,
///  clean halt, condition met) and the provider is that executor, and rejects it when the node can no longer pay
///  (REJECTED, VOIDED, EXPIRED, or FINAL without payment). Until then decide reverts. The dispute, the dependencies and
///  the stakes are OMEGA's; this contract only reads them. It holds no funds, has no owner and cannot be upgraded.
contract OmegaEvaluator8183 {
    uint8 internal constant OPEN = 0;
    uint8 internal constant FUNDED = 1;
    uint8 internal constant SUBMITTED = 2;
    uint8 internal constant FINAL = 4;
    uint8 internal constant REJECTED = 5;
    uint8 internal constant VOIDED = 6;
    uint8 internal constant EXPIRED = 7;
    bytes32 public constant PAID = "OMEGA_PAID";
    bytes32 public constant NOT_PAID = "OMEGA_NOT_PAID";
    bytes32 public constant PROVIDER_MISMATCH = "OMEGA_PROVIDER_MISMATCH";

    IOmegaGraphEscrow public immutable escrow;
    mapping(address => mapping(uint256 => bytes32)) public linkOf; // 8183 contract -> job id -> OMEGA node key

    event Linked(address indexed commerce, uint256 indexed jobId, bytes32 indexed key);
    event Decided(address indexed commerce, uint256 indexed jobId, bytes32 indexed key, bool completed, bytes32 reason);

    error NotClient();
    error NotEvaluator();
    error AlreadyLinked();
    error NotLinked();
    error TooLate();
    error UnknownNode();
    error Undecided();
    error NotSubmitted();
    error NotFunded();
    error Closed();

    constructor(IOmegaGraphEscrow escrow_) {
        escrow = escrow_;
    }

    /// @notice The client binds its job to an OMEGA node, once, before the provider submits.
    function link(IAgenticCommerce commerce, uint256 jobId, bytes32 key) external {
        IAgenticCommerce.Job memory job = commerce.getJob(jobId);
        if (msg.sender != job.client) revert NotClient();
        if (job.evaluator != address(this)) revert NotEvaluator();
        if (job.status != OPEN && job.status != FUNDED) revert TooLate();
        if (linkOf[address(commerce)][jobId] != bytes32(0)) revert AlreadyLinked();
        if (escrow.getNode(key).status == 0) revert UnknownNode();
        linkOf[address(commerce)][jobId] = key;
        emit Linked(address(commerce), jobId, key);
    }

    /// @notice Anyone, once the OMEGA node is decided: complete or reject the linked 8183 job.
    function decide(IAgenticCommerce commerce, uint256 jobId) external {
        bytes32 key = linkOf[address(commerce)][jobId];
        if (key == bytes32(0)) revert NotLinked();
        (bool known, bool paid, address executor) = _outcome(key);
        if (!known) revert Undecided();
        IAgenticCommerce.Job memory job = commerce.getJob(jobId);
        if (job.status == OPEN) revert NotFunded(); // ERC-8183 lets only the client reject an open job
        if (job.status > SUBMITTED) revert Closed(); // completed, rejected or expired already
        if (paid && job.provider == executor) {
            if (job.status != SUBMITTED) revert NotSubmitted();
            commerce.complete(jobId, PAID, "");
            emit Decided(address(commerce), jobId, key, true, PAID);
            return;
        }
        bytes32 reason = paid ? PROVIDER_MISMATCH : NOT_PAID;
        commerce.reject(jobId, reason, "");
        emit Decided(address(commerce), jobId, key, false, reason);
    }

    /// @dev known: the node will not change its payment any more; paid: OMEGA credited its executor with the price.
    ///  The same test as OmegaGraphEscrow.settle: a FINAL node was paid iff its bound claim halted cleanly and met the
    ///  node's condition (an accepted claim does not change afterwards)
    function _outcome(bytes32 key) internal view returns (bool known, bool paid, address executor) {
        IOmegaGraphEscrow.Node memory n = escrow.getNode(key);
        executor = n.executor;
        if (n.status == REJECTED || n.status == VOIDED || n.status == EXPIRED) return (true, false, executor);
        if (n.status != FINAL) return (false, false, executor);
        IReferee.Claim memory c = IReferee(n.referee).getClaim(n.claimId);
        return (true, c.trap == 0 && _meets(n.cond, c.output, n.condArg), executor);
    }

    /// @dev OmegaGraphEscrow._meets: 0 clean halt, 1 output == arg, 2 output <= arg, 3 output >= arg
    function _meets(uint8 cond, uint64 output, uint64 arg) internal pure returns (bool) {
        if (cond == 0) return true;
        if (cond == 1) return output == arg;
        if (cond == 2) return output <= arg;
        return output >= arg;
    }
}
