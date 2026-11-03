// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

/// @title OMEGA settlement with owner-set on-chain mandates.
/// @notice The OMEGA kernel (operator) settles agent intents here. The operator is NOT trusted with funds:
///  every settlement must fit a mandate the account owner set on chain (per-settlement cap, rolling-window cap,
///  allowed targets, expiry, revocation). A stolen operator key can therefore move at most what the mandates
///  allow, only between allowed accounts, and the owner can revoke at once. Each key settles at most once;
///  reusing a key with different contents reverts. Deadlines are enforced by block.timestamp.
contract OmegaSettlement {
    struct Mandate {
        address owner;
        bool revoked;
        uint64 validUntil;
        uint64 window;
        uint64 windowStart;
        uint128 maxPerSettle;
        uint128 maxPerWindow;
        uint128 spentInWindow;
    }

    struct Record {
        bytes32 omegaDigest; // OMEGA-TRANSFER-v1 digest supplied by the operator (journal cross-check)
        bytes32 fieldsHash;  // keccak256(src, dst, amount, deadline) computed here
    }

    IERC20 public immutable token;
    address public immutable operator;
    mapping(bytes32 => Mandate) public mandates;
    mapping(bytes32 => uint256) public balanceOf;
    mapping(bytes32 => mapping(bytes32 => bool)) public targetAllowed;
    mapping(bytes32 => Record) public records;

    error NotOperator();
    error NotOwner();
    error AccountTaken();
    error KeyReuse();
    error DeadlinePassed();
    error MandateRevoked();
    error MandateExpired();
    error TargetDenied();
    error OverPerSettle();
    error OverWindow();
    error InsufficientBalance();
    error ZeroAmount();
    error TokenTransferFailed();

    event Opened(bytes32 indexed account, address indexed owner);
    event Deposited(bytes32 indexed account, address indexed from, uint256 amount);
    event MandateSet(bytes32 indexed account, uint128 maxPerSettle, uint128 maxPerWindow, uint64 window, uint64 validUntil);
    event TargetSet(bytes32 indexed account, bytes32 indexed target, bool allowed);
    event Revoked(bytes32 indexed account);
    event Withdrawn(bytes32 indexed account, address indexed to, uint256 amount);
    event Settled(bytes32 indexed key, bytes32 indexed src, bytes32 indexed dst, uint256 amount, bytes32 omegaDigest);

    constructor(IERC20 token_, address operator_) {
        token = token_;
        operator = operator_;
    }

    modifier onlyOwner(bytes32 account) {
        if (mandates[account].owner != msg.sender) revert NotOwner();
        _;
    }

    function open(bytes32 account) external {
        if (mandates[account].owner != address(0)) revert AccountTaken();
        mandates[account].owner = msg.sender;
        mandates[account].revoked = true; // nothing is allowed until the owner sets a mandate
        emit Opened(account, msg.sender);
    }

    function deposit(bytes32 account, uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        balanceOf[account] += amount;
        emit Deposited(account, msg.sender, amount);
    }

    function setMandate(bytes32 account, uint128 maxPerSettle, uint128 maxPerWindow, uint64 window, uint64 validUntil)
        external onlyOwner(account)
    {
        Mandate storage m = mandates[account];
        (m.maxPerSettle, m.maxPerWindow, m.window, m.validUntil, m.revoked) =
            (maxPerSettle, maxPerWindow, window, validUntil, false);
        emit MandateSet(account, maxPerSettle, maxPerWindow, window, validUntil);
    }

    function setTarget(bytes32 account, bytes32 target, bool allowed) external onlyOwner(account) {
        targetAllowed[account][target] = allowed;
        emit TargetSet(account, target, allowed);
    }

    function revoke(bytes32 account) external onlyOwner(account) {
        mandates[account].revoked = true;
        emit Revoked(account);
    }

    /// @notice The account owner's own exit. The operator has no withdrawal power.
    function withdraw(bytes32 account, address to, uint256 amount) external onlyOwner(account) {
        if (balanceOf[account] < amount) revert InsufficientBalance();
        balanceOf[account] -= amount;
        if (!token.transfer(to, amount)) revert TokenTransferFailed();
        emit Withdrawn(account, to, amount);
    }

    function settle(bytes32 key, bytes32 src, bytes32 dst, uint256 amount, uint64 deadline, bytes32 omegaDigest)
        external
        returns (bool fresh)
    {
        if (msg.sender != operator) revert NotOperator();
        bytes32 fh = keccak256(abi.encode(src, dst, amount, deadline));
        Record storage r = records[key];
        if (r.fieldsHash != bytes32(0)) {
            if (r.fieldsHash != fh || r.omegaDigest != omegaDigest) revert KeyReuse();
            return false; // idempotent replay: already settled, nothing moves
        }
        if (block.timestamp >= deadline) revert DeadlinePassed();
        if (amount == 0) revert ZeroAmount();
        Mandate storage m = mandates[src];
        if (m.revoked) revert MandateRevoked();
        if (block.timestamp >= m.validUntil) revert MandateExpired();
        if (!targetAllowed[src][dst]) revert TargetDenied();
        if (amount > m.maxPerSettle) revert OverPerSettle();
        if (block.timestamp >= uint256(m.windowStart) + m.window) {
            m.windowStart = uint64(block.timestamp);
            m.spentInWindow = 0;
        }
        if (uint256(m.spentInWindow) + amount > m.maxPerWindow) revert OverWindow();
        if (balanceOf[src] < amount) revert InsufficientBalance();
        m.spentInWindow += uint128(amount);
        balanceOf[src] -= amount;
        balanceOf[dst] += amount;
        (r.omegaDigest, r.fieldsHash) = (omegaDigest, fh);
        emit Settled(key, src, dst, amount, omegaDigest);
        return true;
    }
}
