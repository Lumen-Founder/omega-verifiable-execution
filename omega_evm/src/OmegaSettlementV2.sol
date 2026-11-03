// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "./OmegaSettlement.sol";

/// @title OMEGA settlement v2: agent-signed (EIP-712) intents.
/// @notice Same mandates, idempotent keys and deadlines as v1, but authority moves from the operator to the agent:
///  a settlement needs an EIP-712 signature by the agent key the account owner registered. Anyone may relay it and
///  pay the gas, so a stolen relayer/operator key can move nothing. A signature is bound to this chain and contract
///  (domain), to one key (single use) and to a deadline.
///  Optional 2-of-2: if the owner registers a cosigner (e.g. the OMEGA kernel's policy key), plain `settle` is refused
///  and `settleCosigned` needs both signatures, so neither a leaked agent key nor a leaked kernel key moves funds alone,
///  and an agent cannot bypass kernel policy by relaying its own signature directly.
contract OmegaSettlementV2 {
    struct Mandate {
        address owner;
        address agent;
        address cosigner;
        bool revoked;
        uint64 validUntil;
        uint64 window;
        uint64 windowStart;
        uint128 maxPerSettle;
        uint128 maxPerWindow;
        uint128 spentInWindow;
    }

    bytes32 public constant SETTLE_TYPEHASH =
        keccak256("Settle(bytes32 key,bytes32 src,bytes32 dst,uint256 amount,uint64 deadline,bytes32 omegaDigest)");
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    IERC20 public immutable token;
    mapping(bytes32 => Mandate) public mandates;
    mapping(bytes32 => uint256) public balanceOf;
    mapping(bytes32 => mapping(bytes32 => bool)) public targetAllowed;
    mapping(bytes32 => bytes32) public records; // key => EIP-712 struct hash that settled it

    error NotOwner();
    error AccountTaken();
    error BadSignature();
    error BadCosign();
    error CosignRequired();
    error SameKey();
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
    event AgentSet(bytes32 indexed account, address indexed agent);
    event CosignerSet(bytes32 indexed account, address indexed cosigner);

    struct Sig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }
    event Settled(bytes32 indexed key, bytes32 indexed src, bytes32 indexed dst, uint256 amount, bytes32 omegaDigest);

    constructor(IERC20 token_) {
        token = token_;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("OmegaSettlement"), keccak256("2"), block.chainid, address(this)));
    }

    modifier onlyOwner(bytes32 account) {
        if (mandates[account].owner != msg.sender) revert NotOwner();
        _;
    }

    function open(bytes32 account) external {
        if (mandates[account].owner != address(0)) revert AccountTaken();
        mandates[account].owner = msg.sender;
        mandates[account].revoked = true;
        emit Opened(account, msg.sender);
    }

    function deposit(bytes32 account, uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        balanceOf[account] += amount;
    }

    /// @notice Setting a new agent key immediately invalidates every unsettled signature of the old one.
    function setAgent(bytes32 account, address agent) external onlyOwner(account) {
        if (agent != address(0) && agent == mandates[account].cosigner) revert SameKey();
        mandates[account].agent = agent;
        emit AgentSet(account, agent);
    }

    /// @notice address(0) turns the cosign requirement off again.
    function setCosigner(bytes32 account, address cosigner) external onlyOwner(account) {
        if (cosigner != address(0) && cosigner == mandates[account].agent) revert SameKey();
        mandates[account].cosigner = cosigner;
        emit CosignerSet(account, cosigner);
    }

    function setMandate(bytes32 account, uint128 maxPerSettle, uint128 maxPerWindow, uint64 window, uint64 validUntil)
        external onlyOwner(account)
    {
        Mandate storage m = mandates[account];
        (m.maxPerSettle, m.maxPerWindow, m.window, m.validUntil, m.revoked) =
            (maxPerSettle, maxPerWindow, window, validUntil, false);
    }

    function setTarget(bytes32 account, bytes32 target, bool allowed) external onlyOwner(account) {
        targetAllowed[account][target] = allowed;
    }

    function revoke(bytes32 account) external onlyOwner(account) {
        mandates[account].revoked = true;
    }

    function withdraw(bytes32 account, address to, uint256 amount) external onlyOwner(account) {
        if (balanceOf[account] < amount) revert InsufficientBalance();
        balanceOf[account] -= amount;
        if (!token.transfer(to, amount)) revert TokenTransferFailed();
    }

    function digestOf(bytes32 key, bytes32 src, bytes32 dst, uint256 amount, uint64 deadline, bytes32 omegaDigest)
        public view returns (bytes32 structHash, bytes32 digest)
    {
        structHash = keccak256(abi.encode(SETTLE_TYPEHASH, key, src, dst, amount, deadline, omegaDigest));
        digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function settle(bytes32 key, bytes32 src, bytes32 dst, uint256 amount, uint64 deadline, bytes32 omegaDigest,
                    uint8 v, bytes32 r, bytes32 s) external returns (bool fresh)
    {
        (bool replay, bytes32 sh, bytes32 digest) = _begin(key, src, dst, amount, deadline, omegaDigest);
        if (replay) return false; // idempotent replay
        if (mandates[src].cosigner != address(0)) revert CosignRequired();
        _checkAgent(src, digest, v, r, s);
        _finish(key, sh, src, dst, amount, omegaDigest);
        return true;
    }

    /// @notice Same as settle, plus the registered cosigner's signature over the same EIP-712 digest.
    function settleCosigned(bytes32 key, bytes32 src, bytes32 dst, uint256 amount, uint64 deadline, bytes32 omegaDigest,
                            Sig calldata agentSig, Sig calldata cosig) external returns (bool fresh)
    {
        (bool replay, bytes32 sh, bytes32 digest) = _begin(key, src, dst, amount, deadline, omegaDigest);
        if (replay) return false;
        _checkAgent(src, digest, agentSig.v, agentSig.r, agentSig.s);
        address c = mandates[src].cosigner;
        if (c == address(0) || _signer(digest, cosig.v, cosig.r, cosig.s) != c) revert BadCosign();
        _finish(key, sh, src, dst, amount, omegaDigest);
        return true;
    }

    function _begin(bytes32 key, bytes32 src, bytes32 dst, uint256 amount, uint64 deadline, bytes32 omegaDigest)
        internal view returns (bool replay, bytes32 sh, bytes32 digest)
    {
        (sh, digest) = digestOf(key, src, dst, amount, deadline, omegaDigest);
        bytes32 prior = records[key];
        if (prior != bytes32(0)) {
            if (prior != sh) revert KeyReuse();
            return (true, sh, digest);
        }
        if (block.timestamp >= deadline) revert DeadlinePassed();
        if (amount == 0) revert ZeroAmount();
    }

    function _finish(bytes32 key, bytes32 sh, bytes32 src, bytes32 dst, uint256 amount, bytes32 omegaDigest) internal {
        _apply(src, dst, amount);
        records[key] = sh;
        emit Settled(key, src, dst, amount, omegaDigest);
    }

    function _checkAgent(bytes32 src, bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal view {
        address a = mandates[src].agent;
        if (a == address(0) || _signer(digest, v, r, s) != a) revert BadSignature();
    }

    /// @dev -> recovered signer, or address(0) for malformed / high-s signatures. Callers must reject a zero
    ///  registered key first, since address(0) would otherwise match a malformed signature.
    function _signer(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        if (uint256(s) > HALF_N || (v != 27 && v != 28)) return address(0);
        return ecrecover(digest, v, r, s);
    }

    function _apply(bytes32 src, bytes32 dst, uint256 amount) internal {
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
    }
}
