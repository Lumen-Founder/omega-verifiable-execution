// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAgenticCommerce} from "./OmegaEvaluator8183.sol";

/// @title SignedVerdictEvaluator8183 — an ERC-8183 evaluator that acts only on a signed, bound verdict.
/// @notice Reference for the evaluator-accountability discussion on the ERC-8183 thread (ethereum-magicians #436-#442).
///  A verdict is EIP-712 typed data signed by a registered rater key. It binds (#437): chain id and this contract
///  (EIP-712 domain), escrow, job id, deliverable hash, criteria/schema hash, decision and expiry; plus the key id
///  (#438), and measurement fields (#441): model id, severity and its standard error (logits x 1e4) and the
///  calibration run they came from. Decisions: COMPLETE, REJECT, or COULD_NOT_CHECK (recorded, no state change, so
///  silence stays the evaluator's own failure and the job can still expire to a refund).
/// @dev Limits, stated plainly: the ERC's getJob has no deliverable field, so the deliverable hash in a verdict is
///  checked against the escrow's JobSubmitted event off chain, not here. Pre-audit, testnet only.
contract SignedVerdictEvaluator8183 {
    uint8 public constant COMPLETE = 1;
    uint8 public constant REJECT = 2;
    uint8 public constant COULD_NOT_CHECK = 3;
    uint8 internal constant SUBMITTED = 2; // ERC-8183 JobStatus order: Open, Funded, Submitted, ...

    bytes32 public constant VERDICT_TYPEHASH = keccak256(
        "Verdict(address escrow,uint256 jobId,bytes32 deliverableHash,bytes32 criteriaHash,uint8 decision,"
        "bytes32 detailHash,uint64 signedAt,uint64 expiresAt,bytes32 keyId,bytes32 modelId,int32 severityE4,"
        "uint32 severitySeE4,bytes32 calibrationRun)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 internal constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    struct Verdict {
        address escrow;
        uint256 jobId;
        bytes32 deliverableHash;
        bytes32 criteriaHash;
        uint8 decision;
        bytes32 detailHash; // hash of the full signed verdict document (RFC 8785 JSON), fetchable and re-runnable
        uint64 signedAt;
        uint64 expiresAt;
        bytes32 keyId;
        bytes32 modelId;
        int32 severityE4;
        uint32 severitySeE4;
        bytes32 calibrationRun;
    }

    struct Key {
        address signer;
        uint64 validFrom;
        uint64 validUntil; // retire: signatures made before this stay valid
        bool compromised; // revoke: every signature by this key is refused
    }

    address public immutable admin; // the party that configures rater keys (client, committee or registry)
    IAgenticCommerce public immutable escrow;
    mapping(bytes32 => Key) public keys;
    mapping(uint256 => bytes32) public decided; // jobId => digest of the verdict that completed or rejected it
    mapping(bytes32 => bool) public seen; // every accepted verdict digest, so no verdict is recorded twice

    event KeySet(bytes32 indexed keyId, address signer, uint64 validFrom, uint64 validUntil);
    event KeyRevoked(bytes32 indexed keyId);
    event VerdictRecorded(
        uint256 indexed jobId, bytes32 indexed digest, bytes32 indexed keyId, uint8 decision, bytes32 deliverableHash,
        bytes32 criteriaHash
    );
    event RaterMeasurement(
        bytes32 indexed digest, bytes32 indexed modelId, int32 severityE4, uint32 severitySeE4, bytes32 calibrationRun
    );

    error NotAdmin();
    error KeyExists();
    error WrongEscrow();
    error BadDecision();
    error Expired();
    error NotYetSigned();
    error KeyNotValid();
    error BadSignature();
    error AlreadyDecided();
    error Replayed();
    error NotEvaluator();
    error NotSubmitted();

    constructor(IAgenticCommerce escrow_, address admin_) {
        escrow = escrow_;
        admin = admin_;
    }

    // ------------------------------------------------------------------ keys

    function setKey(bytes32 keyId, address signer, uint64 validFrom, uint64 validUntil) external {
        if (msg.sender != admin) revert NotAdmin();
        if (keys[keyId].signer != address(0)) revert KeyExists(); // a key id is never reused for another signer
        keys[keyId] = Key(signer, validFrom, validUntil, false);
        emit KeySet(keyId, signer, validFrom, validUntil);
    }

    function retireKey(bytes32 keyId, uint64 at) external {
        if (msg.sender != admin) revert NotAdmin();
        Key storage k = keys[keyId];
        if (at < k.validUntil) k.validUntil = at;
        emit KeySet(keyId, k.signer, k.validFrom, k.validUntil);
    }

    function revokeKey(bytes32 keyId) external {
        if (msg.sender != admin) revert NotAdmin();
        keys[keyId].compromised = true;
        emit KeyRevoked(keyId);
    }

    // ------------------------------------------------------------------ verdicts

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("SignedVerdictEvaluator8183"), keccak256("1"), block.chainid, address(this))
        );
    }

    function digestOf(Verdict calldata v) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                VERDICT_TYPEHASH,
                v.escrow,
                v.jobId,
                v.deliverableHash,
                v.criteriaHash,
                v.decision,
                v.detailHash,
                v.signedAt,
                v.expiresAt,
                v.keyId,
                v.modelId,
                v.severityE4,
                v.severitySeE4,
                v.calibrationRun
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice anyone may relay a signed verdict; the signature, not the caller, carries the authority.
    function submitVerdict(Verdict calldata v, uint8 sigV, bytes32 r, bytes32 s) external returns (bytes32 digest) {
        if (v.escrow != address(escrow)) revert WrongEscrow();
        if (v.decision < COMPLETE || v.decision > COULD_NOT_CHECK) revert BadDecision();
        if (block.timestamp > v.expiresAt) revert Expired();
        if (v.signedAt > block.timestamp) revert NotYetSigned();
        Key memory k = keys[v.keyId];
        if (k.signer == address(0) || k.compromised || v.signedAt < k.validFrom || v.signedAt >= k.validUntil) {
            revert KeyNotValid();
        }
        digest = digestOf(v);
        if (uint256(s) > HALF_N || (sigV != 27 && sigV != 28)) revert BadSignature();
        address who = ecrecover(digest, sigV, r, s);
        if (who == address(0) || who != k.signer) revert BadSignature();
        if (seen[digest]) revert Replayed();
        if (decided[v.jobId] != bytes32(0)) revert AlreadyDecided();
        seen[digest] = true;

        IAgenticCommerce.Job memory j = escrow.getJob(v.jobId);
        if (j.evaluator != address(this)) revert NotEvaluator();

        _record(v, digest);
        if (v.decision == COULD_NOT_CHECK) return digest; // recorded only; the job may still expire to a refund
        if (j.status != SUBMITTED) revert NotSubmitted();
        decided[v.jobId] = digest;
        if (v.decision == COMPLETE) escrow.complete(v.jobId, digest, "");
        else escrow.reject(v.jobId, digest, "");
    }

    function _record(Verdict calldata v, bytes32 digest) internal {
        emit VerdictRecorded(v.jobId, digest, v.keyId, v.decision, v.deliverableHash, v.criteriaHash);
        emit RaterMeasurement(digest, v.modelId, v.severityE4, v.severitySeE4, v.calibrationRun);
    }
}
