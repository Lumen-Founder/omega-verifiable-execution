// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.28;

/// @title IERC8183VerdictEvaluator — signed, job-bound verdicts for ERC-8183 evaluators (draft, spec/ERC8183_EVALUATOR_VERDICTS.md)
interface IERC8183VerdictEvaluator {
    struct Verdict {
        address escrow;
        uint256 jobId;
        bytes32 deliverableHash;
        bytes32 criteriaHash;
        uint8 decision; // 1 COMPLETE, 2 REJECT, 3 COULD_NOT_CHECK
        bytes32 detailHash;
        uint64 signedAt;
        uint64 expiresAt;
        bytes32 keyId;
        bytes32 modelId; // 0 = no measurement
        int32 severityE4;
        uint32 severitySeE4;
        bytes32 calibrationRun;
    }

    event KeySet(bytes32 indexed keyId, address signer, uint64 validFrom, uint64 validUntil);
    event KeyRevoked(bytes32 indexed keyId);
    event VerdictRecorded(
        uint256 indexed jobId, bytes32 indexed digest, bytes32 indexed keyId, uint8 decision, bytes32 deliverableHash,
        bytes32 criteriaHash
    );
    event RaterMeasurement(
        bytes32 indexed digest, bytes32 indexed modelId, int32 severityE4, uint32 severitySeE4, bytes32 calibrationRun
    );

    function escrow() external view returns (address);
    function digestOf(Verdict calldata v) external view returns (bytes32);
    function submitVerdict(Verdict calldata v, uint8 sigV, bytes32 r, bytes32 s) external returns (bytes32 digest);
    function keys(bytes32 keyId)
        external
        view
        returns (address signer, uint64 validFrom, uint64 validUntil, bool compromised);
    function decided(uint256 jobId) external view returns (bytes32 digest);
    function seen(bytes32 digest) external view returns (bool);

    /// @dev EIP-5267
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
}
