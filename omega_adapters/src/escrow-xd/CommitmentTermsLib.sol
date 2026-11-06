// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title CommitmentTermsLib — EIP-712 hashing for the commitment boundary and hook amendments (pre-audit)
/// @notice Internal helpers; `XDLogic` links them into one external library so the escrow stays under EIP-170.
///  Domain: name "ERC8183CommitmentTerms", version "2", chainId, verifyingContract = the escrow.
library CommitmentTermsLib {
    /// @dev Field order is the order of the type string. Any implementation must hash these 22 fields exactly.
    struct TermsV2 {
        uint256 jobId;
        address client;
        address provider;
        uint256 providerAgentId;
        address evaluator;
        address providerRecipient; // payoutReceiver != 0 ? payoutReceiver : provider
        address paymentToken;
        uint256 budget;
        uint48 expiredAt;
        address hook;
        uint16 evaluatorFeeBP; // locked at createJob
        uint16 platformFeeBP; // locked at createJob
        address evaluatorFeeRecipient; // locked at createJob
        address platformFeeRecipient; // locked at createJob
        uint8 settlementMode; // 0 IMMEDIATE, 1 DEFERRED
        bytes32 hookCodeHash; // extcodehash(hook); 0 when hook == 0
        bytes32 hookConfigHash; // IERC8183HookConfig.hookConfigHash(jobId) if declared, else 0
        uint8 hookClass; // 0 NONE, 1 REQUIRED, 2 AUXILIARY
        uint8 hookFaultPolicy; // 0 EXPIRE_ONLY, 1 REFUND_ON_FAULT, 2 EVALUATOR_ON_FAULT
        uint32 auxHookGas;
        uint32 faultWindow;
        uint8 termsVersion; // 2
    }

    struct HookAmendment {
        uint256 jobId;
        bytes32 oldTermsHash;
        bytes32 newTermsHash;
        address newHook;
        bytes32 newHookCodeHash;
        bytes32 newHookConfigHash;
        uint8 newHookClass;
        uint64 nonce;
        uint48 deadline;
    }

    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant NAME_HASH = keccak256("ERC8183CommitmentTerms");
    bytes32 internal constant VERSION_HASH = keccak256("2");
    bytes32 internal constant TERMS_TYPEHASH = keccak256(
        "CommitmentTermsV2(uint256 jobId,address client,address provider,uint256 providerAgentId,address evaluator,"
        "address providerRecipient,address paymentToken,uint256 budget,uint48 expiredAt,address hook,"
        "uint16 evaluatorFeeBP,uint16 platformFeeBP,address evaluatorFeeRecipient,address platformFeeRecipient,"
        "uint8 settlementMode,bytes32 hookCodeHash,bytes32 hookConfigHash,uint8 hookClass,uint8 hookFaultPolicy,"
        "uint32 auxHookGas,uint32 faultWindow,uint8 termsVersion)"
    );
    bytes32 internal constant AMENDMENT_TYPEHASH = keccak256(
        "HookAmendment(uint256 jobId,bytes32 oldTermsHash,bytes32 newTermsHash,address newHook,bytes32 newHookCodeHash,"
        "bytes32 newHookConfigHash,uint8 newHookClass,uint64 nonce,uint48 deadline)"
    );

    function domainSeparator(address escrow) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, escrow));
    }

    /// @notice EIP-712 digest of the terms. All fields are static, so the two halves concatenate to abi.encode of all.
    function termsHash(TermsV2 memory t, address escrow) internal view returns (bytes32) {
        bytes memory a = abi.encode(
            TERMS_TYPEHASH,
            t.jobId,
            t.client,
            t.provider,
            t.providerAgentId,
            t.evaluator,
            t.providerRecipient,
            t.paymentToken,
            t.budget,
            t.expiredAt,
            t.hook,
            t.evaluatorFeeBP
        );
        bytes memory b = abi.encode(
            t.platformFeeBP,
            t.evaluatorFeeRecipient,
            t.platformFeeRecipient,
            t.settlementMode,
            t.hookCodeHash,
            t.hookConfigHash,
            t.hookClass,
            t.hookFaultPolicy,
            t.auxHookGas,
            t.faultWindow,
            t.termsVersion
        );
        return _typed(escrow, keccak256(bytes.concat(a, b)));
    }

    function amendmentDigest(HookAmendment calldata a, address escrow) internal view returns (bytes32) {
        return _typed(
            escrow,
            keccak256(
                abi.encode(
                    AMENDMENT_TYPEHASH,
                    a.jobId,
                    a.oldTermsHash,
                    a.newTermsHash,
                    a.newHook,
                    a.newHookCodeHash,
                    a.newHookConfigHash,
                    a.newHookClass,
                    a.nonce,
                    a.deadline
                )
            )
        );
    }

    /// @notice ECDSA for EOAs, EIP-1271 for contract accounts.
    function isValidSignature(address signer, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        if (sig.length == 0) return false;
        return SignatureChecker.isValidSignatureNow(signer, digest, sig);
    }

    function _typed(address escrow, bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(escrow), structHash));
    }
}
