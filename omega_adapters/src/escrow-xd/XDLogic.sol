// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC8183Virtual} from "./ERC8183Virtual.sol";
import {IERC8183Hook} from "./IERC8183Hook.sol";
import {CommitmentTermsLib as L} from "./CommitmentTermsLib.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

/// @notice Optional hook-side interface (ERC-165). Declared by hooks that keep per-job configuration.
interface IERC8183HookConfig {
    function hookConfigHash(uint256 jobId) external view returns (bytes32);
}

/// @title XDLogic — commitment-boundary and hook-amendment logic of OmegaEscrowXD (pre-audit)
/// @notice External library, delegatecalled by the escrow: `address(this)`, storage and events are the escrow's.
///  It holds no state of its own and moves no tokens.
library XDLogic {
    uint8 internal constant HOOK_NONE = 0;
    uint8 internal constant HOOK_REQUIRED = 1;
    uint8 internal constant HOOK_AUXILIARY = 2;
    uint8 internal constant POLICY_MAX = 2; // EXPIRE_ONLY, REFUND_ON_FAULT, EVALUATOR_ON_FAULT
    uint8 internal constant POLICY_EXPIRE_ONLY = 0;
    uint8 internal constant MODE_IMMEDIATE = 0;
    uint8 internal constant MODE_DEFERRED = 1;
    uint8 internal constant TERMS_VERSION = 2;

    /// @notice What the creator fixes at creation beyond the base arguments.
    struct CreateTerms {
        uint16 maxEvaluatorFeeBP; // creation reverts if the escrow's evaluator fee is above this
        uint16 maxPlatformFeeBP; // creation reverts if the escrow's platform fee is above this
        uint8 settlementMode;
        uint8 hookClass;
        uint8 hookFaultPolicy;
        uint32 auxHookGas; // 30_000 .. 1_000_000
        uint32 faultWindow; // >= EVALUATION_GRACE_PERIOD
    }

    /// @notice Per-job terms stored by the extension.
    struct XTerms {
        uint16 evaluatorFeeBP;
        uint16 platformFeeBP;
        uint8 settlementMode;
        uint8 hookClass;
        uint8 hookFaultPolicy;
        uint32 auxHookGas;
        uint32 faultWindow;
        bool hookHasConfig; // set at commitment / amendment
        uint64 amendmentNonce;
        uint8 payoutBits; // DEFERRED: 2 bits per payee kind (0 NONE, 1 ENTITLED, 2 CLAIMED), see XDPayout
        uint48 faultAt; // REQUIRED hook fault declared at (0 = none), see XDHooks
        bool evaluatorOverride; // EVALUATOR_ON_FAULT resolved: the evaluator decides once without the hook
        address evaluatorFeeRecipient;
        address platformFeeRecipient;
        bytes32 hookCodeHash; // stored at commitment
        bytes32 hookConfigHash; // stored at commitment
        bytes32 providerConfirmedHash;
        bytes32 committedTermsHash; // 0 until funded
        bytes32 amendmentLogHead;
        bytes32 disburserDataHash; // DEFERRED: keccak256 of complete optParams, 0 if they were empty (DS11)
        bytes32 faultProbeHash; // keccak256(abi.encode(selector, phase, data)) of the declared probe
    }

    struct AmendmentSignatures {
        bytes client;
        bytes provider;
        bytes evaluator;
        bytes platform; // required only when the locked platform fee is > 0
    }

    event FeeTermsLocked(
        uint256 indexed jobId,
        uint16 evaluatorFeeBP,
        uint16 platformFeeBP,
        address evaluatorFeeRecipient,
        address platformFeeRecipient
    );
    event HookAmended(
        uint256 indexed jobId,
        address indexed oldHook,
        address indexed newHook,
        bytes32 oldTermsHash,
        bytes32 newTermsHash,
        uint64 nonce,
        bytes32 amendmentDigest,
        bytes32 signaturesHash,
        uint8 signerMask
    );

    error UnsupportedTerms();
    error FeeAboveCap();
    error TermsHashMismatch();
    error HookBindingChanged(uint256 jobId);
    error AmendmentExpired();
    error AmendmentMismatch();
    error MissingSignature(uint8 role);

    // ──────────────────── Creation ────────────────────

    function lockTerms(
        XTerms storage x,
        uint256 jobId,
        address hook,
        CreateTerms memory t,
        uint256 evaluatorFeeBP,
        uint256 platformFeeBP,
        address evaluatorFeeRecipient,
        address platformFeeRecipient,
        uint256 gracePeriod
    ) external {
        if (t.settlementMode > MODE_DEFERRED || t.hookFaultPolicy > POLICY_MAX) revert UnsupportedTerms();
        if (hook == address(0) ? t.hookClass != HOOK_NONE : t.hookClass == HOOK_NONE || t.hookClass > HOOK_AUXILIARY) {
            revert UnsupportedTerms();
        }
        if (t.auxHookGas < 30_000 || t.auxHookGas > 1_000_000 || t.faultWindow < gracePeriod) revert UnsupportedTerms();
        if (evaluatorFeeBP > t.maxEvaluatorFeeBP || platformFeeBP > t.maxPlatformFeeBP) revert FeeAboveCap();
        x.evaluatorFeeBP = uint16(evaluatorFeeBP);
        x.platformFeeBP = uint16(platformFeeBP);
        x.settlementMode = t.settlementMode;
        x.hookClass = t.hookClass;
        x.hookFaultPolicy = t.hookFaultPolicy;
        x.auxHookGas = t.auxHookGas;
        x.faultWindow = t.faultWindow;
        x.evaluatorFeeRecipient = evaluatorFeeRecipient;
        x.platformFeeRecipient = platformFeeRecipient;
        emit FeeTermsLocked(jobId, x.evaluatorFeeBP, x.platformFeeBP, evaluatorFeeRecipient, platformFeeRecipient);
    }

    // ──────────────────── Terms ────────────────────

    function readConfigHash(address hook, uint256 jobId) public view returns (bytes32 h, bool has) {
        if (hook == address(0)) return (bytes32(0), false);
        has = ERC165Checker.supportsInterface(hook, type(IERC8183HookConfig).interfaceId);
        if (has) h = IERC8183HookConfig(hook).hookConfigHash(jobId);
    }

    /// @dev live = read the hook's code and config now (before commitment); otherwise use the stored values.
    function terms(ERC8183Virtual.Job storage j, XTerms storage x, uint256 jobId, bool live)
        public
        view
        returns (L.TermsV2 memory t)
    {
        t.jobId = jobId;
        t.client = j.client;
        t.provider = j.provider;
        t.providerAgentId = j.providerAgentId;
        t.evaluator = j.evaluator;
        t.providerRecipient = j.payoutReceiver == address(0) ? j.provider : j.payoutReceiver;
        t.paymentToken = j.paymentToken;
        t.budget = j.budget;
        t.expiredAt = j.expiredAt;
        t.hook = j.hook;
        t.evaluatorFeeBP = x.evaluatorFeeBP;
        t.platformFeeBP = x.platformFeeBP;
        t.evaluatorFeeRecipient = x.evaluatorFeeRecipient;
        t.platformFeeRecipient = x.platformFeeRecipient;
        t.settlementMode = x.settlementMode;
        if (live) {
            t.hookCodeHash = j.hook == address(0) ? bytes32(0) : j.hook.codehash;
            (t.hookConfigHash,) = readConfigHash(j.hook, jobId);
        } else {
            t.hookCodeHash = x.hookCodeHash;
            t.hookConfigHash = x.hookConfigHash;
        }
        t.hookClass = x.hookClass;
        t.hookFaultPolicy = x.hookFaultPolicy;
        t.auxHookGas = x.auxHookGas;
        t.faultWindow = x.faultWindow;
        t.termsVersion = TERMS_VERSION;
    }

    function termsHash(ERC8183Virtual.Job storage j, XTerms storage x, uint256 jobId, bool live)
        public
        view
        returns (bytes32)
    {
        return L.termsHash(terms(j, x, jobId, live), address(this));
    }

    function termsAndHash(ERC8183Virtual.Job storage j, XTerms storage x, uint256 jobId, bool live)
        external
        view
        returns (L.TermsV2 memory t, bytes32 h)
    {
        t = terms(j, x, jobId, live);
        h = L.termsHash(t, address(this));
    }

    // ──────────────────── Commitment ────────────────────

    /// @notice Second check of fundWithTermsHash (after the fund hook) and the commitment write.
    function commit(ERC8183Virtual.Job storage j, XTerms storage x, uint256 jobId, bytes32 expected)
        external
        returns (address providerRecipient)
    {
        L.TermsV2 memory t = terms(j, x, jobId, true);
        if (L.termsHash(t, address(this)) != expected) revert TermsHashMismatch();
        (, bool has) = readConfigHash(j.hook, jobId);
        x.hookCodeHash = t.hookCodeHash;
        x.hookConfigHash = t.hookConfigHash;
        x.hookHasConfig = has;
        x.committedTermsHash = expected;
        return t.providerRecipient;
    }

    // ──────────────────── Hook amendment ────────────────────

    /// @notice amendHook body: HA1-HA10. The caller has checked that the job is an XD job.
    function amend(
        ERC8183Virtual.Job storage job,
        XTerms storage x,
        L.HookAmendment calldata a,
        AmendmentSignatures calldata sigs
    ) external {
        bool has = _checkAmendment(job, x, a);
        bytes32 digest = L.amendmentDigest(a, address(this));
        uint8 mask = _verifySigners(job, x, digest, sigs);
        bytes32 sigsHash = keccak256(abi.encode(sigs));
        address oldHook = job.hook;
        // HA9 state
        job.hook = a.newHook;
        x.hookCodeHash = a.newHookCodeHash;
        x.hookConfigHash = a.newHookConfigHash;
        x.hookClass = a.newHookClass;
        x.hookHasConfig = has;
        x.committedTermsHash = a.newTermsHash;
        x.amendmentNonce = a.nonce + 1;
        // HF6: an agreed amendment ends any standing fault and its resolution
        x.faultAt = 0;
        x.faultProbeHash = bytes32(0);
        x.evaluatorOverride = false;
        // HA10 audit chain
        x.amendmentLogHead = keccak256(abi.encode(x.amendmentLogHead, digest, sigsHash));
        emit HookAmended(a.jobId, oldHook, a.newHook, a.oldTermsHash, a.newTermsHash, a.nonce, digest, sigsHash, mask);
    }

    /// @dev HA1-HA6. Returns whether the new hook declares IERC8183HookConfig.
    function _checkAmendment(ERC8183Virtual.Job storage job, XTerms storage x, L.HookAmendment calldata a)
        private
        view
        returns (bool has)
    {
        // HA1 state (and no partial settlement, D-23)
        if (job.status != ERC8183Virtual.JobStatus.Funded && job.status != ERC8183Virtual.JobStatus.Submitted) {
            revert ERC8183Virtual.WrongStatus();
        }
        if (job.settledAmount != 0) revert ERC8183Virtual.WrongStatus();
        // HA2 deadline
        if (block.timestamp > a.deadline || a.deadline > job.expiredAt) revert AmendmentExpired();
        // HA3 old terms, HA4 nonce
        L.TermsV2 memory t = terms(job, x, a.jobId, false);
        if (a.oldTermsHash != x.committedTermsHash || L.termsHash(t, address(this)) != a.oldTermsHash) {
            revert AmendmentMismatch();
        }
        if (a.nonce != x.amendmentNonce) revert AmendmentMismatch();
        // HA6 new hook: interface and binding only, no allowlist (D-21)
        if (a.newHook == address(0)) {
            if (a.newHookCodeHash != 0 || a.newHookConfigHash != 0 || a.newHookClass != HOOK_NONE) {
                revert AmendmentMismatch();
            }
        } else {
            if (a.newHookClass == HOOK_NONE || a.newHookClass > HOOK_AUXILIARY) revert UnsupportedTerms();
            if (!ERC165Checker.supportsInterface(a.newHook, type(IERC8183Hook).interfaceId)) {
                revert ERC8183Virtual.InvalidHook();
            }
            bytes32 cfg;
            (cfg, has) = readConfigHash(a.newHook, a.jobId);
            if (a.newHook.codehash != a.newHookCodeHash || cfg != a.newHookConfigHash) revert AmendmentMismatch();
        }
        // HA5 structural recomputation: only the four hook fields differ from the committed terms
        t.hook = a.newHook;
        t.hookCodeHash = a.newHookCodeHash;
        t.hookConfigHash = a.newHookConfigHash;
        t.hookClass = a.newHookClass;
        if (L.termsHash(t, address(this)) != a.newTermsHash) revert AmendmentMismatch();
    }

    /// @dev HA7. bit0 client, bit1 provider, bit2 evaluator, bit3 platform (only if the locked platform fee is > 0).
    ///  One address holding two roles signs once: an empty signature for a role is filled by an earlier valid
    ///  signature from the same address.
    function _verifySigners(
        ERC8183Virtual.Job storage job,
        XTerms storage x,
        bytes32 digest,
        AmendmentSignatures calldata s
    ) private view returns (uint8 mask) {
        address[4] memory who = [job.client, job.provider, job.evaluator, x.platformFeeRecipient];
        uint8 roles = x.platformFeeBP > 0 ? 4 : 3;
        for (uint8 r = 0; r < roles; r++) {
            bytes calldata sig = r == 0 ? s.client : r == 1 ? s.provider : r == 2 ? s.evaluator : s.platform;
            bool ok;
            if (sig.length == 0) {
                for (uint8 q = 0; q < r; q++) {
                    if (who[q] == who[r] && mask & (uint8(1) << q) != 0) ok = true;
                }
            } else {
                ok = L.isValidSignature(who[r], digest, sig);
            }
            if (!ok) revert MissingSignature(r);
            mask |= uint8(1) << r;
        }
    }
}
