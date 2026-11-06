// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC8183Virtual} from "./ERC8183Virtual.sol";
import {CommitmentTermsLib as L} from "./CommitmentTermsLib.sol";
import {XDLogic} from "./XDLogic.sol";
import {XDPayout} from "./XDPayout.sol";
import {XDHooks} from "./XDHooks.sol";
import {XDFlow} from "./XDFlow.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title OmegaEscrowXD — ERC-8183 escrow extension: contract commitment boundary and committed hooks (pre-audit)
/// @notice Reference implementation, stage 1. Built on `ERC8183Virtual`, which is erc-8183/base-contracts@142e669c with
///  only the `virtual` keyword added (checked by `check_dev_copy.mjs`). It is for new deployments: every job follows
///  the rules below. Upgrading a live base-contracts proxy that has jobs in flight is not supported (decision D-25).
///  - Fee terms: both fee rates and both fee recipients are read once at creation and never change for that job.
///    The creator may cap the rates; creation reverts above the cap.
///  - Commitment boundary: the provider confirms the full EIP-712 terms hash (`confirmTerms`), the client funds with
///    the same hash (`fundWithTermsHash`). The hash is recomputed from live state before and after the fund hook, so
///    nothing the hash covers can change between the parties' check and the funding. The plain `fund` reverts.
///  - Committed hooks: after funding, the hook address, its code hash and config hash are part of the committed terms.
///    `batchDetachHook` reverts for committed jobs; the only way to change a committed hook is `amendHook`, signed by
///    the client, the provider, the evaluator and (if the platform fee is > 0) the platform fee recipient. Every hook
///    call on a committed job first checks that the hook's code and config still match (else `HookBindingChanged`).
///  - Partial settlement (`submitClaim`, `settleClaim`) is not supported for XD jobs.
///  - Settlement mode, fixed at creation: IMMEDIATE pays at completion and refunds at rejection or expiry, as upstream
///    does. DEFERRED records payout rights instead; anyone may claim a right later and it is paid to its fixed
///    recipient only (`claimPayout`, not blocked by pause). Completion then does not depend on any recipient
///    accepting the transfer or the IDisburser callback.
///  - Solvency: per token, the escrow tracks funded budgets and unclaimed rights. `emergencyWithdraw` can take only
///    the balance above both. `claimRefund` is not blocked by pause (decision D-29).
///  - Hook classes (XDHooks): REQUIRED hooks gate the core call as upstream; AUXILIARY hooks run under a gas cap and
///    cannot block it. A REQUIRED-hook fault is declared by the client or provider after the escrow probes the hook,
///    and after the fault window anyone runs the policy fixed at creation (EXPIRE_ONLY, REFUND_ON_FAULT,
///    EVALUATOR_ON_FAULT). No admin role takes part. Fault functions are not blocked by pause (decision D-35).
///  The admin keeps UUPS upgrade power: this contract cannot protect committed terms from an upgrade (trust boundary,
///  see README).
contract OmegaEscrowXD is ERC8183Virtual {
    using SafeERC20 for IERC20;

    uint32 public constant DEFAULT_AUX_HOOK_GAS = 100_000;
    uint32 public constant DEFAULT_FAULT_WINDOW = 72 hours;

    mapping(uint256 => XDLogic.XTerms) internal _x;
    mapping(address => address) public evaluatorDefaultRecipient;
    /// @notice Per token: budgets of funded jobs not yet completed, rejected or expired (DS16).
    mapping(address => uint256) public totalEscrowed;
    /// @notice Per token: payout rights of DEFERRED jobs not yet claimed (DS16).
    mapping(address => uint256) public totalUnclaimed;

    event EvaluatorDefaultRecipientSet(address indexed evaluator, address indexed recipient);
    event TermsConfirmed(uint256 indexed jobId, address indexed provider, bytes32 termsHash);
    event ContractCommitted(uint256 indexed jobId, address indexed client, bytes32 termsHash, address providerRecipient);

    error NotXDJob();
    error TermsHashRequired();
    error TermsNotConfirmed();
    error HookBoundToCommittedJob(uint256 jobId);
    error PartialSettlementUnsupported();
    error ExceedsExcess();

    // ──────────────────── Activation ────────────────────

    function isXDJob(uint256 jobId) public view returns (bool) {
        return jobId != 0 && jobId <= jobCounter;
    }

    // ──────────────────── Fee terms (fixed at creation) ────────────────────

    /// @notice An evaluator names where its fees go. Applies to jobs created afterwards only.
    function setEvaluatorDefaultRecipient(address recipient) external {
        if (recipient == address(0)) revert ZeroAddress();
        if (recipient == address(this)) revert InvalidReceiver();
        evaluatorDefaultRecipient[msg.sender] = recipient;
        emit EvaluatorDefaultRecipientSet(msg.sender, recipient);
    }

    /// @notice Defaults for the base `createJob`: the creator accepts the rates shown now; REQUIRED for any hook.
    function defaultCreateTerms(address hook) public view returns (XDLogic.CreateTerms memory) {
        return XDLogic.CreateTerms({
            maxEvaluatorFeeBP: uint16(evaluatorFeeBP),
            maxPlatformFeeBP: uint16(platformFeeBP),
            settlementMode: 0,
            hookClass: hook == address(0) ? 0 : 1,
            hookFaultPolicy: 0,
            auxHookGas: DEFAULT_AUX_HOOK_GAS,
            faultWindow: DEFAULT_FAULT_WINDOW
        });
    }

    function createJobWithTerms(
        address provider,
        address evaluator,
        uint48 expiredAt,
        string calldata description,
        address hook,
        uint256 providerAgentId,
        XDLogic.CreateTerms calldata terms
    ) external whenNotPaused nonReentrant returns (uint256 jobId) {
        jobId = super._createJob(msg.sender, provider, evaluator, expiredAt, description, hook, providerAgentId);
        _lockTerms(jobId, terms);
    }

    function _createJob(
        address client,
        address provider,
        address evaluator,
        uint48 expiredAt,
        string calldata description,
        address hook,
        uint256 providerAgentId
    ) internal override returns (uint256 jobId) {
        jobId = super._createJob(client, provider, evaluator, expiredAt, description, hook, providerAgentId);
        _lockTerms(jobId, defaultCreateTerms(hook));
    }

    function _lockTerms(uint256 jobId, XDLogic.CreateTerms memory t) internal {
        address evaluator = jobs[jobId].evaluator;
        address evalRecipient = evaluatorDefaultRecipient[evaluator];
        if (evalRecipient == address(0)) evalRecipient = evaluator;
        XDLogic.lockTerms(
            _x[jobId],
            jobId,
            jobs[jobId].hook,
            t,
            evaluatorFeeBP,
            platformFeeBP,
            evalRecipient,
            platformTreasury,
            EVALUATION_GRACE_PERIOD
        );
    }

    // ──────────────────── Views ────────────────────

    /// @notice The terms the parties sign off on, and their hash. Before funding, the hook's code and config are read
    ///  live; after funding, the committed values are used.
    function commitmentTermsOf(uint256 jobId) external view returns (L.TermsV2 memory t, bytes32 termsHash) {
        if (!isXDJob(jobId)) revert NotXDJob();
        return XDLogic.termsAndHash(jobs[jobId], _x[jobId], jobId, _x[jobId].committedTermsHash == bytes32(0));
    }

    function xTermsOf(uint256 jobId) external view returns (XDLogic.XTerms memory) {
        return _x[jobId];
    }

    // ──────────────────── Commitment boundary ────────────────────

    /// @notice The provider agrees to the full terms hash (recipient, budget, fees, hook binding). Open, before expiry.
    function confirmTerms(uint256 jobId, bytes32 termsHash) external whenNotPaused nonReentrant {
        if (!isXDJob(jobId)) revert NotXDJob();
        Job storage job = jobs[jobId];
        if (job.status != JobStatus.Open || block.timestamp >= job.expiredAt) revert WrongStatus();
        if (msg.sender != job.provider) revert Unauthorized();
        if (XDLogic.termsHash(job, _x[jobId], jobId, true) != termsHash) revert XDLogic.TermsHashMismatch();
        _x[jobId].providerConfirmedHash = termsHash;
        emit TermsConfirmed(jobId, msg.sender, termsHash);
    }

    /// @notice Client funds an XD job. The terms hash must equal what the provider confirmed and what storage gives,
    ///  both before and after the fund hook, in this transaction.
    function fundWithTermsHash(uint256 jobId, bytes32 termsHash, bytes calldata optParams)
        external
        whenNotPaused
        nonReentrant
    {
        if (!isXDJob(jobId)) revert NotXDJob();
        Job storage job = jobs[jobId];
        XDLogic.XTerms storage x = _x[jobId];
        if (job.status != JobStatus.Open) revert WrongStatus();
        if (msg.sender != job.client) revert Unauthorized();
        if (job.provider == address(0)) revert ProviderNotSet();
        if (block.timestamp >= job.expiredAt) revert WrongStatus();
        if (x.providerConfirmedHash == bytes32(0)) revert TermsNotConfirmed();
        if (x.providerConfirmedHash != termsHash) revert XDLogic.TermsHashMismatch();
        if (XDLogic.termsHash(job, x, jobId, true) != termsHash) revert XDLogic.TermsHashMismatch();

        bytes memory data = abi.encode(msg.sender, optParams);
        _beforeHook(job.hook, jobId, this.fund.selector, data);

        address providerRecipient = XDLogic.commit(job, x, jobId, termsHash);
        job.status = JobStatus.Funded;
        if (job.budget > 0) {
            IERC20 token = IERC20(job.paymentToken);
            uint256 balanceBefore = token.balanceOf(address(this));
            token.safeTransferFrom(msg.sender, address(this), job.budget);
            if (token.balanceOf(address(this)) - balanceBefore != job.budget) revert UnexpectedFundedAmount();
            totalEscrowed[job.paymentToken] += job.budget;
        }
        emit ContractCommitted(jobId, msg.sender, termsHash, providerRecipient);
        emit JobFunded(jobId, msg.sender, job.budget);

        _afterHook(job.hook, jobId, this.fund.selector, data);
    }

    /// @dev CB5 / D-14: the plain fund checks neither recipient, hook binding nor fee terms.
    function _fund(address, uint256, address, uint256, bytes calldata) internal pure override {
        revert TermsHashRequired();
    }

    // ──────────────────── Committed hooks ────────────────────

    /// @dev HK1: one committed (non-Open) job in the list reverts the whole call; nothing is detached.
    function batchDetachHook(uint256[] calldata jobIds) external override onlyRole(ADMIN_ROLE) {
        for (uint256 i = 0; i < jobIds.length; i++) {
            uint256 id = jobIds[i];
            if (isXDJob(id) && jobs[id].status != JobStatus.Open) revert HookBoundToCommittedJob(id);
        }
        for (uint256 i = 0; i < jobIds.length; i++) {
            uint256 id = jobIds[i];
            if (id == 0 || id > jobCounter) revert InvalidJob();
            address oldHook = jobs[id].hook;
            if (oldHook == address(0)) continue;
            jobs[id].hook = address(0);
            emit HookDetached(id, oldHook);
        }
    }

    /// @dev Every hook call goes through XDHooks: class, binding, auxiliary isolation, fault clearing.
    function _beforeHook(address, uint256 jobId, bytes4 selector, bytes memory data) internal override {
        XDHooks.run(jobs[jobId], _x[jobId], jobId, selector, data, 0);
    }

    function _afterHook(address, uint256 jobId, bytes4 selector, bytes memory data) internal override {
        XDHooks.run(jobs[jobId], _x[jobId], jobId, selector, data, 1);
    }

    // ──────────────────── REQUIRED-hook faults (HF1-HF7) ────────────────────

    /// @notice Client or provider: the escrow probes the hook with this call (phase 0 before, 1 after) and records a
    ///  fault only if the probe reverts or the hook's binding changed.
    function declareHookFault(uint256 jobId, bytes4 selector, uint8 phase, bytes calldata data) external nonReentrant {
        if (!isXDJob(jobId)) revert NotXDJob();
        XDHooks.declareFault(jobs[jobId], _x[jobId], jobId, selector, phase, data);
    }

    /// @notice Anyone: clears the fault when the declared probe passes again.
    function clearHookFault(uint256 jobId, bytes4 selector, uint8 phase, bytes calldata data) external nonReentrant {
        if (!isXDJob(jobId)) revert NotXDJob();
        XDHooks.clearFault(jobs[jobId], _x[jobId], jobId, selector, phase, data);
    }

    /// @notice Anyone, after the fault window: runs the policy fixed at creation.
    function resolveHookFault(uint256 jobId) external nonReentrant {
        if (!isXDJob(jobId)) revert NotXDJob();
        XDHooks.resolveFault(jobs[jobId], _x[jobId], totalEscrowed, totalUnclaimed, jobId);
    }

    /// @dev Self-call only; always reverts with the probe result, so a probe never leaves state behind.
    function probeHook(uint256 jobId, bytes4 selector, uint8 phase, bytes calldata data) external {
        XDHooks.probe(jobs[jobId].hook, jobId, selector, phase, data);
    }

    /// @notice Change the hook of a committed job. Anyone may submit; authority is the signatures alone.
    ///  Only the four hook fields change; every other term is recomputed from storage and must stay equal.
    ///  Neither the old nor the new hook is called.
    function amendHook(L.HookAmendment calldata a, XDLogic.AmendmentSignatures calldata sigs)
        external
        whenNotPaused
        nonReentrant
    {
        if (!isXDJob(a.jobId)) revert NotXDJob();
        XDLogic.amend(jobs[a.jobId], _x[a.jobId], a, sigs);
    }

    // ──────────────────── Settlement with the locked fee terms ────────────────────

    function _complete(address actor, uint256 jobId, bytes32 reason, bytes calldata optParams) internal override {
        if (!isXDJob(jobId)) revert InvalidJob();
        XDFlow.complete(jobs[jobId], _x[jobId], totalEscrowed, totalUnclaimed, jobId, actor, reason, optParams);
    }

    /// @dev Upstream checks and order; the refund goes through XDPayout (pushed for IMMEDIATE, a right for DEFERRED).
    function _reject(address actor, uint256 jobId, bytes32 reason, bytes calldata optParams) internal override {
        if (!isXDJob(jobId)) revert InvalidJob();
        XDFlow.reject(jobs[jobId], _x[jobId], totalEscrowed, totalUnclaimed, jobId, actor, reason, optParams);
    }

    /// @notice Upstream expiry refund; calls no hook. D-29: not blocked by pause, so pausing cannot keep the client's
    ///  money in the escrow after expiry.
    function claimRefund(uint256 jobId) external override nonReentrant {
        if (!isXDJob(jobId)) revert InvalidJob();
        XDFlow.expire(jobs[jobId], _x[jobId], totalEscrowed, totalUnclaimed, jobId, EVALUATION_GRACE_PERIOD);
    }

    // ──────────────────── Deferred payout ────────────────────

    /// @notice A payout right: kind 0 provider, 1 evaluator, 2 platform, 3 client refund. Status 0 NONE, 1 ENTITLED,
    ///  2 CLAIMED. NONE rights report zeros.
    function payoutOf(uint256 jobId, uint8 kind)
        external
        view
        returns (address recipient, address token, uint256 amount, uint8 status)
    {
        if (!isXDJob(jobId)) revert NotXDJob();
        return XDPayout.payoutOf(jobs[jobId], _x[jobId], kind);
    }

    /// @notice Pays a right to its fixed recipient. Anyone may call, also while paused. Returns 0 for NONE or
    ///  CLAIMED. For the provider share, `disburserData` must equal the `optParams` given to `complete`.
    function claimPayout(uint256 jobId, uint8 kind, bytes calldata disburserData)
        external
        nonReentrant
        returns (uint256)
    {
        if (!isXDJob(jobId)) revert NotXDJob();
        return XDPayout.claim(jobs[jobId], _x[jobId], totalUnclaimed, jobId, kind, disburserData);
    }

    /// @notice Upstream emergency withdrawal, limited to the balance above funded budgets and unclaimed rights (DS17).
    function emergencyWithdraw(address token, address to, uint256 amount)
        external
        override
        onlyRole(ADMIN_ROLE)
        whenPaused
    {
        if (to == address(0)) revert ZeroAddress();
        if (token == address(0)) {
            (bool success,) = payable(to).call{value: amount}("");
            require(success, "Transfer failed");
        } else {
            if (amount > XDPayout.excess(totalEscrowed, totalUnclaimed, token)) revert ExceedsExcess();
            IERC20(token).safeTransfer(to, amount);
        }
        emit EmergencyWithdraw(token, to, amount);
    }

    // ──────────────────── Partial settlement: not supported (D-4) ────────────────────

    function _submitClaim(address, uint256, uint256, bytes32, bytes calldata) internal pure override {
        revert PartialSettlementUnsupported();
    }

    function _settleClaim(address, uint256, uint256, bytes32, bytes calldata) internal pure override {
        revert PartialSettlementUnsupported();
    }

    function _approveClaim(address, uint256, uint256, bytes32, bytes calldata) internal pure override {
        revert PartialSettlementUnsupported();
    }

    function _rejectClaim(address, uint256, uint256, bytes32, bytes32, bytes calldata) internal pure override {
        revert PartialSettlementUnsupported();
    }
}
