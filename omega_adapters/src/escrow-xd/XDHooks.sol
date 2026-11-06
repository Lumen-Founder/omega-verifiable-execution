// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC8183Virtual} from "./ERC8183Virtual.sol";
import {IERC8183Hook} from "./IERC8183Hook.sol";
import {XDLogic, IERC8183HookConfig} from "./XDLogic.sol";
import {XDPayout} from "./XDPayout.sol";

/// @notice The escrow's self-call entry for hook probes (see XDHooks.probe).
interface IXDProbe {
    function probeHook(uint256 jobId, bytes4 selector, uint8 phase, bytes calldata data) external;
}

/// @title XDHooks — hook calls by class, auxiliary-hook isolation and REQUIRED-hook fault handling of OmegaEscrowXD
/// @notice External library, delegatecalled by the escrow (pre-audit). Hook calls made here come from the escrow.
///  - REQUIRED hooks: called as upstream does; a revert reverts the core call. On a committed job the hook's code and
///    config must still be the committed ones (D-19).
///  - AUXILIARY hooks (HX1-HX5): called with the gas cap fixed in the terms, return data not copied beyond 256 bytes,
///    a failure only emits AuxHookFailed. If the caller leaves too little gas for the cap, the core call reverts (HX2).
///    A changed binding skips the call and emits AuxHookFailed; it never blocks the core call.
///  - Faults of REQUIRED hooks (HF1-HF7): the client or provider declares a fault; the escrow probes the hook itself.
///    Anyone clears it when the same probe passes; a successful hooked core call or an amendment also clears it.
///    After the fault window, anyone executes the policy fixed at creation. Admin roles have no part in it (HF4).
///  - Probes run in a self-call that always reverts (`probeHook`), so a probe never leaves state in the hook.
library XDHooks {
    uint8 internal constant BEFORE = 0;
    uint8 internal constant AFTER = 1;
    uint8 internal constant POLICY_REFUND_ON_FAULT = 1;
    uint8 internal constant POLICY_EVALUATOR_ON_FAULT = 2;
    /// @dev D-34: probe gas cap. A REQUIRED hook that needs more than this per call counts as faulty.
    uint256 internal constant PROBE_GAS = 1_000_000;
    /// @dev HX2 margin for the call itself (cold account, memory, event).
    uint256 internal constant GAS_MARGIN = 20_000;
    bytes32 internal constant BINDING_CHANGED = keccak256("HookBindingChanged");

    event AuxHookFailed(uint256 indexed jobId, bytes4 selector, uint8 phase, bytes32 reasonHash);
    event HookFaultDeclared(
        uint256 indexed jobId, address indexed declarer, bytes4 selector, uint8 phase, bytes32 dataHash, bytes32 reasonHash
    );
    event HookFaultCleared(uint256 indexed jobId, address indexed caller);
    event HookFaultResolved(uint256 indexed jobId, uint8 policy);

    error InsufficientGasForHook();
    error ProbeResult(bool ok, bytes32 reasonHash);
    error ProbePassed();
    error ProbeFailed();
    error NoHookFault();
    error HookFaultActive();
    error FaultWindowOpen();

    // ──────────────────── Hook calls ────────────────────

    function run(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        uint256 jobId,
        bytes4 selector,
        bytes memory data,
        uint8 phase
    ) external {
        address hook = j.hook;
        if (hook == address(0)) return;
        // EVALUATOR_ON_FAULT resolved: the evaluator decides once without the hook (HF3)
        if (
            x.evaluatorOverride
                && (selector == ERC8183Virtual.complete.selector || selector == ERC8183Virtual.reject.selector)
        ) return;
        bool committed = x.committedTermsHash != bytes32(0);
        if (x.hookClass == XDLogic.HOOK_AUXILIARY) {
            bytes memory cd = abi.encodeWithSelector(
                phase == BEFORE ? IERC8183Hook.beforeAction.selector : IERC8183Hook.afterAction.selector,
                jobId,
                selector,
                data
            );
            if (committed && !_bound(x, hook, jobId, x.auxHookGas)) {
                emit AuxHookFailed(jobId, selector, phase, BINDING_CHANGED);
                return;
            }
            (bool ok, bytes32 rh) = _cappedCall(hook, x.auxHookGas, cd);
            if (!ok) emit AuxHookFailed(jobId, selector, phase, rh);
            return;
        }
        // REQUIRED
        if (committed && !_bound(x, hook, jobId, gasleft())) revert XDLogic.HookBindingChanged(jobId);
        if (phase == BEFORE) {
            IERC8183Hook(hook).beforeAction(jobId, selector, data);
        } else {
            IERC8183Hook(hook).afterAction(jobId, selector, data);
            if (x.faultAt != 0) _clear(x, jobId); // HF2: a successful hooked core call clears the fault
        }
    }

    // ──────────────────── Faults ────────────────────

    /// @notice HF1. Client or provider, REQUIRED hook, Funded or Submitted job, no fault already standing.
    function declareFault(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        uint256 jobId,
        bytes4 selector,
        uint8 phase,
        bytes calldata data
    ) external {
        if (msg.sender != j.client && msg.sender != j.provider) revert ERC8183Virtual.Unauthorized();
        if (j.status != ERC8183Virtual.JobStatus.Funded && j.status != ERC8183Virtual.JobStatus.Submitted) {
            revert ERC8183Virtual.WrongStatus();
        }
        if (j.hook == address(0) || x.hookClass != XDLogic.HOOK_REQUIRED || phase > AFTER) {
            revert XDLogic.UnsupportedTerms();
        }
        if (x.faultAt != 0 || x.evaluatorOverride) revert HookFaultActive();
        bytes32 rh = BINDING_CHANGED;
        if (_bound(x, j.hook, jobId, PROBE_GAS)) {
            bool ok;
            (ok, rh) = _probe(jobId, selector, phase, data);
            if (ok) revert ProbePassed();
        }
        x.faultAt = uint48(block.timestamp);
        x.faultProbeHash = keccak256(abi.encode(selector, phase, data));
        emit HookFaultDeclared(jobId, msg.sender, selector, phase, keccak256(data), rh);
    }

    /// @notice HF2. Anyone, with the declared probe, once the binding holds and the probe passes.
    function clearFault(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        uint256 jobId,
        bytes4 selector,
        uint8 phase,
        bytes calldata data
    ) external {
        if (x.faultAt == 0) revert NoHookFault();
        if (keccak256(abi.encode(selector, phase, data)) != x.faultProbeHash) revert XDLogic.AmendmentMismatch();
        if (!_bound(x, j.hook, jobId, PROBE_GAS)) revert ProbeFailed();
        (bool ok,) = _probe(jobId, selector, phase, data);
        if (!ok) revert ProbeFailed();
        _clear(x, jobId);
    }

    /// @notice HF3. Anyone, after the fault window, on a Funded or Submitted job. Runs the policy fixed at creation.
    function resolveFault(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        mapping(address => uint256) storage escrowed,
        mapping(address => uint256) storage unclaimed,
        uint256 jobId
    ) external {
        if (x.faultAt == 0) revert NoHookFault();
        if (block.timestamp < uint256(x.faultAt) + x.faultWindow) revert FaultWindowOpen();
        if (j.status != ERC8183Virtual.JobStatus.Funded && j.status != ERC8183Virtual.JobStatus.Submitted) {
            revert ERC8183Virtual.WrongStatus();
        }
        uint8 policy = x.hookFaultPolicy;
        if (policy == POLICY_REFUND_ON_FAULT) {
            j.status = ERC8183Virtual.JobStatus.Expired;
            XDPayout.settleRefund(j, x, escrowed, unclaimed, jobId);
            emit ERC8183Virtual.JobExpired(jobId);
        } else if (policy == POLICY_EVALUATOR_ON_FAULT) {
            x.evaluatorOverride = true;
        }
        emit HookFaultResolved(jobId, policy);
    }

    /// @notice Body of the escrow's `probeHook`: one capped hook call, then always revert with the result.
    function probe(address hook, uint256 jobId, bytes4 selector, uint8 phase, bytes calldata data) external {
        if (msg.sender != address(this)) revert ERC8183Virtual.Unauthorized();
        bytes memory cd = abi.encodeWithSelector(
            phase == BEFORE ? IERC8183Hook.beforeAction.selector : IERC8183Hook.afterAction.selector, jobId, selector, data
        );
        (bool ok, bytes32 rh) = _cappedCall(hook, PROBE_GAS, cd);
        revert ProbeResult(ok, rh);
    }

    // ──────────────────── internals ────────────────────

    function _clear(XDLogic.XTerms storage x, uint256 jobId) private {
        x.faultAt = 0;
        x.faultProbeHash = bytes32(0);
        emit HookFaultCleared(jobId, msg.sender);
    }

    /// @dev Runs the probe in a self-call that always reverts, and decodes ProbeResult from the revert data.
    function _probe(uint256 jobId, bytes4 selector, uint8 phase, bytes calldata data)
        private
        returns (bool ok, bytes32 rh)
    {
        (, bytes memory ret) = address(this).call(abi.encodeCall(IXDProbe.probeHook, (jobId, selector, phase, data)));
        if (ret.length != 68 || bytes4(ret) != ProbeResult.selector) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        assembly {
            ok := mload(add(ret, 36))
            rh := mload(add(ret, 68))
        }
    }

    /// @dev HX2 + HX3: refuse to run when the caller left too little gas for the cap; copy at most 256 bytes back.
    function _cappedCall(address target, uint256 cap, bytes memory cd) private returns (bool ok, bytes32 rh) {
        if (gasleft() < (cap * 64) / 63 + GAS_MARGIN) revert InsufficientGasForHook();
        assembly {
            ok := call(cap, target, 0, add(cd, 32), mload(cd), 0, 0)
            let n := returndatasize()
            if gt(n, 256) { n := 256 }
            let p := mload(0x40)
            returndatacopy(p, 0, n)
            rh := keccak256(p, n)
        }
    }

    /// @dev Code hash and (if declared at commitment) config hash still the committed ones. The config read is a
    ///  staticcall capped at `cap` that copies 32 bytes; a failing read counts as changed.
    function _bound(XDLogic.XTerms storage x, address hook, uint256 jobId, uint256 cap) private view returns (bool) {
        if (hook.codehash != x.hookCodeHash) return false;
        if (!x.hookHasConfig) return true;
        bytes memory cd = abi.encodeCall(IERC8183HookConfig.hookConfigHash, (jobId));
        bool ok;
        bytes32 h;
        assembly {
            ok := staticcall(cap, hook, add(cd, 32), mload(cd), 0, 32)
            if lt(returndatasize(), 32) { ok := 0 }
            h := mload(0)
        }
        return ok && h == x.hookConfigHash;
    }
}
