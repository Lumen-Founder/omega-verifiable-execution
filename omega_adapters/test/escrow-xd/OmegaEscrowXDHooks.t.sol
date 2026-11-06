// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OmegaEscrowXD} from "../../src/escrow-xd/OmegaEscrowXD.sol";
import {ERC8183Virtual} from "../../src/escrow-xd/ERC8183Virtual.sol";
import {XDLogic} from "../../src/escrow-xd/XDLogic.sol";
import {XDHooks} from "../../src/escrow-xd/XDHooks.sol";
import {CommitmentTermsLib as L} from "../../src/escrow-xd/CommitmentTermsLib.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TestERC20} from "../integration/TestERC20.sol";
import {ConfigHook} from "./XDHooks.sol";
import {PhaseHook, GasBurnerHook, BigRevertHook, ReenteringHook} from "./XDStage3Hooks.sol";
import {TermsVectorHarness} from "./TermsVectors.t.sol";

interface VmH {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function prank(address) external;
    function warp(uint256) external;
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// @notice Stage-3 tests of the XD escrow: AUXILIARY hooks (HX1-HX5) and REQUIRED-hook faults (HF1-HF7).
///  IDs refer to Deferred Payout Settlement design v0.3, 4B.8 (HK-29 .. HK-45), and the decision record.
contract OmegaEscrowXDHooksTest {
    VmH internal constant vm = VmH(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant PK_C = 0xC1;
    uint256 internal constant PK_P = 0xB2;
    uint256 internal constant PK_E = 0xE3;
    address internal constant EADMIN = address(0xEAD);
    address internal constant TREASURY = address(0x7EA5);
    address internal constant STRANGER = address(0x5157);
    uint256 internal constant BUDGET = 1_000_000;
    uint48 internal constant EXPIRY = 2_000_000_000;
    uint8 internal constant NONE = 0;
    uint8 internal constant REQUIRED = 1;
    uint8 internal constant AUX = 2;
    uint8 internal constant EXPIRE_ONLY = 0;
    uint8 internal constant REFUND_ON_FAULT = 1;
    uint8 internal constant EVALUATOR_ON_FAULT = 2;

    address internal CLIENT;
    address internal PROV;
    address internal EVAL;
    OmegaEscrowXD internal xd;
    TestERC20 internal token;
    TermsVectorHarness internal th;

    function setUp() public {
        vm.warp(1_000_000);
        CLIENT = vm.addr(PK_C);
        PROV = vm.addr(PK_P);
        EVAL = vm.addr(PK_E);
        token = new TestERC20("usdc");
        th = new TermsVectorHarness();
        OmegaEscrowXD impl = new OmegaEscrowXD();
        xd = OmegaEscrowXD(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(ERC8183Virtual.initialize, (TREASURY, EADMIN))))
        );
        vm.prank(EADMIN);
        xd.setPaymentTokenAllowed(address(token), true);
    }

    // ──────────────────── helpers ────────────────────

    function _job(address hook, uint8 class, uint8 policy, uint8 mode) internal returns (uint256 id) {
        if (hook != address(0)) {
            vm.prank(EADMIN);
            xd.setHookWhitelist(hook, true);
        }
        XDLogic.CreateTerms memory ct = xd.defaultCreateTerms(hook);
        ct.hookClass = class;
        ct.hookFaultPolicy = policy;
        ct.settlementMode = mode;
        vm.prank(CLIENT);
        id = xd.createJobWithTerms(PROV, EVAL, EXPIRY, "xd job", hook, 0, ct);
        vm.prank(PROV);
        xd.setBudget(id, address(token), BUDGET, "");
        (, bytes32 h) = xd.commitmentTermsOf(id);
        vm.prank(PROV);
        xd.confirmTerms(id, h);
        token.mint(CLIENT, BUDGET);
        vm.prank(CLIENT);
        token.approve(address(xd), BUDGET);
        vm.prank(CLIENT);
        xd.fundWithTermsHash(id, h, "");
    }

    function _submit(uint256 id) internal {
        vm.prank(PROV);
        xd.submit(id, keccak256("deliverable"), "");
    }

    function _status(uint256 id) internal view returns (ERC8183Virtual.JobStatus) {
        return xd.getJob(id).status;
    }

    function _count(VmH.Log[] memory logs, bytes32 topic) internal pure returns (uint256 n) {
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == topic) n++;
        }
    }

    bytes4 internal constant SUBMIT = ERC8183Virtual.submit.selector;
    bytes4 internal constant COMPLETE = ERC8183Virtual.complete.selector;

    function _declare(uint256 id) internal {
        vm.prank(CLIENT);
        xd.declareHookFault(id, COMPLETE, 0, "");
    }

    function _sig(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _amendTo(uint256 id, address newHook, uint8 newClass) internal {
        (L.TermsV2 memory t, bytes32 h) = xd.commitmentTermsOf(id);
        L.HookAmendment memory a;
        a.jobId = id;
        a.oldTermsHash = h;
        a.newHook = newHook;
        a.newHookCodeHash = newHook.codehash;
        a.newHookClass = newClass;
        t.hook = newHook;
        t.hookCodeHash = a.newHookCodeHash;
        t.hookConfigHash = 0;
        t.hookClass = newClass;
        a.newTermsHash = th.termsHash(t, address(xd));
        a.nonce = xd.xTermsOf(id).amendmentNonce;
        a.deadline = uint48(block.timestamp + 1 days);
        bytes32 d = th.amendmentDigest(a, address(xd));
        XDLogic.AmendmentSignatures memory s;
        s.client = _sig(PK_C, d);
        s.provider = _sig(PK_P, d);
        s.evaluator = _sig(PK_E, d);
        xd.amendHook(a, s);
    }

    // ──────────────────── creation rules ────────────────────

    function test_classes_and_policies_accepted_at_creation() public {
        PhaseHook h = new PhaseHook();
        for (uint8 c = REQUIRED; c <= AUX; c++) {
            for (uint8 p; p <= EVALUATOR_ON_FAULT; p++) {
                uint256 id = _job(address(h), c, p, 0);
                require(xd.xTermsOf(id).hookClass == c && xd.xTermsOf(id).hookFaultPolicy == p, "locked");
            }
        }
        XDLogic.CreateTerms memory ct = xd.defaultCreateTerms(address(h));
        ct.hookClass = NONE; // a hook needs a class
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.UnsupportedTerms.selector);
        xd.createJobWithTerms(PROV, EVAL, EXPIRY, "x", address(h), 0, ct);
        ct = xd.defaultCreateTerms(address(0));
        ct.hookClass = AUX; // no hook, no class
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.UnsupportedTerms.selector);
        xd.createJobWithTerms(PROV, EVAL, EXPIRY, "x", address(0), 0, ct);
    }

    // ──────────────────── AUXILIARY hooks (HX1-HX5) ────────────────────

    function test_HK29_failing_auxiliary_hook_cannot_block_the_core_calls() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), AUX, EXPIRE_ONLY, 0);
        h.set(true, true);
        vm.recordLogs();
        _submit(id);
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), "");
        VmH.Log[] memory logs = vm.getRecordedLogs();
        require(_status(id) == ERC8183Virtual.JobStatus.Completed, "core calls succeed");
        require(token.balanceOf(PROV) == BUDGET, "paid");
        require(_count(logs, XDHooks.AuxHookFailed.selector) == 4, "before + after, for submit and complete");
    }

    function test_HK30_gas_burning_auxiliary_hook_is_cut_at_the_cap() public {
        GasBurnerHook h = new GasBurnerHook();
        uint256 id = _job(address(h), AUX, EXPIRE_ONLY, 0);
        uint256 g = gasleft();
        _submit(id);
        uint256 used = g - gasleft();
        require(_status(id) == ERC8183Virtual.JobStatus.Submitted, "core call succeeds");
        require(used < 2 * 100_000 + 80_000, "two capped calls, nothing more");
    }

    function test_HK31_too_little_gas_for_the_auxiliary_cap_reverts_the_core_call() public {
        PhaseHook h = new PhaseHook();
        uint256 a = _job(address(h), AUX, EXPIRE_ONLY, 0);
        uint256 b = _job(address(h), AUX, EXPIRE_ONLY, 0);
        uint256 g = gasleft();
        _submit(a);
        uint256 used = g - gasleft();
        // Same call with only the gas a full run needs: the hook itself would succeed on it, but the cap is not
        // reserved, so the escrow refuses instead of letting a caller starve the hook (HX2).
        vm.prank(PROV);
        (bool ok, bytes memory ret) =
            address(xd).call{gas: used}(abi.encodeCall(ERC8183Virtual.submit, (b, keccak256("deliverable"), "")));
        require(!ok && bytes4(ret) == XDHooks.InsufficientGasForHook.selector, "HX2");
        require(_status(b) == ERC8183Virtual.JobStatus.Funded, "nothing happened");
    }

    function test_HK32_large_revert_data_is_hashed_from_the_first_256_bytes_only() public {
        BigRevertHook h = new BigRevertHook();
        uint256 id = _job(address(h), AUX, EXPIRE_ONLY, 0);
        vm.recordLogs();
        _submit(id);
        VmH.Log[] memory logs = vm.getRecordedLogs();
        bytes memory first = new bytes(256);
        for (uint256 i; i < 256; i++) first[i] = 0xab;
        bool seen;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] != XDHooks.AuxHookFailed.selector) continue;
            (,, bytes32 rh) = abi.decode(logs[i].data, (bytes4, uint8, bytes32));
            require(rh == keccak256(first), "HX3: 256-byte prefix");
            seen = true;
        }
        require(seen && _status(id) == ERC8183Virtual.JobStatus.Submitted, "core call succeeds");
    }

    function test_HK33_reentering_auxiliary_hook_is_blocked() public {
        ReenteringHook h = new ReenteringHook();
        h.setEscrow(address(xd));
        uint256 id = _job(address(h), AUX, EXPIRE_ONLY, 0);
        vm.recordLogs();
        _submit(id);
        VmH.Log[] memory logs = vm.getRecordedLogs();
        require(!h.reentered(), "re-entry reverted inside the hook");
        require(_count(logs, XDHooks.AuxHookFailed.selector) == 1, "reported");
        require(_status(id) == ERC8183Virtual.JobStatus.Submitted, "core state as expected");
    }

    function test_auxiliary_binding_change_skips_the_hook_and_does_not_block() public {
        ConfigHook h = new ConfigHook();
        uint256 id = _job(address(h), AUX, EXPIRE_ONLY, 0);
        h.setConfig(id, keccak256("changed after funding"));
        uint256 calls = h.calls();
        vm.recordLogs();
        _submit(id);
        VmH.Log[] memory logs = vm.getRecordedLogs();
        require(h.calls() == calls, "not called");
        require(_count(logs, XDHooks.AuxHookFailed.selector) == 2, "reported for both phases");
        require(_status(id) == ERC8183Virtual.JobStatus.Submitted, "core call succeeds");
    }

    function test_required_hook_still_blocks_as_upstream() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(false, true);
        vm.prank(PROV);
        vm.expectRevert(bytes("after failed"));
        xd.submit(id, keccak256("deliverable"), "");
    }

    // ──────────────────── faults: declare (HF1) ────────────────────

    function test_HK34_client_declares_a_fault_of_a_reverting_required_hook() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(true, false);
        vm.recordLogs();
        _declare(id);
        VmH.Log[] memory logs = vm.getRecordedLogs();
        require(xd.xTermsOf(id).faultAt == block.timestamp, "fault recorded");
        require(_count(logs, XDHooks.HookFaultDeclared.selector) == 1, "one event");
    }

    function test_HK34b_provider_declares_an_after_phase_fault() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(false, true);
        vm.prank(PROV);
        xd.declareHookFault(id, SUBMIT, 1, "");
        require(xd.xTermsOf(id).faultAt != 0, "fault recorded");
    }

    function test_HK35_healthy_hook_cannot_be_declared_faulty() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        vm.prank(CLIENT);
        vm.expectRevert(XDHooks.ProbePassed.selector);
        xd.declareHookFault(id, COMPLETE, 0, "");
    }

    function test_HK35b_declaring_with_too_little_gas_reverts() public {
        GasBurnerHook h = new GasBurnerHook();
        // The burner is not a working hook; we only need a REQUIRED binding. Fund with a PhaseHook, then amend.
        PhaseHook ok = new PhaseHook();
        uint256 id = _job(address(ok), REQUIRED, EXPIRE_ONLY, 0);
        vm.prank(EADMIN);
        xd.setHookWhitelist(address(h), true);
        _amendTo(id, address(h), REQUIRED);
        vm.prank(CLIENT);
        (bool success, bytes memory ret) =
            address(xd).call{gas: 600_000}(abi.encodeCall(OmegaEscrowXD.declareHookFault, (id, COMPLETE, 0, "")));
        require(!success && bytes4(ret) == XDHooks.InsufficientGasForHook.selector, "no fake fault from low gas");
        vm.prank(CLIENT);
        xd.declareHookFault(id, COMPLETE, 0, ""); // with enough gas the burner is a real fault
        require(xd.xTermsOf(id).faultAt != 0, "fault recorded");
    }

    function test_HK36_only_client_or_provider_declares() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(true, true);
        address[3] memory others = [STRANGER, EADMIN, EVAL];
        for (uint256 i; i < 3; i++) {
            vm.prank(others[i]);
            vm.expectRevert(ERC8183Virtual.Unauthorized.selector);
            xd.declareHookFault(id, COMPLETE, 0, "");
        }
    }

    function test_declare_rejects_auxiliary_none_and_open_jobs() public {
        PhaseHook h = new PhaseHook();
        uint256 aux = _job(address(h), AUX, EXPIRE_ONLY, 0);
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.UnsupportedTerms.selector);
        xd.declareHookFault(aux, COMPLETE, 0, "");
        uint256 none = _job(address(0), NONE, EXPIRE_ONLY, 0);
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.UnsupportedTerms.selector);
        xd.declareHookFault(none, COMPLETE, 0, "");
        vm.prank(CLIENT);
        uint256 open = xd.createJob(PROV, EVAL, EXPIRY, "open", address(0), 0);
        vm.prank(CLIENT);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.declareHookFault(open, COMPLETE, 0, "");
    }

    function test_binding_change_is_a_fault_without_a_probe() public {
        ConfigHook h = new ConfigHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.setConfig(id, keccak256("changed"));
        _declare(id);
        require(xd.xTermsOf(id).faultAt != 0, "fault recorded");
    }

    // ──────────────────── faults: clear (HF2) and probes leave no state ────────────────────

    function test_HK37_anyone_clears_once_the_same_probe_passes() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(true, false);
        _declare(id);
        vm.prank(STRANGER);
        vm.expectRevert(XDHooks.ProbeFailed.selector);
        xd.clearHookFault(id, COMPLETE, 0, "");
        h.set(false, false);
        vm.prank(STRANGER);
        vm.expectRevert(XDLogic.AmendmentMismatch.selector);
        xd.clearHookFault(id, SUBMIT, 0, ""); // not the declared probe
        uint256 calls = h.calls();
        vm.prank(STRANGER);
        xd.clearHookFault(id, COMPLETE, 0, "");
        require(xd.xTermsOf(id).faultAt == 0, "cleared");
        require(h.calls() == calls, "the passing probe left no state in the hook");
    }

    function test_HK38_successful_hooked_core_call_clears_the_fault() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(true, false);
        _declare(id);
        h.set(false, false);
        _submit(id);
        require(xd.xTermsOf(id).faultAt == 0, "cleared by the core call");
    }

    // ──────────────────── faults: resolve (HF3, HF5) ────────────────────

    function test_HK39_resolve_waits_for_the_fault_window() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, REFUND_ON_FAULT, 0);
        h.set(true, true);
        _declare(id);
        vm.warp(block.timestamp + 72 hours - 1);
        vm.expectRevert(XDHooks.FaultWindowOpen.selector);
        xd.resolveHookFault(id);
        vm.warp(block.timestamp + 1);
        xd.resolveHookFault(id);
        require(_status(id) == ERC8183Virtual.JobStatus.Expired, "resolved");
    }

    function test_HK40a_expire_only_changes_nothing() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(true, true);
        _declare(id);
        vm.warp(block.timestamp + 72 hours);
        xd.resolveHookFault(id);
        require(_status(id) == ERC8183Virtual.JobStatus.Funded && token.balanceOf(CLIENT) == 0, "nothing moves");
        vm.warp(EXPIRY);
        xd.claimRefund(id); // HK-43: the expiry path stays open
        require(token.balanceOf(CLIENT) == BUDGET, "expiry refund");
    }

    function test_HK40b_refund_on_fault_refunds_now() public {
        PhaseHook h = new PhaseHook();
        uint256 imm = _job(address(h), REQUIRED, REFUND_ON_FAULT, 0);
        uint256 def = _job(address(h), REQUIRED, REFUND_ON_FAULT, 1);
        h.set(true, true);
        _declare(imm);
        _declare(def);
        vm.warp(block.timestamp + 72 hours);
        vm.prank(STRANGER);
        xd.resolveHookFault(imm);
        vm.prank(STRANGER);
        xd.resolveHookFault(def);
        require(token.balanceOf(CLIENT) == BUDGET, "IMMEDIATE: pushed, no fees");
        (,, uint256 amt, uint8 st) = xd.payoutOf(def, 3);
        require(st == 1 && amt == BUDGET, "DEFERRED: refund right");
        require(xd.totalEscrowed(address(token)) == 0 && xd.totalUnclaimed(address(token)) == BUDGET, "books");
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.resolveHookFault(imm); // once
    }

    function test_HK40c_HK41_evaluator_on_fault_allows_one_decision_without_the_hook() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EVALUATOR_ON_FAULT, 0);
        _submit(id);
        h.set(true, true);
        _declare(id);
        vm.prank(EVAL);
        vm.expectRevert(bytes("before failed"));
        xd.complete(id, bytes32("ok"), ""); // not yet resolved
        vm.warp(block.timestamp + 72 hours);
        xd.resolveHookFault(id);
        uint256 calls = h.calls();
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), "");
        require(h.calls() == calls, "hook not called");
        require(token.balanceOf(PROV) == BUDGET, "HF5: paid to the locked recipient");
        vm.prank(EVAL);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.complete(id, bytes32("again"), "");
    }

    function test_evaluator_override_does_not_unblock_other_calls() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EVALUATOR_ON_FAULT, 0);
        h.set(true, true);
        _declare(id);
        vm.warp(block.timestamp + 72 hours);
        xd.resolveHookFault(id);
        vm.prank(PROV);
        vm.expectRevert(bytes("before failed"));
        xd.submit(id, keccak256("deliverable"), ""); // only complete/reject skip the hook
        vm.prank(EVAL);
        xd.reject(id, bytes32("no"), ""); // a Funded job can still be rejected by the evaluator
        require(token.balanceOf(CLIENT) == BUDGET, "refunded");
    }

    // ──────────────────── amendment, pause, admin ────────────────────

    function test_HK42_amendment_during_a_fault_clears_it() public {
        PhaseHook broken = new PhaseHook();
        PhaseHook fresh = new PhaseHook();
        uint256 id = _job(address(broken), REQUIRED, EVALUATOR_ON_FAULT, 0);
        broken.set(true, true);
        _declare(id);
        vm.warp(block.timestamp + 72 hours);
        xd.resolveHookFault(id);
        vm.prank(EADMIN);
        xd.setHookWhitelist(address(fresh), true);
        _amendTo(id, address(fresh), AUX);
        XDLogic.XTerms memory x = xd.xTermsOf(id);
        require(x.faultAt == 0 && x.faultProbeHash == 0 && !x.evaluatorOverride, "fault and override cleared");
        require(x.hookClass == AUX, "amended to an auxiliary hook");
        _submit(id);
        require(fresh.calls() == 2, "new hook runs");
    }

    function test_fault_functions_work_while_paused_and_admin_has_no_path() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, REFUND_ON_FAULT, 0);
        h.set(true, true);
        vm.prank(EADMIN);
        xd.pause();
        _declare(id); // D-35
        vm.prank(EADMIN);
        vm.expectRevert(ERC8183Virtual.Unauthorized.selector);
        xd.declareHookFault(id, COMPLETE, 0, "");
        vm.warp(block.timestamp + 72 hours);
        xd.resolveHookFault(id);
        require(token.balanceOf(CLIENT) == BUDGET, "refund while paused");
    }

    function test_probe_hook_is_self_call_only() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        vm.prank(STRANGER);
        vm.expectRevert(ERC8183Virtual.Unauthorized.selector);
        xd.probeHook(id, COMPLETE, 0, "");
    }

    // ──────────────────── gas scenarios (HK-45; run alone with --isolate --gas-report --match-test) ────────────────────

    function test_gas_required_hook_submit() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        _submit(id);
    }

    function test_gas_auxiliary_hook_submit() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), AUX, EXPIRE_ONLY, 0);
        _submit(id);
    }

    function test_gas_declare_fault() public {
        PhaseHook h = new PhaseHook();
        uint256 id = _job(address(h), REQUIRED, EXPIRE_ONLY, 0);
        h.set(true, true);
        _declare(id);
    }
}
