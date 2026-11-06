// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OmegaEscrowXD} from "../../src/escrow-xd/OmegaEscrowXD.sol";
import {ERC8183Virtual} from "../../src/escrow-xd/ERC8183Virtual.sol";
import {XDLogic} from "../../src/escrow-xd/XDLogic.sol";
import {XDPayout} from "../../src/escrow-xd/XDPayout.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TestERC20} from "../integration/TestERC20.sol";
import {CountingHook} from "./XDHooks.sol";
import {BlockingERC20, FalseERC20, ReentrantERC20, RecordingDisburser} from "./XDPayoutMocks.sol";

interface VmP {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function prank(address) external;
    function warp(uint256) external;
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// @notice Stage-2 tests of the XD escrow: deferred payout (DS), refund rights (D-10), claims not blocked by pause
///  (D-11, D-29), solvency accounting and the excess-only emergency withdrawal (DS16, DS17).
///  IDs refer to Deferred Payout Settlement design v0.3, section 9, and the decision record.
contract OmegaEscrowXDPayoutTest {
    VmP internal constant vm = VmP(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant EADMIN = address(0xEAD);
    address internal constant CLIENT = address(0xC11E);
    address internal constant PROV = address(0xB0B);
    address internal constant EVAL = address(0xE7A1);
    address internal constant TREASURY = address(0x7EA5);
    address internal constant EVAL_FEES = address(0xFEE);
    address internal constant STRANGER = address(0x5157);
    uint256 internal constant BUDGET = 1_000_007; // M-1 vector: e 333, p 77
    uint48 internal constant EXPIRY = 2_000_000_000;
    uint8 internal constant DEFERRED = 1;
    uint8 internal constant K_PROV = 0;
    uint8 internal constant K_EVAL = 1;
    uint8 internal constant K_PLAT = 2;
    uint8 internal constant K_REFUND = 3;

    OmegaEscrowXD internal xd;
    TestERC20 internal token;

    function setUp() public {
        vm.warp(1_000_000);
        token = new TestERC20("usdc");
        OmegaEscrowXD impl = new OmegaEscrowXD();
        xd = OmegaEscrowXD(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(ERC8183Virtual.initialize, (TREASURY, EADMIN))))
        );
        vm.prank(EADMIN);
        xd.setPaymentTokenAllowed(address(token), true);
        vm.prank(EADMIN);
        xd.setEvaluatorFee(333);
        vm.prank(EADMIN);
        xd.setPlatformFee(77, TREASURY);
        vm.prank(EVAL);
        xd.setEvaluatorDefaultRecipient(EVAL_FEES);
    }

    // ──────────────────── helpers ────────────────────

    function _allowToken(TestERC20 t) internal {
        vm.prank(EADMIN);
        xd.setPaymentTokenAllowed(address(t), true);
    }

    /// @dev Open job with the given mode, hook, token and provider recipient, confirmed and funded.
    function _funded(uint8 mode, address hook, TestERC20 t, address recipient) internal returns (uint256 id) {
        XDLogic.CreateTerms memory ct = xd.defaultCreateTerms(hook);
        ct.settlementMode = mode;
        vm.prank(CLIENT);
        id = xd.createJobWithTerms(PROV, EVAL, EXPIRY, "xd job", hook, 0, ct);
        vm.prank(PROV);
        xd.setBudget(id, address(t), BUDGET, "");
        if (recipient != address(0)) {
            vm.prank(PROV);
            xd.setPayoutReceiver(id, recipient);
        }
        (, bytes32 h) = xd.commitmentTermsOf(id);
        vm.prank(PROV);
        xd.confirmTerms(id, h);
        t.mint(CLIENT, BUDGET);
        vm.prank(CLIENT);
        t.approve(address(xd), BUDGET);
        vm.prank(CLIENT);
        xd.fundWithTermsHash(id, h, "");
    }

    function _deferred() internal returns (uint256) {
        return _funded(DEFERRED, address(0), token, address(0));
    }

    function _complete(uint256 id, bytes memory optParams) internal {
        vm.prank(PROV);
        xd.submit(id, keccak256("deliverable"), "");
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), optParams);
    }

    function _status(uint256 id, uint8 kind) internal view returns (uint8 s) {
        (,,, s) = xd.payoutOf(id, kind);
    }

    function _amount(uint256 id, uint8 kind) internal view returns (uint256 a) {
        (,, a,) = xd.payoutOf(id, kind);
    }

    function _claim(uint256 id, uint8 kind) internal returns (uint256) {
        vm.prank(STRANGER);
        return xd.claimPayout(id, kind, "");
    }

    // M-1: evalFee 33,300 / platformFee 7,700 / net 959,007
    uint256 internal constant EF = 33_300;
    uint256 internal constant PF = 7_700;
    uint256 internal constant NET = 959_007;

    // ──────────────────── completion fixes rights (DS1-DS3) ────────────────────

    function test_DS1_completion_records_rights_and_moves_nothing() public {
        uint256 id = _deferred();
        require(xd.totalEscrowed(address(token)) == BUDGET, "funded budget is escrowed");
        vm.recordLogs();
        _complete(id, "");
        VmP.Log[] memory logs = vm.getRecordedLogs();
        require(uint8(xd.getJob(id).status) == uint8(ERC8183Virtual.JobStatus.Completed), "completed");
        require(token.balanceOf(PROV) == 0 && token.balanceOf(EVAL_FEES) == 0 && token.balanceOf(TREASURY) == 0, "no pay");
        require(token.balanceOf(address(xd)) == BUDGET, "all stays in the escrow");
        require(_amount(id, K_PROV) == NET && _amount(id, K_EVAL) == EF && _amount(id, K_PLAT) == PF, "M1 shares");
        require(NET + EF + PF == BUDGET, "S2");
        for (uint8 k; k < 3; k++) require(_status(id, k) == 1, "ENTITLED");
        require(_status(id, K_REFUND) == 0, "no refund right");
        require(xd.totalEscrowed(address(token)) == 0 && xd.totalUnclaimed(address(token)) == BUDGET, "DS16 books");
        uint256 entitled;
        for (uint256 i; i < logs.length; i++) {
            bytes32 t0 = logs[i].topics[0];
            require(t0 != ERC8183Virtual.PaymentReleased.selector, "no PaymentReleased at completion");
            require(t0 != ERC8183Virtual.EvaluatorFeePaid.selector, "no EvaluatorFeePaid at completion");
            require(t0 != ERC8183Virtual.PlatformFeePaid.selector, "no PlatformFeePaid at completion");
            if (t0 == XDPayout.PayoutEntitled.selector) entitled++;
        }
        require(entitled == 3, "three PayoutEntitled");
    }

    function test_DS2_anyone_claims_each_right_to_its_fixed_recipient() public {
        uint256 id = _deferred();
        _complete(id, "");
        vm.recordLogs();
        require(_claim(id, K_PROV) == NET && _claim(id, K_EVAL) == EF && _claim(id, K_PLAT) == PF, "returns amount");
        VmP.Log[] memory logs = vm.getRecordedLogs();
        require(token.balanceOf(PROV) == NET, "provider");
        require(token.balanceOf(EVAL_FEES) == EF, "evaluator fee recipient locked at creation");
        require(token.balanceOf(TREASURY) == PF, "platform");
        require(token.balanceOf(STRANGER) == 0, "caller gets nothing");
        require(token.balanceOf(address(xd)) == 0 && xd.totalUnclaimed(address(token)) == 0, "books cleared");
        for (uint8 k; k < 3; k++) require(_status(id, k) == 2, "CLAIMED");
        uint256 claimed;
        bool released;
        bool evalPaid;
        bool platPaid;
        for (uint256 i; i < logs.length; i++) {
            bytes32 t0 = logs[i].topics[0];
            if (t0 == XDPayout.PayoutClaimed.selector) claimed++;
            if (t0 == ERC8183Virtual.PaymentReleased.selector) released = true;
            if (t0 == ERC8183Virtual.EvaluatorFeePaid.selector) evalPaid = true;
            if (t0 == ERC8183Virtual.PlatformFeePaid.selector) platPaid = true;
        }
        require(claimed == 3 && released && evalPaid && platPaid, "D-13: upstream events at claim time");
    }

    function test_DS3_DS4_blocked_recipient_cannot_stop_completion_and_keeps_its_right() public {
        BlockingERC20 bt = new BlockingERC20();
        _allowToken(bt);
        uint256 id = _funded(DEFERRED, address(0), bt, address(0));
        bt.setBlocked(PROV, true);
        _complete(id, "");
        require(uint8(xd.getJob(id).status) == uint8(ERC8183Virtual.JobStatus.Completed), "S9: completion succeeds");
        vm.prank(STRANGER);
        vm.expectRevert(bytes("blocked"));
        xd.claimPayout(id, K_PROV, "");
        require(_status(id, K_PROV) == 1 && xd.totalUnclaimed(address(bt)) == BUDGET, "S8: right and books kept");
        require(_claim(id, K_EVAL) == EF, "other shares are not held hostage");
        bt.setBlocked(PROV, false);
        require(_claim(id, K_PROV) == NET && bt.balanceOf(PROV) == NET, "paid after unblocking");
    }

    function test_DS3B_immediate_job_with_blocked_recipient_cannot_complete() public {
        BlockingERC20 bt = new BlockingERC20();
        _allowToken(bt);
        uint256 id = _funded(0, address(0), bt, address(0));
        bt.setBlocked(PROV, true);
        vm.prank(PROV);
        xd.submit(id, keccak256("deliverable"), "");
        vm.prank(EVAL);
        vm.expectRevert(bytes("blocked"));
        xd.complete(id, bytes32("ok"), "");
    }

    function test_DS5_second_claim_returns_zero_and_pays_nothing() public {
        uint256 id = _deferred();
        _complete(id, "");
        require(_claim(id, K_PROV) == NET, "first");
        require(_claim(id, K_PROV) == 0, "second is 0, no revert");
        require(token.balanceOf(PROV) == NET, "no double pay");
        require(_claim(id, K_REFUND) == 0, "NONE right returns 0");
        require(_claim(id, 9) == 0, "unknown kind returns 0");
        (address r, address t, uint256 a, uint8 s) = xd.payoutOf(id, 9);
        require(r == address(0) && t == address(0) && a == 0 && s == 0, "unknown kind is NONE");
    }

    function test_DS7_recipient_cannot_change_after_funding() public {
        uint256 id = _deferred();
        vm.prank(PROV);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.setPayoutReceiver(id, address(0xBAD));
    }

    // ──────────────────── IDisburser (DS9-DS12, DS14, DS15) ────────────────────

    function test_DS9_DS12_disburser_called_at_claim_with_complete_selector_and_original_data() public {
        RecordingDisburser d = new RecordingDisburser();
        d.setOnlySelector(ERC8183Virtual.complete.selector);
        uint256 id = _funded(DEFERRED, address(0), token, address(d));
        _complete(id, hex"c0ffee");
        require(d.callCount() == 0, "no callback at completion");
        vm.prank(STRANGER);
        require(xd.claimPayout(id, K_PROV, hex"c0ffee") == NET, "claimed");
        require(d.callCount() == 1, "one callback");
        (uint256 jid, bytes4 sel, address tk, uint256 amt) = _call0(d);
        require(jid == id && sel == ERC8183Virtual.complete.selector && tk == address(token) && amt == NET, "args");
        require(keccak256(d.lastData()) == keccak256(hex"c0ffee"), "original optParams");
        require(token.balanceOf(address(d)) == NET, "funds at the receiver");
    }

    function _call0(RecordingDisburser d) internal view returns (uint256 jid, bytes4 sel, address tk, uint256 amt) {
        (jid, sel, tk, amt,) = d.calls(0);
    }

    function test_DS10_reverting_disburser_cannot_stop_completion_and_keeps_its_right() public {
        RecordingDisburser d = new RecordingDisburser();
        d.setBroken(true);
        uint256 id = _funded(DEFERRED, address(0), token, address(d));
        _complete(id, "");
        vm.prank(STRANGER);
        vm.expectRevert(bytes("disburser broken"));
        xd.claimPayout(id, K_PROV, "");
        require(_status(id, K_PROV) == 1, "ENTITLED kept");
        require(token.balanceOf(address(d)) == 0, "DS15: transfer undone with the callback");
        d.setBroken(false);
        require(_claim(id, K_PROV) == NET, "paid once the receiver accepts");
    }

    function test_DS10B_immediate_job_with_reverting_disburser_cannot_complete() public {
        RecordingDisburser d = new RecordingDisburser();
        d.setBroken(true);
        uint256 id = _funded(0, address(0), token, address(d));
        vm.prank(PROV);
        xd.submit(id, keccak256("deliverable"), "");
        vm.prank(EVAL);
        vm.expectRevert(bytes("disburser broken"));
        xd.complete(id, bytes32("ok"), "");
    }

    function test_DS11_claimer_cannot_choose_the_disburser_data() public {
        RecordingDisburser d = new RecordingDisburser();
        uint256 id = _funded(DEFERRED, address(0), token, address(d));
        _complete(id, hex"0102");
        vm.prank(STRANGER);
        vm.expectRevert(XDPayout.DisburserDataMismatch.selector);
        xd.claimPayout(id, K_PROV, hex"0103");
        vm.prank(STRANGER);
        vm.expectRevert(XDPayout.DisburserDataMismatch.selector);
        xd.claimPayout(id, K_PROV, "");
        // empty optParams at completion: only empty data is accepted
        uint256 id2 = _funded(DEFERRED, address(0), token, address(d));
        _complete(id2, "");
        vm.prank(STRANGER);
        vm.expectRevert(XDPayout.DisburserDataMismatch.selector);
        xd.claimPayout(id2, K_PROV, hex"01");
        require(_claim(id2, K_PROV) == NET, "empty data accepted");
    }

    function test_DS13_reentrant_token_pays_once() public {
        ReentrantERC20 rt = new ReentrantERC20();
        _allowToken(rt);
        uint256 id = _funded(DEFERRED, address(0), rt, address(0));
        _complete(id, "");
        rt.arm(address(xd), id, K_PROV);
        require(_claim(id, K_PROV) == NET, "claimed");
        require(rt.reentryBlocked(), "inner claim reverted");
        require(rt.balanceOf(PROV) == NET && rt.balanceOf(address(xd)) == EF + PF, "paid once");
    }

    function test_DS14_false_returning_token_reverts_the_claim_and_keeps_the_right() public {
        FalseERC20 ft = new FalseERC20();
        _allowToken(ft);
        uint256 id = _funded(DEFERRED, address(0), ft, address(0));
        _complete(id, "");
        ft.setFailing(true);
        vm.prank(STRANGER);
        vm.expectRevert();
        xd.claimPayout(id, K_PROV, "");
        require(_status(id, K_PROV) == 1 && xd.totalUnclaimed(address(ft)) == BUDGET, "kept");
    }

    // ──────────────────── refund rights (D-10) ────────────────────

    function test_D10_rejection_of_a_deferred_job_records_the_refund_right() public {
        uint256 id = _deferred();
        vm.prank(EVAL);
        xd.reject(id, bytes32("no"), "");
        require(token.balanceOf(CLIENT) == 0, "nothing pushed");
        require(_status(id, K_REFUND) == 1 && _amount(id, K_REFUND) == BUDGET, "CLIENT_REFUND right");
        require(_status(id, K_PROV) == 0, "no provider right");
        require(xd.totalEscrowed(address(token)) == 0 && xd.totalUnclaimed(address(token)) == BUDGET, "books");
        require(_claim(id, K_REFUND) == BUDGET && token.balanceOf(CLIENT) == BUDGET, "refund claimed to the client");
    }

    function test_D10_blocked_client_cannot_stop_rejection_and_keeps_the_refund() public {
        BlockingERC20 bt = new BlockingERC20();
        _allowToken(bt);
        uint256 id = _funded(DEFERRED, address(0), bt, address(0));
        bt.setBlocked(CLIENT, true);
        vm.prank(EVAL);
        xd.reject(id, bytes32("no"), "");
        require(uint8(xd.getJob(id).status) == uint8(ERC8183Virtual.JobStatus.Rejected), "rejected");
        vm.prank(STRANGER);
        vm.expectRevert(bytes("blocked"));
        xd.claimPayout(id, K_REFUND, "");
        bt.setBlocked(CLIENT, false);
        require(_claim(id, K_REFUND) == BUDGET, "refund after unblocking");
    }

    function test_D10_expiry_of_a_deferred_job_records_the_refund_right() public {
        uint256 id = _deferred();
        vm.warp(EXPIRY);
        xd.claimRefund(id);
        require(uint8(xd.getJob(id).status) == uint8(ERC8183Virtual.JobStatus.Expired), "expired");
        require(token.balanceOf(CLIENT) == 0 && _status(id, K_REFUND) == 1, "right, not a push");
        require(_claim(id, K_REFUND) == BUDGET, "claimed");
    }

    function test_immediate_rejection_and_expiry_still_push_the_refund() public {
        uint256 a = _funded(0, address(0), token, address(0));
        vm.prank(EVAL);
        xd.reject(a, bytes32("no"), "");
        require(token.balanceOf(CLIENT) == BUDGET, "reject pushes");
        uint256 b = _funded(0, address(0), token, address(0));
        vm.warp(EXPIRY);
        xd.claimRefund(b);
        require(token.balanceOf(CLIENT) == 2 * BUDGET, "expiry pushes");
        require(_status(a, K_REFUND) == 0 && _status(b, K_REFUND) == 0, "no rights for IMMEDIATE");
        require(xd.totalEscrowed(address(token)) == 0 && xd.totalUnclaimed(address(token)) == 0, "books");
    }

    function test_open_job_rejection_and_expiry_refund_nothing() public {
        vm.prank(CLIENT);
        uint256 id = xd.createJob(PROV, EVAL, EXPIRY, "open", address(0), 0);
        vm.prank(CLIENT);
        xd.reject(id, bytes32("no"), "");
        require(_status(id, K_REFUND) == 0, "no right for an unfunded job");
        vm.prank(CLIENT);
        uint256 id2 = xd.createJob(PROV, EVAL, EXPIRY, "open", address(0), 0);
        vm.prank(STRANGER);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.claimRefund(id2);
        vm.warp(EXPIRY);
        xd.claimRefund(id2);
        require(uint8(xd.getJob(id2).status) == uint8(ERC8183Virtual.JobStatus.Expired), "expired, nothing owed");
    }

    function test_submitted_job_expiry_waits_for_the_grace_period() public {
        uint256 id = _deferred();
        vm.prank(PROV);
        xd.submit(id, keccak256("deliverable"), "");
        vm.warp(EXPIRY);
        vm.expectRevert(ERC8183Virtual.GracePeriodActive.selector);
        xd.claimRefund(id);
        vm.warp(uint256(EXPIRY) + xd.EVALUATION_GRACE_PERIOD());
        xd.claimRefund(id);
        require(_status(id, K_REFUND) == 1, "refund right after the grace period");
    }

    // ──────────────────── pause and admin (DS16-DS18, D-11, D-29) ────────────────────

    function test_DS17_claims_and_expiry_refunds_work_while_paused() public {
        uint256 id = _deferred();
        _complete(id, "");
        uint256 other = _deferred();
        vm.prank(EADMIN);
        xd.pause();
        require(_claim(id, K_PROV) == NET, "DS18: claim while paused");
        vm.prank(EVAL);
        vm.expectRevert();
        xd.reject(other, bytes32("no"), ""); // state transitions stay pausable
        vm.warp(EXPIRY);
        xd.claimRefund(other); // D-29
        require(_claim(other, K_REFUND) == BUDGET, "refund while paused");
    }

    function test_DS16_emergency_withdraw_takes_only_the_excess() public {
        uint256 funded = _deferred(); // escrowed
        uint256 done = _deferred();
        _complete(done, ""); // unclaimed
        token.mint(address(xd), 500); // a donation: the only excess
        vm.prank(EADMIN);
        xd.pause();
        uint256 bal = token.balanceOf(address(xd));
        require(bal == 2 * BUDGET + 500, "balance");
        vm.prank(EADMIN);
        vm.expectRevert(OmegaEscrowXD.ExceedsExcess.selector);
        xd.emergencyWithdraw(address(token), EADMIN, bal);
        vm.prank(EADMIN);
        vm.expectRevert(OmegaEscrowXD.ExceedsExcess.selector);
        xd.emergencyWithdraw(address(token), EADMIN, 501);
        vm.prank(EADMIN);
        xd.emergencyWithdraw(address(token), EADMIN, 500);
        require(token.balanceOf(EADMIN) == 500, "excess withdrawn");
        require(_claim(done, K_PROV) == NET, "rights intact");
        vm.prank(EADMIN);
        xd.unpause();
        vm.prank(EVAL);
        xd.reject(funded, bytes32("no"), "");
        require(_claim(funded, K_REFUND) == BUDGET, "collateral intact");
    }

    function test_DS22_zero_fee_share_creates_no_right() public {
        vm.prank(EADMIN);
        xd.setEvaluatorFee(0);
        uint256 id = _deferred();
        _complete(id, "");
        require(_status(id, K_EVAL) == 0 && _claim(id, K_EVAL) == 0, "NONE");
        require(_amount(id, K_PROV) == BUDGET - PF, "provider gets the rest");
    }

    function test_DS23_rights_do_not_move_with_later_global_fee_changes() public {
        uint256 id = _deferred();
        _complete(id, "");
        vm.prank(EADMIN);
        xd.setEvaluatorFee(1000);
        vm.prank(EADMIN);
        xd.setPlatformFee(500, address(0xD00D));
        require(_amount(id, K_PROV) == NET && _amount(id, K_EVAL) == EF && _amount(id, K_PLAT) == PF, "unchanged");
        _claim(id, K_PLAT);
        require(token.balanceOf(TREASURY) == PF && token.balanceOf(address(0xD00D)) == 0, "locked recipient");
    }

    function test_DS24_broken_hook_cannot_block_claims() public {
        CountingHook hook = new CountingHook();
        vm.prank(EADMIN);
        xd.setHookWhitelist(address(hook), true);
        uint256 id = _funded(DEFERRED, address(hook), token, address(0));
        _complete(id, "");
        uint256 calls = hook.calls();
        hook.setBroken(true);
        require(_claim(id, K_PROV) == NET, "claim calls no hook");
        require(hook.calls() == calls, "hook not called");
    }

    function test_terms_hash_covers_the_settlement_mode() public {
        XDLogic.CreateTerms memory ct = xd.defaultCreateTerms(address(0));
        vm.prank(CLIENT);
        uint256 a = xd.createJobWithTerms(PROV, EVAL, EXPIRY, "same", address(0), 0, ct);
        ct.settlementMode = DEFERRED;
        vm.prank(CLIENT);
        uint256 b = xd.createJobWithTerms(PROV, EVAL, EXPIRY, "same", address(0), 0, ct);
        (, bytes32 ha) = xd.commitmentTermsOf(a);
        (, bytes32 hb) = xd.commitmentTermsOf(b);
        require(ha != hb, "mode is in the hash");
    }

    // ──────────────────── gas scenarios (DS-28; run alone with --isolate --gas-report --match-test) ────────────────────

    function test_gas_immediate_with_fees() public {
        uint256 id = _funded(0, address(0), token, address(0));
        _complete(id, "");
        require(token.balanceOf(PROV) == NET, "paid");
    }

    function test_gas_deferred_with_fees_and_three_claims() public {
        uint256 id = _deferred();
        _complete(id, "");
        _claim(id, K_PROV);
        _claim(id, K_EVAL);
        _claim(id, K_PLAT);
        require(token.balanceOf(PROV) == NET, "paid");
    }

    // ──────────────────── DS-15: solvency under random call orders ────────────────────

    uint256[] internal _ids;

    /// @dev Random sequences of fund / submit / complete / reject / expire / claim / donate, both modes. After every
    ///  step: balance >= escrowed + unclaimed (S6), and both books equal what the job states say they should be.
    function test_DS15_fuzz_books_match_job_states(uint256 seed) public {
        delete _ids;
        for (uint256 step; step < 40; step++) {
            uint256 r = uint256(keccak256(abi.encode(seed, step)));
            uint256 op = r % 7;
            if (op == 0 || _ids.length == 0) {
                _ids.push(_funded(uint8((r >> 8) % 2), address(0), token, address(0)));
            } else {
                uint256 id = _ids[(r >> 16) % _ids.length];
                ERC8183Virtual.JobStatus s = xd.getJob(id).status;
                if (op == 1 && s == ERC8183Virtual.JobStatus.Funded) {
                    vm.prank(PROV);
                    xd.submit(id, keccak256("d"), "");
                } else if (op == 2 && s == ERC8183Virtual.JobStatus.Submitted) {
                    vm.prank(EVAL);
                    xd.complete(id, bytes32("ok"), "");
                } else if (op == 3 && (s == ERC8183Virtual.JobStatus.Funded || s == ERC8183Virtual.JobStatus.Submitted)) {
                    vm.prank(EVAL);
                    xd.reject(id, bytes32("no"), "");
                } else if (op == 4) {
                    _claim(id, uint8((r >> 24) % 4));
                } else if (op == 5) {
                    token.mint(address(xd), (r >> 32) % 1000);
                }
            }
            _checkBooks();
        }
        vm.warp(EXPIRY + 2 days);
        for (uint256 i; i < _ids.length; i++) {
            ERC8183Virtual.JobStatus s = xd.getJob(_ids[i]).status;
            if (s == ERC8183Virtual.JobStatus.Funded || s == ERC8183Virtual.JobStatus.Submitted) xd.claimRefund(_ids[i]);
            for (uint8 k; k < 4; k++) _claim(_ids[i], k);
        }
        _checkBooks();
        require(xd.totalEscrowed(address(token)) == 0 && xd.totalUnclaimed(address(token)) == 0, "all paid out");
    }

    function _checkBooks() internal view {
        uint256 escrowed;
        uint256 unclaimed;
        for (uint256 i; i < _ids.length; i++) {
            uint256 id = _ids[i];
            ERC8183Virtual.JobStatus s = xd.getJob(id).status;
            if (s == ERC8183Virtual.JobStatus.Funded || s == ERC8183Virtual.JobStatus.Submitted) escrowed += BUDGET;
            for (uint8 k; k < 4; k++) {
                (,, uint256 a, uint8 st) = xd.payoutOf(id, k);
                if (st == 1) unclaimed += a;
            }
        }
        require(xd.totalEscrowed(address(token)) == escrowed, "escrowed book");
        require(xd.totalUnclaimed(address(token)) == unclaimed, "unclaimed book");
        require(token.balanceOf(address(xd)) >= escrowed + unclaimed, "S6 solvency");
    }
}
