// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAgenticCommerce} from "../src/OmegaEvaluator8183.sol";
import {SignedVerdictEvaluator8183 as E} from "../src/SignedVerdictEvaluator8183.sol";
import {IERC8183VerdictEvaluator as I} from "../src/IERC8183VerdictEvaluator.sol";
import {MockAgenticCommerce} from "./OmegaEvaluator8183.t.sol";

interface Vm2 {
    function prank(address) external;
    function warp(uint256) external;
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert(bytes4) external;
}

contract SignedVerdictEvaluator8183Test {
    Vm2 internal constant vm = Vm2(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    address internal constant ADMIN = address(0xAD);
    address internal constant CLIENT = address(0xC11E);
    address internal constant PROV = address(0xE0E0);
    uint256 internal constant PK = 0xA11CE;
    uint256 internal constant PK_OTHER = 0xB0B;
    bytes32 internal constant K1 = keccak256("rater-1/2026-11");
    MockAgenticCommerce internal acp;
    E internal ev;
    uint256 internal job;

    function setUp() public {
        vm.warp(5_000);
        acp = new MockAgenticCommerce();
        ev = new E(IAgenticCommerce(address(acp)), ADMIN);
        vm.prank(ADMIN);
        ev.setKey(K1, vm.addr(PK), 1_000, 10_000_000_000);
        job = _job(acp, address(ev));
    }

    function _job(MockAgenticCommerce a, address evaluator) internal returns (uint256 id) {
        vm.prank(CLIENT);
        id = a.createJob(PROV, evaluator, 2_000_000_000, "write a 200-word product summary");
        vm.prank(CLIENT);
        a.fund(id, 1_000);
        vm.prank(PROV);
        a.submit(id);
    }

    function _v(uint256 id, uint8 decision) internal view returns (I.Verdict memory v) {
        v = I.Verdict({
            escrow: address(acp),
            jobId: id,
            deliverableHash: keccak256("deliverable bytes"),
            criteriaHash: keccak256("schema v1"),
            decision: decision,
            detailHash: keccak256("rfc8785 verdict json"),
            signedAt: 4_000,
            expiresAt: 9_000,
            keyId: K1,
            modelId: keccak256("mfrm-dichotomous-v0"),
            severityE4: -3_512,
            severitySeE4: 1_840,
            calibrationRun: keccak256("calibration run 2026-11-06")
        });
    }

    function _send(E target, I.Verdict memory v, uint256 pk) internal returns (bytes32) {
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(pk, target.digestOf(v));
        return target.submitVerdict(v, sv, r, s);
    }

    function _fail(E target, I.Verdict memory v, uint256 pk, bytes4 sel) internal {
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(pk, target.digestOf(v));
        vm.expectRevert(sel);
        target.submitVerdict(v, sv, r, s);
    }

    function _status(MockAgenticCommerce a, uint256 id) internal view returns (uint8) {
        return a.getJob(id).status;
    }

    // ---------------------------------------------------------------- decisions

    function test_complete_pays_provider_and_records_digest() public {
        bytes32 d = _send(ev, _v(job, 1), PK);
        require(acp.paidTo(job) == PROV, "paid provider");
        require(acp.reasonOf(job) == d && ev.decided(job) == d, "reason is the verdict digest");
        require(_status(acp, job) == 3, "completed");
    }

    function test_reject_refunds_client() public {
        bytes32 d = _send(ev, _v(job, 2), PK);
        require(acp.paidTo(job) == CLIENT && acp.reasonOf(job) == d, "refund");
        require(_status(acp, job) == 4, "rejected");
    }

    function test_could_not_check_is_recorded_without_state_change() public {
        bytes32 d = _send(ev, _v(job, 3), PK);
        require(ev.seen(d) && ev.decided(job) == bytes32(0), "recorded, undecided");
        require(_status(acp, job) == 2, "still submitted");
        _send(ev, _v(job, 1), PK); // a later real decision still works
        require(_status(acp, job) == 3, "completed after");
    }

    function test_bad_decision_code() public {
        I.Verdict memory v = _v(job, 4);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        vm.expectRevert(E.BadDecision.selector);
        ev.submitVerdict(v, sv, r, s);
    }

    // ---------------------------------------------------------------- replay (#437)

    function test_replay_same_verdict_refused() public {
        I.Verdict memory v = _v(job, 3);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        ev.submitVerdict(v, sv, r, s);
        vm.expectRevert(E.Replayed.selector);
        ev.submitVerdict(v, sv, r, s);
    }

    function test_second_decision_refused() public {
        _send(ev, _v(job, 1), PK);
        _fail(ev, _v(job, 2), PK, E.AlreadyDecided.selector);
    }

    function test_replay_to_another_job_refused() public {
        uint256 job2 = _job(acp, address(ev));
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        v.jobId = job2;
        vm.expectRevert(E.BadSignature.selector);
        ev.submitVerdict(v, sv, r, s);
    }

    function test_replay_to_another_escrow_refused() public {
        MockAgenticCommerce acp2 = new MockAgenticCommerce();
        E ev2 = new E(IAgenticCommerce(address(acp2)), ADMIN);
        vm.prank(ADMIN);
        ev2.setKey(K1, vm.addr(PK), 1_000, 10_000_000_000);
        _job(acp2, address(ev2));
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        vm.expectRevert(E.WrongEscrow.selector); // escrow field names acp, ev2 serves acp2
        ev2.submitVerdict(v, sv, r, s);
        v.escrow = address(acp2);
        vm.expectRevert(E.BadSignature.selector); // rebinding the escrow breaks the signature
        ev2.submitVerdict(v, sv, r, s);
    }

    function test_replay_to_another_evaluator_deployment_refused() public {
        E ev3 = new E(IAgenticCommerce(address(acp)), ADMIN); // same escrow, same key, other contract
        vm.prank(ADMIN);
        ev3.setKey(K1, vm.addr(PK), 1_000, 10_000_000_000);
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        vm.expectRevert(E.BadSignature.selector); // EIP-712 domain binds verifyingContract and chain id
        ev3.submitVerdict(v, sv, r, s);
    }

    // ---------------------------------------------------------------- binding and signature

    function test_tampered_measurement_refused() public {
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        v.severityE4 = 0;
        vm.expectRevert(E.BadSignature.selector);
        ev.submitVerdict(v, sv, r, s);
    }

    function test_tampered_deliverable_refused() public {
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        v.deliverableHash = keccak256("other bytes");
        vm.expectRevert(E.BadSignature.selector);
        ev.submitVerdict(v, sv, r, s);
    }

    function test_unregistered_signer_refused() public {
        _fail(ev, _v(job, 1), PK_OTHER, E.BadSignature.selector);
    }

    function test_high_s_refused() public {
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, ev.digestOf(v));
        bytes32 s2 = bytes32(N - uint256(s));
        uint8 v2 = sv == 27 ? 28 : 27;
        vm.expectRevert(E.BadSignature.selector);
        ev.submitVerdict(v, v2, r, s2);
    }

    function test_not_this_evaluator_refused() public {
        uint256 other = _job(acp, address(0xBEEF));
        _fail(ev, _v(other, 1), PK, MockAgenticCommerce.Unauthorized.selector); // the escrow's own rule (V6)
    }

    // ---------------------------------------------------------------- time and keys (#438)

    function test_expired_verdict_refused() public {
        vm.warp(9_001);
        _fail(ev, _v(job, 1), PK, E.Expired.selector);
    }

    function test_future_signed_at_refused() public {
        I.Verdict memory v = _v(job, 1);
        v.signedAt = 6_000;
        _fail(ev, v, PK, E.NotYetSigned.selector);
    }

    // Reported by Douglas Borthwick (ethereum-magicians 27902): the key window used to be checked against the
    // signer-written signedAt, so a retired key could backdate a new verdict into its old window. The clock is 5_000.
    function test_retired_key_refuses_backdated_verdict() public {
        vm.prank(ADMIN);
        ev.retireKey(K1, 4_500); // retired before now; the verdict claims signedAt 4_000, inside the old window
        _fail(ev, _v(job, 1), PK, E.KeyNotValid.selector);
        require(_status(acp, job) == 2, "job still Submitted");
    }

    function test_verdict_recorded_before_retirement_stays_valid() public {
        _send(ev, _v(job, 1), PK);
        vm.prank(ADMIN);
        ev.retireKey(K1, 5_000); // retired after the verdict was recorded on chain
        require(_status(acp, job) == 3, "recorded verdict unaffected");
        bytes32 d = ev.digestOf(_v(job, 1));
        require(ev.seen(d) && ev.decided(job) == d, "record kept");
    }

    function test_retirement_in_future_takes_effect_at_its_time() public {
        vm.prank(ADMIN);
        ev.retireKey(K1, 6_000);
        vm.warp(6_000); // signedAt 4_000 and expiresAt 9_000 still fine; the key is not
        _fail(ev, _v(job, 1), PK, E.KeyNotValid.selector);
        vm.warp(5_999);
        _send(ev, _v(job, 1), PK);
        require(_status(acp, job) == 3, "accepted one second before retirement");
    }

    function test_retired_key_refuses_later_signatures() public {
        vm.prank(ADMIN);
        ev.retireKey(K1, 3_000);
        _fail(ev, _v(job, 1), PK, E.KeyNotValid.selector);
    }

    function test_key_not_yet_valid_refused() public {
        I.Verdict memory v = _v(job, 1);
        v.signedAt = 500;
        _fail(ev, v, PK, E.KeyNotValid.selector);
    }

    function test_compromised_key_refuses_everything() public {
        vm.prank(ADMIN);
        ev.revokeKey(K1);
        _fail(ev, _v(job, 1), PK, E.KeyNotValid.selector);
    }

    function test_unknown_key_id_refused() public {
        I.Verdict memory v = _v(job, 1);
        v.keyId = keccak256("nobody");
        _fail(ev, v, PK, E.KeyNotValid.selector);
    }

    function test_only_admin_sets_keys_and_ids_are_not_reused() public {
        vm.expectRevert(E.NotAdmin.selector);
        ev.setKey(keccak256("k2"), vm.addr(PK_OTHER), 0, 1);
        vm.prank(ADMIN);
        vm.expectRevert(E.KeyExists.selector);
        ev.setKey(K1, vm.addr(PK_OTHER), 0, 1);
    }

    function test_could_not_check_after_decision_refused() public {
        _send(ev, _v(job, 2), PK);
        _fail(ev, _v(job, 3), PK, E.AlreadyDecided.selector);
    }

    function test_complete_on_unsubmitted_job_refused() public {
        vm.prank(CLIENT);
        uint256 id = acp.createJob(PROV, address(ev), 2_000_000_000, "x");
        vm.prank(CLIENT);
        acp.fund(id, 1);
        _fail(ev, _v(id, 1), PK, MockAgenticCommerce.WrongStatus.selector); // the escrow's own rule (V8)
    }
}
