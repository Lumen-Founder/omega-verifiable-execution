// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.28;

import {IERC8183VerdictEvaluator as I} from "../src/IERC8183VerdictEvaluator.sol";

struct VmLog {
    bytes32[] topics;
    bytes data;
    address emitter;
}

interface VmC {
    function prank(address) external;
    function warp(uint256) external;
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert() external;
    function recordLogs() external;
    function getRecordedLogs() external returns (VmLog[] memory);
}

/// @title VerdictConformanceBase — escrow-agnostic conformance suite for spec/ERC8183_EVALUATOR_VERDICTS.md (V1-V15)
/// @notice Two sets of hooks:
///  - evaluator hooks (deploy bound to an escrow, set / retire / revoke a key): supplied by the implementation under test;
///  - escrow hooks (new escrow, make a job, read its status, pause, observe settlement): supplied by an escrow binding.
///  `VerdictConformance` binds the mock escrow (unchanged entry point for implementers). `BaseContracts8183Conformance`
///  binds the real erc-8183/base-contracts escrow behind an ERC1967 proxy. Tests never assume error names, only that a
///  call reverts or succeeds and what the escrow shows.
abstract contract VerdictConformanceBase {
    VmC internal constant vm = VmC(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes32 internal constant VERDICT_TYPEHASH = keccak256(
        "Verdict(address escrow,uint256 jobId,bytes32 deliverableHash,bytes32 criteriaHash,uint8 decision,"
        "bytes32 detailHash,uint64 signedAt,uint64 expiresAt,bytes32 keyId,bytes32 modelId,int32 severityE4,"
        "uint32 severitySeE4,bytes32 calibrationRun)"
    );
    address internal constant CLIENT = address(0xC11E);
    address internal constant PROV = address(0xE0E0);
    uint256 internal constant PK = 0xA11CE;
    uint256 internal constant PK_OTHER = 0xB0B;
    bytes32 internal constant K1 = keccak256("conformance-key-1");
    uint64 internal constant T0 = 5_000;
    uint8 internal constant ST_SUBMITTED = 2;
    uint8 internal constant ST_COMPLETED = 3;
    uint8 internal constant ST_REJECTED = 4;

    address internal escrowAddr;
    I internal ev;
    uint256 internal job;

    // ---------------------------------------------------------------- evaluator hooks (implementation under test)
    function _deploy(address escrow) internal virtual returns (I);
    function _setKey(I e, bytes32 keyId, address signer, uint64 validFrom, uint64 validUntil) internal virtual;
    function _retireKey(I e, bytes32 keyId, uint64 at) internal virtual;
    function _revokeKey(I e, bytes32 keyId) internal virtual;

    // ---------------------------------------------------------------- escrow hooks (escrow binding)
    /// @dev A fresh escrow, ready to create jobs. Called once in setUp and again by tests that need a second escrow.
    function _newEscrow() internal virtual returns (address);
    /// @dev A job by CLIENT for PROV judged by `evaluator`, funded, and submitted when `submitted` is true.
    function _makeJob(address escrow, address evaluator, bool submitted) internal virtual returns (uint256);
    /// @dev ERC-8183 status as uint8: 2 Submitted, 3 Completed, 4 Rejected.
    function _jobStatus(address escrow, uint256 id) internal view virtual returns (uint8);
    function _setEscrowPaused(address escrow, bool paused) internal virtual;
    /// @dev Called right before a decision; the binding may start recording what it needs to observe settlement.
    function _watchSettlement(address escrow, uint256 id) internal virtual;
    /// @dev Who received the money of job `id` and the reason the escrow recorded, observed since `_watchSettlement`.
    function _settlement(address escrow, uint256 id) internal virtual returns (address payee, bytes32 reason);

    function setUp() public virtual {
        vm.warp(T0);
        escrowAddr = _newEscrow();
        ev = _deploy(escrowAddr);
        _setKey(ev, K1, vm.addr(PK), 1_000, 10_000_000_000);
        job = _makeJob(escrowAddr, address(ev), true);
    }

    function _v(uint256 id, uint8 decision) internal view returns (I.Verdict memory v) {
        v = I.Verdict({
            escrow: escrowAddr,
            jobId: id,
            deliverableHash: keccak256("deliverable"),
            criteriaHash: keccak256("criteria"),
            decision: decision,
            detailHash: keccak256("detail"),
            signedAt: T0 - 1_000,
            expiresAt: T0 + 4_000,
            keyId: K1,
            modelId: keccak256("model"),
            severityE4: -1_234,
            severitySeE4: 987,
            calibrationRun: keccak256("run")
        });
    }

    function _sig(I e, I.Verdict memory v, uint256 pk) internal returns (uint8 sv, bytes32 r, bytes32 s) {
        (sv, r, s) = vm.sign(pk, e.digestOf(v));
    }

    function _ok(I e, I.Verdict memory v, uint256 pk) internal returns (bytes32) {
        (uint8 sv, bytes32 r, bytes32 s) = _sig(e, v, pk);
        return e.submitVerdict(v, sv, r, s);
    }

    function _reverts(I e, I.Verdict memory v, uint8 sv, bytes32 r, bytes32 s) internal {
        vm.expectRevert();
        e.submitVerdict(v, sv, r, s);
    }

    function _revertsSigned(I e, I.Verdict memory v, uint256 pk) internal {
        (uint8 sv, bytes32 r, bytes32 s) = _sig(e, v, pk);
        _reverts(e, v, sv, r, s);
    }

    function _status(uint256 id) internal view returns (uint8) {
        return _jobStatus(escrowAddr, id);
    }

    // ---------------------------------------------------------------- V1, V2: typed data and domain
    function test_V1_V2_digest_is_eip712_over_the_published_domain() public view {
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address vc,,) = ev.eip712Domain();
        require(fields == hex"0f", "V2 fields name|version|chainId|verifyingContract");
        require(chainId == block.chainid && vc == address(ev), "V2 domain binds chain and evaluator");
        bytes32 ds = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                vc
            )
        );
        I.Verdict memory v = _v(job, 1);
        bytes32 sh = keccak256(
            abi.encode(
                VERDICT_TYPEHASH, v.escrow, v.jobId, v.deliverableHash, v.criteriaHash, v.decision, v.detailHash,
                v.signedAt, v.expiresAt, v.keyId, v.modelId, v.severityE4, v.severitySeE4, v.calibrationRun
            )
        );
        require(ev.digestOf(v) == keccak256(abi.encodePacked("\x19\x01", ds, sh)), "V1 type string / encoding");
        require(ev.escrow() == escrowAddr, "escrow()");
    }

    // ---------------------------------------------------------------- V3: escrow binding
    function test_V3_other_escrow_refused() public {
        address escrow2 = _newEscrow();
        I ev2 = _deploy(escrow2);
        _setKey(ev2, K1, vm.addr(PK), 1_000, 10_000_000_000);
        _makeJob(escrow2, address(ev2), true);
        I.Verdict memory v = _v(job, 1); // names the first escrow
        _revertsSigned(ev2, v, PK);
    }

    // ---------------------------------------------------------------- V4: signature
    function test_V4_unregistered_signer_refused() public {
        _revertsSigned(ev, _v(job, 1), PK_OTHER);
    }

    function test_V4_high_s_refused() public {
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = _sig(ev, v, PK);
        _reverts(ev, v, sv == 27 ? 28 : 27, r, bytes32(SECP_N - uint256(s)));
    }

    function test_V4_any_field_change_breaks_signature() public {
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = _sig(ev, v, PK);
        I.Verdict memory w = v;
        w.deliverableHash = keccak256("other");
        _reverts(ev, w, sv, r, s);
        w = _v(job, 1);
        w.severityE4 = 0;
        _reverts(ev, w, sv, r, s);
        w = _v(job, 1);
        w.criteriaHash = keccak256("other");
        _reverts(ev, w, sv, r, s);
        w = _v(job, 2);
        _reverts(ev, w, sv, r, s); // decision flipped
    }

    function test_V4_replay_to_other_job_refused() public {
        uint256 job2 = _makeJob(escrowAddr, address(ev), true);
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = _sig(ev, v, PK);
        v.jobId = job2;
        _reverts(ev, v, sv, r, s);
    }

    function test_V2_V4_replay_to_other_evaluator_on_same_escrow_refused() public {
        I ev3 = _deploy(escrowAddr);
        _setKey(ev3, K1, vm.addr(PK), 1_000, 10_000_000_000);
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = _sig(ev, v, PK); // signed for ev's domain
        _reverts(ev3, v, sv, r, s);
    }

    // ---------------------------------------------------------------- V5: time and key validity
    function test_V5_expired_refused() public {
        vm.warp(T0 + 4_001);
        _revertsSigned(ev, _v(job, 1), PK);
    }

    function test_V5_future_signed_at_refused() public {
        I.Verdict memory v = _v(job, 1);
        v.signedAt = T0 + 1;
        _revertsSigned(ev, v, PK);
    }

    function test_V5_before_key_valid_from_refused() public {
        I.Verdict memory v = _v(job, 1);
        v.signedAt = 999;
        _revertsSigned(ev, v, PK);
    }

    function test_V5_unknown_key_refused() public {
        I.Verdict memory v = _v(job, 1);
        v.keyId = keccak256("unknown");
        _revertsSigned(ev, v, PK);
    }

    // ---------------------------------------------------------------- V6: evaluator of the job
    function test_V6_job_with_other_evaluator_refused() public {
        uint256 other = _makeJob(escrowAddr, address(0xBEEF), true);
        _revertsSigned(ev, _v(other, 1), PK);
    }

    // ---------------------------------------------------------------- V7, V8: once, and the escrow call
    function test_V8_complete_pays_with_digest_as_reason() public {
        _watchSettlement(escrowAddr, job);
        bytes32 d = _ok(ev, _v(job, 1), PK);
        (address payee, bytes32 reason) = _settlement(escrowAddr, job);
        require(_status(job) == ST_COMPLETED && payee == PROV, "V8 completed to provider");
        require(reason == d && ev.decided(job) == d && ev.seen(d), "V8 reason is the digest");
    }

    function test_V8_reject_refunds_with_digest_as_reason() public {
        _watchSettlement(escrowAddr, job);
        bytes32 d = _ok(ev, _v(job, 2), PK);
        (address payee, bytes32 reason) = _settlement(escrowAddr, job);
        require(_status(job) == ST_REJECTED && payee == CLIENT && reason == d, "V8 rejected");
    }

    function test_V7_same_verdict_twice_refused() public {
        I.Verdict memory v = _v(job, 3);
        (uint8 sv, bytes32 r, bytes32 s) = _sig(ev, v, PK);
        ev.submitVerdict(v, sv, r, s);
        _reverts(ev, v, sv, r, s);
    }

    function test_V8_second_decision_refused() public {
        _ok(ev, _v(job, 1), PK);
        _revertsSigned(ev, _v(job, 2), PK);
    }

    function test_V8_unsubmitted_job_refused() public {
        uint256 id = _makeJob(escrowAddr, address(ev), false);
        _revertsSigned(ev, _v(id, 1), PK);
    }

    // ---------------------------------------------------------------- V15: an escrow refusal is not swallowed
    function test_V15_escrow_refusal_reverts_and_leaves_nothing() public {
        I.Verdict memory v = _v(job, 1);
        (uint8 sv, bytes32 r, bytes32 s) = _sig(ev, v, PK);
        bytes32 d = ev.digestOf(v);
        _setEscrowPaused(escrowAddr, true);
        _reverts(ev, v, sv, r, s);
        require(!ev.seen(d) && ev.decided(job) == bytes32(0) && _status(job) == ST_SUBMITTED, "V15 nothing recorded");
        _setEscrowPaused(escrowAddr, false);
        ev.submitVerdict(v, sv, r, s);
        require(_status(job) == ST_COMPLETED && ev.decided(job) == d, "V15 the same verdict still decides the job later");
    }

    // ---------------------------------------------------------------- V9, V10: outcomes
    function test_V9_could_not_check_changes_nothing_then_decision_still_possible() public {
        bytes32 d = _ok(ev, _v(job, 3), PK);
        require(ev.seen(d) && ev.decided(job) == bytes32(0) && _status(job) == ST_SUBMITTED, "V9 recorded only");
        _ok(ev, _v(job, 1), PK);
        require(_status(job) == ST_COMPLETED, "V9 later decision");
    }

    function test_V10_unknown_decision_refused() public {
        _revertsSigned(ev, _v(job, 0), PK);
        _revertsSigned(ev, _v(job, 4), PK);
    }

    // ---------------------------------------------------------------- V12, V13: keys
    function test_V12_key_id_not_reassigned() public {
        (address before,,,) = ev.keys(K1);
        try this.ext_setKey(K1, vm.addr(PK_OTHER)) {} catch {}
        (address afterw,,,) = ev.keys(K1);
        require(before == afterw, "V12 signer unchanged");
    }

    function ext_setKey(bytes32 keyId, address signer) external {
        _setKey(ev, keyId, signer, 0, 1);
    }

    /// V13: a retired key settles nothing new, whatever signedAt it writes (backdating into the old window).
    function test_V13_retired_key_refuses_backdated_verdict() public {
        _retireKey(ev, K1, T0 - 500); // now is T0; the verdict claims signedAt T0-1000, inside the old window
        _revertsSigned(ev, _v(job, 1), PK);
        require(_status(job) == ST_SUBMITTED, "V13 job untouched");
    }

    /// V13: a verdict recorded on chain before the retirement stays valid.
    function test_V13_recorded_verdict_survives_retirement() public {
        bytes32 d = _ok(ev, _v(job, 1), PK);
        _retireKey(ev, K1, T0);
        require(_status(job) == ST_COMPLETED && ev.seen(d), "V13 earlier record valid");
    }

    /// V5/V13: the key window is judged at block.timestamp, so a retirement set in the future takes effect at its time.
    function test_V13_retirement_takes_effect_at_its_time() public {
        _retireKey(ev, K1, T0 + 100);
        vm.warp(T0 + 100);
        _revertsSigned(ev, _v(job, 1), PK);
        vm.warp(T0 + 99);
        _ok(ev, _v(job, 1), PK);
        require(_status(job) == ST_COMPLETED, "V13 accepted before retirement time");
    }

    function test_V13_retire_refuses_later_signatures() public {
        _retireKey(ev, K1, T0 - 1_500);
        _revertsSigned(ev, _v(job, 1), PK);
    }

    function test_V13_revoke_refuses_all() public {
        _revokeKey(ev, K1);
        _revertsSigned(ev, _v(job, 1), PK);
    }

    // ---------------------------------------------------------------- V14: measurement may be absent
    function test_V14_no_measurement_is_accepted() public {
        I.Verdict memory v = _v(job, 1);
        (v.modelId, v.severityE4, v.severitySeE4, v.calibrationRun) = (bytes32(0), 0, 0, bytes32(0));
        _ok(ev, v, PK);
        require(_status(job) == ST_COMPLETED, "V14");
    }
}
