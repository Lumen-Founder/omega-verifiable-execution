// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAgenticCommerce} from "../src/OmegaEvaluator8183.sol";
import {SignedVerdictEvaluator8183 as E} from "../src/SignedVerdictEvaluator8183.sol";
import {IERC8183VerdictEvaluator as I} from "../src/IERC8183VerdictEvaluator.sol";
import {SignedVerdictEvaluator8183TwoArg as E2} from "../src/SignedVerdictEvaluator8183TwoArg.sol";

interface VmL {
    function prank(address) external;
    function warp(uint256) external;
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert() external;
}

/// @dev Our own mock with the Job layout of erc-8183/base-contracts ERC8183.sol (13 fields, status second),
///  written from that struct's declaration (commit 142e669c). The evaluator must work on it without decoding it.
contract MockBaseLayoutEscrow {
    enum JobStatus { Open, Funded, Submitted, Completed, Rejected, Expired }
    struct Job {
        address client;
        JobStatus status;
        address provider;
        uint48 expiredAt;
        address evaluator;
        uint48 submittedAt;
        uint256 budget;
        address hook;
        address paymentToken;
        uint256 providerAgentId;
        string description;
        uint256 settledAmount;
        address payoutReceiver;
    }
    mapping(uint256 => Job) internal jobs;
    mapping(uint256 => bytes32) public reasonOf;
    uint256 public jobCounter;
    error Unauthorized();
    error WrongStatus();

    function createSubmitted(address provider, address evaluator) external returns (uint256 id) {
        id = ++jobCounter;
        Job storage j = jobs[id];
        j.client = msg.sender;
        j.provider = provider;
        j.evaluator = evaluator;
        j.status = JobStatus.Submitted;
        j.budget = 1000;
        j.description = "base layout job";
    }

    function getJob(uint256 id) external view returns (Job memory) {
        return jobs[id];
    }

    function complete(uint256 id, bytes32 reason, bytes calldata) external {
        Job storage j = jobs[id];
        if (j.status != JobStatus.Submitted) revert WrongStatus();
        if (msg.sender != j.evaluator) revert Unauthorized();
        (j.status, reasonOf[id]) = (JobStatus.Completed, reason);
    }

    function reject(uint256 id, bytes32 reason, bytes calldata) external {
        Job storage j = jobs[id];
        if (j.status != JobStatus.Funded && j.status != JobStatus.Submitted) revert WrongStatus();
        if (msg.sender != j.evaluator) revert Unauthorized();
        (j.status, reasonOf[id]) = (JobStatus.Rejected, reason);
    }

    function statusOf(uint256 id) external view returns (uint8) {
        return uint8(jobs[id].status);
    }
}

/// @dev A two-argument escrow (complete(uint256,bytes32)), as some deployed ERC-8183 variants have. It applies the
///  ERC-8183 rules itself: only the job's evaluator; complete only when Submitted; reject when Funded or Submitted.
contract MockTwoArgEscrow {
    struct J {
        address evaluator;
        uint8 status; // 1 Funded, 2 Submitted, 3 Completed, 4 Rejected
        bytes32 reason;
    }
    mapping(uint256 => J) public jobs;
    uint256 public n;
    bool public paused;
    error Unauthorized();
    error WrongStatus();
    error Paused();

    function create(address evaluator, uint8 status) external returns (uint256 id) {
        id = ++n;
        jobs[id] = J(evaluator, status, bytes32(0));
    }

    function setPaused(bool p) external {
        paused = p;
    }

    function complete(uint256 id, bytes32 reason) external {
        if (paused) revert Paused();
        J storage j = jobs[id];
        if (j.status != 2) revert WrongStatus();
        if (msg.sender != j.evaluator) revert Unauthorized();
        (j.status, j.reason) = (3, reason);
    }

    function reject(uint256 id, bytes32 reason) external {
        if (paused) revert Paused();
        J storage j = jobs[id];
        if (j.status != 1 && j.status != 2) revert WrongStatus();
        if (msg.sender != j.evaluator) revert Unauthorized();
        (j.status, j.reason) = (4, reason);
    }
}

contract EscrowLayoutsTest {
    VmL internal constant vm = VmL(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant PK = 0xA11CE;
    bytes32 internal constant K1 = keccak256("rater-1/2026-11");
    address internal constant ADMIN = address(0xAD);

    function _v(address escrow, uint256 id, uint8 decision) internal pure returns (I.Verdict memory) {
        return I.Verdict(escrow, id, keccak256("d"), keccak256("c"), decision, keccak256("x"), 4_000, 9_000, K1,
            bytes32(0), 0, 0, bytes32(0));
    }

    function _deploy(address escrow) internal returns (E ev) {
        vm.warp(5_000);
        ev = new E(IAgenticCommerce(escrow), ADMIN);
        vm.prank(ADMIN);
        ev.setKey(K1, vm.addr(PK), 1_000, 10_000_000_000);
    }

    function _submit(E ev, I.Verdict memory v) internal returns (bytes32 d) {
        d = ev.digestOf(v);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, d);
        ev.submitVerdict(v, sv, r, s);
    }

    function test_works_on_base_contracts_job_layout() public {
        MockBaseLayoutEscrow b = new MockBaseLayoutEscrow();
        E ev = _deploy(address(b));
        uint256 j1 = b.createSubmitted(address(0xE0E0), address(ev));
        bytes32 d1 = _submit(ev, _v(address(b), j1, 1));
        require(b.statusOf(j1) == 3 && b.reasonOf(j1) == d1, "complete on base layout");
        uint256 j2 = b.createSubmitted(address(0xE0E0), address(ev));
        _submit(ev, _v(address(b), j2, 3));
        require(b.statusOf(j2) == 2, "could-not-check leaves the job");
        bytes32 d2 = _submit(ev, _v(address(b), j2, 2));
        require(b.statusOf(j2) == 4 && b.reasonOf(j2) == d2, "reject on base layout");
    }

    function test_job_naming_another_evaluator_is_refused_by_the_escrow() public {
        MockBaseLayoutEscrow b = new MockBaseLayoutEscrow();
        E ev = _deploy(address(b));
        uint256 j = b.createSubmitted(address(0xE0E0), address(0xBEEF));
        I.Verdict memory v = _v(address(b), j, 1);
        bytes32 d = ev.digestOf(v);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, d);
        vm.expectRevert();
        ev.submitVerdict(v, sv, r, s);
        require(!ev.seen(d), "nothing recorded");
    }

    function _deploy2(address escrow) internal returns (E2 ev) {
        vm.warp(5_000);
        ev = new E2(escrow, ADMIN);
        vm.prank(ADMIN);
        ev.setKey(K1, vm.addr(PK), 1_000, 10_000_000_000);
    }

    function _send(E ev, I.Verdict memory v) internal returns (bytes32 d, bool ok) {
        d = ev.digestOf(v);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, d);
        try ev.submitVerdict(v, sv, r, s) {
            ok = true;
        } catch {}
    }

    function test_two_arg_variant_completes_rejects_and_records() public {
        MockTwoArgEscrow t = new MockTwoArgEscrow();
        E2 ev = _deploy2(address(t));
        uint256 a = t.create(address(ev), 2);
        (bytes32 d, bool ok) = _send(ev, _v(address(t), a, 1));
        (, uint8 st, bytes32 why) = t.jobs(a);
        require(ok && st == 3 && why == d, "complete");
        uint256 b = t.create(address(ev), 2);
        (, ok) = _send(ev, _v(address(t), b, 3));
        (, st,) = t.jobs(b);
        require(ok && st == 2, "could-not-check leaves the job");
        (d, ok) = _send(ev, _v(address(t), b, 2));
        (, st, why) = t.jobs(b);
        require(ok && st == 4 && why == d, "reject");
    }

    function test_two_arg_variant_escrow_rules_and_v15() public {
        MockTwoArgEscrow t = new MockTwoArgEscrow();
        E2 ev = _deploy2(address(t));
        uint256 other = t.create(address(0xBEEF), 2);
        (bytes32 d, bool ok) = _send(ev, _v(address(t), other, 1));
        require(!ok && !ev.seen(d), "V6 via escrow: job of another evaluator refused, nothing recorded");
        uint256 funded = t.create(address(ev), 1);
        (d, ok) = _send(ev, _v(address(t), funded, 1));
        require(!ok && !ev.seen(d), "V8 via escrow: complete on an unsubmitted job refused");
        uint256 j = t.create(address(ev), 2);
        t.setPaused(true);
        (d, ok) = _send(ev, _v(address(t), j, 1));
        require(!ok && !ev.seen(d) && ev.decided(j) == bytes32(0), "V15 refusal leaves nothing");
        t.setPaused(false);
        (d, ok) = _send(ev, _v(address(t), j, 1));
        (, uint8 st,) = t.jobs(j);
        require(ok && st == 3, "V15 the same verdict decides later");
    }

    function test_two_arg_variant_on_three_arg_escrow_fails_loudly() public {
        MockBaseLayoutEscrow b = new MockBaseLayoutEscrow();
        E2 ev = _deploy2(address(b));
        uint256 j = b.createSubmitted(address(0xE0E0), address(ev));
        (bytes32 d, bool ok) = _send(ev, _v(address(b), j, 1));
        require(!ok && !ev.seen(d) && b.statusOf(j) == 2, "selector mismatch reverts, nothing recorded");
    }

    function test_three_arg_evaluator_on_two_arg_escrow_fails_loudly() public {
        MockTwoArgEscrow t = new MockTwoArgEscrow();
        E ev = _deploy(address(t));
        I.Verdict memory v = _v(address(t), 1, 1);
        bytes32 d = ev.digestOf(v);
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(PK, d);
        vm.expectRevert(); // selector mismatch, no fallback: reverts instead of silently "deciding"
        ev.submitVerdict(v, sv, r, s);
    }
}
