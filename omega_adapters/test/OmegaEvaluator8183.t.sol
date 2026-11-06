// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OmegaEvaluator8183, IAgenticCommerce, IOmegaGraphEscrow, IReferee} from "../src/OmegaEvaluator8183.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
}

/// @notice TEST-ONLY: the ERC-8183 state machine and access rules as the EIP text states them (createJob, setProvider,
///  fund, submit, complete, reject, claimRefund), without tokens or fees: the budget is a number and payment is recorded.
contract MockAgenticCommerce {
    uint8 internal constant OPEN = 0;
    uint8 internal constant FUNDED = 1;
    uint8 internal constant SUBMITTED = 2;
    uint8 internal constant COMPLETED = 3;
    uint8 internal constant REJECTED = 4;
    uint8 internal constant EXPIRED = 5;
    mapping(uint256 => IAgenticCommerce.Job) internal jobs;
    mapping(uint256 => address) public paidTo;
    mapping(uint256 => bytes32) public reasonOf;
    uint256 public jobCounter;

    error Unauthorized();
    error WrongStatus();
    error Paused();
    bool public paused; // lets the conformance suite make the escrow refuse a call (V15)

    function setPaused(bool p) external {
        paused = p;
    }

    function createJob(address provider, address evaluator, uint256 expiredAt, string calldata desc) external returns (uint256 id) {
        id = ++jobCounter;
        jobs[id] = IAgenticCommerce.Job(id, msg.sender, provider, evaluator, desc, 0, expiredAt, OPEN, address(0));
    }

    function setProvider(uint256 id, address p) external {
        if (msg.sender != jobs[id].client) revert Unauthorized();
        jobs[id].provider = p;
    }

    function fund(uint256 id, uint256 budget) external {
        IAgenticCommerce.Job storage j = jobs[id];
        if (msg.sender != j.client) revert Unauthorized();
        if (j.status != OPEN) revert WrongStatus();
        (j.budget, j.status) = (budget, FUNDED);
    }

    function submit(uint256 id) external {
        IAgenticCommerce.Job storage j = jobs[id];
        if (msg.sender != j.provider) revert Unauthorized();
        if (j.status != FUNDED) revert WrongStatus();
        j.status = SUBMITTED;
    }

    function complete(uint256 id, bytes32 reason, bytes calldata) external {
        if (paused) revert Paused();
        IAgenticCommerce.Job storage j = jobs[id];
        if (msg.sender != j.evaluator) revert Unauthorized();
        if (j.status != SUBMITTED) revert WrongStatus();
        (j.status, paidTo[id], reasonOf[id]) = (COMPLETED, j.provider, reason);
    }

    function reject(uint256 id, bytes32 reason, bytes calldata) external {
        if (paused) revert Paused();
        IAgenticCommerce.Job storage j = jobs[id];
        if (j.status == OPEN) {
            if (msg.sender != j.client) revert Unauthorized();
        } else if (j.status == FUNDED || j.status == SUBMITTED) {
            if (msg.sender != j.evaluator) revert Unauthorized();
        } else {
            revert WrongStatus();
        }
        (j.status, paidTo[id], reasonOf[id]) = (REJECTED, j.client, reason); // a refund to the client
    }

    function getJob(uint256 id) external view returns (IAgenticCommerce.Job memory) {
        return jobs[id];
    }
}

/// @notice TEST-ONLY: getNode and getClaim answers set by the test
contract MockEscrowAndReferee {
    mapping(bytes32 => IOmegaGraphEscrow.Node) internal nodes;
    mapping(uint256 => IReferee.Claim) internal claims;

    function setNode(bytes32 key, uint8 status, address executor, uint64 claimId, uint8 cond, uint64 condArg) external {
        IOmegaGraphEscrow.Node storage n = nodes[key];
        n.status = status;
        n.executor = executor;
        n.claimId = claimId;
        n.referee = address(this);
        n.cond = cond;
        n.condArg = condArg;
    }

    function setClaim(uint256 id, uint64 output, uint8 trap) external {
        (claims[id].status, claims[id].output, claims[id].trap) = (2, output, trap);
    }

    function getNode(bytes32 key) external view returns (IOmegaGraphEscrow.Node memory) {
        return nodes[key];
    }

    function getClaim(uint256 id) external view returns (IReferee.Claim memory) {
        return claims[id];
    }
}

contract OmegaEvaluator8183Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant CLIENT = address(0xC11E);
    address internal constant EXEC = address(0xE0E0);
    address internal constant OTHER = address(0x0BAD);
    bytes32 internal constant KEY = keccak256("node");
    MockAgenticCommerce internal acp;
    MockEscrowAndReferee internal esc;
    OmegaEvaluator8183 internal ev;

    function setUp() public {
        acp = new MockAgenticCommerce();
        esc = new MockEscrowAndReferee();
        ev = new OmegaEvaluator8183(IOmegaGraphEscrow(address(esc)));
        esc.setNode(KEY, 2, EXEC, 7, 0, 0); // claimed, not decided
        esc.setClaim(7, 55, 0);
    }

    function _job(address provider) internal returns (uint256 id) {
        vm.prank(CLIENT);
        id = acp.createJob(provider, address(ev), 2_000_000_000, "sum 1..10 on OMEGA");
        vm.prank(CLIENT);
        acp.fund(id, 1_000);
        vm.prank(CLIENT);
        ev.link(IAgenticCommerce(address(acp)), id, KEY);
    }

    function _submit(uint256 id, address provider) internal {
        vm.prank(provider);
        acp.submit(id);
    }

    function test_completes_when_omega_pays_the_provider() public {
        uint256 id = _job(EXEC);
        _submit(id, EXEC);
        vm.expectRevert(OmegaEvaluator8183.Undecided.selector);
        ev.decide(IAgenticCommerce(address(acp)), id); // claimed: OMEGA has not decided
        esc.setNode(KEY, 4, EXEC, 7, 0, 0); // final
        vm.prank(OTHER); // anyone may call it
        ev.decide(IAgenticCommerce(address(acp)), id);
        require(acp.paidTo(id) == EXEC && acp.reasonOf(id) == ev.PAID(), "paid");
        vm.expectRevert(OmegaEvaluator8183.Closed.selector);
        ev.decide(IAgenticCommerce(address(acp)), id); // once
    }

    function test_an_unfunded_job_is_left_to_its_client() public {
        vm.prank(CLIENT);
        uint256 id = acp.createJob(EXEC, address(ev), 2_000_000_000, "never funded");
        vm.prank(CLIENT);
        ev.link(IAgenticCommerce(address(acp)), id, KEY);
        esc.setNode(KEY, 5, EXEC, 7, 0, 0); // rejected
        vm.expectRevert(OmegaEvaluator8183.NotFunded.selector);
        ev.decide(IAgenticCommerce(address(acp)), id);
    }

    function test_rejects_every_way_omega_does_not_pay() public {
        uint8[3] memory ended = [uint8(5), 6, 7]; // rejected, voided, expired
        for (uint256 i; i < 3; ++i) {
            bytes32 key = keccak256(abi.encode(i));
            esc.setNode(key, 2, EXEC, 7, 0, 0);
            vm.prank(CLIENT);
            uint256 id = acp.createJob(EXEC, address(ev), 2_000_000_000, "x");
            vm.prank(CLIENT);
            acp.fund(id, 1_000);
            vm.prank(CLIENT);
            ev.link(IAgenticCommerce(address(acp)), id, key);
            if (i == 1) _submit(id, EXEC); // before and after submission alike
            esc.setNode(key, ended[i], EXEC, 7, 0, 0);
            ev.decide(IAgenticCommerce(address(acp)), id);
            require(acp.paidTo(id) == CLIENT && acp.reasonOf(id) == ev.NOT_PAID(), "refunded");
        }
    }

    function test_final_without_payment_is_a_rejection() public {
        esc.setNode(KEY, 4, EXEC, 7, 1, 56); // output must equal 56; the claim says 55
        uint256 id = _job(EXEC);
        _submit(id, EXEC);
        ev.decide(IAgenticCommerce(address(acp)), id);
        require(acp.reasonOf(id) == ev.NOT_PAID(), "condition missed");
        bytes32 k2 = keccak256("trapped");
        esc.setNode(k2, 2, EXEC, 8, 0, 0);
        esc.setClaim(8, 55, 3);
        vm.prank(CLIENT);
        uint256 id2 = acp.createJob(EXEC, address(ev), 2_000_000_000, "y");
        vm.prank(CLIENT);
        acp.fund(id2, 1);
        vm.prank(CLIENT);
        ev.link(IAgenticCommerce(address(acp)), id2, k2);
        _submit(id2, EXEC);
        esc.setNode(k2, 4, EXEC, 8, 0, 0);
        ev.decide(IAgenticCommerce(address(acp)), id2);
        require(acp.reasonOf(id2) == ev.NOT_PAID(), "trapped");
        esc.setNode(KEY, 4, EXEC, 7, 2, 55); // output <= 55: met
        bytes32 k3 = KEY;
        vm.prank(CLIENT);
        uint256 id3 = acp.createJob(EXEC, address(ev), 2_000_000_000, "z");
        vm.prank(CLIENT);
        acp.fund(id3, 1);
        vm.prank(CLIENT);
        ev.link(IAgenticCommerce(address(acp)), id3, k3);
        _submit(id3, EXEC);
        ev.decide(IAgenticCommerce(address(acp)), id3);
        require(acp.reasonOf(id3) == ev.PAID(), "condition met");
    }

    function test_someone_else_as_provider_is_refused() public {
        uint256 id = _job(OTHER); // the 8183 provider is not the executor OMEGA paid
        _submit(id, OTHER);
        esc.setNode(KEY, 4, EXEC, 7, 0, 0);
        ev.decide(IAgenticCommerce(address(acp)), id);
        require(acp.paidTo(id) == CLIENT && acp.reasonOf(id) == ev.PROVIDER_MISMATCH(), "mismatch refunded");
    }

    function test_a_paid_job_waits_for_the_submission() public {
        uint256 id = _job(EXEC);
        esc.setNode(KEY, 4, EXEC, 7, 0, 0);
        vm.expectRevert(OmegaEvaluator8183.NotSubmitted.selector);
        ev.decide(IAgenticCommerce(address(acp)), id);
        _submit(id, EXEC);
        ev.decide(IAgenticCommerce(address(acp)), id);
        require(acp.paidTo(id) == EXEC, "paid after submission");
    }

    function test_link_rules() public {
        vm.prank(CLIENT);
        uint256 id = acp.createJob(EXEC, address(ev), 2_000_000_000, "x");
        vm.expectRevert(OmegaEvaluator8183.NotClient.selector);
        ev.link(IAgenticCommerce(address(acp)), id, KEY);
        vm.prank(CLIENT);
        vm.expectRevert(OmegaEvaluator8183.UnknownNode.selector);
        ev.link(IAgenticCommerce(address(acp)), id, keccak256("nothing"));
        vm.prank(CLIENT);
        uint256 other = acp.createJob(EXEC, OTHER, 2_000_000_000, "another evaluator");
        vm.prank(CLIENT);
        vm.expectRevert(OmegaEvaluator8183.NotEvaluator.selector);
        ev.link(IAgenticCommerce(address(acp)), other, KEY);
        vm.prank(CLIENT);
        ev.link(IAgenticCommerce(address(acp)), id, KEY);
        vm.prank(CLIENT);
        vm.expectRevert(OmegaEvaluator8183.AlreadyLinked.selector);
        ev.link(IAgenticCommerce(address(acp)), id, keccak256("swap"));
        vm.prank(CLIENT);
        uint256 late = acp.createJob(EXEC, address(ev), 2_000_000_000, "late");
        vm.prank(CLIENT);
        acp.fund(late, 1);
        _submit(late, EXEC);
        vm.prank(CLIENT);
        vm.expectRevert(OmegaEvaluator8183.TooLate.selector); // the provider has already delivered
        ev.link(IAgenticCommerce(address(acp)), late, KEY);
        vm.expectRevert(OmegaEvaluator8183.NotLinked.selector);
        ev.decide(IAgenticCommerce(address(acp)), late);
    }
}
