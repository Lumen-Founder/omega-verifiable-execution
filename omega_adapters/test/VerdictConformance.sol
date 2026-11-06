// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.28;

import {MockAgenticCommerce} from "./OmegaEvaluator8183.t.sol";
import {VerdictConformanceBase} from "./VerdictConformanceBase.sol";

/// @title VerdictConformance — conformance suite for spec/ERC8183_EVALUATOR_VERDICTS.md (V1-V15), mock escrow binding
/// @notice To test an implementation, inherit this contract and implement the four evaluator hooks: deploy the evaluator
///  bound to an escrow, register a key, retire a key, revoke a key. The escrow here is a mock of the ERC-8183 state
///  machine. To run the same 25 tests on the real erc-8183/base-contracts escrow, inherit
///  `test/integration/BaseContracts8183Conformance.sol` instead; the four hooks are the same.
abstract contract VerdictConformance is VerdictConformanceBase {
    MockAgenticCommerce internal acp;

    function setUp() public virtual override {
        super.setUp();
        acp = MockAgenticCommerce(escrowAddr);
    }

    function _newEscrow() internal virtual override returns (address) {
        return address(new MockAgenticCommerce());
    }

    function _makeJob(address escrow, address evaluator, bool submitted) internal virtual override returns (uint256 id) {
        MockAgenticCommerce a = MockAgenticCommerce(escrow);
        vm.prank(CLIENT);
        id = a.createJob(PROV, evaluator, 2_000_000_000, "conformance job");
        vm.prank(CLIENT);
        a.fund(id, 1_000);
        if (submitted) {
            vm.prank(PROV);
            a.submit(id);
        }
    }

    /// @dev Kept for implementers who called the v0.2 helper directly.
    function _job(MockAgenticCommerce a, address evaluator) internal returns (uint256) {
        return _makeJob(address(a), evaluator, true);
    }

    function _jobStatus(address escrow, uint256 id) internal view virtual override returns (uint8) {
        return MockAgenticCommerce(escrow).getJob(id).status;
    }

    function _setEscrowPaused(address escrow, bool paused) internal virtual override {
        MockAgenticCommerce(escrow).setPaused(paused);
    }

    function _watchSettlement(address, uint256) internal virtual override {}

    function _settlement(address escrow, uint256 id) internal virtual override returns (address, bytes32) {
        MockAgenticCommerce a = MockAgenticCommerce(escrow);
        return (a.paidTo(id), a.reasonOf(id));
    }
}
