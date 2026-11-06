// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Copy into test/ of your evaluator repository and replace the four adapter functions with calls to your contract.
// The suite deploys the real erc-8183/base-contracts escrow (142e669c) behind a proxy, creates and funds jobs on it,
// and checks V1-V15 of the Evaluator Verdicts draft: 25 tests. As shipped, it runs the reference evaluator so that
// you can see it pass before you swap in yours.
import {BaseContracts8183Conformance} from "omega/test/integration/BaseContracts8183Conformance.sol";
import {IERC8183VerdictEvaluator as I} from "omega/src/IERC8183VerdictEvaluator.sol";
import {IAgenticCommerce} from "omega/src/OmegaEvaluator8183.sol";
// Replace with your evaluator:
import {SignedVerdictEvaluator8183 as MyEvaluator} from "omega/src/SignedVerdictEvaluator8183.sol";

contract MyEvaluatorConformance is BaseContracts8183Conformance {
    address internal constant OWNER = address(0xAD);

    /// Deploy your evaluator for the given escrow.
    function _deploy(address escrow) internal override returns (I) {
        return I(address(new MyEvaluator(IAgenticCommerce(escrow), OWNER)));
    }

    /// Register a signing key, valid from validFrom until validUntil (0 = open-ended).
    function _setKey(I e, bytes32 keyId, address signer, uint64 validFrom, uint64 validUntil) internal override {
        vm.prank(OWNER);
        MyEvaluator(address(e)).setKey(keyId, signer, validFrom, validUntil);
    }

    /// Retire a key: verdicts signed before `at` stay valid.
    function _retireKey(I e, bytes32 keyId, uint64 at) internal override {
        vm.prank(OWNER);
        MyEvaluator(address(e)).retireKey(keyId, at);
    }

    /// Revoke a key: no verdict signed with it is valid any more.
    function _revokeKey(I e, bytes32 keyId) internal override {
        vm.prank(OWNER);
        MyEvaluator(address(e)).revokeKey(keyId);
    }
}
