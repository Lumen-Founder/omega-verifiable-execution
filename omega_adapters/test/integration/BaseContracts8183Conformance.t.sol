// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAgenticCommerce} from "../../src/OmegaEvaluator8183.sol";
import {IERC8183VerdictEvaluator as I} from "../../src/IERC8183VerdictEvaluator.sol";
import {SignedVerdictEvaluator8183 as Core} from "../../src/SignedVerdictEvaluator8183.sol";
import {BaseContracts8183Conformance} from "./BaseContracts8183Conformance.sol";

/// @notice The reference Core evaluator through the V1-V15 suite on the real base-contracts escrow.
contract CoreOnBaseContractsConformance is BaseContracts8183Conformance {
    address internal constant ADMIN = address(0xAD);

    function _deploy(address escrow) internal override returns (I) {
        return I(address(new Core(IAgenticCommerce(escrow), ADMIN)));
    }

    function _setKey(I e, bytes32 keyId, address signer, uint64 validFrom, uint64 validUntil) internal override {
        vm.prank(ADMIN);
        Core(address(e)).setKey(keyId, signer, validFrom, validUntil);
    }

    function _retireKey(I e, bytes32 keyId, uint64 at) internal override {
        vm.prank(ADMIN);
        Core(address(e)).retireKey(keyId, at);
    }

    function _revokeKey(I e, bytes32 keyId) internal override {
        vm.prank(ADMIN);
        Core(address(e)).revokeKey(keyId);
    }
}
