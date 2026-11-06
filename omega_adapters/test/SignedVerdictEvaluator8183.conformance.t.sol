// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAgenticCommerce} from "../src/OmegaEvaluator8183.sol";
import {IERC8183VerdictEvaluator as I} from "../src/IERC8183VerdictEvaluator.sol";
import {SignedVerdictEvaluator8183 as E} from "../src/SignedVerdictEvaluator8183.sol";
import {VerdictConformance} from "./VerdictConformance.sol";

/// @notice The reference evaluator run through the conformance suite. Another implementation copies this file and
///  replaces the four hooks.
contract SignedVerdictEvaluator8183Conformance is VerdictConformance {
    address internal constant ADMIN = address(0xAD);

    function _deploy(address escrow) internal override returns (I) {
        return I(address(new E(IAgenticCommerce(escrow), ADMIN)));
    }

    function _setKey(I e, bytes32 keyId, address signer, uint64 validFrom, uint64 validUntil) internal override {
        vm.prank(ADMIN);
        E(address(e)).setKey(keyId, signer, validFrom, validUntil);
    }

    function _retireKey(I e, bytes32 keyId, uint64 at) internal override {
        vm.prank(ADMIN);
        E(address(e)).retireKey(keyId, at);
    }

    function _revokeKey(I e, bytes32 keyId) internal override {
        vm.prank(ADMIN);
        E(address(e)).revokeKey(keyId);
    }
}
