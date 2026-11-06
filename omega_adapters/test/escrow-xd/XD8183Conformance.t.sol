// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OmegaEscrowXD} from "../../src/escrow-xd/OmegaEscrowXD.sol";
import {ERC8183Virtual} from "../../src/escrow-xd/ERC8183Virtual.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAgenticCommerce} from "../../src/OmegaEvaluator8183.sol";
import {IERC8183VerdictEvaluator as I} from "../../src/IERC8183VerdictEvaluator.sol";
import {SignedVerdictEvaluator8183 as Core} from "../../src/SignedVerdictEvaluator8183.sol";
import {BaseContracts8183Conformance} from "../integration/BaseContracts8183Conformance.sol";

/// @notice The reference Core evaluator through the V1-V15 suite on the XD escrow. Same suite and settlement checks
///  as on base-contracts; only escrow creation and funding differ (confirmTerms + fundWithTermsHash).
contract CoreOnXDConformance is BaseContracts8183Conformance {
    address internal constant ADMIN = address(0xAD);

    function _newEscrow() internal override returns (address) {
        OmegaEscrowXD impl = new OmegaEscrowXD();
        OmegaEscrowXD x = OmegaEscrowXD(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(ERC8183Virtual.initialize, (TREASURY, EADMIN))))
        );
        vm.prank(EADMIN);
        x.setPaymentTokenAllowed(address(token), true);
        return address(x);
    }

    function _makeJob(address escrow, address evaluator, bool submitted) internal override returns (uint256 id) {
        OmegaEscrowXD x = OmegaEscrowXD(escrow);
        vm.prank(CLIENT);
        id = x.createJob(PROV, evaluator, EXPIRY, "conformance job", address(0), 0);
        vm.prank(PROV);
        x.setBudget(id, address(token), BUDGET, "");
        (, bytes32 h) = x.commitmentTermsOf(id);
        vm.prank(PROV);
        x.confirmTerms(id, h);
        token.mint(CLIENT, BUDGET);
        vm.prank(CLIENT);
        token.approve(escrow, BUDGET);
        vm.prank(CLIENT);
        x.fundWithTermsHash(id, h, "");
        if (submitted) {
            vm.prank(PROV);
            x.submit(id, keccak256("deliverable"), "");
        }
    }

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
