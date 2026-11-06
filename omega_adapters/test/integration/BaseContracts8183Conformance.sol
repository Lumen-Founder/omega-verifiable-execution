// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.28;

import {ERC8183} from "erc8183-base/ERC8183.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {VerdictConformanceBase, VmLog} from "../VerdictConformanceBase.sol";
import {TestERC20} from "./TestERC20.sol";

/// @title BaseContracts8183Conformance — the V1-V15 suite bound to the real ERC-8183 reference escrow
/// @notice erc-8183/base-contracts@142e669c1fd318486a4628395b629f033654dd06 (contracts/ERC8183.sol copied unmodified to
///  third_party/, sha256 in its SOURCE.md) with OpenZeppelin 5.6.1, behind an ERC1967 proxy, initialised as its own
///  deploy path does. Fees are 0 (the escrow's initial state), so the whole budget must reach the payee.
///  Settlement is observed twice and the two must agree: the escrow's own events (JobCompleted / JobRejected with the
///  reason, PaymentReleased / Refunded with the recipient) and the payee's token balance.
///  To test your evaluator on the real escrow, inherit this contract and implement the same four evaluator hooks as for
///  `VerdictConformance`.
abstract contract BaseContracts8183Conformance is VerdictConformanceBase {
    address internal constant TREASURY = address(0x7EA5);
    address internal constant EADMIN = address(0xEAD); // escrow DEFAULT_ADMIN_ROLE + ADMIN_ROLE (test address)
    uint256 internal constant BUDGET = 1_000_000;
    uint48 internal constant EXPIRY = 2_000_000_000;

    bytes32 internal constant EV_COMPLETED = keccak256("JobCompleted(uint256,address,bytes32)");
    bytes32 internal constant EV_REJECTED = keccak256("JobRejected(uint256,address,bytes32)");
    bytes32 internal constant EV_PAID = keccak256("PaymentReleased(uint256,address,uint256)");
    bytes32 internal constant EV_REFUNDED = keccak256("Refunded(uint256,address,uint256)");

    TestERC20 internal token;
    uint256 internal provBefore;
    uint256 internal clientBefore;

    function setUp() public virtual override {
        token = new TestERC20("usdc");
        super.setUp();
    }

    function _newEscrow() internal virtual override returns (address) {
        ERC8183 impl = new ERC8183();
        ERC8183 acp =
            ERC8183(address(new ERC1967Proxy(address(impl), abi.encodeCall(ERC8183.initialize, (TREASURY, EADMIN)))));
        vm.prank(EADMIN);
        acp.setPaymentTokenAllowed(address(token), true);
        return address(acp);
    }

    function _makeJob(address escrow, address evaluator, bool submitted) internal virtual override returns (uint256 id) {
        ERC8183 acp = ERC8183(escrow);
        vm.prank(CLIENT);
        id = acp.createJob(PROV, evaluator, EXPIRY, "conformance job", address(0), 0);
        vm.prank(PROV);
        acp.setBudget(id, address(token), BUDGET, "");
        token.mint(CLIENT, BUDGET);
        vm.prank(CLIENT);
        token.approve(escrow, BUDGET);
        vm.prank(CLIENT);
        acp.fund(id, address(token), BUDGET, "");
        if (submitted) {
            vm.prank(PROV);
            acp.submit(id, keccak256("deliverable"), "");
        }
    }

    function _jobStatus(address escrow, uint256 id) internal view virtual override returns (uint8) {
        return uint8(ERC8183(escrow).getJob(id).status);
    }

    function _setEscrowPaused(address escrow, bool paused) internal virtual override {
        vm.prank(EADMIN);
        if (paused) ERC8183(escrow).pause();
        else ERC8183(escrow).unpause();
    }

    function _watchSettlement(address, uint256) internal virtual override {
        provBefore = token.balanceOf(PROV);
        clientBefore = token.balanceOf(CLIENT);
        vm.recordLogs();
    }

    function _settlement(address escrow, uint256 id) internal virtual override returns (address payee, bytes32 reason) {
        VmLog[] memory logs = vm.getRecordedLogs();
        uint256 decisions;
        uint256 payments;
        for (uint256 i; i < logs.length; i++) {
            VmLog memory l = logs[i];
            if (l.emitter != escrow || l.topics.length < 2 || uint256(l.topics[1]) != id) continue;
            bytes32 t = l.topics[0];
            if (t == EV_COMPLETED || t == EV_REJECTED) {
                reason = abi.decode(l.data, (bytes32));
                decisions++;
            } else if (t == EV_PAID || t == EV_REFUNDED) {
                payee = address(uint160(uint256(l.topics[2])));
                require(abi.decode(l.data, (uint256)) == BUDGET, "fee 0: whole budget settles");
                payments++;
            }
        }
        require(decisions == 1 && payments == 1, "exactly one decision event and one payment event");
        // second, independent observation: balances
        if (payee == PROV) require(token.balanceOf(PROV) - provBefore == BUDGET, "provider balance");
        else if (payee == CLIENT) require(token.balanceOf(CLIENT) - clientBefore == BUDGET, "client balance");
    }
}
