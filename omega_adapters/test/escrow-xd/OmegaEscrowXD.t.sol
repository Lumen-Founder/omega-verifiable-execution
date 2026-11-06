// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OmegaEscrowXD} from "../../src/escrow-xd/OmegaEscrowXD.sol";
import {ERC8183Virtual} from "../../src/escrow-xd/ERC8183Virtual.sol";
import {XDLogic} from "../../src/escrow-xd/XDLogic.sol";
import {CommitmentTermsLib as L} from "../../src/escrow-xd/CommitmentTermsLib.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TestERC20} from "../integration/TestERC20.sol";
import {CountingHook, ConfigHook, SelfDetachingHook} from "./XDHooks.sol";

interface VmX {
    function prank(address) external;
    function warp(uint256) external;
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
    function etch(address, bytes calldata) external;
}

/// @notice Stage-1 tests of the XD escrow: commitment boundary (CB), committed hooks (HK), locked fee terms.
///  IDs refer to Deferred Payout Settlement design v0.3 (4A.8, 4B.8) and the decision record D-3..D-25.
contract OmegaEscrowXDTest {
    VmX internal constant vm = VmX(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant PK_C = 0xC1;
    uint256 internal constant PK_P = 0xB2;
    uint256 internal constant PK_E = 0xE3;
    uint256 internal constant PK_T = 0x7A;
    address internal constant EADMIN = address(0xEAD);
    uint256 internal constant BUDGET = 1_000_000;
    uint48 internal constant EXPIRY = 2_000_000_000;

    address internal CLIENT;
    address internal PROV;
    address internal EVAL;
    address internal TREASURY;
    OmegaEscrowXD internal xd;
    TestERC20 internal token;

    function setUp() public {
        vm.warp(1_000_000);
        CLIENT = vm.addr(PK_C);
        PROV = vm.addr(PK_P);
        EVAL = vm.addr(PK_E);
        TREASURY = vm.addr(PK_T);
        token = new TestERC20("usdc");
        OmegaEscrowXD impl = new OmegaEscrowXD();
        xd = OmegaEscrowXD(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(ERC8183Virtual.initialize, (TREASURY, EADMIN))))
        );
        vm.prank(EADMIN);
        xd.setPaymentTokenAllowed(address(token), true);
    }

    // ──────────────────── helpers ────────────────────

    function _allow(address hook) internal {
        vm.prank(EADMIN);
        xd.setHookWhitelist(hook, true);
    }

    function _open(address hook) internal returns (uint256 id) {
        vm.prank(CLIENT);
        id = xd.createJob(PROV, EVAL, EXPIRY, "xd job", hook, 0);
        vm.prank(PROV);
        xd.setBudget(id, address(token), BUDGET, "");
    }

    function _hash(uint256 id) internal view returns (bytes32 h) {
        (, h) = xd.commitmentTermsOf(id);
    }

    function _confirm(uint256 id) internal returns (bytes32 h) {
        h = _hash(id);
        vm.prank(PROV);
        xd.confirmTerms(id, h);
    }

    function _pay(uint256 id, bytes32 h) internal {
        token.mint(CLIENT, BUDGET);
        vm.prank(CLIENT);
        token.approve(address(xd), BUDGET);
        vm.prank(CLIENT);
        xd.fundWithTermsHash(id, h, "");
    }

    function _committed(address hook) internal returns (uint256 id) {
        id = _open(hook);
        _pay(id, _confirm(id));
    }

    function _submit(uint256 id) internal {
        vm.prank(PROV);
        xd.submit(id, keccak256("deliverable"), "");
    }

    function _status(uint256 id) internal view returns (uint8) {
        return uint8(xd.getJob(id).status);
    }

    function _one(uint256 id) internal pure returns (uint256[] memory ids) {
        ids = new uint256[](1);
        ids[0] = id;
    }

    /// @dev Independent EIP-712 encoding of CommitmentTermsV2 (does not use the library).
    function _independentHash(L.TermsV2 memory t) internal view returns (bytes32) {
        bytes32 typeHash = keccak256(
            bytes(
                string.concat(
                    "CommitmentTermsV2(uint256 jobId,address client,address provider,uint256 providerAgentId,",
                    "address evaluator,address providerRecipient,address paymentToken,uint256 budget,uint48 expiredAt,",
                    "address hook,uint16 evaluatorFeeBP,uint16 platformFeeBP,address evaluatorFeeRecipient,",
                    "address platformFeeRecipient,uint8 settlementMode,bytes32 hookCodeHash,bytes32 hookConfigHash,",
                    "uint8 hookClass,uint8 hookFaultPolicy,uint32 auxHookGas,uint32 faultWindow,uint8 termsVersion)"
                )
            )
        );
        bytes memory p1 = abi.encode(
            typeHash, t.jobId, t.client, t.provider, t.providerAgentId, t.evaluator, t.providerRecipient, t.paymentToken
        );
        bytes memory p2 = abi.encode(t.budget, t.expiredAt, t.hook, t.evaluatorFeeBP, t.platformFeeBP);
        bytes memory p3 = abi.encode(
            t.evaluatorFeeRecipient, t.platformFeeRecipient, t.settlementMode, t.hookCodeHash, t.hookConfigHash
        );
        bytes memory p4 = abi.encode(t.hookClass, t.hookFaultPolicy, t.auxHookGas, t.faultWindow, t.termsVersion);
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ERC8183CommitmentTerms"),
                keccak256("2"),
                block.chainid,
                address(xd)
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, keccak256(bytes.concat(p1, p2, p3, p4))));
    }

    function _amendDigest(L.HookAmendment memory a) internal view returns (bytes32) {
        bytes32 typeHash = keccak256(
            "HookAmendment(uint256 jobId,bytes32 oldTermsHash,bytes32 newTermsHash,address newHook,bytes32 newHookCodeHash,"
            "bytes32 newHookConfigHash,uint8 newHookClass,uint64 nonce,uint48 deadline)"
        );
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ERC8183CommitmentTerms"),
                keccak256("2"),
                block.chainid,
                address(xd)
            )
        );
        bytes32 s = keccak256(
            abi.encode(
                typeHash,
                a.jobId,
                a.oldTermsHash,
                a.newTermsHash,
                a.newHook,
                a.newHookCodeHash,
                a.newHookConfigHash,
                a.newHookClass,
                a.nonce,
                a.deadline
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, s));
    }

    function _amendment(uint256 id, address newHook) internal view returns (L.HookAmendment memory a) {
        (L.TermsV2 memory t, bytes32 h) = xd.commitmentTermsOf(id);
        a.jobId = id;
        a.oldTermsHash = h;
        a.newHook = newHook;
        a.newHookCodeHash = newHook == address(0) ? bytes32(0) : newHook.codehash;
        a.newHookClass = newHook == address(0) ? 0 : 1;
        t.hook = newHook;
        t.hookCodeHash = a.newHookCodeHash;
        t.hookConfigHash = 0;
        t.hookClass = a.newHookClass;
        a.newTermsHash = _independentHash(t);
        a.nonce = xd.xTermsOf(id).amendmentNonce;
        a.deadline = uint48(block.timestamp + 1 days);
    }

    function _sig(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sigs3(L.HookAmendment memory a) internal returns (XDLogic.AmendmentSignatures memory s) {
        bytes32 d = _amendDigest(a);
        s.client = _sig(PK_C, d);
        s.provider = _sig(PK_P, d);
        s.evaluator = _sig(PK_E, d);
    }

    // ──────────────────── commitment boundary ────────────────────

    function test_CB1_confirm_fund_submit_complete_pays_the_whole_budget() public {
        uint256 id = _open(address(0));
        bytes32 h = _confirm(id);
        _pay(id, h);
        require(_status(id) == 1, "funded");
        require(xd.xTermsOf(id).committedTermsHash == h, "committed hash stored (D-17)");
        _submit(id);
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), "");
        require(_status(id) == 3 && token.balanceOf(PROV) == BUDGET, "provider paid in full at fee 0");
    }

    function test_CB20_terms_hash_matches_an_independent_encoding() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 id = _open(address(hook));
        (L.TermsV2 memory t, bytes32 h) = xd.commitmentTermsOf(id);
        require(h == _independentHash(t), "library hash == independent encoding");
        require(t.hookCodeHash == address(hook).codehash && t.hookClass == 1 && t.termsVersion == 2, "hook binding");
        require(t.auxHookGas == 100_000 && t.faultWindow == 72 hours, "D-24 defaults");
    }

    function test_CB2_flipped_hash_reverts_and_moves_nothing() public {
        uint256 id = _open(address(0));
        bytes32 h = _confirm(id);
        token.mint(CLIENT, BUDGET);
        vm.prank(CLIENT);
        token.approve(address(xd), BUDGET);
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector);
        xd.fundWithTermsHash(id, h ^ bytes32(uint256(1)), "");
        require(_status(id) == 0 && token.balanceOf(CLIENT) == BUDGET, "state and balance unchanged");
    }

    function test_CB3_fund_before_provider_confirmation_reverts() public {
        uint256 id = _open(address(0));
        bytes32 h = _hash(id);
        vm.prank(CLIENT);
        vm.expectRevert(OmegaEscrowXD.TermsNotConfirmed.selector);
        xd.fundWithTermsHash(id, h, "");
    }

    function test_CB4_no_provider_cannot_confirm_or_fund() public {
        vm.prank(CLIENT);
        uint256 id = xd.createJob(address(0), EVAL, EXPIRY, "xd job", address(0), 0);
        bytes32 h = _hash(id);
        vm.prank(PROV);
        vm.expectRevert(ERC8183Virtual.Unauthorized.selector);
        xd.confirmTerms(id, h);
        vm.prank(CLIENT);
        vm.expectRevert(ERC8183Virtual.ProviderNotSet.selector);
        xd.fundWithTermsHash(id, h, "");
    }

    function test_CB5_recipient_change_after_confirmation_reverts_the_old_hash() public {
        uint256 id = _open(address(0));
        bytes32 h = _confirm(id);
        vm.prank(PROV);
        xd.setPayoutReceiver(id, address(0xBEEF));
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector);
        xd.fundWithTermsHash(id, h, "");
    }

    function test_CB6_budget_change_after_confirmation_reverts_the_old_hash() public {
        uint256 id = _open(address(0));
        bytes32 h = _confirm(id);
        vm.prank(PROV);
        xd.setBudget(id, address(token), BUDGET + 1, "");
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector);
        xd.fundWithTermsHash(id, h, "");
    }

    function test_CB7_admin_detach_before_funding_is_visible_in_the_hash() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 id = _open(address(hook));
        bytes32 h = _confirm(id);
        vm.prank(EADMIN);
        xd.batchDetachHook(_one(id)); // allowed before the boundary (HK4)
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector);
        xd.fundWithTermsHash(id, h, "");
    }

    function test_CB7b_client_cannot_fund_terms_the_provider_did_not_confirm() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 id = _open(address(hook));
        _confirm(id);
        vm.prank(EADMIN);
        xd.batchDetachHook(_one(id));
        bytes32 hNew = _hash(id); // the client reads the new terms and agrees to them
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector); // the provider has not
        xd.fundWithTermsHash(id, hNew, "");
        vm.prank(PROV);
        xd.confirmTerms(id, hNew);
        _pay(id, hNew);
        require(_status(id) == 1, "funded once both sides agree");
    }

    function test_CB8_global_fee_change_after_confirmation_leaves_the_job_terms() public {
        uint256 id = _open(address(0));
        bytes32 h = _confirm(id);
        vm.prank(EADMIN);
        xd.setPlatformFee(500, address(0x7EA2));
        vm.prank(EADMIN);
        xd.setEvaluatorFee(300);
        _pay(id, h); // same hash still valid
        _submit(id);
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), "");
        require(token.balanceOf(PROV) == BUDGET, "fees fixed at creation (0), not at completion");
        require(token.balanceOf(address(0x7EA2)) == 0 && token.balanceOf(EVAL) == 0, "no fee taken");
    }

    function test_CB12_hook_detaching_itself_during_fund_reverts() public {
        SelfDetachingHook hook = new SelfDetachingHook();
        _allow(address(hook));
        bytes32 adminRole = xd.ADMIN_ROLE();
        vm.prank(EADMIN);
        xd.grantRole(adminRole, address(hook));
        uint256 id = _open(address(hook));
        bytes32 h = _confirm(id);
        hook.arm(address(xd));
        token.mint(CLIENT, BUDGET);
        vm.prank(CLIENT);
        token.approve(address(xd), BUDGET);
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector); // second check, after the hook (4A.4 step 5)
        xd.fundWithTermsHash(id, h, "");
        require(xd.getJob(id).hook == address(hook) && _status(id) == 0, "detach rolled back, still Open");
    }

    function test_CB14_hash_of_another_job_reverts() public {
        uint256 a = _open(address(0));
        uint256 b = _open(address(0));
        bytes32 ha = _confirm(a);
        _confirm(b);
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector);
        xd.fundWithTermsHash(b, ha, "");
    }

    function test_CB15_plain_fund_reverts() public {
        uint256 id = _open(address(0));
        _confirm(id);
        vm.prank(CLIENT);
        vm.expectRevert(OmegaEscrowXD.TermsHashRequired.selector);
        xd.fund(id, address(token), BUDGET, "");
    }

    function test_CB17_nothing_in_the_terms_changes_after_funding() public {
        uint256 id = _committed(address(0));
        bytes32 h = _hash(id);
        vm.prank(PROV);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.setPayoutReceiver(id, address(0xBEEF));
        vm.prank(PROV);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.setBudget(id, address(token), 1, "");
        vm.prank(CLIENT);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.setProvider(id, address(0xBEEF), 0);
        vm.prank(PROV);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.confirmTerms(id, h);
        require(_hash(id) == h, "hash unchanged");
    }

    function test_CB23_fund_after_expiry_reverts() public {
        uint256 id = _open(address(0));
        bytes32 h = _confirm(id);
        vm.warp(EXPIRY);
        vm.prank(CLIENT);
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.fundWithTermsHash(id, h, "");
    }

    function test_CB24_provider_cannot_confirm_a_different_hash() public {
        uint256 id = _open(address(0));
        bytes32 h = _hash(id);
        vm.prank(PROV);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector);
        xd.confirmTerms(id, h ^ bytes32(uint256(1)));
        vm.prank(CLIENT);
        vm.expectRevert(ERC8183Virtual.Unauthorized.selector);
        xd.confirmTerms(id, h);
    }

    function test_HB1_hook_config_change_between_confirmation_and_funding_reverts() public {
        ConfigHook hook = new ConfigHook();
        _allow(address(hook));
        uint256 id = _open(address(hook));
        hook.setConfig(id, keccak256("cfg-1"));
        bytes32 h = _confirm(id);
        hook.setConfig(id, keccak256("cfg-2"));
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.TermsHashMismatch.selector);
        xd.fundWithTermsHash(id, h, "");
    }

    // ──────────────────── committed hooks ────────────────────

    function test_HK6_detach_reverts_for_every_committed_state() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 funded = _committed(address(hook));
        uint256 submitted = _committed(address(hook));
        _submit(submitted);
        uint256 completed = _committed(address(hook));
        _submit(completed);
        vm.prank(EVAL);
        xd.complete(completed, bytes32("ok"), "");
        uint256 rejected = _committed(address(hook));
        vm.prank(EVAL);
        xd.reject(rejected, bytes32("no"), "");
        uint256[4] memory ids = [funded, submitted, completed, rejected];
        for (uint256 i; i < 4; i++) {
            vm.prank(EADMIN);
            vm.expectRevert(abi.encodeWithSelector(OmegaEscrowXD.HookBoundToCommittedJob.selector, ids[i]));
            xd.batchDetachHook(_one(ids[i]));
            require(xd.getJob(ids[i]).hook == address(hook), "hook kept");
        }
        vm.warp(EXPIRY);
        xd.claimRefund(funded);
        require(_status(funded) == 5, "expired");
        vm.prank(EADMIN);
        vm.expectRevert(abi.encodeWithSelector(OmegaEscrowXD.HookBoundToCommittedJob.selector, funded));
        xd.batchDetachHook(_one(funded));
    }

    function test_HK7_one_committed_job_in_the_list_reverts_the_whole_call() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 open = _open(address(hook));
        uint256 funded = _committed(address(hook));
        uint256[] memory ids = new uint256[](2);
        ids[0] = open;
        ids[1] = funded;
        vm.prank(EADMIN);
        vm.expectRevert(abi.encodeWithSelector(OmegaEscrowXD.HookBoundToCommittedJob.selector, funded));
        xd.batchDetachHook(ids);
        require(xd.getJob(open).hook == address(hook), "open job not detached either");
    }

    function test_HK9_dewhitelisted_hook_keeps_running_for_committed_jobs() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 id = _committed(address(hook));
        vm.prank(EADMIN);
        xd.setHookWhitelist(address(hook), false);
        uint256 before = hook.calls();
        _submit(id);
        require(hook.calls() == before + 2 && xd.getJob(id).hook == address(hook), "still called, field unchanged");
    }

    function test_D19_hook_code_change_blocks_every_hooked_call() public {
        CountingHook hook = new CountingHook();
        ConfigHook other = new ConfigHook();
        _allow(address(hook));
        uint256 id = _committed(address(hook));
        vm.etch(address(hook), address(other).code);
        vm.prank(PROV);
        vm.expectRevert(abi.encodeWithSelector(XDLogic.HookBindingChanged.selector, id));
        xd.submit(id, keccak256("deliverable"), "");
        vm.prank(EVAL);
        vm.expectRevert(abi.encodeWithSelector(XDLogic.HookBindingChanged.selector, id));
        xd.reject(id, bytes32("no"), "");
        vm.warp(EXPIRY);
        xd.claimRefund(id); // not hooked: the client still gets the money back
        require(token.balanceOf(CLIENT) == BUDGET, "refund path open");
    }

    function test_D19_hook_config_change_after_commitment_blocks_hooked_calls() public {
        ConfigHook hook = new ConfigHook();
        _allow(address(hook));
        uint256 id = _open(address(hook));
        hook.setConfig(id, keccak256("cfg-1"));
        _pay(id, _confirm(id));
        require(xd.xTermsOf(id).hookConfigHash == keccak256("cfg-1") && xd.xTermsOf(id).hookHasConfig, "stored");
        hook.setConfig(id, keccak256("cfg-2"));
        vm.prank(PROV);
        vm.expectRevert(abi.encodeWithSelector(XDLogic.HookBindingChanged.selector, id));
        xd.submit(id, keccak256("deliverable"), "");
    }

    function test_HK10_amend_with_client_provider_evaluator_signatures() public {
        CountingHook oldHook = new CountingHook();
        CountingHook newHook = new CountingHook();
        _allow(address(oldHook));
        uint256 id = _committed(address(oldHook));
        L.HookAmendment memory a = _amendment(id, address(newHook)); // newHook not on the allowlist (D-21)
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        xd.amendHook(a, s); // anyone may relay
        XDLogic.XTerms memory x = xd.xTermsOf(id);
        require(xd.getJob(id).hook == address(newHook) && x.committedTermsHash == a.newTermsHash, "new terms");
        require(x.amendmentNonce == 1, "nonce");
        require(
            x.amendmentLogHead == keccak256(abi.encode(bytes32(0), _amendDigest(a), keccak256(abi.encode(s)))),
            "audit chain"
        );
        require(_hash(id) == a.newTermsHash, "view agrees");
        uint256 oldCalls = oldHook.calls();
        _submit(id);
        require(newHook.calls() == 2 && oldHook.calls() == oldCalls, "only the new hook runs");
    }

    function test_HK11_the_same_signatures_cannot_be_replayed() public {
        CountingHook newHook = new CountingHook();
        uint256 id = _committed(address(0));
        L.HookAmendment memory a = _amendment(id, address(newHook));
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        xd.amendHook(a, s);
        vm.expectRevert(XDLogic.AmendmentMismatch.selector);
        xd.amendHook(a, s);
    }

    function test_AR1_signatures_stay_spent_after_the_terms_return_to_the_same_hash() public {
        CountingHook hookA = new CountingHook();
        CountingHook hookB = new CountingHook();
        _allow(address(hookA));
        uint256 id = _committed(address(hookA));
        bytes32 h0 = _hash(id);
        L.HookAmendment memory first = _amendment(id, address(hookB));
        XDLogic.AmendmentSignatures memory s1 = _sigs3(first);
        xd.amendHook(first, s1); // A -> B, nonce 0
        L.HookAmendment memory back = _amendment(id, address(hookA));
        xd.amendHook(back, _sigs3(back)); // B -> A, nonce 1
        require(_hash(id) == h0, "terms hash is back to the original");
        vm.expectRevert(XDLogic.AmendmentMismatch.selector); // old/new hashes match again; only the nonce refuses
        xd.amendHook(first, s1);
        require(xd.getJob(id).hook == address(hookA) && xd.xTermsOf(id).amendmentNonce == 2, "not replayed");
    }

    function test_HK13_missing_evaluator_signature_reverts() public {
        uint256 id = _committed(address(0));
        L.HookAmendment memory a = _amendment(id, address(new CountingHook()));
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        s.evaluator = "";
        vm.expectRevert(abi.encodeWithSelector(XDLogic.MissingSignature.selector, uint8(2)));
        xd.amendHook(a, s);
        s = _sigs3(a);
        s.provider = _sig(PK_C, _amendDigest(a)); // client's key in the provider slot
        vm.expectRevert(abi.encodeWithSelector(XDLogic.MissingSignature.selector, uint8(1)));
        xd.amendHook(a, s);
    }

    function test_HK14_platform_signs_only_when_its_locked_fee_is_positive() public {
        vm.prank(EADMIN);
        xd.setPlatformFee(100, TREASURY);
        uint256 id = _committed(address(0));
        L.HookAmendment memory a = _amendment(id, address(new CountingHook()));
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        vm.expectRevert(abi.encodeWithSelector(XDLogic.MissingSignature.selector, uint8(3)));
        xd.amendHook(a, s);
        s.platform = _sig(PK_T, _amendDigest(a));
        xd.amendHook(a, s);
        // a job created at platform fee 0 needs no platform signature, even if the fee rises later
        vm.prank(EADMIN);
        xd.setPlatformFee(0, TREASURY);
        uint256 id2 = _committed(address(0));
        vm.prank(EADMIN);
        xd.setPlatformFee(100, TREASURY);
        L.HookAmendment memory a2 = _amendment(id2, address(new CountingHook()));
        xd.amendHook(a2, _sigs3(a2));
    }

    function test_HK15_one_address_in_two_roles_signs_once() public {
        vm.prank(CLIENT);
        uint256 id = xd.createJob(PROV, CLIENT, EXPIRY, "self-evaluated", address(0), 0);
        vm.prank(PROV);
        xd.setBudget(id, address(token), BUDGET, "");
        _pay(id, _confirm(id));
        L.HookAmendment memory a = _amendment(id, address(new CountingHook()));
        bytes32 d = _amendDigest(a);
        XDLogic.AmendmentSignatures memory s;
        s.client = _sig(PK_C, d);
        s.provider = _sig(PK_P, d);
        xd.amendHook(a, s);
        require(xd.xTermsOf(id).amendmentNonce == 1, "amended");
    }

    function test_HK17_new_hash_that_changes_any_other_term_reverts() public {
        uint256 id = _committed(address(0));
        CountingHook newHook = new CountingHook();
        L.HookAmendment memory a = _amendment(id, address(newHook));
        (L.TermsV2 memory t,) = xd.commitmentTermsOf(id);
        t.hook = address(newHook);
        t.hookCodeHash = address(newHook).codehash;
        t.hookClass = 1;
        t.budget = BUDGET / 2; // smuggled change
        a.newTermsHash = _independentHash(t);
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        vm.expectRevert(XDLogic.AmendmentMismatch.selector);
        xd.amendHook(a, s);
    }

    function test_HK19_amend_after_completion_reverts() public {
        uint256 id = _committed(address(0));
        L.HookAmendment memory a = _amendment(id, address(new CountingHook()));
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        _submit(id);
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), "");
        vm.expectRevert(ERC8183Virtual.WrongStatus.selector);
        xd.amendHook(a, s);
    }

    function test_HK20_deadline_passed_or_beyond_expiry_reverts() public {
        uint256 id = _committed(address(0));
        L.HookAmendment memory a = _amendment(id, address(new CountingHook()));
        a.deadline = uint48(EXPIRY) + 1;
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        vm.expectRevert(XDLogic.AmendmentExpired.selector);
        xd.amendHook(a, s);
        a.deadline = uint48(block.timestamp + 10);
        s = _sigs3(a);
        vm.warp(block.timestamp + 11);
        vm.expectRevert(XDLogic.AmendmentExpired.selector);
        xd.amendHook(a, s);
    }

    function test_HK22_broken_hook_can_be_removed_without_being_called() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 id = _committed(address(hook));
        hook.setBroken(true);
        vm.prank(PROV);
        vm.expectRevert(bytes("hook broken"));
        xd.submit(id, keccak256("deliverable"), "");
        L.HookAmendment memory a = _amendment(id, address(0));
        xd.amendHook(a, _sigs3(a));
        _submit(id);
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), "");
        require(token.balanceOf(PROV) == BUDGET, "paid after the parties removed the broken hook");
    }

    function test_HK24_removal_with_a_code_hash_reverts() public {
        uint256 id = _committed(address(0));
        L.HookAmendment memory a = _amendment(id, address(0));
        a.newHookCodeHash = keccak256("x");
        XDLogic.AmendmentSignatures memory s = _sigs3(a);
        vm.expectRevert(XDLogic.AmendmentMismatch.selector);
        xd.amendHook(a, s);
    }

    function test_HK44_fuzz_admin_calls_never_change_committed_terms(uint8 op, uint16 fee) public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        uint256 id = _committed(address(hook));
        bytes32 h = _hash(id);
        uint256 f = uint256(fee) % 5001;
        vm.prank(EADMIN);
        if (op % 6 == 0) xd.setPlatformFee(f, address(0x7EA2));
        else if (op % 6 == 1) xd.setEvaluatorFee(f);
        else if (op % 6 == 2) xd.setHookWhitelist(address(hook), false);
        else if (op % 6 == 3) xd.setPaymentTokenAllowed(address(token), false);
        else if (op % 6 == 4) xd.pause();
        else {
            vm.expectRevert(abi.encodeWithSelector(OmegaEscrowXD.HookBoundToCommittedJob.selector, id));
            xd.batchDetachHook(_one(id));
        }
        require(_hash(id) == h && xd.xTermsOf(id).committedTermsHash == h, "committed terms unchanged");
    }

    // ──────────────────── fee terms, stage-1 limits ────────────────────

    function test_fee_terms_are_capped_and_locked_at_creation() public {
        vm.prank(EADMIN);
        xd.setEvaluatorFee(300);
        vm.prank(EVAL);
        xd.setEvaluatorDefaultRecipient(address(0xFEE));
        XDLogic.CreateTerms memory ct = xd.defaultCreateTerms(address(0));
        ct.maxEvaluatorFeeBP = 200;
        vm.prank(CLIENT);
        vm.expectRevert(XDLogic.FeeAboveCap.selector);
        xd.createJobWithTerms(PROV, EVAL, EXPIRY, "capped", address(0), 0, ct);
        ct.maxEvaluatorFeeBP = 300;
        vm.prank(CLIENT);
        uint256 id = xd.createJobWithTerms(PROV, EVAL, EXPIRY, "capped", address(0), 0, ct);
        vm.prank(PROV);
        xd.setBudget(id, address(token), BUDGET, "");
        _pay(id, _confirm(id));
        vm.prank(EADMIN);
        xd.setEvaluatorFee(0); // later change does not reach this job
        vm.prank(EVAL);
        xd.setEvaluatorDefaultRecipient(address(0xFEE2)); // later jobs only
        _submit(id);
        vm.prank(EVAL);
        xd.complete(id, bytes32("ok"), "");
        require(token.balanceOf(address(0xFEE)) == 30_000, "3 % to the recipient locked at creation");
        require(token.balanceOf(PROV) == BUDGET - 30_000, "net to provider");
        require(token.balanceOf(address(0xFEE2)) == 0 && token.balanceOf(EVAL) == 0, "no other recipient");
    }

    function test_rejects_terms_it_does_not_implement_yet() public {
        CountingHook hook = new CountingHook();
        _allow(address(hook));
        XDLogic.CreateTerms memory base = xd.defaultCreateTerms(address(hook));
        XDLogic.CreateTerms[4] memory bad = [base, base, base, base];
        bad[0].settlementMode = 2; // undefined mode
        bad[1].hookClass = 3; // undefined class
        bad[2].hookFaultPolicy = 3; // undefined policy
        bad[3].auxHookGas = 10_000; // below the D-24 floor
        for (uint256 i; i < 4; i++) {
            vm.prank(CLIENT);
            vm.expectRevert(XDLogic.UnsupportedTerms.selector);
            xd.createJobWithTerms(PROV, EVAL, EXPIRY, "bad", address(hook), 0, bad[i]);
        }
    }

    function test_partial_settlement_is_not_supported() public {
        uint256 id = _committed(address(0));
        vm.prank(PROV);
        vm.expectRevert(OmegaEscrowXD.PartialSettlementUnsupported.selector);
        xd.submitClaim(id, BUDGET / 2, keccak256("half"), "");
        vm.prank(CLIENT);
        vm.expectRevert(OmegaEscrowXD.PartialSettlementUnsupported.selector);
        xd.settleClaim(id, BUDGET / 2, keccak256("half"), "");
    }
}
