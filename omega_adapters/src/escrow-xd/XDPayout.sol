// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC8183Virtual} from "./ERC8183Virtual.sol";
import {IDisburser} from "./IDisburser.sol";
import {XDLogic} from "./XDLogic.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

/// @title XDPayout — settlement, payout rights and solvency accounting of OmegaEscrowXD (pre-audit)
/// @notice External library, delegatecalled by the escrow: `address(this)`, storage, balances and events are the
///  escrow's. It moves the escrow's tokens only to a job's fixed recipients.
///  IMMEDIATE jobs pay at completion and refund at rejection or expiry, as base-contracts does.
///  DEFERRED jobs record payout rights instead (DS1, D-10): completion fixes the provider, evaluator and platform
///  shares, rejection or expiry of a funded job fixes the client refund. Anyone may later claim a right; the tokens go
///  to its fixed recipient only (DS5, DS8). Amounts are recomputed from inputs that do not change after settlement
///  (budget, settledAmount = 0, locked rates), not stored (D-12).
///  Solvency (DS16): for every token, balance >= totalEscrowed (funded, unsettled budgets) + totalUnclaimed (rights).
library XDPayout {
    using SafeERC20 for IERC20;

    uint8 internal constant PROVIDER = 0;
    uint8 internal constant EVALUATOR = 1;
    uint8 internal constant PLATFORM = 2;
    uint8 internal constant CLIENT_REFUND = 3;

    uint8 internal constant NONE = 0;
    uint8 internal constant ENTITLED = 1;
    uint8 internal constant CLAIMED = 2;

    event PayoutEntitled(
        uint256 indexed jobId, uint8 indexed kind, address indexed recipient, address token, uint256 amount
    );
    event PayoutClaimed(
        uint256 indexed jobId, uint8 indexed kind, address indexed recipient, address token, uint256 amount, address caller
    );

    error DisburserDataMismatch();

    // ──────────────────── Views ────────────────────

    function statusOf(XDLogic.XTerms storage x, uint8 kind) internal view returns (uint8) {
        if (kind > CLIENT_REFUND) return NONE;
        return (x.payoutBits >> (2 * kind)) & 3;
    }

    /// @dev M1: fees round down, the provider gets the rest. Only budget, the locked rates and the recipients are read;
    ///  none of them can change once the job is funded.
    function _share(ERC8183Virtual.Job storage j, XDLogic.XTerms storage x, uint8 kind)
        private
        view
        returns (address recipient, uint256 amount)
    {
        uint256 a = j.budget; // settledAmount is always 0 for XD jobs
        uint256 pf = (a * x.platformFeeBP) / 10000;
        uint256 ef = (a * x.evaluatorFeeBP) / 10000;
        if (kind == PROVIDER) return (j.payoutReceiver == address(0) ? j.provider : j.payoutReceiver, a - pf - ef);
        if (kind == EVALUATOR) return (x.evaluatorFeeRecipient, ef);
        if (kind == PLATFORM) return (x.platformFeeRecipient, pf);
        if (kind == CLIENT_REFUND) return (j.client, a);
    }

    /// @notice A payout right of a DEFERRED job. NONE rights report amount 0.
    function payoutOf(ERC8183Virtual.Job storage j, XDLogic.XTerms storage x, uint8 kind)
        external
        view
        returns (address recipient, address token, uint256 amount, uint8 status)
    {
        status = statusOf(x, kind);
        if (status == NONE) return (address(0), address(0), 0, NONE);
        (recipient, amount) = _share(j, x, kind);
        token = j.paymentToken;
    }

    /// @notice What an admin may withdraw: the balance above all funded budgets and unclaimed rights (DS17).
    function excess(
        mapping(address => uint256) storage escrowed,
        mapping(address => uint256) storage unclaimed,
        address token
    ) public view returns (uint256) {
        uint256 bal = IERC20(token).balanceOf(address(this));
        uint256 owed = escrowed[token] + unclaimed[token];
        return bal > owed ? bal - owed : 0;
    }

    // ──────────────────── Settlement ────────────────────

    /// @notice Completion of a funded job. IMMEDIATE: pay the three shares now. DEFERRED: record them as rights and
    ///  fix the disburser data (DS1, DS11); no transfer, no callback.
    function settleComplete(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        mapping(address => uint256) storage escrowed,
        mapping(address => uint256) storage unclaimed,
        uint256 jobId,
        bytes calldata optParams
    ) external {
        address token = j.paymentToken;
        escrowed[token] -= j.budget;
        if (x.settlementMode == XDLogic.MODE_DEFERRED) {
            unclaimed[token] += j.budget;
            if (optParams.length > 0) x.disburserDataHash = keccak256(optParams);
            _entitle(j, x, jobId, PLATFORM);
            _entitle(j, x, jobId, EVALUATOR);
            _entitle(j, x, jobId, PROVIDER);
        } else {
            _pay(j, jobId, PLATFORM, x, optParams);
            _pay(j, jobId, EVALUATOR, x, optParams);
            _pay(j, jobId, PROVIDER, x, optParams);
        }
    }

    /// @notice Rejection or expiry of a funded job. IMMEDIATE: refund now. DEFERRED: record the refund right (D-10).
    function settleRefund(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        mapping(address => uint256) storage escrowed,
        mapping(address => uint256) storage unclaimed,
        uint256 jobId
    ) external {
        address token = j.paymentToken;
        escrowed[token] -= j.budget;
        if (x.settlementMode == XDLogic.MODE_DEFERRED) {
            unclaimed[token] += j.budget;
            _entitle(j, x, jobId, CLIENT_REFUND);
        } else {
            _pay(j, jobId, CLIENT_REFUND, x, "");
        }
    }

    /// @dev DS2: a zero share creates no right.
    function _entitle(ERC8183Virtual.Job storage j, XDLogic.XTerms storage x, uint256 jobId, uint8 kind) private {
        (address recipient, uint256 amount) = _share(j, x, kind);
        if (amount == 0) return;
        x.payoutBits |= ENTITLED << (2 * kind);
        emit PayoutEntitled(jobId, kind, recipient, j.paymentToken, amount);
    }

    // ──────────────────── Claims ────────────────────

    /// @notice DS5-DS7, DS10-DS15, DS21. Anyone may call; pays the fixed recipient only; NONE or CLAIMED returns 0.
    ///  A failed transfer or callback reverts the whole claim, so the right stays ENTITLED. Calls no job hook.
    function claim(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        mapping(address => uint256) storage unclaimed,
        uint256 jobId,
        uint8 kind,
        bytes calldata disburserData
    ) external returns (uint256 amount) {
        if (statusOf(x, kind) != ENTITLED) return 0;
        if (kind == PROVIDER) {
            bytes32 fixedHash = x.disburserDataHash;
            if (fixedHash == bytes32(0) ? disburserData.length != 0 : keccak256(disburserData) != fixedHash) {
                revert DisburserDataMismatch();
            }
        }
        address recipient;
        (recipient, amount) = _share(j, x, kind);
        // effects before interactions
        x.payoutBits = (x.payoutBits & ~(uint8(3) << (2 * kind))) | (CLAIMED << (2 * kind));
        unclaimed[j.paymentToken] -= amount;
        _pay(j, jobId, kind, x, disburserData);
        emit PayoutClaimed(jobId, kind, recipient, j.paymentToken, amount, msg.sender);
    }

    /// @dev One share to its fixed recipient, with the base-contracts event for that share (D-13). For the provider
    ///  share, a recipient that advertises IDisburser gets `onDisbursement` with the `complete` selector (DS10), in
    ///  the same transaction, not wrapped in try/catch (DS15).
    function _pay(ERC8183Virtual.Job storage j, uint256 jobId, uint8 kind, XDLogic.XTerms storage x, bytes memory data)
        private
    {
        (address recipient, uint256 amount) = _share(j, x, kind);
        if (amount == 0) return;
        address token = j.paymentToken;
        IERC20(token).safeTransfer(recipient, amount);
        if (kind == PROVIDER) {
            emit ERC8183Virtual.PaymentReleased(jobId, recipient, amount);
            if (
                recipient.code.length > 0
                    && ERC165Checker.supportsInterface(recipient, type(IDisburser).interfaceId)
            ) {
                bytes4 selector = ERC8183Virtual.complete.selector;
                IDisburser(recipient).onDisbursement(jobId, selector, token, amount, data);
                emit ERC8183Virtual.Disbursed(jobId, recipient, selector, amount);
            }
        } else if (kind == EVALUATOR) {
            emit ERC8183Virtual.EvaluatorFeePaid(jobId, recipient, amount);
        } else if (kind == PLATFORM) {
            emit ERC8183Virtual.PlatformFeePaid(jobId, recipient, amount);
        } else {
            emit ERC8183Virtual.Refunded(jobId, recipient, amount);
        }
    }
}
