// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC8183Virtual} from "./ERC8183Virtual.sol";
import {XDLogic} from "./XDLogic.sol";
import {XDPayout} from "./XDPayout.sol";
import {XDHooks} from "./XDHooks.sol";

/// @title XDFlow — the settling transitions of OmegaEscrowXD: complete, reject, expiry refund (pre-audit)
/// @notice External library, delegatecalled by the escrow. Same checks and order as base-contracts; hook calls go
///  through XDHooks, money through XDPayout. It exists to keep the escrow under the EIP-170 size limit.
///  Linking order has no cycle: XDFlow -> XDHooks -> XDPayout.
library XDFlow {
    function complete(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        mapping(address => uint256) storage escrowed,
        mapping(address => uint256) storage unclaimed,
        uint256 jobId,
        address actor,
        bytes32 reason,
        bytes calldata optParams
    ) external {
        if (j.status != ERC8183Virtual.JobStatus.Submitted) revert ERC8183Virtual.WrongStatus();
        if (actor != j.evaluator) revert ERC8183Virtual.Unauthorized();
        bytes memory data = abi.encode(actor, reason, optParams);
        XDHooks.run(j, x, jobId, ERC8183Virtual.complete.selector, data, 0);
        j.status = ERC8183Virtual.JobStatus.Completed;
        XDPayout.settleComplete(j, x, escrowed, unclaimed, jobId, optParams);
        emit ERC8183Virtual.JobCompleted(jobId, actor, reason);
        XDHooks.run(j, x, jobId, ERC8183Virtual.complete.selector, data, 1);
    }

    function reject(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        mapping(address => uint256) storage escrowed,
        mapping(address => uint256) storage unclaimed,
        uint256 jobId,
        address actor,
        bytes32 reason,
        bytes calldata optParams
    ) external {
        ERC8183Virtual.JobStatus prev = j.status;
        if (prev == ERC8183Virtual.JobStatus.Open) {
            if (actor != j.client && actor != j.provider) revert ERC8183Virtual.Unauthorized();
        } else if (prev == ERC8183Virtual.JobStatus.Funded || prev == ERC8183Virtual.JobStatus.Submitted) {
            if (actor != j.evaluator) revert ERC8183Virtual.Unauthorized();
        } else {
            revert ERC8183Virtual.WrongStatus();
        }
        bytes memory data = abi.encode(actor, reason, optParams);
        XDHooks.run(j, x, jobId, ERC8183Virtual.reject.selector, data, 0);
        j.status = ERC8183Virtual.JobStatus.Rejected;
        if (prev != ERC8183Virtual.JobStatus.Open) XDPayout.settleRefund(j, x, escrowed, unclaimed, jobId);
        emit ERC8183Virtual.JobRejected(jobId, actor, reason);
        XDHooks.run(j, x, jobId, ERC8183Virtual.reject.selector, data, 1);
    }

    /// @notice Upstream expiry refund; calls no hook.
    function expire(
        ERC8183Virtual.Job storage j,
        XDLogic.XTerms storage x,
        mapping(address => uint256) storage escrowed,
        mapping(address => uint256) storage unclaimed,
        uint256 jobId,
        uint256 gracePeriod
    ) external {
        ERC8183Virtual.JobStatus prev = j.status;
        if (prev == ERC8183Virtual.JobStatus.Submitted) {
            if (block.timestamp < j.expiredAt + gracePeriod) revert ERC8183Virtual.GracePeriodActive();
        } else if (prev == ERC8183Virtual.JobStatus.Open || prev == ERC8183Virtual.JobStatus.Funded) {
            if (block.timestamp < j.expiredAt) revert ERC8183Virtual.WrongStatus();
        } else {
            revert ERC8183Virtual.WrongStatus();
        }
        j.status = ERC8183Virtual.JobStatus.Expired;
        if (prev != ERC8183Virtual.JobStatus.Open) XDPayout.settleRefund(j, x, escrowed, unclaimed, jobId);
        emit ERC8183Virtual.JobExpired(jobId);
    }
}
