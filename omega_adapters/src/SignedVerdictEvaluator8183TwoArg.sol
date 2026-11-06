// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAgenticCommerce} from "./OmegaEvaluator8183.sol";
import {SignedVerdictEvaluator8183} from "./SignedVerdictEvaluator8183.sol";

/// @notice The two-argument escrow form some ERC-8183 deployments use: complete(uint256,bytes32), reject(uint256,bytes32).
interface IERC8183TwoArgEscrow {
    function complete(uint256 jobId, bytes32 reason) external;
    function reject(uint256 jobId, bytes32 reason) external;
}

/// @title SignedVerdictEvaluator8183TwoArg — the same signed-verdict evaluator for two-argument escrows.
/// @notice Identical acceptance rules (V1-V15); only the escrow call differs. The escrow's own evaluator and status
///  checks decide, and their revert propagates (V15). The EIP-712 domain name stays "SignedVerdictEvaluator8183":
///  the domain binds chain and contract address, so a verdict for one deployment never verifies on another.
contract SignedVerdictEvaluator8183TwoArg is SignedVerdictEvaluator8183 {
    constructor(address escrow_, address admin_) SignedVerdictEvaluator8183(IAgenticCommerce(escrow_), admin_) {}

    function _settle(uint256 jobId, bytes32 digest, bool complete_) internal override {
        if (complete_) IERC8183TwoArgEscrow(_escrowAddress()).complete(jobId, digest);
        else IERC8183TwoArgEscrow(_escrowAddress()).reject(jobId, digest);
    }
}
