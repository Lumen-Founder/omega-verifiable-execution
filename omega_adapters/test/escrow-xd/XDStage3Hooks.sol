// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC8183Hook} from "../../src/escrow-xd/IERC8183Hook.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

abstract contract HookBase is IERC8183Hook {
    function supportsInterface(bytes4 id) public view virtual returns (bool) {
        return id == type(IERC8183Hook).interfaceId || id == type(IERC165).interfaceId;
    }
}

/// @notice Counts successful calls; can fail on the before phase, the after phase, or both.
contract PhaseHook is HookBase {
    uint256 public calls;
    bool public failBefore;
    bool public failAfter;

    function set(bool b, bool a) external {
        (failBefore, failAfter) = (b, a);
    }

    function beforeAction(uint256, bytes4, bytes calldata) external {
        require(!failBefore, "before failed");
        calls++;
    }

    function afterAction(uint256, bytes4, bytes calldata) external {
        require(!failAfter, "after failed");
        calls++;
    }
}

/// @notice Burns all gas it is given.
contract GasBurnerHook is HookBase {
    function beforeAction(uint256, bytes4, bytes calldata) external pure {
        while (true) {}
    }

    function afterAction(uint256, bytes4, bytes calldata) external pure {
        while (true) {}
    }
}

/// @notice Reverts with 4,096 bytes of 0xAB.
contract BigRevertHook is HookBase {
    function beforeAction(uint256, bytes4, bytes calldata) external pure {
        assembly {
            for { let i := 0 } lt(i, 4096) { i := add(i, 32) } {
                mstore(i, 0xabababababababababababababababababababababababababababababababab)
            }
            revert(0, 4096)
        }
    }

    function afterAction(uint256, bytes4, bytes calldata) external pure {}
}

interface IXDReenter {
    function claimRefund(uint256 jobId) external;
}

/// @notice Tries to re-enter the escrow from the hook.
contract ReenteringHook is HookBase {
    address public escrow;
    bool public reentered;

    function setEscrow(address e) external {
        escrow = e;
    }

    function beforeAction(uint256 jobId, bytes4, bytes calldata) external {
        IXDReenter(escrow).claimRefund(jobId);
        reentered = true;
    }

    function afterAction(uint256, bytes4, bytes calldata) external {}
}
