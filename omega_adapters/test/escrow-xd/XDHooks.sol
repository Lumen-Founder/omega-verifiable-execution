// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC8183Hook} from "../../src/escrow-xd/IERC8183Hook.sol";
import {IERC8183HookConfig} from "../../src/escrow-xd/XDLogic.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice Counts calls; can be switched to revert on every call.
contract CountingHook is IERC8183Hook {
    uint256 public calls;
    bool public broken;

    function setBroken(bool b) external {
        broken = b;
    }

    function supportsInterface(bytes4 id) public view virtual returns (bool) {
        return id == type(IERC8183Hook).interfaceId || id == type(IERC165).interfaceId;
    }

    function beforeAction(uint256, bytes4, bytes calldata) external virtual {
        require(!broken, "hook broken");
        calls++;
    }

    function afterAction(uint256, bytes4, bytes calldata) external virtual {
        require(!broken, "hook broken");
        calls++;
    }
}

/// @notice Same, plus a per-job configuration exposed through IERC8183HookConfig.
contract ConfigHook is CountingHook, IERC8183HookConfig {
    mapping(uint256 => bytes32) public config;

    function setConfig(uint256 jobId, bytes32 h) external {
        config[jobId] = h;
    }

    function hookConfigHash(uint256 jobId) external view returns (bytes32) {
        return config[jobId];
    }

    function supportsInterface(bytes4 id) public view override returns (bool) {
        return id == type(IERC8183HookConfig).interfaceId || super.supportsInterface(id);
    }
}

interface IDetach {
    function batchDetachHook(uint256[] calldata jobIds) external;
}

/// @notice Holds ADMIN_ROLE in the test and detaches itself while the client's fund is running (CB-12).
contract SelfDetachingHook is CountingHook {
    address public escrow;
    bool public armed;

    function arm(address escrow_) external {
        escrow = escrow_;
        armed = true;
    }

    function beforeAction(uint256 jobId, bytes4, bytes calldata) external override {
        calls++;
        if (armed) {
            armed = false;
            uint256[] memory ids = new uint256[](1);
            ids[0] = jobId;
            IDetach(escrow).batchDetachHook(ids);
        }
    }
}
