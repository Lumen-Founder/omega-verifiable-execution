// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TestERC20} from "../integration/TestERC20.sol";
import {IDisburser} from "../../src/escrow-xd/IDisburser.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice Refuses transfers to blocked addresses, like a stablecoin blacklist.
contract BlockingERC20 is TestERC20 {
    mapping(address => bool) public blocked;

    constructor() TestERC20("blocking") {}

    function setBlocked(address a, bool b) external {
        blocked[a] = b;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(!blocked[to], "blocked");
        _move(msg.sender, to, amount);
        return true;
    }
}

/// @notice Returns false from transfer while `failing` is set, without moving anything.
contract FalseERC20 is TestERC20 {
    bool public failing;

    constructor() TestERC20("false") {}

    function setFailing(bool b) external {
        failing = b;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (failing) return false;
        _move(msg.sender, to, amount);
        return true;
    }
}

interface IClaim {
    function claimPayout(uint256 jobId, uint8 kind, bytes calldata disburserData) external returns (uint256);
}

/// @notice On transfer, tries once to claim the same right again from inside the escrow's call (DS-13).
contract ReentrantERC20 is TestERC20 {
    address public escrow;
    uint256 public jobId;
    uint8 public kind;
    bool public armed;
    bool public reentryBlocked;

    constructor() TestERC20("reentrant") {}

    function arm(address escrow_, uint256 jobId_, uint8 kind_) external {
        (escrow, jobId, kind, armed) = (escrow_, jobId_, kind_, true);
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (armed) {
            armed = false;
            try IClaim(escrow).claimPayout(jobId, kind, "") returns (uint256) {}
            catch {
                reentryBlocked = true;
            }
        }
        _move(msg.sender, to, amount);
        return true;
    }
}

/// @notice IDisburser receiver that records each callback. Can be set to revert, or to accept only one selector.
contract RecordingDisburser is IDisburser {
    struct Call {
        uint256 jobId;
        bytes4 selector;
        address token;
        uint256 amount;
        bytes data;
    }

    Call[] public calls;
    bool public broken;
    bytes4 public onlySelector;

    function setBroken(bool b) external {
        broken = b;
    }

    function setOnlySelector(bytes4 s) external {
        onlySelector = s;
    }

    function callCount() external view returns (uint256) {
        return calls.length;
    }

    function lastData() external view returns (bytes memory) {
        return calls[calls.length - 1].data;
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IDisburser).interfaceId || id == type(IERC165).interfaceId;
    }

    function onDisbursement(uint256 jobId, bytes4 selector, address token, uint256 amount, bytes calldata data)
        external
    {
        require(!broken, "disburser broken");
        require(onlySelector == bytes4(0) || selector == onlySelector, "unexpected selector");
        calls.push(Call(jobId, selector, token, amount, data));
    }
}
