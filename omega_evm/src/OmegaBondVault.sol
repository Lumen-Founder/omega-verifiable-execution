// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Bond custody for OmegaCannonGames, with no owner
/// @notice Optimism's FaultDisputeGame keeps its bonds in a DelayedWETH: deposit at each move, then, after
///  resolution, unlock(recipient, amount) and, once `delay` has passed, withdraw(recipient, amount), which returns the
///  ETH to the game to pay the recipient. Optimism's and Base's DelayedWETH have an owner that can take any balance
///  (hold, recover) and a pause. This vault keeps those three calls with the same meaning and nothing else, so
///  nobody but the games themselves can move a bond.
/// @dev Balances are per game (msg.sender); a game can only spend what it deposited.
contract OmegaBondVault {
    struct WithdrawalRequest {
        uint256 amount;
        uint256 timestamp;
    }

    uint256 public immutable delay;
    mapping(address => uint256) public balanceOf; // per game
    mapping(address => mapping(address => WithdrawalRequest)) public withdrawals; // game => recipient => request

    error NotUnlocked();
    error DelayNotMet();
    error Insufficient();
    error TransferFailed();

    constructor(uint256 delay_) {
        delay = delay_;
    }

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function unlock(address guy, uint256 wad) external {
        WithdrawalRequest storage w = withdrawals[msg.sender][guy];
        w.timestamp = block.timestamp;
        w.amount += wad;
    }

    function withdraw(address guy, uint256 wad) external {
        WithdrawalRequest storage w = withdrawals[msg.sender][guy];
        if (w.timestamp == 0) revert NotUnlocked();
        if (w.timestamp + delay > block.timestamp) revert DelayNotMet();
        if (w.amount < wad || balanceOf[msg.sender] < wad) revert Insufficient();
        w.amount -= wad;
        balanceOf[msg.sender] -= wad;
        (bool ok,) = msg.sender.call{value: wad}("");
        if (!ok) revert TransferFailed();
    }
}
