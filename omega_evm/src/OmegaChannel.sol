// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "./OmegaSettlement.sol";

/// @title Minimal unidirectional (star) payment channel: one payer -> one payee, ERC-20, L1 trust.
/// @notice Research artifact for E-S1a (cost measurement). The payer signs cumulative EIP-712 vouchers off chain;
///  the payee closes once with the highest voucher; after expiry the payer can reclaim the deposit. Not audited.
contract OmegaChannel {
    struct Channel {
        address payer;
        address payee;
        uint64 expiry;
        uint128 deposit;
    }

    bytes32 public constant VOUCHER_TYPEHASH = keccak256("Voucher(bytes32 channelId,uint256 cumulative)");
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    IERC20 public immutable token;
    mapping(bytes32 => Channel) public channels;

    error Exists();
    error NoChannel();
    error NotPayee();
    error NotPayer();
    error BadSignature();
    error OverDeposit();
    error NotExpired();
    error TokenTransferFailed();

    event Opened(bytes32 indexed id, address indexed payer, address indexed payee, uint256 deposit, uint64 expiry);
    event Closed(bytes32 indexed id, uint256 paid, uint256 refunded);

    constructor(IERC20 token_) {
        token = token_;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("OmegaChannel"), keccak256("1"), block.chainid, address(this)));
    }

    function open(bytes32 id, address payee, uint128 deposit, uint64 expiry) external {
        if (channels[id].payer != address(0)) revert Exists();
        channels[id] = Channel(msg.sender, payee, expiry, deposit);
        if (!token.transferFrom(msg.sender, address(this), deposit)) revert TokenTransferFailed();
        emit Opened(id, msg.sender, payee, deposit, expiry);
    }

    function voucherDigest(bytes32 id, uint256 cumulative) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, keccak256(abi.encode(VOUCHER_TYPEHASH, id, cumulative))));
    }

    /// @notice Payee settles once with the payer's highest cumulative voucher; the rest returns to the payer.
    function close(bytes32 id, uint256 cumulative, uint8 v, bytes32 r, bytes32 s) external {
        Channel memory c = channels[id];
        if (c.payer == address(0)) revert NoChannel();
        if (msg.sender != c.payee) revert NotPayee();
        if (cumulative > c.deposit) revert OverDeposit();
        if (uint256(s) > HALF_N || ecrecover(voucherDigest(id, cumulative), v, r, s) != c.payer) revert BadSignature();
        delete channels[id];
        if (!token.transfer(c.payee, cumulative)) revert TokenTransferFailed();
        if (c.deposit > cumulative && !token.transfer(c.payer, c.deposit - cumulative)) revert TokenTransferFailed();
        emit Closed(id, cumulative, c.deposit - cumulative);
    }

    function refund(bytes32 id) external {
        Channel memory c = channels[id];
        if (c.payer == address(0)) revert NoChannel();
        if (msg.sender != c.payer) revert NotPayer();
        if (block.timestamp < c.expiry) revert NotExpired();
        delete channels[id];
        if (!token.transfer(c.payer, c.deposit)) revert TokenTransferFailed();
        emit Closed(id, 0, c.deposit);
    }
}
