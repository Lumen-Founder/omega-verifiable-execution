// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OVM0Dispute} from "./OVM0Dispute.sol";

/// @dev What this referee reads from Optimism's L1 dispute contracts, checked on Ethereum mainnet state on 2026-10-30
///  (DisputeGameFactory 1.6.1 at 0xe5965Ab5962eDc7477C8520243A95517CD252fA9, respected game type 9 with
///  FaultDisputeGame 0.8.0, AnchorStateRegistry 3.9.0). Optimism's value types are plain ABI types here (Timestamp
///  uint64, GameType uint32, Claim bytes32, GameStatus uint8), so selectors and encodings are the same.
interface ISuperGame {
    function createdAt() external view returns (uint64);
    function status() external view returns (uint8); // 0 IN_PROGRESS, 1 CHALLENGER_WINS, 2 DEFENDER_WINS
    function gameType() external view returns (uint32);
    function gameCreator() external view returns (address);
    function rootClaim() external view returns (bytes32);
    function extraData() external view returns (bytes memory);
}

interface ISuperGameFactory {
    function games(uint32 gameType, bytes32 rootClaim, bytes calldata extraData)
        external view returns (address proxy, uint64 timestamp);
}

interface ISuperGameRegistry {
    function isGameProper(address game) external view returns (bool);
    function isGameFinalized(address game) external view returns (bool);
    function isGameClaimValid(address game) external view returns (bool);
}

/// @title OMEGA referee backed by Optimism's own fault proof system (ADR-0012 C3, ADR-0013)
/// @notice A job of program PROG asks "what is the output root of L2 chain `l2ChainId` at L2 time t?". Its claim is an
///  Optimism super-root dispute game the executor created with extraData = 0x01 || uint64 t || uint256 l2ChainId ||
///  bytes32 outputRoot (the game itself enforces rootClaim == keccak256(extraData)). The job's inputs are
///  inputsOf(t); its output (what children read) is the first 8 bytes of the output root; rootOf() gives all of it.
///  Who judges: Optimism's FaultDisputeGame (bisection + the on-chain MIPS step) and its honest challengers, which on
///  mainnet attack every false super root; the AnchorStateRegistry's guardian (blacklist, pause, retirement) can
///  hold any result at Claimed, never turn it around. This contract decides nothing and holds no funds.
///  - register() only within `registerGrace` seconds of the game's creation: claims count in creation order, so an
///    executor cannot keep games in reserve and register only the ones nobody challenged (S-1);
///  - adopt(): the factory keeps one game per (type, root, extraData), so anyone can open the executor's game first. The
///    executor then defends that game as its own claim, within the same grace: it answered the question, the game is
///    real and its verdict is the same. Who posted the game's bond does not matter here; the executor's stake does
///    (THREAT_MODEL T29, re-audit 2026-11-03 F3);
///  - Accepted only if the registry says the claim is valid (proper, respected, finalized, defender won); Rejected only
///    if the game is proper and finalized and the challenger won; anything else is still Claimed.
contract OmegaSuperRootReferee {
    bytes32 public constant PROG = keccak256("omega.op-super-root-output.v1");
    uint64 public constant stepCap = 1; // a job of this referee has maxSteps 1: there are no steps to bound
    uint64 public constant clock = 0; // the game's own chess clocks are inside `window`
    uint8 internal constant CHALLENGER_WINS = 1;
    uint256 internal constant EXTRA_LEN = 73; // version, timestamp, one (chain id, output root) pair

    struct Rec {
        address game;
        address defender;
        uint64 createdAt;
        uint64 l2Time;
        bytes32 outputRoot;
    }

    ISuperGameFactory public immutable factory;
    ISuperGameRegistry public immutable registry;
    uint32 public immutable gameType;
    uint256 public immutable l2ChainId;
    uint64 public immutable window; // createdAt + window >= the latest time the game can be finalized
    uint64 public immutable registerGrace;
    uint256 public claims;
    mapping(uint256 => Rec) internal _recs;
    mapping(address => uint256) public idOf; // game -> the claim of its creator
    mapping(address => mapping(address => uint256)) public adoptedId; // game -> defender -> the claim of an adopter

    event Registered(uint256 indexed id, address indexed game, address indexed defender, uint64 l2Time, bytes32 root);

    error AlreadyRegistered();
    error WrongGameType();
    error BadExtraData();
    error WrongChain();
    error UnknownGame();
    error StaleGame();

    constructor(
        ISuperGameFactory factory_,
        ISuperGameRegistry registry_,
        uint32 gameType_,
        uint256 l2ChainId_,
        uint64 window_,
        uint64 registerGrace_
    ) {
        (factory, registry, gameType, l2ChainId) = (factory_, registry_, gameType_, l2ChainId_);
        (window, registerGrace) = (window_, registerGrace_);
    }

    function inputsOf(uint64 l2Time) public view returns (bytes32) {
        return keccak256(abi.encode(l2ChainId, l2Time));
    }

    /// @notice the claim of the game's creator; anyone may send it
    function register(address game) external returns (uint256 id) {
        if (idOf[game] != 0) revert AlreadyRegistered();
        id = _record(game, ISuperGame(game).gameCreator());
        idOf[game] = id;
    }

    /// @notice the sender's claim on a game someone else opened: see the contract's notes
    function adopt(address game) external returns (uint256 id) {
        if (adoptedId[game][msg.sender] != 0) revert AlreadyRegistered();
        id = _record(game, msg.sender);
        adoptedId[game][msg.sender] = id;
    }

    function _record(address game, address defender) internal returns (uint256 id) {
        ISuperGame g = ISuperGame(game);
        if (g.gameType() != gameType) revert WrongGameType();
        bytes memory x = g.extraData();
        if (x.length != EXTRA_LEN || x[0] != 0x01) revert BadExtraData();
        uint64 t;
        uint256 chain;
        bytes32 root;
        assembly {
            t := shr(192, mload(add(x, 33)))
            chain := mload(add(x, 41))
            root := mload(add(x, 73))
        }
        if (chain != l2ChainId) revert WrongChain();
        bytes32 rc = g.rootClaim();
        if (rc != keccak256(x)) revert BadExtraData();
        (address proxy,) = factory.games(gameType, rc, x);
        if (proxy != game) revert UnknownGame();
        uint64 created = g.createdAt();
        if (block.timestamp > uint256(created) + registerGrace) revert StaleGame();
        id = ++claims;
        _recs[id] = Rec(game, defender, created, t, root);
        emit Registered(id, game, defender, t, root);
    }

    function rootOf(uint256 id) external view returns (address game, uint64 l2Time, bytes32 outputRoot) {
        Rec storage r = _recs[id];
        return (r.game, r.l2Time, r.outputRoot);
    }

    function getClaim(uint256 id) external view returns (OVM0Dispute.Claim memory c) {
        Rec storage r = _recs[id];
        if (r.game == address(0)) return c; // None
        c.defender = r.defender;
        (c.prog, c.inputs, c.maxSteps) = (PROG, inputsOf(r.l2Time), 1);
        c.deadline = r.createdAt + window;
        c.output = uint64(bytes8(r.outputRoot));
        c.status = _status(r.game);
    }

    /// @dev the common answers in as few calls as possible: getClaim runs under the escrow's REFEREE_GAS cap
    function _status(address game) internal view returns (OVM0Dispute.ClaimStatus) {
        if (registry.isGameClaimValid(game)) return OVM0Dispute.ClaimStatus.Accepted;
        if (ISuperGame(game).status() == CHALLENGER_WINS && registry.isGameProper(game) && registry.isGameFinalized(game))
        {
            return OVM0Dispute.ClaimStatus.Rejected;
        }
        return OVM0Dispute.ClaimStatus.Claimed;
    }
}
