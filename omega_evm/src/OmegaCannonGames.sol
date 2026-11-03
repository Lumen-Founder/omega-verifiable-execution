// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @dev the part of Optimism's FaultDisputeGame (2.2.0, deployed on Ethereum mainnet) this factory uses
interface ICannonGame {
    function initialize() external payable;
    function status() external view returns (uint8); // 0 IN_PROGRESS, 1 CHALLENGER_WINS, 2 DEFENDER_WINS
    function resolvedAt() external view returns (uint64);
    function createdAt() external view returns (uint64);
    function rootClaim() external view returns (bytes32);
    function absolutePrestate() external view returns (bytes32);
    function gameCreator() external view returns (address);
}

/// @title Games that judge one OVM0 job with Optimism's deployed fault proof contracts
/// @notice Each game is a clone of Optimism's FaultDisputeGame implementation (the same bytecode its
///  permissionless Cannon games run) with immutable arguments set by this contract:
///  - the absolute prestate commits to the OVM0 Cannon guest and one job
///    (tools/world/cannon_guest/ovm0, "oracle" mode);
///  - the VM is Optimism's MIPS64 with its PreimageOracle;
///  - the anchor registry is this contract, whose anchor is the fixed ANCHOR at sequence 0;
///  - the root claim, at sequence 1, is the claimed output commitment
///    sha256("OVM0-OUT-v1 <top> <trap> <steps>").
///  The guest exits valid iff the disputed claim is the true output's commitment, so the game is won
///  by the side that tells the truth about the job, with every step re-executable by MIPS64.
///  This contract has no owner and no admin path: it cannot pause, retire or blacklist a game.
/// @dev The clone layout is Solady's LibClone CWIA proxy as Optimism's DisputeGameFactory makes it
///  (checked byte for byte against a mainnet game in tests/test_omega_cannon_game.py):
///  creator, rootClaim, parent block hash, game type, extraData, then the implementation args
///  (prestate, vm, anchor registry, weth, l2 chain id).
contract OmegaCannonGames {
    bytes32 public constant ANCHOR = sha256("OMEGA-OVM0-ANCHOR-v1");
    uint256 public constant SEQUENCE = 1; // every job game claims the output at sequence 1

    address public immutable impl;
    address public immutable vm;
    address public immutable weth;
    uint32 public immutable gameTypeId;
    uint256 public immutable initBond;
    uint64 public immutable finality; // seconds after resolution before a game counts as finalized

    mapping(address => bool) public isOurs;
    mapping(bytes32 => address) public gameOf; // keyOf(prestate, rootClaim, creator, nonce) -> game
    mapping(address => uint256) public nonces; // games created so far by each creator

    event GameCreated(address indexed game, bytes32 indexed prestate, bytes32 rootClaim, address creator);

    error IncorrectBond();
    error CloneFailed();

    constructor(address impl_, address vm_, address weth_, uint32 gameTypeId_, uint256 initBond_, uint64 finality_) {
        (impl, vm, weth, gameTypeId, initBond, finality) = (impl_, vm_, weth_, gameTypeId_, initBond_, finality_);
    }

    /// @dev the creator and its nonce are part of the key: a third party that opens the same (prestate, claim) first
    ///  gets its own game and cannot take the executor's, and an executor that missed its registration grace can open
    ///  a fresh game (independent review D24: with a key of (prestate, claim) alone a copied true claim blocked the
    ///  executor for good, nearly for free)
    function keyOf(bytes32 prestate, bytes32 rootClaim, address creator, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(prestate, rootClaim, creator, nonce));
    }

    /// @notice open a game claiming that the job behind `prestate` has the output committed by `rootClaim`
    function create(bytes32 prestate, bytes32 rootClaim) external payable returns (address game) {
        if (msg.value != initBond) revert IncorrectBond();
        bytes32 key = keyOf(prestate, rootClaim, msg.sender, nonces[msg.sender]++);
        bytes memory args = abi.encodePacked(
            msg.sender, rootClaim, blockhash(block.number - 1), gameTypeId, abi.encode(SEQUENCE),
            prestate, vm, address(this), weth, uint256(0)
        );
        game = _clone(args, key);
        isOurs[game] = true;
        gameOf[key] = game;
        emit GameCreated(game, prestate, rootClaim, msg.sender);
        ICannonGame(game).initialize{value: msg.value}();
    }

    function _clone(bytes memory args, bytes32 salt) internal returns (address game) {
        uint16 n = uint16(args.length + 2);
        bytes memory runtime = abi.encodePacked(
            hex"36602c57343d527f9e4ac34f21c619cefc926c8bd93b54bf5a39c7ab2127a895af1cc0691d7e3dff593da1005b363d3d373d3d3d3d61",
            n, hex"806062363936013d73", impl, hex"5af43d3d93803e606057fd5bf3", args, n
        );
        bytes memory init = abi.encodePacked(hex"61", uint16(runtime.length), hex"80600a3d393df3", runtime);
        assembly {
            game := create2(0, add(init, 32), mload(init), salt)
        }
        if (game == address(0)) revert CloneFailed();
    }

    // ---- the anchor registry surface that FaultDisputeGame calls ----

    function getAnchorRoot() external pure returns (bytes32, uint256) {
        return (ANCHOR, 0);
    }

    function anchors(uint32) external pure returns (bytes32, uint256) {
        return (ANCHOR, 0);
    }

    function respectedGameType() external view returns (uint32) {
        return gameTypeId;
    }

    function paused() external pure returns (bool) {
        return false;
    }

    function isGameRegistered(address game) public view returns (bool) {
        return isOurs[game];
    }

    function isGameProper(address game) public view returns (bool) {
        return isOurs[game];
    }

    function isGameRespected(address game) external view returns (bool) {
        return isOurs[game];
    }

    function isGameBlacklisted(address) external pure returns (bool) {
        return false;
    }

    function isGameRetired(address) external pure returns (bool) {
        return false;
    }

    function isGameResolved(address game) public view returns (bool) {
        return isOurs[game] && ICannonGame(game).resolvedAt() != 0;
    }

    function isGameFinalized(address game) public view returns (bool) {
        return isGameResolved(game) && block.timestamp > uint256(ICannonGame(game).resolvedAt()) + finality;
    }

    function isGameClaimValid(address game) external view returns (bool) {
        return isGameFinalized(game) && ICannonGame(game).status() == 2;
    }

    /// @dev the anchor never moves: each job game starts from ANCHOR, whatever earlier games decided
    function setAnchorState(address) external pure {}
}
