// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OVM0Dispute} from "./OVM0Dispute.sol";
import {ICannonGame} from "./OmegaCannonGames.sol";

interface ICannonGames {
    function isOurs(address game) external view returns (bool);
    function isGameProper(address game) external view returns (bool);
    function isGameFinalized(address game) external view returns (bool);
}

/// @title OVM0 jobs judged by Optimism's fault dispute game over Cannon, as an OmegaGraphEscrow referee
/// @notice A claim is one game of OmegaCannonGames. What the escrow compares:
///  - prog is the game's absolute prestate. It commits to the OVM0 Cannon guest and to the job (program, inputs,
///    step limit). The poster of a job computes it with a reproducible build (tools/world/cannon_check.py) and
///    names it as the job's program, so the escrow binds the node to exactly that computation. The executor
///    rebuilds it from the job before reserving: a prestate that is not this guest with a well-formed job can decide
///    the game regardless of the truth, and no contract can see inside a prestate (independent review D25).
///  - inputs and maxSteps are the node's fields. The defender gives the input values and the step limit at
///    registration; the contract recomputes the escrow's inputs commitment from the values, and the root claim
///    (outputCommit, v2) commits to the values and the limit as the guest read them from its embedded job. So a
///    registration whose fields differ from the job the prestate runs claims something false and loses the game.
///  - output and trap are revealed at registration and checked against the root claim, so children can read the
///    output.
///  Accepted = the game is finalized and the defender won; Rejected = finalized and the challenger won. Only the
///  game's creator (the defender) registers its game: nobody else can bind someone's game to wrong fields first.
contract OmegaCannonReferee {
    uint64 public constant clock = 0; // the game's chess clocks are inside `window`
    uint8 internal constant CHALLENGER_WINS = 1;
    uint8 internal constant DEFENDER_WINS = 2;
    uint8 internal constant MAX_TRAP = 7; // omega_compute.evm_step.TRAPS

    struct Rec {
        address game;
        address defender;
        uint64 createdAt;
        uint64 maxSteps;
        uint64 output;
        uint8 trap;
        bytes32 inputs;
    }

    ICannonGames public immutable games;
    uint64 public immutable stepCap;
    uint64 public immutable window; // createdAt + window >= the latest time the game can be finalized
    uint64 public immutable registerGrace;
    uint256 public claims;
    mapping(uint256 => Rec) internal _recs;
    mapping(address => uint256) public idOf;

    event Registered(uint256 indexed id, address indexed game, address indexed defender, bytes32 prestate);

    error AlreadyRegistered();
    error UnknownGame();
    error NotCreator();
    error StaleGame();
    error WrongOutput();
    error TooManySteps();

    constructor(ICannonGames games_, uint64 stepCap_, uint64 window_, uint64 registerGrace_) {
        (games, stepCap, window, registerGrace) = (games_, stepCap_, window_, registerGrace_);
    }

    /// @notice the root claim of a game that claims this output of the job with these input values and step limit
    ///  (the guest's commitment): sha256("OVM0-OUT-v2" || sha256(values as 32-byte words) || maxSteps u64 ||
    ///  hasTop u8 || top u64 || trap u8 || steps u64)
    function outputCommit(uint256[] calldata vals, uint64 maxSteps, bool hasTop, uint64 top, uint8 trap, uint64 steps)
        public
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(bytes11("OVM0-OUT-v2"), sha256(abi.encodePacked(vals)), maxSteps,
                                       hasTop ? uint8(1) : uint8(0), top, trap, steps));
    }

    /// @notice OmegaGraphEscrow.inputsCommit (omega_compute.evm_step.inputs_commit): leaves keccak(i, x) padded with
    ///  zero words to a power of two, a keccak Merkle root, then keccak(root, n)
    function inputsCommit(uint256[] calldata vals) public pure returns (bytes32) {
        uint256 n = vals.length;
        uint256 size = 1;
        while (size < n) size <<= 1;
        bytes32[] memory lv = new bytes32[](size);
        for (uint256 i; i < n; ++i) lv[i] = keccak256(abi.encode(i, vals[i]));
        for (uint256 w = size; w > 1; w >>= 1) {
            for (uint256 i; i < w / 2; ++i) lv[i] = keccak256(abi.encodePacked(lv[2 * i], lv[2 * i + 1]));
        }
        return keccak256(abi.encode(lv[0], n));
    }

    function register(address game, uint256[] calldata vals, uint64 maxSteps, bool hasTop, uint64 top, uint8 trap,
                      uint64 steps) external returns (uint256 id)
    {
        if (idOf[game] != 0) revert AlreadyRegistered();
        if (!games.isOurs(game)) revert UnknownGame();
        ICannonGame g = ICannonGame(game);
        if (msg.sender != g.gameCreator()) revert NotCreator();
        if (maxSteps > stepCap) revert TooManySteps();
        if (trap > MAX_TRAP || (!hasTop && top != 0) || g.rootClaim() != outputCommit(vals, maxSteps, hasTop, top, trap, steps)) {
            revert WrongOutput();
        }
        uint64 created = g.createdAt();
        if (block.timestamp > uint256(created) + registerGrace) revert StaleGame();
        id = ++claims;
        idOf[game] = id;
        _recs[id] = Rec(game, msg.sender, created, maxSteps, top, trap, inputsCommit(vals));
        emit Registered(id, game, msg.sender, g.absolutePrestate());
    }

    function gameOf(uint256 id) external view returns (address) {
        return _recs[id].game;
    }

    function getClaim(uint256 id) external view returns (OVM0Dispute.Claim memory c) {
        Rec storage r = _recs[id];
        if (r.game == address(0)) return c; // None
        c.defender = r.defender;
        c.prog = ICannonGame(r.game).absolutePrestate();
        (c.inputs, c.maxSteps) = (r.inputs, r.maxSteps);
        c.deadline = r.createdAt + window;
        (c.output, c.trap) = (r.output, r.trap);
        c.status = _status(r.game);
    }

    function _status(address game) internal view returns (OVM0Dispute.ClaimStatus) {
        if (!games.isGameFinalized(game)) return OVM0Dispute.ClaimStatus.Claimed;
        uint8 s = ICannonGame(game).status();
        if (s == DEFENDER_WINS) return OVM0Dispute.ClaimStatus.Accepted;
        if (s == CHALLENGER_WINS && games.isGameProper(game)) return OVM0Dispute.ClaimStatus.Rejected;
        return OVM0Dispute.ClaimStatus.Claimed;
    }
}
