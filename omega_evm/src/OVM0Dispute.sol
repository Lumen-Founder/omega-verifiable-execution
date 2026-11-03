// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IOVM0Referee} from "./IOVM0Referee.sol";
import {OVM0Inbox} from "./OVM0Inbox.sol";

/// @title Bonded, multi-challenger bisection game over OVM-0 execution traces, settled by the one-step referee.
/// @notice A defender claims, with a bond, that program P on inputs I halts after exactly n transitions in the state
///  it reveals. Within the window any number of challengers may each open a game by posting the same bond. In a game
///  the two narrow [lo, hi] (h_lo agreed, h_hi disputed) by halving: the defender posts the hash at the midpoint, the
///  challenger says whether it agrees. At hi - lo == 1 anyone submits the full pre-state at lo plus witnesses and
///  the referee (IOVM0Referee) recomputes the one transition. If its post-state hash equals the defender's h_hi the defender wins the
///  game, otherwise (or if the agreed pre-state is already halted, so the claimed successor cannot exist) the
///  challenger wins. Whoever lets its deadline pass loses. Deadlines run on a chess clock: each side has `clock`
///  seconds for all of its moves in a game (the challenger's clock also runs at Prove), so a game lasts at most
///  2 * clock however many rounds it takes, and a claim is final at most window + 2 * clock after it is made.
///  Money: a challenger who loses pays its bond to the defender. The first challenger win rejects the claim; that
///  challenger gets its bond back plus `reward` out of the defender's bond, and the rest of the defender's bond
///  (bond - reward > 0) is burned (kept in this contract for good, counted in `burned`). Games still open on a rejected
///  claim stop and can only be refunded. A claim is accepted only after the window with no open game, which returns the
///  defender's bond. Payouts are credited and pulled with withdraw().
///  Why burn: anyone may challenge, the defender included, so the defender of a false claim can win the race to defeat
///  it with a key of its own (stalling the honest games, front-running a timeout). Paying the whole bond to the first
///  winner would then hand the bond back to the liar; with the burn a defeated false claim costs at least bond - reward
///  whoever wins (the same reason TrueBit sends at most half a caught Solver's deposit to Verifiers, TrueBit 4.6, 5.1).
///  `reward` is meant to repay an honest challenger's worst-case gas (omega_compute/dispute_econ.py); it is not a
///  guarantee: a challenger that loses the race only gets its bond back.
///  h_0 is computed on chain from the commitments, so no game starts from a state the defender chose.
///  A run takes at most maxSteps + 1 transitions (the last one is the STEP_LIMIT halt), and maxSteps <= stepCap, so
///  no claim can stretch a game past ceil(log2(stepCap + 1)) rounds; the bond is sized against that bound
///  (omega_compute/dispute_econ.py). Only computations published in the inbox can be claimed, so every watcher can
///  re-execute what it is asked to accept, and only within daMaxAge of the last publication, so the data a watcher
///  needs is never older than daMaxAge + window + 2 * clock (keep that inside the chain's history retention).
contract OVM0Dispute {
    enum ClaimStatus { None, Claimed, Accepted, Rejected }
    enum GameStatus { None, Active, DefenderWon, ChallengerWon, Refunded }
    enum Turn { Defender, Challenger, Prove }

    struct Claim {
        address defender;
        bytes32 prog;
        bytes32 inputs;
        uint64 maxSteps;
        uint64 n;
        uint64 deadline; // end of the challenge window
        uint32 open; // games not yet decided
        ClaimStatus status;
        bytes32 hN;
        uint64 output; // stack top of the revealed final state (0 if empty)
        uint8 trap;
    }

    struct Game {
        uint256 claimId;
        address challenger;
        uint64 lo;
        uint64 hi;
        uint64 deadline;
        GameStatus status;
        Turn turn;
        bytes32 hLo;
        bytes32 hHi;
        bytes32 hMid;
        uint64 clockD; // defender's remaining time in this game
        uint64 clockC; // challenger's remaining time (also used at Prove)
        uint64 since; // when the current turn started
    }

    IOVM0Referee public immutable referee;
    OVM0Inbox public immutable inbox;
    uint64 public immutable window;
    uint256 public immutable bond;
    uint256 public immutable reward; // what the first winning challenger gets on top of its own bond; < bond
    uint64 public immutable stepCap;
    uint64 public immutable clock;
    uint64 public immutable daMaxAge;
    uint256 public claims;
    uint256 public games;
    uint256 public burned; // defenders' bonds of rejected claims beyond the reward; never paid out
    mapping(uint256 => Claim) internal _c;
    mapping(uint256 => Game) internal _g;
    mapping(address => uint256) public credit;

    event Claimed(uint256 indexed id, address indexed defender, uint64 n, bytes32 finalHash);
    event Challenged(uint256 indexed claimId, uint256 indexed gameId, address indexed challenger);
    event Bisected(uint256 indexed gameId, uint64 mid, bytes32 hMid);
    event Responded(uint256 indexed gameId, bool agree, uint64 lo, uint64 hi);
    event GameResolved(uint256 indexed gameId, GameStatus status);
    event ClaimResolved(uint256 indexed id, ClaimStatus status);

    error BadFinalState();
    error ZeroSteps();
    error TooManySteps();
    error NotPublished();
    error StalePublication();
    error WrongBond();
    error WrongStatus();
    error WrongTurn();
    error NotParty();
    error TooLate();
    error TooEarly();
    error NotSingleStep();
    error BadPreState();
    error StillOpen();
    error NothingToWithdraw();
    error PayoutFailed();
    error BadReward();

    constructor(IOVM0Referee referee_, OVM0Inbox inbox_, uint64 window_, uint256 bond_, uint256 reward_, uint64 stepCap_,
                uint64 clock_, uint64 daMaxAge_) {
        if (reward_ >= bond_) revert BadReward(); // something must burn, or a liar's own challenger recovers it all
        (referee, inbox, window, bond, stepCap, clock) = (referee_, inbox_, window_, bond_, stepCap_, clock_);
        (reward, daMaxAge) = (reward_, daMaxAge_);
    }

    function getClaim(uint256 id) external view returns (Claim memory) {
        return _c[id];
    }

    function getGame(uint256 id) external view returns (Game memory) {
        return _g[id];
    }

    /// @notice the referee's hash of vm.initial for these commitments (pc 0, nothing on stack or in memory)
    function initialHash(bytes32 prog, bytes32 inputs) public view returns (bytes32) {
        return referee.initialHash(prog, inputs);
    }

    /// @param outWitness the referee's proof of the final top of stack (see IOVM0Referee.finalInfo)
    function claim(bytes32 prog, bytes32 inputs, uint64 maxSteps, uint64 n, bytes calldata finalEnc,
                   bytes calldata outWitness) external payable returns (uint256 id)
    {
        if (msg.value != bond) revert WrongBond();
        if (n == 0) revert ZeroSteps();
        if (maxSteps > stepCap || n > uint256(maxSteps) + 1) revert TooManySteps();
        (bool halted, bytes32 fp, bytes32 fi, uint64 output, uint8 trap) = referee.finalInfo(finalEnc, outWitness);
        if (!halted || fp != prog || fi != inputs) revert BadFinalState();
        _requireFresh(prog, inputs);
        id = ++claims;
        Claim storage c = _c[id];
        (c.defender, c.prog, c.inputs, c.maxSteps, c.n) = (msg.sender, prog, inputs, maxSteps, n);
        (c.hN, c.output, c.trap) = (keccak256(finalEnc), output, trap);
        (c.status, c.deadline) = (ClaimStatus.Claimed, uint64(block.timestamp) + window);
        emit Claimed(id, msg.sender, n, c.hN);
    }

    function challenge(uint256 claimId) external payable returns (uint256 gid) {
        Claim storage c = _c[claimId];
        if (msg.value != bond) revert WrongBond();
        if (c.status != ClaimStatus.Claimed) revert WrongStatus();
        if (block.timestamp > c.deadline) revert TooLate();
        gid = ++games;
        Game storage g = _g[gid];
        (g.claimId, g.challenger, g.status) = (claimId, msg.sender, GameStatus.Active);
        (g.lo, g.hi, g.hLo, g.hHi) = (0, c.n, initialHash(c.prog, c.inputs), c.hN);
        (g.clockD, g.clockC, g.since) = (clock, clock, uint64(block.timestamp));
        c.open += 1;
        _next(g);
        emit Challenged(claimId, gid, msg.sender);
    }

    function bisect(uint256 gid, bytes32 hMid) external {
        Game storage g = _live(gid, Turn.Defender, _c[_g[gid].claimId].defender);
        g.hMid = hMid;
        _turn(g, Turn.Challenger);
        emit Bisected(gid, _mid(g), hMid);
    }

    function respond(uint256 gid, bool agree) external {
        Game storage g = _live(gid, Turn.Challenger, _g[gid].challenger);
        uint64 m = _mid(g);
        if (agree) (g.lo, g.hLo) = (m, g.hMid);
        else (g.hi, g.hHi) = (m, g.hMid);
        _next(g);
        emit Responded(gid, agree, g.lo, g.hi);
    }

    /// @notice Settle the single disputed step. Either party may call; reverts unless preEnc is the agreed state at lo
    ///  and the witnesses are valid for it (both parties know P and I, so the honest one can always build them).
    function prove(uint256 gid, bytes calldata preEnc, bytes calldata auxEnc) external {
        Game storage g = _active(gid);
        if (g.turn != Turn.Prove) revert NotSingleStep();
        if (block.timestamp > g.deadline) revert TooLate();
        if (keccak256(preEnc) != g.hLo) revert BadPreState();
        bool defenderRight;
        try referee.stepHash(preEnc, auxEnc, _c[g.claimId].maxSteps) returns (bytes32, bytes32 post) {
            defenderRight = post == g.hHi;
        } catch (bytes memory err) {
            if (bytes4(err) != IOVM0Referee.NoSuccessor.selector) _bubble(err);
            defenderRight = false; // a halted agreed state has no successor, so the claimed h_hi cannot be one
        }
        _decide(gid, g, defenderRight);
    }

    /// @notice Close a game whose deadline has passed: the side that had to act loses (at Prove the burden is the
    ///  challenger's, who asserted the fault).
    function timeout(uint256 gid) external {
        Game storage g = _active(gid);
        if (block.timestamp <= g.deadline) revert TooEarly();
        _decide(gid, g, g.turn != Turn.Defender);
    }

    /// @notice A game left open on a claim another challenger has already defeated returns its bond.
    function refund(uint256 gid) external {
        Game storage g = _g[gid];
        if (g.status != GameStatus.Active || _c[g.claimId].status != ClaimStatus.Rejected) revert WrongStatus();
        g.status = GameStatus.Refunded;
        _c[g.claimId].open -= 1;
        credit[g.challenger] += bond;
        emit GameResolved(gid, GameStatus.Refunded);
    }

    /// @notice Accept a claim once the window has passed with every game decided for the defender.
    function finalize(uint256 id) external {
        Claim storage c = _c[id];
        if (c.status != ClaimStatus.Claimed) revert WrongStatus();
        if (block.timestamp <= c.deadline) revert TooEarly();
        if (c.open != 0) revert StillOpen();
        c.status = ClaimStatus.Accepted;
        credit[c.defender] += bond;
        emit ClaimResolved(id, ClaimStatus.Accepted);
    }

    function withdraw() external {
        uint256 amt = credit[msg.sender];
        if (amt == 0) revert NothingToWithdraw();
        credit[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        if (!ok) revert PayoutFailed();
    }

    function _decide(uint256 gid, Game storage g, bool defenderWins) internal {
        Claim storage c = _c[g.claimId];
        c.open -= 1;
        if (defenderWins) {
            g.status = GameStatus.DefenderWon;
            credit[c.defender] += bond; // the challenger's bond
        } else {
            g.status = GameStatus.ChallengerWon;
            c.status = ClaimStatus.Rejected; // games are only decided while the claim stands (_active)
            credit[g.challenger] += bond + reward; // own bond back plus the reward out of the defender's
            burned += bond - reward;
            emit ClaimResolved(g.claimId, ClaimStatus.Rejected);
        }
        emit GameResolved(gid, g.status);
    }

    /// @dev An open game on a rejected claim can only be refunded, so the defender of a false claim never collects.
    function _active(uint256 gid) internal view returns (Game storage g) {
        g = _g[gid];
        if (g.status != GameStatus.Active || _c[g.claimId].status != ClaimStatus.Claimed) revert WrongStatus();
    }

    function _live(uint256 gid, Turn t, address who) internal view returns (Game storage g) {
        g = _active(gid);
        if (g.turn != t) revert WrongTurn();
        if (msg.sender != who) revert NotParty();
        if (block.timestamp > g.deadline) revert TooLate();
    }

    function _mid(Game storage g) internal view returns (uint64) {
        return g.lo + (g.hi - g.lo) / 2;
    }

    function _next(Game storage g) internal {
        _turn(g, g.hi - g.lo == 1 ? Turn.Prove : Turn.Defender);
    }

    /// @dev charge the time since the turn began to the side that just moved, then start `t` on its mover's clock
    ///  (never underflows: a move is only accepted before since + that side's remaining time)
    function _turn(Game storage g, Turn t) internal {
        uint64 now_ = uint64(block.timestamp);
        uint64 used = now_ - g.since;
        if (g.turn == Turn.Defender) g.clockD -= used;
        else g.clockC -= used;
        (g.turn, g.since) = (t, now_);
        g.deadline = now_ + (t == Turn.Defender ? g.clockD : g.clockC);
    }

    /// @dev the computation was published, recently enough that its logs are still in every node's history
    function _requireFresh(bytes32 prog, bytes32 inputs) internal view {
        uint64 at = inbox.lastPublished(prog, inputs);
        if (at == 0) revert NotPublished();
        if (block.timestamp - at > daMaxAge) revert StalePublication();
    }

    function _bubble(bytes memory err) internal pure {
        assembly {
            revert(add(err, 32), mload(err))
        }
    }
}
