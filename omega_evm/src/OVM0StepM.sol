// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IOVM0Referee} from "./IOVM0Referee.sol";

/// @title One-step referee for OVM-0 with a constant-size state commitment.
/// @notice Same semantics as OVM0Step (and vm.transition), but the state is 9 static words: the stack is committed as
///  a hash chain h_k = keccak(h_{k-1} || word(v_k)) (empty = 0) with its length, memory as the root of a fixed
///  256-cell keccak Merkle tree of word(value) leaves (unset = 0, which vm.step reads as 0 too). A step's witness
///  carries only the stack elements the instruction touches (top first) plus the chain hash below them, and one
///  memory cell with its proof, so calldata no longer grows with the stack or memory size.
///  State encoding (omega_compute/evm_step_m.py): abi.encode(prog, inputs, pc, steps, halted, trap, stackLen,
///  stackHash, memRoot).
contract OVM0StepM is IOVM0Referee {
    uint256 internal constant MOD = 2 ** 64;
    uint256 internal constant MAX_STACK = 256;
    uint256 internal constant MAX_MEM = 256;
    uint256 internal constant MEM_DEPTH = 8;
    uint256 internal constant PUSH = 0; uint256 internal constant POP = 1; uint256 internal constant DUP = 2;
    uint256 internal constant SWAP = 3; uint256 internal constant ADD = 4; uint256 internal constant SUB = 5;
    uint256 internal constant MUL = 6; uint256 internal constant DIV = 7; uint256 internal constant MODOP = 8;
    uint256 internal constant LT = 9; uint256 internal constant EQ = 10; uint256 internal constant JMP = 11;
    uint256 internal constant JZ = 12; uint256 internal constant LOAD = 13; uint256 internal constant MLOAD = 14;
    uint256 internal constant MSTORE = 15; uint256 internal constant HALT = 16;
    uint8 internal constant PC_OUT_OF_RANGE = 1; uint8 internal constant STACK_UNDERFLOW = 2;
    uint8 internal constant DIV_BY_ZERO = 3; uint8 internal constant INPUT_OUT_OF_RANGE = 4;
    uint8 internal constant MEM_OUT_OF_RANGE = 5; uint8 internal constant STACK_OVERFLOW = 6;
    uint8 internal constant STEP_LIMIT = 7;

    struct State {
        bytes32 prog;
        bytes32 inputs;
        uint64 pc;
        uint64 steps;
        bool halted;
        uint8 trap;
        uint64 stackLen;
        bytes32 stackHash;
        bytes32 memRoot;
    }

    struct Aux {
        bytes32 progRoot;
        uint256 progLen;
        uint256 op;
        uint256 imm;
        bytes32[] insProof;
        bytes32 inRoot;
        uint256 inLen;
        uint256 inVal;
        bytes32[] inProof;
        uint64[] top; // the touched stack elements, top first
        bytes32 rest; // chain hash of the stack below them
        uint256 memVal;
        bytes32[] memProof;
    }

    error BadProgramCommitment();
    error BadInputsCommitment();
    error BadInstructionProof();
    error BadInputProof();
    error BadStackWitness();
    error BadMemoryProof();

    function initialHash(bytes32 prog, bytes32 inputs) external pure returns (bytes32) {
        bytes32 empty; // root of the all-zero memory tree
        for (uint256 i; i < MEM_DEPTH; ++i) empty = keccak256(abi.encodePacked(empty, empty));
        return keccak256(abi.encode(State(prog, inputs, 0, 0, false, 0, 0, bytes32(0), empty)));
    }

    /// @dev outWitness = abi.encode(uint64 top, bytes32 chainBelowTop), empty for an empty stack
    function finalInfo(bytes calldata finalEnc, bytes calldata outWitness)
        external pure returns (bool halted, bytes32 prog, bytes32 inputs, uint64 output, uint8 trap)
    {
        State memory f = abi.decode(finalEnc, (State));
        if (f.stackLen == 0) {
            if (outWitness.length != 0) revert BadStackWitness();
        } else {
            if (outWitness.length != 64) revert BadStackWitness();
            (uint64 top, bytes32 below) = abi.decode(outWitness, (uint64, bytes32));
            if (keccak256(abi.encodePacked(below, uint256(top))) != f.stackHash) revert BadStackWitness();
            output = top;
        }
        return (f.halted, f.prog, f.inputs, output, f.trap);
    }

    /// @return pre keccak of the supplied pre-state, post keccak of its unique successor
    function stepHash(bytes calldata preEnc, bytes calldata auxEnc, uint256 maxSteps)
        external pure returns (bytes32 pre, bytes32 post)
    {
        State memory s = abi.decode(preEnc, (State));
        Aux memory a = abi.decode(auxEnc, (Aux));
        pre = keccak256(preEnc);
        if (s.halted) revert NoSuccessor();
        if (keccak256(abi.encode(a.progRoot, a.progLen)) != s.prog) revert BadProgramCommitment();
        if (keccak256(abi.encode(a.inRoot, a.inLen)) != s.inputs) revert BadInputsCommitment();
        if (s.steps >= maxSteps) {
            (s.halted, s.trap) = (true, STEP_LIMIT);
        } else {
            s.steps += 1;
            if (s.pc >= a.progLen) {
                _trap(s, PC_OUT_OF_RANGE);
            } else {
                bytes32 leaf = keccak256(abi.encode(uint256(s.pc), a.op, a.imm));
                if (!_verify(leaf, s.pc, a.insProof, a.progRoot)) revert BadInstructionProof();
                _exec(s, a);
            }
        }
        post = keccak256(abi.encode(s));
    }

    /// @dev stack elements an instruction reads (and so pops), or type(uint256).max when the stack is too short
    function _need(uint256 op, uint256 imm, uint256 n) internal pure returns (uint256 k) {
        if (op == POP || op == JZ || op == MLOAD) k = 1;
        else if (op == DUP) k = imm + 1;
        else if (op == SWAP) k = imm < 1 ? type(uint256).max : imm + 1;
        else if ((op >= ADD && op <= EQ) || op == MSTORE) k = 2;
        if (k > n) k = type(uint256).max;
    }

    function _exec(State memory s, Aux memory a) internal pure {
        uint256 op = a.op;
        if (op == HALT) {
            s.halted = true;
            return;
        }
        uint256 k = _need(op, a.imm, s.stackLen);
        if (k == type(uint256).max) return _trap(s, STACK_UNDERFLOW);
        uint64[] memory w = _open(s, a, k); // bottom -> top
        uint64[] memory out;
        uint64 nxt = s.pc + 1;
        if (op == PUSH) {
            out = _one(uint64(a.imm));
        } else if (op == POP) {
            out = new uint64[](0);
        } else if (op == DUP) {
            // the stack is unchanged below the copy, so the new chain is one link on top of the old one
            (a.rest, k) = (s.stackHash, 0);
            out = _one(w[0]);
        } else if (op == SWAP) {
            (w[0], w[k - 1]) = (w[k - 1], w[0]);
            out = w;
        } else if (op >= ADD && op <= EQ) {
            (uint256 x, uint256 b) = (w[0], w[1]);
            if ((op == DIV || op == MODOP) && b == 0) return _close(s, a, new uint64[](0), k, DIV_BY_ZERO);
            uint256 r;
            if (op == ADD) r = (x + b) % MOD;
            else if (op == SUB) r = (x + MOD - b) % MOD;
            else if (op == MUL) r = (x * b) % MOD;
            else if (op == DIV) r = x / b;
            else if (op == MODOP) r = x % b;
            else if (op == LT) r = x < b ? 1 : 0;
            else r = x == b ? 1 : 0;
            out = _one(uint64(r));
        } else if (op == JMP) {
            out = new uint64[](0);
            nxt = uint64(a.imm);
        } else if (op == JZ) {
            out = new uint64[](0);
            if (w[0] == 0) nxt = uint64(a.imm);
        } else if (op == LOAD) {
            if (a.imm >= a.inLen) return _trap(s, INPUT_OUT_OF_RANGE);
            if (!_verify(keccak256(abi.encode(a.imm, a.inVal)), a.imm, a.inProof, a.inRoot)) revert BadInputProof();
            out = _one(uint64(a.inVal));
        } else if (op == MLOAD) {
            uint64 addr = w[0];
            if (addr < MAX_MEM && !_memOk(a, addr, s.memRoot)) revert BadMemoryProof();
            out = _one(addr < MAX_MEM ? uint64(a.memVal) : 0);
        } else if (op == MSTORE) {
            (uint64 val, uint64 addr) = (w[0], w[1]);
            if (addr >= MAX_MEM) return _close(s, a, new uint64[](0), k, MEM_OUT_OF_RANGE); // popped first, as vm
            if (!_memOk(a, addr, s.memRoot)) revert BadMemoryProof();
            s.memRoot = _root(bytes32(uint256(val)), addr, a.memProof);
            out = new uint64[](0);
        }
        _close(s, a, out, k, 0);
        if (s.trap == 0) s.pc = nxt;
    }

    /// @dev verify a.top against the committed stack and return the touched elements bottom -> top
    function _open(State memory s, Aux memory a, uint256 k) internal pure returns (uint64[] memory w) {
        if (a.top.length != k) revert BadStackWitness();
        w = new uint64[](k);
        bytes32 h = a.rest;
        for (uint256 j; j < k; ++j) {
            w[j] = a.top[k - 1 - j];
            h = keccak256(abi.encodePacked(h, uint256(w[j])));
        }
        if (h != s.stackHash) revert BadStackWitness();
    }

    /// @dev replace the k touched elements by `out`; trap with `code` (or STACK_OVERFLOW if it grew past the limit)
    function _close(State memory s, Aux memory a, uint64[] memory out, uint256 k, uint8 code) internal pure {
        bytes32 h = a.rest;
        for (uint256 j; j < out.length; ++j) h = keccak256(abi.encodePacked(h, uint256(out[j])));
        s.stackHash = h;
        s.stackLen = uint64(s.stackLen - k + out.length);
        if (code != 0) _trap(s, code);
        else if (s.stackLen > MAX_STACK) _trap(s, STACK_OVERFLOW);
    }

    /// @dev memory leaves are raw words, so a proof must be exactly MEM_DEPTH long (a shorter one would let an inner
    ///  node pose as a leaf value)
    function _memOk(Aux memory a, uint256 addr, bytes32 root) internal pure returns (bool) {
        return a.memProof.length == MEM_DEPTH && _verify(bytes32(a.memVal), addr, a.memProof, root);
    }

    function _one(uint64 v) internal pure returns (uint64[] memory o) {
        o = new uint64[](1);
        o[0] = v;
    }

    function _trap(State memory s, uint8 code) internal pure {
        (s.halted, s.trap) = (true, code);
    }

    function _root(bytes32 leaf, uint256 index, bytes32[] memory proof) internal pure returns (bytes32 h) {
        h = leaf;
        for (uint256 i; i < proof.length; ++i) {
            h = (index >> i) & 1 == 0 ? keccak256(abi.encodePacked(h, proof[i])) : keccak256(abi.encodePacked(proof[i], h));
        }
    }

    function _verify(bytes32 leaf, uint256 index, bytes32[] memory proof, bytes32 root) internal pure returns (bool) {
        return _root(leaf, index, proof) == root && index >> proof.length == 0;
    }
}
