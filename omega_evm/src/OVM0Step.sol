// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IOVM0Referee} from "./IOVM0Referee.sol";

/// @title On-chain one-step referee for OVM-0 (omega_compute/vm.py), EVM encoding.
/// @notice Recomputes exactly one transition from a full pre-state plus Merkle proofs of the executed instruction
///  and (for LOAD) the input word, and returns keccak of the post-state. A dispute contract compares it with the
///  executor's committed hash at the bisection point. Semantics mirror vm.transition() line for line, including
///  partial pops before DIV_BY_ZERO / MEM_OUT_OF_RANGE traps and the step limit not consuming a step.
///  State encoding (omega_compute/evm_step.py): abi.encode(State) = offset word + (prog, inputs, pc, steps, halted,
///  trap, stack, memAddr, memVal); memAddr sorted ascending
///  with prog = keccak(abi.encode(programRoot, programLen)), inputs = keccak(abi.encode(inputsRoot, inputsLen)).
contract OVM0Step is IOVM0Referee {
    uint256 internal constant MOD = 2 ** 64;
    uint256 internal constant MAX_STACK = 256;
    uint256 internal constant MAX_MEM = 256;
    // opcodes in vm.OPS order
    uint256 internal constant PUSH = 0; uint256 internal constant POP = 1; uint256 internal constant DUP = 2;
    uint256 internal constant SWAP = 3; uint256 internal constant ADD = 4; uint256 internal constant SUB = 5;
    uint256 internal constant MUL = 6; uint256 internal constant DIV = 7; uint256 internal constant MODOP = 8;
    uint256 internal constant LT = 9; uint256 internal constant EQ = 10; uint256 internal constant JMP = 11;
    uint256 internal constant JZ = 12; uint256 internal constant LOAD = 13; uint256 internal constant MLOAD = 14;
    uint256 internal constant MSTORE = 15; uint256 internal constant HALT = 16;
    // trap codes
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
        uint64[] stack;
        uint64[] memAddr;
        uint64[] memVal;
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
    }

    error BadProgramCommitment();
    error BadInputsCommitment();
    error BadInstructionProof();
    error BadInputProof();

    function initialHash(bytes32 prog, bytes32 inputs) external pure returns (bytes32) {
        uint64[] memory e = new uint64[](0);
        return keccak256(abi.encode(State(prog, inputs, 0, 0, false, 0, e, e, e)));
    }

    function finalInfo(bytes calldata finalEnc, bytes calldata)
        external pure returns (bool halted, bytes32 prog, bytes32 inputs, uint64 output, uint8 trap)
    {
        State memory f = _decode(finalEnc);
        uint256 n = f.stack.length;
        return (f.halted, f.prog, f.inputs, n == 0 ? 0 : f.stack[n - 1], f.trap);
    }

    /// @return pre keccak of the supplied pre-state, post keccak of its unique successor
    function stepHash(bytes calldata preEnc, bytes calldata auxEnc, uint256 maxSteps)
        external pure returns (bytes32 pre, bytes32 post)
    {
        State memory s = _decode(preEnc);
        Aux memory a = abi.decode(auxEnc, (Aux));
        pre = keccak256(preEnc);
        if (s.halted) revert NoSuccessor();
        if (keccak256(abi.encode(a.progRoot, a.progLen)) != s.prog) revert BadProgramCommitment();
        if (keccak256(abi.encode(a.inRoot, a.inLen)) != s.inputs) revert BadInputsCommitment();
        if (s.steps >= maxSteps) {
            s.halted = true;
            s.trap = STEP_LIMIT;
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
        post = keccak256(_encode(s));
    }

    function _exec(State memory s, Aux memory a) internal pure {
        uint256 op = a.op;
        uint256 n = s.stack.length;
        uint64 nxt = s.pc + 1;
        if (op == PUSH) {
            s.stack = _push(s.stack, uint64(a.imm));
        } else if (op == POP) {
            if (n < 1) return _trap(s, STACK_UNDERFLOW);
            s.stack = _pop(s.stack, 1);
        } else if (op == DUP) {
            if (n < a.imm + 1) return _trap(s, STACK_UNDERFLOW);
            s.stack = _push(s.stack, s.stack[n - 1 - a.imm]);
        } else if (op == SWAP) {
            if (a.imm < 1 || n < a.imm + 1) return _trap(s, STACK_UNDERFLOW);
            (s.stack[n - 1], s.stack[n - 1 - a.imm]) = (s.stack[n - 1 - a.imm], s.stack[n - 1]);
        } else if (op >= ADD && op <= EQ) {
            if (n < 2) return _trap(s, STACK_UNDERFLOW);
            uint256 b = s.stack[n - 1];
            uint256 x = s.stack[n - 2];
            s.stack = _pop(s.stack, 2); // popped before the DIV_BY_ZERO trap, as in vm.step
            if ((op == DIV || op == MODOP) && b == 0) return _trap(s, DIV_BY_ZERO);
            uint256 r;
            if (op == ADD) r = (x + b) % MOD;
            else if (op == SUB) r = (x + MOD - b) % MOD;
            else if (op == MUL) r = (x * b) % MOD;
            else if (op == DIV) r = x / b;
            else if (op == MODOP) r = x % b;
            else if (op == LT) r = x < b ? 1 : 0;
            else r = x == b ? 1 : 0;
            s.stack = _push(s.stack, uint64(r));
        } else if (op == JMP) {
            nxt = uint64(a.imm);
        } else if (op == JZ) {
            if (n < 1) return _trap(s, STACK_UNDERFLOW);
            uint64 top = s.stack[n - 1];
            s.stack = _pop(s.stack, 1);
            if (top == 0) nxt = uint64(a.imm);
        } else if (op == LOAD) {
            if (a.imm >= a.inLen) return _trap(s, INPUT_OUT_OF_RANGE);
            if (!_verify(keccak256(abi.encode(a.imm, a.inVal)), a.imm, a.inProof, a.inRoot)) revert BadInputProof();
            s.stack = _push(s.stack, uint64(a.inVal));
        } else if (op == MLOAD) {
            if (n < 1) return _trap(s, STACK_UNDERFLOW);
            uint64 addr = s.stack[n - 1];
            s.stack[n - 1] = _memGet(s, addr); // pop + push in place
        } else if (op == MSTORE) {
            if (n < 2) return _trap(s, STACK_UNDERFLOW);
            uint64 addr = s.stack[n - 1];
            uint64 val = s.stack[n - 2];
            s.stack = _pop(s.stack, 2);
            if (addr >= MAX_MEM) return _trap(s, MEM_OUT_OF_RANGE);
            _memSet(s, addr, val);
        } else if (op == HALT) {
            s.halted = true;
            return;
        }
        if (s.stack.length > MAX_STACK) return _trap(s, STACK_OVERFLOW);
        s.pc = nxt;
    }

    function _trap(State memory s, uint8 code) internal pure {
        s.halted = true;
        s.trap = code;
    }

    function _push(uint64[] memory st, uint64 v) internal pure returns (uint64[] memory out) {
        out = new uint64[](st.length + 1);
        for (uint256 i; i < st.length; ++i) out[i] = st[i];
        out[st.length] = v;
    }

    function _pop(uint64[] memory st, uint256 k) internal pure returns (uint64[] memory st2) {
        st2 = st;
        assembly { mstore(st2, sub(mload(st2), k)) } // shrink length in place
    }

    function _memGet(State memory s, uint64 addr) internal pure returns (uint64) {
        for (uint256 i; i < s.memAddr.length; ++i) if (s.memAddr[i] == addr) return s.memVal[i];
        return 0;
    }

    /// @dev keeps memAddr sorted ascending (canonical encoding)
    function _memSet(State memory s, uint64 addr, uint64 val) internal pure {
        uint256 n = s.memAddr.length;
        uint256 i;
        while (i < n && s.memAddr[i] < addr) ++i;
        if (i < n && s.memAddr[i] == addr) {
            s.memVal[i] = val;
            return;
        }
        uint64[] memory ka = new uint64[](n + 1);
        uint64[] memory va = new uint64[](n + 1);
        for (uint256 j; j < n + 1; ++j) {
            (ka[j], va[j]) = j < i ? (s.memAddr[j], s.memVal[j]) : j == i ? (addr, val) : (s.memAddr[j - 1], s.memVal[j - 1]);
        }
        (s.memAddr, s.memVal) = (ka, va);
    }

    function _verify(bytes32 leaf, uint256 index, bytes32[] memory proof, bytes32 root) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i; i < proof.length; ++i) {
            h = (index >> i) & 1 == 0 ? keccak256(abi.encodePacked(h, proof[i])) : keccak256(abi.encodePacked(proof[i], h));
        }
        return h == root && index >> proof.length == 0;
    }

    function _decode(bytes calldata enc) internal pure returns (State memory s) {
        s = abi.decode(enc, (State));
    }

    function _encode(State memory s) internal pure returns (bytes memory) {
        return abi.encode(s);
    }
}
