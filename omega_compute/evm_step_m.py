"""Constant-size EVM state commitment for OVM-0 (omega_evm/src/OVM0StepM.sol).

Same states as vm.py, re-encoded so a one-step witness no longer carries the whole stack and memory: the stack is a
keccak hash chain (h_k = keccak(h_{k-1} || word(v_k)), empty = 0) plus its length, memory the root of a fixed
256-cell keccak Merkle tree whose leaves are word(value) (unset = 0, which vm.step also reads as 0). Program and
inputs commitments are those of evm_step. vm.step stays the single source of semantics.
"""
from omega_compute import vm
from omega_compute import evm_step as E
from omega_kernel.settlement.evm_crypto import keccak, word

MEM_CELLS = 256
_ZERO_LEAVES = [bytes(32)] * MEM_CELLS


def stack_chain(values, base=bytes(32)):
    h = base
    for v in values:
        h = keccak(h + word(v))
    return h


def mem_levels(mem):
    leaves = list(_ZERO_LEAVES)
    for k, v in mem.items():
        leaves[int(k)] = word(v)
    return E._tree(leaves)


def encode_state(s, pc_, ic_):
    return b''.join([pc_.commitment, ic_.commitment, word(s['pc']), word(s['steps']), word(int(s['halted'])),
                     word(E.TRAPS[s['trap']]), word(len(s['stack'])), stack_chain(s['stack']), mem_levels(s['mem'])[-1][0]])


def evm_state_hash(s, pc_, ic_):
    return keccak(encode_state(s, pc_, ic_))


def out_witness(s):
    """Top-of-stack witness for OVM0Dispute.claim: abi.encode(top, chain below it), empty for an empty stack."""
    st = s['stack']
    return word(st[-1]) + stack_chain(st[:-1]) if st else b''


def touched(op, imm, n):
    """Stack elements the instruction reads, or None if the stack is too short (STACK_UNDERFLOW)."""
    if op in ('POP', 'JZ', 'MLOAD'):
        k = 1
    elif op == 'DUP':
        k = imm + 1
    elif op == 'SWAP':
        if imm < 1:
            return None
        k = imm + 1
    elif op in ('ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'LT', 'EQ', 'MSTORE'):
        k = 2
    else:
        k = 0
    return None if k > n else k


def aux_for(program, inputs, s, pc_, ic_):
    """Witness for one step from s: instruction proof, LOAD input proof, touched stack top + chain below, memory cell."""
    op = imm = 0
    ins_proof, in_val, in_proof = [], 0, []
    top, rest, mem_val, mem_proof = [], stack_chain(s['stack']), 0, []
    if 0 <= s['pc'] < len(program) and not s['halted']:
        ins = program[s['pc']]
        name, im = ins[0], (ins[1] if len(ins) > 1 else 0)
        op, imm = E.OPCODES[name], im
        ins_proof = pc_.proof(s['pc'])
        if name == 'LOAD' and im < len(inputs):
            in_val, in_proof = inputs[im], ic_.proof(im)
        k = touched(name, im, len(s['stack'])) if name != 'HALT' else None
        if k is not None:
            st = s['stack']
            top, rest = list(reversed(st[len(st) - k:])), stack_chain(st[:len(st) - k])
            addr = st[-1] if name in ('MLOAD', 'MSTORE') else None
            if addr is not None and addr < MEM_CELLS:
                mem_val, mem_proof = s['mem'].get(str(addr), 0), E._proof(mem_levels(s['mem']), addr)
    return word(32) + E.abi_encode([('w', pc_.root), ('w', word(pc_.n)), ('w', word(op)), ('w', word(imm)),
                                    ('a', ins_proof), ('w', ic_.root), ('w', word(ic_.n)), ('w', word(in_val)),
                                    ('a', in_proof), ('a', top), ('w', rest), ('w', word(mem_val)), ('a', mem_proof)])
