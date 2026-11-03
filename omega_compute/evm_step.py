"""EVM encoding of OVM-0 states for the on-chain one-step referee (omega_evm/src/OVM0Step.sol).

The in-process dispute game commits to vm.state_hash (SHA-256 over canonical JSON). On chain that is expensive,
so a game settled by OVM0Step commits instead to evm_state_hash: keccak over abi.encode of the same fields, with
program and inputs committed as keccak Merkle roots. vm.step stays the single source of semantics; this module only
re-encodes its states and produces the proofs the contract needs.
"""
from omega_compute import vm
from omega_kernel.settlement.evm_crypto import keccak, word

OPCODES = {op: i for i, op in enumerate(vm.OPS)}
TRAPS = {None: 0, 'PC_OUT_OF_RANGE': 1, 'STACK_UNDERFLOW': 2, 'DIV_BY_ZERO': 3, 'INPUT_OUT_OF_RANGE': 4,
         'MEM_OUT_OF_RANGE': 5, 'STACK_OVERFLOW': 6, 'STEP_LIMIT': 7}


def abi_encode(items):
    """items: list of ('w', 32-byte word) static or ('a', [int, ...]) dynamic uint array or ('b', bytes)."""
    head, tail = [], b''
    n = 32 * len(items)
    for kind, v in items:
        if kind == 'w':
            head.append(v)
            continue
        head.append(word(n + len(tail)))
        if kind == 'a':
            tail += word(len(v)) + b''.join(word(x) for x in v)
        else:
            tail += word(len(v)) + v + bytes(-len(v) % 32)
    return b''.join(head) + tail


def _tree(leaves):
    level = list(leaves)
    size = 1
    while size < len(level):
        size *= 2
    level += [bytes(32)] * (size - len(level))
    levels = [level]
    while len(level) > 1:
        level = [keccak(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def _proof(levels, index):
    out = []
    for lv in levels[:-1]:
        out.append(lv[index ^ 1])
        index //= 2
    return out


class Commit:
    def __init__(self, leaves):
        self.levels = _tree(leaves)
        self.root, self.n = self.levels[-1][0], len(leaves)
        self.commitment = keccak(self.root + word(self.n))

    def proof(self, i):
        return _proof(self.levels, i)


def program_commit(program):
    return Commit([keccak(word(i) + word(OPCODES[ins[0]]) + word(ins[1] if len(ins) > 1 else 0))
                   for i, ins in enumerate(vm.check_program(program))])


def inputs_commit(inputs):
    return Commit([keccak(word(i) + word(x)) for i, x in enumerate(inputs)])  # empty: root 0, n 0 (LOAD traps)


def encode_state(s, pc_, ic_):
    mem = sorted((int(k), v) for k, v in s['mem'].items())
    return word(32) + abi_encode([('w', pc_.commitment), ('w', ic_.commitment), ('w', word(s['pc'])), ('w', word(s['steps'])),
                       ('w', word(int(s['halted']))), ('w', word(TRAPS[s['trap']])), ('a', s['stack']),
                       ('a', [k for k, _ in mem]), ('a', [v for _, v in mem])])


def evm_state_hash(s, pc_, ic_):
    return keccak(encode_state(s, pc_, ic_))


def out_witness(s):
    """Top-of-stack witness for OVM0Dispute.claim: none, the full encoding carries the stack."""
    return b''


def aux_for(program, inputs, s, pc_, ic_):
    """Witness for one step from s: the instruction at pc (if in range) and, for LOAD, the input word."""
    op = imm = 0
    ins_proof = []
    in_val, in_proof = 0, []
    if 0 <= s['pc'] < len(program):
        ins = program[s['pc']]
        op, imm = OPCODES[ins[0]], (ins[1] if len(ins) > 1 else 0)
        ins_proof = pc_.proof(s['pc'])
        if ins[0] == 'LOAD' and imm < len(inputs):
            in_val, in_proof = inputs[imm], ic_.proof(imm)
    # abi.decode(aux, (Aux)): a dynamic struct is one tuple argument, so it is preceded by its offset word
    return word(32) + abi_encode([('w', pc_.root), ('w', word(pc_.n)), ('w', word(op)), ('w', word(imm)),
                                  ('a', ins_proof), ('w', ic_.root), ('w', word(ic_.n)), ('w', word(in_val)),
                                  ('a', in_proof)])
