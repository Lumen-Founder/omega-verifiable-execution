"""OVM-0: a tiny deterministic stack machine whose every step is hashable.

Values are integers modulo 2**64; division by zero, stack under/overflow, bad
jumps and step exhaustion are traps that halt the machine with a code. The full
machine state is small and canonical, so one step can be re-executed by a
referee from the state alone (one-step proof).
"""
import hashlib
from omega_kernel.canonical import canonical

MOD = 2 ** 64
MAX_STACK = 256
MAX_MEM = 256
OPS = {'PUSH': 1, 'POP': 0, 'DUP': 1, 'SWAP': 1, 'ADD': 0, 'SUB': 0, 'MUL': 0, 'DIV': 0, 'MOD': 0, 'LT': 0, 'EQ': 0,
       'JMP': 1, 'JZ': 1, 'LOAD': 1, 'MLOAD': 0, 'MSTORE': 0, 'HALT': 0}
STATE_DOMAIN = b'OVM0-STATE\x00'


class ProgramError(ValueError):
    pass


def check_program(program):
    if type(program) is not list or not 1 <= len(program) <= 4096:
        raise ProgramError('PROGRAM_SIZE')
    for ins in program:
        if type(ins) is not list or not ins or ins[0] not in OPS or len(ins) != 1 + OPS[ins[0]]:
            raise ProgramError(f'BAD_INSTRUCTION:{ins!r}')
        if len(ins) == 2 and (type(ins[1]) is not int or not 0 <= ins[1] < MOD):
            raise ProgramError(f'BAD_IMMEDIATE:{ins!r}')
    return program


def program_hash(program):
    return hashlib.sha256(b'OVM0-PROGRAM\x00' + canonical(check_program(program))).hexdigest()


def initial(program, inputs):
    if type(inputs) is not list or len(inputs) > 1024 or any(type(x) is not int or not 0 <= x < MOD for x in inputs):
        raise ProgramError('BAD_INPUTS')
    return {'prog': program_hash(program), 'inputs': hashlib.sha256(canonical(inputs)).hexdigest(),
            'pc': 0, 'stack': [], 'mem': {}, 'steps': 0, 'halted': False, 'trap': None}


def state_hash(s):
    return hashlib.sha256(STATE_DOMAIN + canonical(s)).hexdigest()


def _trap(s, code):
    return s | {'halted': True, 'trap': code}


def step(program, inputs, s):
    """Pure function: state -> next state. A halted state is a fixed point."""
    if s['halted']:
        return s
    s = s | {'stack': list(s['stack']), 'mem': dict(s['mem']), 'steps': s['steps'] + 1}
    if not 0 <= s['pc'] < len(program):
        return _trap(s, 'PC_OUT_OF_RANGE')
    op, *arg = program[s['pc']]
    st, nxt = s['stack'], s['pc'] + 1

    def need(n):
        return len(st) >= n
    if op == 'PUSH':
        st.append(arg[0])
    elif op == 'POP':
        if not need(1):
            return _trap(s, 'STACK_UNDERFLOW')
        st.pop()
    elif op == 'DUP':
        if not need(arg[0] + 1):
            return _trap(s, 'STACK_UNDERFLOW')
        st.append(st[-1 - arg[0]])
    elif op == 'SWAP':
        if arg[0] < 1 or not need(arg[0] + 1):
            return _trap(s, 'STACK_UNDERFLOW')
        st[-1], st[-1 - arg[0]] = st[-1 - arg[0]], st[-1]
    elif op in ('ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'LT', 'EQ'):
        if not need(2):
            return _trap(s, 'STACK_UNDERFLOW')
        b, a = st.pop(), st.pop()
        if op in ('DIV', 'MOD') and b == 0:
            return _trap(s, 'DIV_BY_ZERO')
        st.append({'ADD': (a + b) % MOD, 'SUB': (a - b) % MOD, 'MUL': (a * b) % MOD, 'DIV': a // b if b else 0,
                   'MOD': a % b if b else 0, 'LT': int(a < b), 'EQ': int(a == b)}[op])
    elif op == 'JMP':
        nxt = arg[0]
    elif op == 'JZ':
        if not need(1):
            return _trap(s, 'STACK_UNDERFLOW')
        if st.pop() == 0:
            nxt = arg[0]
    elif op == 'LOAD':
        if arg[0] >= len(inputs):
            return _trap(s, 'INPUT_OUT_OF_RANGE')
        st.append(inputs[arg[0]])
    elif op == 'MLOAD':
        if not need(1):
            return _trap(s, 'STACK_UNDERFLOW')
        st.append(s['mem'].get(str(st.pop()), 0))
    elif op == 'MSTORE':
        if not need(2):
            return _trap(s, 'STACK_UNDERFLOW')
        addr, val = st.pop(), st.pop()
        if addr >= MAX_MEM:
            return _trap(s, 'MEM_OUT_OF_RANGE')
        s['mem'][str(addr)] = val
    elif op == 'HALT':
        return s | {'halted': True}
    if len(st) > MAX_STACK:
        return _trap(s, 'STACK_OVERFLOW')
    return s | {'pc': nxt}


def transition(program, inputs, s, max_steps):
    """The one and only valid successor of s, or None if s is halted (a halted state has no successor,
    so a trace cannot be padded past termination to inflate its length)."""
    if s['halted']:
        return None
    if s['steps'] >= max_steps:
        return _trap(s | {'stack': list(s['stack']), 'mem': dict(s['mem'])}, 'STEP_LIMIT')
    return step(program, inputs, s)


def run(program, inputs, max_steps):
    """-> (final state, list of state hashes h_0..h_n)."""
    check_program(program)
    s = initial(program, inputs)
    hs = [state_hash(s)]
    while True:
        nxt = transition(program, inputs, s, max_steps)
        if nxt is None:
            return s, hs
        s = nxt
        hs.append(state_hash(s))


def output(s):
    return {'stack_top': s['stack'][-1] if s['stack'] else None, 'trap': s['trap'], 'steps': s['steps']}
