"""Optimistic verification of OVM-0 execution: claim, bisection, one-step proof.

The executor commits to the Merkle root of its state-hash trace h_0..h_n. A
challenger who disagrees with the final state opens a dispute; the referee keeps
an interval [lo, hi] where the challenger agrees with h_lo and disagrees with
h_hi, halving it with Merkle-proven midpoints until hi = lo + 1, then executes
ONE transition from the revealed state s_lo. The referee never runs the program.

Security assumption (I5): at least one honest challenger observes the claim within
the challenge window and the program/inputs are available to it. A party that
does not answer loses.
"""
from omega_compute import vm
from omega_compute.merkle import Tree, verify

MAX_ROUNDS = 64


class Referee:
    def __init__(self, program, inputs, max_steps):
        self.program, self.inputs, self.max_steps = vm.check_program(program), inputs, max_steps
        self.h0 = vm.state_hash(vm.initial(program, inputs))
        self.prog, self.inp = vm.program_hash(program), vm.initial(program, inputs)['inputs']
        self.cost = {'merkle_checks': 0, 'hashes': 0, 'steps_executed': 0, 'rounds': 0}

    def _leaf_ok(self, claim, i, h, path):
        self.cost['merkle_checks'] += 1
        self.cost['hashes'] += 1 + len(path) if isinstance(path, list) else 1
        return type(h) is str and verify(claim['trace_root'], claim['n'] + 1, i, h, path)

    def validate_claim(self, claim, final_state, proof0, proofn):
        """Static checks at submission. -> None if acceptable, else a refusal code."""
        need = {'program_hash', 'inputs_hash', 'max_steps', 'n', 'trace_root', 'final_hash', 'output'}
        if type(claim) is not dict or set(claim) != need:
            return 'BAD_CLAIM_SHAPE'
        if (claim['program_hash'], claim['inputs_hash'], claim['max_steps']) != (self.prog, self.inp, self.max_steps):
            return 'WRONG_JOB'
        if type(claim['n']) is not int or not 1 <= claim['n'] <= self.max_steps + 1:
            return 'BAD_LENGTH'
        if type(final_state) is not dict or vm.state_hash(final_state) != claim['final_hash']:
            return 'FINAL_STATE_MISMATCH'
        if not final_state.get('halted') or vm.output(final_state) != claim['output']:
            return 'FINAL_NOT_HALTED_OR_OUTPUT_MISMATCH'
        if (final_state.get('prog'), final_state.get('inputs')) != (self.prog, self.inp):
            return 'FINAL_STATE_WRONG_JOB'
        if not self._leaf_ok(claim, 0, self.h0, proof0):
            return 'BAD_INITIAL_COMMITMENT'
        if not self._leaf_ok(claim, claim['n'], claim['final_hash'], proofn):
            return 'BAD_FINAL_COMMITMENT'
        return None

    def resolve(self, claim, executor, challenger):
        """-> {'winner': 'executor'|'challenger', 'reason': str, 'cost': {...}}"""
        def lose(who, reason):
            return {'winner': 'challenger' if who == 'executor' else 'executor', 'reason': reason, 'cost': dict(self.cost)}
        n = claim['n']
        opening = _ask(challenger.agrees, n, claim['final_hash'])
        if opening is None:
            return lose('challenger', 'CHALLENGER_NO_RESPONSE')
        if opening:
            return lose('challenger', 'CHALLENGER_AGREES_WITH_FINAL')
        lo, hi, h_lo, h_hi = 0, n, self.h0, claim['final_hash']
        while hi - lo > 1:
            self.cost['rounds'] += 1
            if self.cost['rounds'] > MAX_ROUNDS:
                return lose('executor', 'TOO_MANY_ROUNDS')
            mid = (lo + hi) // 2
            got = _ask(executor.leaf, mid)
            if not got or len(got) != 2:
                return lose('executor', 'EXECUTOR_NO_RESPONSE')
            h, path = got
            if not self._leaf_ok(claim, mid, h, path):
                return lose('executor', 'BAD_MERKLE_PROOF')
            agree = _ask(challenger.agrees, mid, h)
            if agree is None:
                return lose('challenger', 'CHALLENGER_NO_RESPONSE')
            if agree:
                lo, h_lo = mid, h
            else:
                hi, h_hi = mid, h
        s = _ask(executor.reveal, lo)
        if type(s) is not dict:
            return lose('executor', 'EXECUTOR_NO_RESPONSE')
        self.cost['hashes'] += 1
        try:
            if vm.state_hash(s) != h_lo:
                return lose('executor', 'REVEAL_MISMATCH')
        except (TypeError, ValueError):
            return lose('executor', 'REVEAL_MALFORMED')
        if (s.get('prog'), s.get('inputs')) != (self.prog, self.inp):
            return lose('executor', 'REVEAL_WRONG_JOB')
        self.cost['steps_executed'] += 1
        try:
            nxt = vm.transition(self.program, self.inputs, s, self.max_steps)
        except Exception:  # malformed state that still hashed correctly
            return lose('executor', 'REVEAL_MALFORMED')
        self.cost['hashes'] += 1
        if nxt is None:
            return lose('executor', 'FRAUD_TRANSITION_FROM_HALTED')
        if vm.state_hash(nxt) != h_hi:
            return lose('executor', 'FRAUD_PROVEN')
        return lose('challenger', 'TRANSITION_VALID')


def _ask(fn, *a):
    try:
        return fn(*a)
    except Exception:
        return None


# --- parties -----------------------------------------------------------------
class HonestExecutor:
    def __init__(self, program, inputs, max_steps):
        self.program, self.inputs, self.max_steps = program, inputs, max_steps
        self.final, self.hs = vm.run(program, inputs, max_steps)
        self.tree = Tree(self.hs)

    def claim(self):
        return {'program_hash': vm.program_hash(self.program), 'inputs_hash': self.final['inputs'],
                'max_steps': self.max_steps, 'n': len(self.hs) - 1, 'trace_root': self.tree.root,
                'final_hash': self.hs[-1], 'output': vm.output(self.final)}

    def submission(self):
        return self.claim(), self.final, self.tree.proof(0), self.tree.proof(len(self.hs) - 1)

    def leaf(self, i):
        return self.hs[i], self.tree.proof(i)

    def reveal(self, i):
        s = vm.initial(self.program, self.inputs)
        for _ in range(i):
            s = vm.transition(self.program, self.inputs, s, self.max_steps)
        return s


class ForkingExecutor(HonestExecutor):
    """Lies from step k on: corrupts the top of stack at k, then executes honestly from the corrupted state.
    The trace is internally consistent everywhere except the single transition k-1 -> k."""

    def __init__(self, program, inputs, max_steps, k, delta=1):
        self.program, self.inputs, self.max_steps = program, inputs, max_steps
        s = vm.initial(program, inputs)
        states = [s]
        while True:
            nxt = vm.transition(program, inputs, s, max_steps)
            if nxt is None:
                break
            if len(states) == k:
                st = list(nxt['stack']) or [0]
                st[-1] = (st[-1] + delta) % vm.MOD
                nxt = nxt | {'stack': st}
            s = nxt
            states.append(s)
        self._states = states
        self.final, self.hs = states[-1], [vm.state_hash(x) for x in states]
        self.tree = Tree(self.hs)

    def reveal(self, i):
        return self._states[i]


class FinalOnlyLiar(HonestExecutor):
    """Replaces only the last state (wrong output) and recommits; earlier leaves are honest."""

    def __init__(self, program, inputs, max_steps):
        super().__init__(program, inputs, max_steps)
        st = list(self.final['stack']) or [0]
        st[-1] = (st[-1] + 1) % vm.MOD
        self.final = self.final | {'stack': st}
        self.hs = self.hs[:-1] + [vm.state_hash(self.final)]
        self.tree = Tree(self.hs)


class PaddingLiar(HonestExecutor):
    """Claims extra steps after termination (to inflate a per-step fee)."""

    def __init__(self, program, inputs, max_steps, extra=5):
        super().__init__(program, inputs, max_steps)
        self.hs = self.hs + [self.hs[-1]] * extra
        self.tree = Tree(self.hs)
        self._honest_n = len(self.hs) - 1 - extra

    def reveal(self, i):
        return super().reveal(min(i, self._honest_n))


class SilentExecutor(HonestExecutor):
    def leaf(self, i):
        raise TimeoutError


class HonestChallenger:
    def __init__(self, program, inputs, max_steps):
        _, self.hs = vm.run(program, inputs, max_steps)

    def agrees(self, i, h):
        return i < len(self.hs) and self.hs[i] == h


class ContrarianChallenger:
    """Disputes a correct claim and always answers 'disagree'."""

    def agrees(self, i, h):
        return False


class RandomChallenger:
    def __init__(self, rnd):
        self.rnd = rnd

    def agrees(self, i, h):
        return self.rnd.random() < 0.5


class SilentChallenger:
    def agrees(self, i, h):
        raise TimeoutError
