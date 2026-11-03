"""Referee cost vs full re-execution (ADR-0002 I6). Usage: python -m omega_compute.bench OUT.json [max_log2]

For each trace length n ~ 2**k the executor lies only about the final state (worst case for bisection depth),
an honest challenger disputes, and we time the referee's own work separately from the parties' answers.
"""
import json
import platform
import sys
import time
from omega_compute import vm
from omega_compute.dispute import Referee, FinalOnlyLiar, HonestChallenger

SUM = [['PUSH', 0], ['LOAD', 0], ['DUP', 0], ['JZ', 11], ['SWAP', 1], ['DUP', 1], ['ADD'], ['SWAP', 1], ['PUSH', 1],
       ['SUB'], ['JMP', 2], ['POP'], ['HALT']]


class Timed:
    def __init__(self, inner):
        self.inner, self.seconds = inner, 0.0

    def __getattr__(self, name):
        fn = getattr(self.inner, name)

        def wrapped(*a):
            t = time.perf_counter()
            try:
                return fn(*a)
            finally:
                self.seconds += time.perf_counter() - t
        return wrapped


def one(k):
    N = max(1, (2 ** k - 6) // 9)
    m = 10 ** 9
    t = time.perf_counter()
    final, hs = vm.run(SUM, [N], m)
    t_exec = time.perf_counter() - t
    liar = FinalOnlyLiar(SUM, [N], m)
    challenger = HonestChallenger(SUM, [N], m)
    ex, ch = Timed(liar), Timed(challenger)
    ref = Referee(SUM, [N], m)
    t = time.perf_counter()
    refusal = ref.validate_claim(*liar.submission())
    res = ref.resolve(liar.claim(), ex, ch)
    t_total = time.perf_counter() - t
    assert refusal is None and res['winner'] == 'challenger', res
    n = len(hs) - 1
    return {'log2_target': k, 'n_steps': n, 'result_ok': vm.output(final)['stack_top'] == N * (N + 1) // 2 % vm.MOD,
            'full_reexecution_s': round(t_exec, 4), 'referee_s': round(t_total - ex.seconds - ch.seconds, 6),
            'executor_answer_s': round(ex.seconds, 4), 'challenger_answer_s': round(ch.seconds, 6),
            'rounds': res['cost']['rounds'], 'referee_hashes': res['cost']['hashes'],
            'merkle_checks': res['cost']['merkle_checks'], 'vm_steps_by_referee': res['cost']['steps_executed'],
            'reason': res['reason']}


def main(out, max_k=20):
    rows = []
    for k in range(10, max_k + 1, 2):
        rows.append(one(k))
        print(json.dumps(rows[-1]), flush=True)
    doc = {'schema': 'omega.compute.bench_referee.v1', 'python': platform.python_version(), 'machine': platform.machine(),
           'processor': platform.processor(), 'program': 'SUM 1..N (OVM-0)', 'rows': rows,
           'note': 'referee_s excludes time spent waiting for party answers; executor_answer_s includes re-deriving '
                   'the revealed state from scratch (O(n)), which an executor that stores checkpoints avoids.'}
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)


if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 20)
