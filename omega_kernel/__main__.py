"""Reproducible end-to-end demo on the mock backend: python -m omega_kernel demo <empty-dir>

Prints one JSON document: a normal transfer, an idempotent duplicate, a replay, a
policy denial, and an ambiguous (ack lost) settlement recovered after a restart.
All keys are generated per run and never written to disk.
"""
import json
import os
import secrets
import sys
from pathlib import Path
from omega_kernel import Kernel, KeyRing, Policy, tag
from omega_kernel.settlement import MockLedger


def demo(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise SystemExit('demo directory must be empty')
    t = [1_800_000_000]
    clock = lambda: t[0]
    key = secrets.token_bytes(32)
    keys = KeyRing({'agent-a': key})
    ledger = MockLedger(root / 'ledger.sqlite')
    ledger.mint('acct:agent-a', 'USDC', 1_000_000)
    k = Kernel(root / 'journal.sqlite', ledger, keys, clock=clock)
    k.put_policy(Policy('agent-a', 1, 'acct:agent-a', {'transfer'}, {'acct:shop'}, {'USDC'}, 100_000, 5_000,
                        3600, 300_000, 100, 0, 2_000_000_000))

    def env(n, amount='25000', target='acct:shop'):
        e = {'v': 1, 'intent_id': secrets.token_hex(16), 'agent_id': 'agent-a', 'nonce': n, 'action': 'transfer',
             'target': target, 'params': {'asset': 'USDC', 'amount': amount}, 'constraints': {'max_fee': '2000'},
             'created_at': t[0], 'expires_at': t[0] + 600}
        return e, tag(key, e)

    out = {}
    e1, g1 = env(1)
    out['submit'] = k.submit(json.dumps(e1), g1)
    out['execute'] = k.execute(e1['intent_id'])
    out['duplicate'] = k.submit(json.dumps(e1), g1)
    e2 = dict(e1, intent_id=secrets.token_hex(16))
    out['replay_same_nonce'] = k.submit(json.dumps(e2), tag(key, e2))
    e3, g3 = env(3, target='acct:unknown')
    out['denied_target'] = k.submit(json.dumps(e3), g3)
    e4, g4 = env(4)
    k.submit(json.dumps(e4), g4)
    ledger.faults['lose_ack'] = 1
    out['ack_lost'] = k.execute(e4['intent_id'])
    t[0] += 60  # restart: new kernel instance on the same journal
    k2 = Kernel(root / 'journal.sqlite', ledger, keys, clock=clock)
    out['recover'] = k2.recover()
    out['verify'] = {i: k2.verify(i)['consistent'] for i in (e1['intent_id'], e4['intent_id'])}
    out['ledger'] = {'agent': ledger.balance('acct:agent-a', 'USDC'), 'shop': ledger.balance('acct:shop', 'USDC'),
                     'total_supply': ledger.total('USDC'), 'confirmed_txs': ledger.settled_count()}
    out['journal_chain'] = k2.j.verify_chain()
    return out


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != 'demo':
        raise SystemExit('usage: python -m omega_kernel demo <empty-dir>')
    print(json.dumps(demo(sys.argv[2]), indent=1, sort_keys=True))
