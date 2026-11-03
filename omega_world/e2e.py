"""The end of an end-to-end run and what an outsider can check of it (ADR-0014 section 4, technology and reproducibility).

close() runs on the state folder of a finished omega_world.rehearsal: the money comes back. A job nobody takes expires and its
price returns to the account; once every node is past its expiry the executors' bonds are released; then the owner, the executors
and the game's creditors take out what is theirs, as real tokens and ether. After this the escrow holds nothing, so any token left
there is a finding. It can be stopped and run again with the same folder.

transcript() needs no key and no state folder: an RPC and the run's public description (run_description()). It reads the logs and
writes down what happened, in terms that do not depend on who ran it, where or when: each job's events and amounts, each claim's
outcome, the moves of each game, the tokens in and out per role. Addresses become roles and block times are left out, so two
independent runs of the same plan give the same `economics_sha256`, on a local chain or a public one. `build_sha256` is over the
compiled contracts with the compiler's metadata tail and immutables out; `code_matches_build` says the chain holds this build.

What equal digests show: the same contracts did the same accounting on this scripted run. They say nothing about an attacker, the
ether costs (gas differs by chain), the Optimism and Cannon referees' paths (tools/world/sepolia_long_jobs.py) or whether anyone
wants this. Test chains only for close(); transcript() reads any chain."""
import hashlib
import json
from pathlib import Path
from omega_compute.dispute_agent import Board
from omega_kernel.settlement.evm_crypto import call_data
from omega_world import deploy as DP
from omega_world import indexer as IX
from omega_world.orchestrator import claim_view
from omega_world.plan import Plan, Task
from omega_world.rehearsal import PROGRAMS, _sleep_wait, _State
from omega_world.sdk import WorldClient

REFUND_TTL = 300  # seconds to post it in: nobody is meant to take the job
CLAIM_STATUS = {0: 'none', 1: 'claimed', 2: 'accepted', 3: 'rejected'}
AMOUNTS = {'Reserved': ('bond', 'cover'), 'Settled': ('paid', 'price'), 'Rejected': ('bond', 'surplus'),
           'Voided': ('comp', 'compToExecutor', 'ext'), 'Released': ('bond',), 'Slashed': ('bond',)}
# Events that depend on when someone called, not on what happened: `verify` is open to anyone, moves no token and only
# frees the node's cover early; settle and voidNode free it anyway. A node whose parent is rejected while its own claim
# is accepted shows Verified before Voided in one run and not in the next (two local runs, 2026-11-03).
WHEN_DEPENDENT = {'Verified'}


def _plans(st):
    return [Plan.from_json(st.d['plan'])] + ([Plan.from_json(st.d['refund_plan'])] if 'refund_plan' in st.d else [])


def _keys(plan):
    return {plan.key(t.name, a): f'{t.name}#{a}' for t in plan.tasks for a in range(plan.max_attempts)}


def close(chain, signers, config, state_dir, wait=None, confirmations=0):
    """-> report, see the module's docstring"""
    DP.require_writable(chain, config)
    st = _State(state_dir)
    if 'withdrawn' not in st.d:
        raise RuntimeError('REHEARSAL_NOT_FINISHED')
    s, wait = signers, wait or _sleep_wait(chain)
    addr = {x['contract']: bytes.fromhex(x['address'][2:]) for x in st.d['manifest']['steps']}
    escrow, game, acct = addr['OmegaGraphEscrow'], addr['OVM0Dispute'], bytes.fromhex(st.d['acct'])
    token = bytes.fromhex(config['token'][2:])
    board = Board(chain, game, from_block=st.d['manifest']['from_block'])
    client = WorldClient(chain, escrow, s['agent'], s['relayer'], token=token, boards={game: board},
                         archive=Path(state_dir) / 'archive.jsonl', confirmations=confirmations)
    esc = client.esc
    if 'refund_plan' not in st.d:
        st.d['refund_before'] = esc.balance(acct)
        plan = client.plan(acct, [Task('R', PROGRAMS['add1'], (41,), (), ('0x' + s['executor'].address.hex(),), '0x' + game.hex())],
                           ttl=REFUND_TTL, max_attempts=1)
        st.d['refund_plan'] = plan.to_json()
        st.save()
    orch = client.orchestrator(Plan.from_json(st.d['refund_plan']))
    for _ in range(100):
        orch.tick()
        n = orch.current('R')[2]
        if n is not None and n['state'] == 'expired':
            break
        if n is not None and n['expiry'] >= client.now():
            wait(n['expiry'] + 1 - client.now())
    else:
        raise RuntimeError('REFUND_DID_NOT_EXPIRE')
    if 'refund_after' not in st.d:
        st.d['refund_after'] = esc.balance(acct)
        st.save()
    nodes = {k: esc.node(k) for p in _plans(st) for k in _keys(p)}
    bonded = {k: n for k, n in nodes.items() if n['bonded']}
    if bonded:
        last = max(n['expiry'] for n in bonded.values())
        while client.now() <= last:
            wait(last + 1 - client.now())
    for key in bonded:
        client._send(s['relayer'], escrow, call_data('release(bytes32)', key))
    for who in (s['executor'], s['liar']):
        if esc.bond_of(who.address):
            client.unstake(who, esc.bond_of(who.address))
    if esc.balance(acct):
        client.withdraw(s['owner'], acct, esc.balance(acct))
    credit = lambda who: int.from_bytes(chain.call(game, call_data('credit(address)', who.address)), 'big')
    for who in (s['executor'], s['liar'], s['watcher']):
        if credit(who):
            client._send(who, game, call_data('withdraw()'))
    left = int.from_bytes(chain.call(token, call_data('balanceOf(address)', escrow)), 'big')
    totals, game_eth = esc.totals(), int(chain.rpc('eth_getBalance', '0x' + game.hex(), 'latest'), 16)
    burned = int.from_bytes(chain.call(game, call_data('burned()')), 'big')  # a defeated claim's bond - reward stays for good
    st.d.setdefault('closed_at_block', int(chain.rpc('eth_blockNumber'), 16))
    st.save()
    refund = {'before': st.d['refund_before'], 'after_expiry': st.d['refund_after']}
    return {'ok': (left == 0 and not any(totals.values()) and game_eth == burned > 0 and refund['before'] == refund['after_expiry']),
            'refund': refund, 'escrow_tokens_left': left, 'totals': totals, 'dispute_contract_wei_left': game_eth,
            'dispute_burned_wei': burned, 'closed_at_block': st.d['closed_at_block']}


def run_description(st_dir, signers, config):
    """the run's public part: everything transcript() needs and no secret. Addresses of the roles, never their keys"""
    st = _State(st_dir)
    return {'chain_id': config['chain_id'], 'config': config, 'manifest': st.d['manifest'], 'account': st.d['acct'],
            'plans': [p.to_json() for p in _plans(st)], 'to_block': st.d['closed_at_block'],
            'roles': {r: '0x' + signers[r].address.hex() for r in ('owner', 'executor', 'liar', 'watcher')}}


def _strip(code):
    """runtime bytecode without the compiler's CBOR metadata tail: its last two bytes are the tail's length"""
    return code[:-(int.from_bytes(code[-2:], 'big') + 2)]


def build_hashes():
    out = {}
    for name in DP.STACK + (DP.OP_REFEREE,) + DP.CANNON:
        code = bytes.fromhex(DP.artifact(name)['deployedBytecode']['object'][2:])
        out[name] = hashlib.sha256(_strip(code)).hexdigest()
    return out


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def transcript(chain, run):
    """-> see the module's docstring. `chain` needs only reads: a ReadOnlyChain does"""
    addr = {x['contract']: bytes.fromhex(x['address'][2:]) for x in run['manifest']['steps']}
    escrow, game, inbox = addr['OmegaGraphEscrow'], addr['OVM0Dispute'], addr['OVM0Inbox']
    token = bytes.fromhex(run['config']['token'][2:])
    role = {v: k for k, v in run['roles'].items()}
    labels = {'0x' + k.hex(): v for p in (Plan.from_json(x) for x in run['plans']) for k, v in _keys(p).items()}
    ix = IX.Indexer(chain, escrow, inboxes=(inbox,), token=token, from_block=run['manifest']['from_block'], confirmations=0,
                    referees=(game,))
    records = [(IX.decode(lg), lg) for lg in ix.fetch() if int(lg['blockNumber'], 16) <= run['to_block']]
    nodes, claims, games, flows = {}, {}, {}, {}
    escrow_hex = '0x' + escrow.hex()
    for (ev, a), lg in records:
        if ev == 'Transfer':
            who, side = (a['from'], 'in') if a['to'] == escrow_hex else (a['to'], 'out')
            row = flows.setdefault(role.get(who, 'other'), {'in': 0, 'out': 0})
            row[side] += a['value']
        elif ev == 'Claimed':
            claims[a['id']] = {'defender': role.get(a['defender'], 'other'), 'n': a['n'], 'games': []}
        elif ev == 'Challenged':
            games[a['gameId']] = g = {'challenger': role.get(a['challenger'], 'other'), 'moves': 0, 'resolved': None}
            claims[a['claimId']]['games'].append(g)
        elif ev in ('Bisected', 'Responded'):
            games[a['gameId']]['moves'] += 1
        elif ev == 'GameResolved':
            games[a['gameId']]['resolved'] = a['status']
        elif ev == 'ClaimResolved':
            claims[a['id']]['status'] = CLAIM_STATUS.get(a['status'], a['status'])
        elif ev in IX.ESCROW_EVENTS and a.get('key') in labels and ev not in WHEN_DEPENDENT:
            row = nodes.setdefault(labels[a['key']], {'events': [], 'claim': None})
            row['events'].append([ev] + [a[f] for f in AMOUNTS.get(ev, ())])
            if ev == 'Posted':
                row['executor'] = role.get(a['executor'], 'other')
            if ev == 'Bound':
                row['claim'] = a['claimId']
    outputs = {}
    for name, row in nodes.items():
        cid = row['claim']
        if cid is not None:
            view = claim_view(chain, game, cid)
            outputs[name] = {'output': view['output'], 'trap': view['trap']}
            row['claim'] = claims.get(cid)
    economics = {'nodes': nodes, 'outputs': outputs, 'token_flows': flows,
                 'escrow_tokens_left': sum(f['in'] - f['out'] for f in flows.values())}
    build = build_hashes()
    verified = DP.verify(chain, run['manifest'], run['config'])
    return {'chain_id': run['chain_id'], 'contracts': {k: '0x' + v.hex() for k, v in addr.items()}, 'economics': economics,
            'economics_sha256': _digest(economics), 'build': build, 'build_sha256': _digest(build),
            'code_matches_build': bool(verified['ok'])}


def compare(a, b):
    """-> the differences between two transcripts that are meant to be the same; empty when they are"""
    out = []
    if a['build_sha256'] != b['build_sha256']:
        out.append({'build': sorted(k for k in a['build'] if a['build'][k] != b['build'].get(k))})
    if a['economics_sha256'] != b['economics_sha256']:
        ea, eb = a['economics'], b['economics']
        out += [{'economics': k} for k in sorted(set(ea) | set(eb)) if ea.get(k) != eb.get(k)]
        na, nb = ea.get('nodes', {}), eb.get('nodes', {})
        out += [{'job': k, 'a': na.get(k), 'b': nb.get(k)} for k in sorted(set(na) | set(nb)) if na.get(k) != nb.get(k)]
    return out
