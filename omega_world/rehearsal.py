"""Network rehearsal (docs/adr/ADR-0012 X2; runbook docs/world_computer/RUNBOOK_DEPLOY.md section 0): the release checks on
a real network before mainnet. run() deploys the stack from a chain config, verifies the bytecode, opens an account, stakes an
honest executor and a false one, and runs a three-step plan with a watchtower. The first attempt of the first step goes to the
false executor: the watchtower disputes it to the end, the plan recovers by retry. In the middle of that game every object is
dropped and made again (a restart). Then it takes the executor's credit out of the escrow as real tokens and returns a report:
addresses, gas per call, inclusion latency, the watcher's reaction, the restart, payment, health, archive head.

It can be stopped at any moment and run again with the same `state_dir`: rehearsal.json holds what was done (token, manifest,
account, plan, measurements), archive.jsonl the archive; a window of a day should not cost the deployment. A crash during the
deployment itself starts that deployment again from the current nonce (a partial one is never used, RUNBOOK_DEPLOY section 3).

It runs on the configuration's own test chain; any other chain is refused unless armed by the user (deploy.require_writable).
The settlement token is the configuration's `token`, one rule for every chain. It must have code; if it cannot mint, the keys
must already hold enough (REHEARSAL_TOKEN_SHORT:<role>). deploy_token() puts a TestToken on a test chain for that value.

Scope: the configuration's contracts. deploy/chains/sepolia.json has no op_referee or cannon_referee section (their external
contracts differ on Sepolia and are not pinned): 4 of the 8 mainnet contracts; the report's `scope` names the difference.

On a dev chain `wait(seconds)` can advance time; on a real network it must really wait (default: sleep and poll the chain).

    python -X utf8 -B -m omega_world.rehearsal <rpc-url>[,<rpc-url>...] <config.json> <state dir> <report.json>
    python -X utf8 -B -m omega_world.rehearsal deploy-token <rpc-url>[,<rpc-url>...] <config.json>

with OMEGA_REHEARSAL_KEYS = a directory holding deployer.key, owner.key, agent.key, relayer.key, executor.key, liar.key and
watcher.key (one 32-byte hex secret each, funded with test ETH by the operator). The keys are read from those files only
inside LocalTestSigner objects and are never printed, logged or written. Requires explicit user approval (testnet keys
and funds): this module does not decide to run itself."""
import json
import os
import sys
import time
from pathlib import Path
from omega_compute import evm_step as E
from omega_compute.dispute_agent import Board, Trace, Watchtower
from omega_kernel.settlement.evm import TX_GAS_CAP, TEST_CHAIN_IDS, Chain, RpcError, account_id, until_mined
from omega_kernel.settlement.evm_crypto import LocalTestSigner, call_data
from omega_world import deploy as DP
from omega_world import indexer as IX
from omega_world.executor import AcceptPolicy, WorldExecutor
from omega_world.plan import Plan, Task
from omega_world.sdk import WorldClient

ROOT = Path(__file__).resolve().parent.parent
ROLES = ('deployer', 'owner', 'agent', 'relayer', 'executor', 'liar', 'watcher')
PROGRAMS = {
    'sum': (('PUSH', 0), ('LOAD', 0), ('DUP', 0), ('JZ', 11), ('DUP', 0), ('SWAP', 2), ('ADD',), ('SWAP', 1),
            ('PUSH', 1), ('SUB',), ('JMP', 2), ('POP',), ('HALT',)),
    'add1': (('LOAD', 0), ('PUSH', 1), ('ADD',), ('HALT',)),
    'mul2': (('LOAD', 0), ('PUSH', 2), ('MUL',), ('HALT',)),
}
EXPECTED = {'A': 55, 'B': 56, 'C': 112}
MAINNET_CONTRACTS = ('OVM0Step', 'OVM0Inbox', 'OVM0Dispute', 'OmegaGraphEscrow', 'OmegaSuperRootReferee', 'OmegaBondVault',
                     'OmegaCannonGames', 'OmegaCannonReferee')


def load_signers(directory):
    """role -> signer from <directory>/<role>.key; the secret never leaves the signer object"""
    out = {}
    for role in ROLES:
        text = (Path(directory) / f'{role}.key').read_text().strip()
        out[role] = LocalTestSigner(bytes.fromhex(text[2:] if text.startswith('0x') else text))
        del text
    return out


def _sleep_wait(chain):
    """until the chain's clock has moved that far: deadlines are the chain's, not this machine's"""
    now = lambda: int(chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)

    def wait(seconds):
        end = now() + seconds
        while now() < end:
            time.sleep(min(15, max(1, end - now())))
    return wait


def _false_run(t):
    """the false executor's run: half of it honest, then an extra stack word, so the game ends in a real one-step proof"""
    k = max(1, t.n // 2)
    fake = [dict(s) for s in t.states[:k]] + [dict(s) | {'stack': list(s['stack']) + [777]} for s in t.states[k:]]
    return Trace(E, t.program, t.inputs, t.max_steps, fake)


def deploy_token(chain, deployer):
    """a TestToken (anyone can mint, no value) on a test chain: the address goes into the configuration's `token`"""
    if chain.chain_id not in TEST_CHAIN_IDS:
        raise RuntimeError('TEST_TOKEN_ON_A_PRODUCTION_CHAIN')
    return chain.deploy(deployer, bytes.fromhex(json.loads(
        (ROOT / 'omega_evm' / 'out' / 'TestToken.sol' / 'TestToken.json').read_text())['bytecode']['object'][2:]))


class _State:
    """rehearsal.json: replaced whole, read at the start of each run"""

    def __init__(self, folder):
        self.path = Path(folder) / 'rehearsal.json'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.d = json.loads(self.path.read_text(encoding='utf-8')) if self.path.exists() else {
            'runs': 0, 'gas': [], 'included': [], 'wall_s': 0.0}

    def save(self):
        IX._replace(self.path, json.dumps(self.d, sort_keys=True).encode('utf-8'))


def _pct(values, p):
    v = sorted(values)
    return v[min(len(v) - 1, int(len(v) * p))]


def run(chain, signers, config, state_dir, wait=None, stake=100_000, deposit=1_000_000, confirmations=0, on_phase=None):
    """-> report; state_dir as in the module docstring. confirmations: the archive's depth (a real network reorganizes).
    on_phase(name): called at each phase, for tests that stop the run there"""
    try:
        DP.require_writable(chain, config)
    except DP.ConfigError as e:
        raise RuntimeError(str(e)) from e
    token = bytes.fromhex(config['token'][2:])
    if chain.rpc('eth_getCode', config['token'], 'latest') in ('0x', '0x0', None):
        raise RuntimeError('REHEARSAL_TOKEN_HAS_NO_CODE')
    st, phase = _State(state_dir), on_phase or (lambda name: None)
    st.d['runs'] += 1
    t0, wall0 = time.time(), st.d['wall_s']
    s = signers
    wait = wait or _sleep_wait(chain)
    raw_send, raw_deploy = chain.send, chain.deploy_tx

    def timed(send):
        t = time.monotonic()
        out = until_mined(send)
        st.d['included'].append(round(time.monotonic() - t, 3))
        return out

    def send(signer, to, data, value=0):
        rc = timed(lambda: raw_send(signer, to, data, value=value))
        st.d['gas'].append((data[:4].hex(), int(rc['gasUsed'], 16)))
        return rc
    chain.send = send
    chain.deploy_tx = lambda signer, *a: timed(lambda: raw_deploy(signer, *a))
    try:
        return _run(chain, s, config, token, st, Path(state_dir), wait, stake, deposit, confirmations, phase, t0, wall0)
    finally:
        chain.send, chain.deploy_tx = raw_send, raw_deploy
        st.d['wall_s'] = wall0 + time.time() - t0
        st.save()


def _fund(chain, signer, token, role, amount):
    tok = lambda: int.from_bytes(chain.call(token, call_data('balanceOf(address)', signer.address)), 'big')
    if tok() < amount:
        try:
            chain.send(signer, token, call_data('mint(address,uint256)', signer.address, amount - tok()))
        except RpcError as e:
            raise RuntimeError(f'REHEARSAL_TOKEN_SHORT:{role}') from e


def _run(chain, s, cfg, token, st, folder, wait, stake, deposit, confirmations, phase, t0, wall0):
    if 'manifest' not in st.d:
        manifest = DP.deploy(chain, s['deployer'], cfg)
        verified = DP.verify(chain, manifest, cfg)
        if not verified['ok']:
            raise RuntimeError(f'VERIFY_FAILED:{verified}')
        st.d.update(manifest=manifest, verified=verified, acct=account_id(f'acct:rehearsal:{int(t0)}').hex())
        st.save()
    manifest, verified = st.d['manifest'], st.d['verified']
    phase('deployed')
    addr = {x['contract']: bytes.fromhex(x['address'][2:]) for x in manifest['steps']}
    escrow, game = addr['OmegaGraphEscrow'], addr['OVM0Dispute']
    acct = bytes.fromhex(st.d['acct'])
    from_block = manifest['from_block']
    archive = folder / 'archive.jsonl'
    ex, liar = s['executor'], s['liar']
    bond = cfg['dispute']['bond_wei']

    def client_and_players():
        board = Board(chain, game, from_block=from_block)  # log scans from the deployment block (D15)
        client = WorldClient(chain, escrow, s['agent'], s['relayer'], token=token, boards={game: board}, archive=archive,
                             confirmations=confirmations)
        policy = AcceptPolicy(frozenset({acct}), frozenset({game}), min_price=1, max_cover=stake)
        return client, [WorldExecutor(board, client.esc, liar, bond, lie=_false_run, policy=policy),
                        WorldExecutor(board, client.esc, ex, bond, policy=policy), Watchtower(board, s['watcher'], bond, E)]
    client, players = client_and_players()
    if not st.d.get('setup'):
        _fund(chain, s['owner'], token, 'owner', deposit)
        client.open_account(s['owner'], acct, deposit=deposit,
                            mandate={'max_per_job': 10_000, 'max_per_window': 100_000, 'window': 86_400,
                                     'valid_until': 2_000_000_000, 'max_steps': 10_000},
                            programs=list(PROGRAMS.values()), executors=[ex.address, liar.address], referees={game: 2},
                            agent=s['agent'].address)
        for who, role in ((ex, 'executor'), (liar, 'liar')):
            short = stake - client.esc.bond_of(who.address)
            if short > 0:
                _fund(chain, who, token, role, short)
                client.stake(who, short)
        st.d['setup'] = True
        st.save()
    phase('account')
    if 'plan' not in st.d:
        exs, ref = ('0x' + liar.address.hex(), '0x' + ex.address.hex()), '0x' + game.hex()
        honest = ('0x' + ex.address.hex(),)
        plan = client.plan(acct, [Task('A', PROGRAMS['sum'], (10,), (), exs, ref, comp=50),
                                  Task('B', PROGRAMS['add1'], (), ('A',), honest, ref, comp=50),
                                  Task('C', PROGRAMS['mul2'], (), ('B',), honest, ref, comp=50)],
                           ttl=cfg['dispute']['window'] * 4)
        st.d.update(plan=plan.to_json(), start=client.now())
        st.save()
    plan = Plan.from_json(st.d['plan'])
    phase('planned')
    status, game_seen = None, False
    for _ in range(2_000):
        status = client.run_local(plan, players, warp=wait, rounds=1)
        st.d['wall_s'] = wall0 + time.time() - t0
        st.save()
        if client.orchestrator(plan).done():
            break
        if not game_seen and client.esc.node(plan.key('A', 0))['claimId'] and Board(chain, game, from_block).counts()[1]:
            game_seen = True
            phase('disputed')
            if 'restart' not in st.d:
                # a restart in the middle of the game: all that was in memory is gone, the next move is made by new objects
                t, moves = time.monotonic(), [m for p in players for m in p.moves]
                client, players = client_and_players()
                st.d['restart'] = {'moves_before': len(moves), 'state': {k: v['state'] for k, v in status.items()}}
                status = client.run_local(plan, players, warp=wait, rounds=1)
                st.d['restart'] |= {'recovered_s': round(time.monotonic() - t, 3), 'moves_first_pass': sum(
                    len(p.moves) for p in players), 'attempts_used': {k: v['attempts_used'] for k, v in status.items()}}
                st.save()
    phase('finished')
    orch = client.orchestrator(plan)
    # settling only credits the free balance: a payment is real once withdrawBond has moved the tokens
    free = client.esc.bond_of(ex.address)
    earned = free + client.esc.totals()['bondsHeld'] - stake  # the bonds stay held until expiry
    tok = lambda: int.from_bytes(chain.call(token, call_data('balanceOf(address)', ex.address)), 'big')
    tok0 = tok()
    if free:
        client.unstake(ex, free)
    withdrawn = tok() - tok0
    if 'withdrawn' in st.d:  # taken in a run that stopped after it: the report is about the first time
        free, earned, withdrawn = st.d['withdrawn']['free'], st.d['withdrawn']['earned'], st.d['withdrawn']['withdrawn']
    st.d['withdrawn'] = {'free': free, 'earned': earned, 'withdrawn': withdrawn}
    st.save()
    last = int(chain.rpc('eth_blockNumber'), 16)
    while int(chain.rpc('eth_blockNumber'), 16) - last < confirmations:  # until the archive can hold the last event
        wait(12)
    health, alerts = client.health()
    recs, head = IX.verify_archive(archive)
    on_chain = client.ix.check_on_chain(recs)
    by = {}
    for sel, g in st.d['gas']:
        by.setdefault(sel, []).append(g)
    outputs = {k: v['output'] for k, v in status.items()}
    first = {t.name: orch.attempts(t.name)[0][2]['state'] for t in plan.tasks}
    comps = sum(r['args']['comp'] for r in recs if r['event'] == 'Voided' and r['args']['compToExecutor']
                and IX.rebuild(recs)[r['args']['key']]['executor'] == '0x' + ex.address.hex())
    lost = client.esc.bond_of(liar.address)
    dispute = _dispute_report(chain, client, plan, recs)
    deployed = [x['contract'] for x in manifest['steps']]
    included = st.d['included']
    return {'chain_id': chain.chain_id, 'config': cfg['name'], 'token': cfg['token'], 'manifest': manifest, 'verify': verified,
            'outputs': outputs, 'executor_earned': earned, 'executor_withdrawn': withdrawn, 'comps': comps,
            'first_attempts': first, 'dispute': dispute, 'restart': st.d.get('restart'), 'runs': st.d['runs'],
            'liar_free_stake_left': lost,
            'ok': (outputs == EXPECTED and health == 'ok' and not on_chain and withdrawn == free
                   and earned == sum(t.price for t in plan.tasks) + comps and first['A'] == 'rejected'
                   and dispute['games'] >= 1 and 'restart' in st.d),
            'final_settlement_chain_s': client.now() - st.d['start'], 'wall_s': round(wall0 + time.time() - t0, 1),
            'inclusion_s': {'n': len(included), 'mean': round(sum(included) / len(included), 3), 'p50': _pct(included, 0.5),
                            'p90': _pct(included, 0.9), 'max': round(max(included), 3)},
            'scope': {'deployed': deployed, 'not_deployed': [c for c in MAINNET_CONTRACTS if c not in deployed],
                      'paths_exercised': ['OVM0Dispute'], 'state_dir': str(folder)},
            'health': health, 'alerts': [a.code for a in alerts], 'archive_records': len(recs),
            'archive_head': head, 'archive_mismatch': on_chain,
            'gas_by_selector': {k: {'n': len(v), 'mean': sum(v) // len(v)} for k, v in by.items()}}


def _dispute_report(chain, client, plan, recs):
    """what the game cost in time, from the archive: the chain's seconds from the false claim to the challenge is the
    watcher's reaction, inclusion of its transaction included"""
    at = lambda block: int(chain.rpc('eth_getBlockByNumber', hex(block), False)['timestamp'], 16)
    cid = client.esc.node(plan.key('A', 0))['claimId']
    h = IX.disputes(recs).get(cid)
    if not h or not h['games']:
        return {'games': 0}
    g = h['games'][0]
    resolved = next((r['block'] for r in recs if r['event'] == 'ClaimResolved' and r['args']['id'] == cid), None)
    claimed, challenged = at(h['claimed']['block']), at(g['block'])
    return {'games': len(h['games']), 'moves': g['moves'], 'watcher_reaction_chain_s': challenged - claimed,
            'claim_to_rejected_chain_s': at(resolved) - claimed if resolved else None, 'claim_status': h['status']}


def _chain(urls, config, state_dir=None):
    from omega_world.daemon import FailoverRpc
    return Chain(FailoverRpc(urls.split(','), config['chain_id'], allow_remote=True, timeout=60), config['chain_id'],
                 state_dir=state_dir, tx_gas_cap=config.get('tx_gas_cap', TX_GAS_CAP))


if __name__ == '__main__':
    if sys.argv[1] == 'deploy-token':
        c = json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))  # the template may still say REQUIRED
        chain = _chain(sys.argv[2], c)
        print('0x' + deploy_token(chain, load_signers(os.environ['OMEGA_REHEARSAL_KEYS'])['deployer']).hex())
        sys.exit(0)
    urls, cfg_path, folder, report = sys.argv[1:5]
    conf = DP.load_config(cfg_path)
    chain = _chain(urls, conf, folder)  # a killed run finds its transaction in flight again
    signers = load_signers(os.environ['OMEGA_REHEARSAL_KEYS'])
    while True:
        try:
            rep = run(chain, signers, conf, folder, confirmations=2)
            break
        except OSError as e:  # every endpoint down: what was done is in the folder, and the same run goes on from there
            print(json.dumps({'rpc_down': type(e).__name__}), flush=True)
            time.sleep(60)
    Path(report).write_text(json.dumps(rep, indent=1, default=str), encoding='utf-8')
    print(json.dumps({k: rep[k] for k in ('ok', 'outputs', 'health', 'final_settlement_chain_s', 'wall_s')}))
