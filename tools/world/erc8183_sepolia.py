"""OmegaEvaluator8183 on Sepolia against the r2 deployment: three ERC-8183 jobs, each linked to a node the r2 run already
decided, and decided by the adapter from what OmegaGraphEscrow says.

    OMEGA_REHEARSAL_KEYS=<test keys> <venv>/python -X utf8 -B tools/world/erc8183_sepolia.py
        <rpc,rpc> <config> <r2 state dir> <own state dir> <report.json>

- A#1 (FINAL, paid to the executor), provider = that executor: submitted, then `decide` completes it (OMEGA_PAID).
- A#0 (REJECTED), provider = the executor: `decide` rejects it while funded (OMEGA_NOT_PAID).
- B#1 (FINAL, paid to the executor), provider = the deployer: `decide` rejects it (OMEGA_PROVIDER_MISMATCH).

What this is not: the commerce contract is our MockAgenticCommerce (test/OmegaEvaluator8183.t.sol), written from the EIP's
text; no ERC-8183 deployment of someone else is involved, and it moves no budget. It shows the adapter reading a real
OmegaGraphEscrow on a real chain and driving the job's state from it. Test chains only; it can be run again and goes on
from its state file.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from omega_compute.graph_escrow import GraphEscrow  # noqa: E402
from omega_kernel.settlement.evm import TEST_CHAIN_IDS  # noqa: E402
from omega_kernel.settlement.evm_crypto import call_data, selector, word, words  # noqa: E402
from omega_world import deploy as DP  # noqa: E402
from omega_world.e2e import _keys  # noqa: E402
from omega_world.plan import Plan  # noqa: E402
from omega_world.rehearsal import _chain, load_signers  # noqa: E402

ADAPTERS = ROOT / 'omega_adapters'
STATUS = {0: 'Open', 1: 'Funded', 2: 'Submitted', 3: 'Completed', 4: 'Rejected', 5: 'Expired'}
EXPECTED = {'J1': ('Completed', 'OMEGA_PAID'), 'J2': ('Rejected', 'OMEGA_NOT_PAID'), 'J3': ('Rejected', 'OMEGA_PROVIDER_MISMATCH')}
DAY = 86_400


def artifact(src, name):
    a = json.loads((ADAPTERS / 'out' / src / f'{name}.json').read_text(encoding='utf-8'))
    return a['bytecode']['object'], a['deployedBytecode']


def masked(runtime, refs):
    """the runtime with the immutable slots zeroed, the way forge reports them"""
    b = bytearray(runtime)
    for slots in refs.values():
        for s in slots:
            b[s['start']:s['start'] + s['length']] = bytes(s['length'])
    return bytes(b)


def create_job(provider, evaluator, expired_at, desc):
    text = desc.encode()
    pad = text + bytes(-len(text) % 32)
    return (selector('createJob(address,address,uint256,string)') + word(provider) + word(evaluator) + word(expired_at)
            + word(0x80) + word(len(text)) + pad)


def job_status(chain, commerce, jid):
    w = words(chain.call(commerce, call_data('getJob(uint256)', jid)))
    return STATUS[int.from_bytes(w[1 + 7], 'big')]  # word 0 points at the tuple; status is its 8th field


def reason_name(raw):
    return raw.rstrip(b'\0').decode() if raw.strip(b'\0') else ''


def main(argv):
    urls, cfg_path, r2_dir, folder, out = argv
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    cfg = DP.load_config(cfg_path)
    chain = _chain(urls, cfg, folder / 'tx')
    if chain.chain_id not in TEST_CHAIN_IDS or int(chain.rpc('eth_chainId'), 16) != cfg['chain_id']:
        raise SystemExit('TEST_CHAINS_ONLY')
    r2 = json.loads((Path(r2_dir) / 'rehearsal.json').read_text(encoding='utf-8'))
    escrow = next(bytes.fromhex(x['address'][2:]) for x in r2['manifest']['steps'] if x['contract'] == 'OmegaGraphEscrow')
    esc = GraphEscrow(chain, escrow)
    names = {v: k for k, v in _keys(Plan.from_json(r2['plan'])).items()}
    nodes = {n: esc.node(names[n]) for n in ('A#0', 'A#1', 'B#1')}
    if [nodes[n]['state'] for n in ('A#0', 'A#1', 'B#1')] != ['rejected', 'final', 'final']:
        raise SystemExit(f'R2_NODES_NOT_AS_EXPECTED:{ {n: v["state"] for n, v in nodes.items()} }')
    s = load_signers(os.environ['OMEGA_REHEARSAL_KEYS'])
    if nodes['A#1']['executor'] != s['executor'].address:
        raise SystemExit('A1_NOT_PAID_TO_THE_EXECUTOR_KEY')
    dep, exe = s['deployer'], s['executor']
    state = folder / 'erc8183.json'
    st = json.loads(state.read_text(encoding='utf-8')) if state.exists() else {'gas': {}, 'tx': {}}
    save = lambda: state.write_text(json.dumps(st, indent=1), encoding='utf-8')

    def send(step, signer, to, data):
        if step in st['tx']:
            return
        rc = chain.send(signer, to, data)
        st['tx'][step], st['gas'][step] = rc['transactionHash'], int(rc['gasUsed'], 16)
        save()

    forge = shutil.which('forge') or shutil.which(str(Path.home() / '.foundry' / 'bin' / 'forge'))
    if not forge:
        raise SystemExit('NEEDS_FOUNDRY:forge')
    subprocess.run([forge, 'build'], cwd=ADAPTERS, check=True, capture_output=True, timeout=1800)
    mock_init, mock_rt = artifact('OmegaEvaluator8183.t.sol', 'MockAgenticCommerce')
    ev_init, ev_rt = artifact('OmegaEvaluator8183.sol', 'OmegaEvaluator8183')
    for name, init, args in (('commerce', mock_init, ()), ('evaluator', ev_init, (escrow,))):
        if name not in st:
            addr, rc = chain.deploy_tx(dep, bytes.fromhex(init[2:]), *args)
            st[name], st['tx'][f'deploy_{name}'], st['gas'][f'deploy_{name}'] = '0x' + addr.hex(), rc['transactionHash'], int(rc['gasUsed'], 16)
            save()
    commerce, evaluator = bytes.fromhex(st['commerce'][2:]), bytes.fromhex(st['evaluator'][2:])
    code = {n: bytes.fromhex(chain.rpc('eth_getCode', st[n], 'latest')[2:]) for n in ('commerce', 'evaluator')}
    built = {'commerce': bytes.fromhex(mock_rt['object'][2:]), 'evaluator': bytes.fromhex(ev_rt['object'][2:])}
    refs = {'commerce': mock_rt.get('immutableReferences') or {}, 'evaluator': ev_rt.get('immutableReferences') or {}}
    st['code_matches_build'] = {n: masked(code[n], refs[n]) == masked(built[n], refs[n]) for n in code}
    if int.from_bytes(chain.call(evaluator, call_data('escrow()')), 'big') != int.from_bytes(escrow, 'big'):
        raise SystemExit('EVALUATOR_POINTS_ELSEWHERE')

    plan = {'J1': ('A#1', exe.address), 'J2': ('A#0', exe.address), 'J3': ('B#1', dep.address)}
    expired_at = int(chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16) + 30 * DAY
    st.setdefault('jobs', {})
    for j, (node, provider) in plan.items():
        if j not in st['jobs']:
            before = int.from_bytes(chain.call(commerce, call_data('jobCounter()')), 'big')
            send(f'{j}_create', dep, commerce, create_job(provider, evaluator, st.setdefault('expired_at', expired_at),
                                                          f'OMEGA node {node} of Sepolia run r2'))
            st['jobs'][j] = before + 1
            save()
        jid = st['jobs'][j]
        send(f'{j}_link', dep, evaluator, call_data('link(address,uint256,bytes32)', commerce, jid, names[node]))
        send(f'{j}_fund', dep, commerce, call_data('fund(uint256,uint256)', jid, 1_000))
    send('J1_submit', exe, commerce, call_data('submit(uint256)', st['jobs']['J1']))
    for j in plan:
        send(f'{j}_decide', dep, evaluator, call_data('decide(address,uint256)', commerce, st['jobs'][j]))

    got = {}
    for j, (node, provider) in plan.items():
        jid = st['jobs'][j]
        got[j] = {'node': node, 'node_state': nodes[node]['state'], 'job_id': jid, 'status': job_status(chain, commerce, jid),
                  'reason': reason_name(chain.call(commerce, call_data('reasonOf(uint256)', jid))),
                  'paid_to': '0x' + chain.call(commerce, call_data('paidTo(uint256)', jid))[12:].hex(),
                  'provider_is_node_executor': provider == nodes[node]['executor']}
    ok = all((got[j]['status'], got[j]['reason']) == EXPECTED[j] for j in EXPECTED) and all(st['code_matches_build'].values())
    report = {'ok': ok, 'chain_id': chain.chain_id, 'escrow': '0x' + escrow.hex(), 'commerce': st['commerce'],
              'evaluator': st['evaluator'], 'code_matches_build': st['code_matches_build'], 'jobs': got, 'expected': EXPECTED,
              'gas': st['gas'], 'tx': st['tx'],
              'scope': 'MockAgenticCommerce from the EIP text; no third-party ERC-8183 deployment; no budget moves'}
    Path(out).write_text(json.dumps(report, indent=1), encoding='utf-8')
    print(json.dumps({'ok': ok, 'jobs': {j: (v['status'], v['reason']) for j, v in got.items()}}))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
