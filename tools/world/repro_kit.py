"""The outside team's kit (docs/world_computer/REPRODUCE.md): run the end-to-end job with a dispute, payment and a refund, then
compare what happened with someone else's run.

    python -X utf8 -B tools/world/repro_kit.py local <work dir>
        own loopback anvil with Sepolia's chain id, throwaway keys made here, time advanced. No funds, nothing leaves the machine.
    OMEGA_REHEARSAL_KEYS=<dir> python -X utf8 -B tools/world/repro_kit.py network <rpc,rpc> <config.json> <work dir>
        a public test chain, with your test keys and test ether. Takes hours: it really waits. Run it again to resume.
    python -X utf8 -B tools/world/repro_kit.py check <RUN.json> <rpc,rpc> <out.json>
        no key: the transcript of a run from the chain's logs alone
    python -X utf8 -B tools/world/repro_kit.py compare <a.json> <b.json>
        exit code 0: same contracts, same accounting
    python -X utf8 -B tools/world/repro_kit.py bundle <out dir>
        the kit as one local zip of the committed files
"""
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from omega_kernel.settlement.evm import Chain, ReadOnlyChain, Rpc  # noqa: E402
from omega_world import deploy as DP  # noqa: E402
from omega_world import e2e as E2E  # noqa: E402
from omega_world import rehearsal as RH  # noqa: E402
from omega_world.daemon import FailoverRpc  # noqa: E402

SEPOLIA = 11_155_111
FOUNDRY = Path.home() / '.foundry' / 'bin'
BUNDLE = ['omega_evm/src', 'omega_evm/foundry.toml', 'omega_evm/.gitignore', 'omega_world', 'omega_compute', 'omega_kernel',
          'deploy', 'tools/world/repro_kit.py', 'tests/__init__.py', 'tests/test_omega_e2e.py', 'LICENSE', 'runs/sepolia',
          'docs/world_computer/REPRODUCE.md', 'docs/world_computer/LAYERS_AND_TRUST.md', 'docs/world_computer/THREAT_MODEL.md',
          'docs/world_computer/BRIEF_EN.md']


def tool(name):
    found = shutil.which(name) or shutil.which(str(FOUNDRY / name))
    if not found:
        raise SystemExit(f'NEEDS_FOUNDRY:{name}')
    return found


def environment():
    """what ran it, and nothing about who: no host name, no user, no path"""
    run = lambda *c: subprocess.run(c, capture_output=True, text=True, timeout=60).stdout.splitlines()[0]
    return {'os': platform.system(), 'machine': platform.machine(), 'python': platform.python_version(),
            'forge': run(tool('forge'), '--version')}


def build():
    subprocess.run([tool('forge'), 'build'], cwd=ROOT / 'omega_evm', check=True, capture_output=True, timeout=1800)


def finish(chain, signers, cfg, state, work, wait, out):
    report = RH.run(chain, signers, cfg, state, wait=wait, confirmations=out)
    closed = E2E.close(chain, signers, cfg, state, wait=wait, confirmations=out)
    run = E2E.run_description(state, signers, cfg)
    (work / 'RUN.json').write_text(json.dumps(run, indent=1), encoding='utf-8')
    got = E2E.transcript(chain, run)
    result = {'ok': report['ok'] and closed['ok'] and got['code_matches_build'], 'environment': environment(),
              'rehearsal': {k: report[k] for k in ('ok', 'outputs', 'dispute', 'restart', 'scope', 'health', 'inclusion_s',
                                                   'executor_earned', 'executor_withdrawn')},
              'close': closed, 'transcript': got}
    (work / 'RESULT.json').write_text(json.dumps(result, indent=1, default=str), encoding='utf-8')
    (work / 'TRANSCRIPT.json').write_text(json.dumps(got, indent=1), encoding='utf-8')
    print(json.dumps({k: (result[k] if k == 'ok' else got[k]) for k in ('ok', 'economics_sha256', 'build_sha256')}))
    return 0 if result['ok'] else 1


def local(work):
    work.mkdir(parents=True, exist_ok=True)
    build()
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    anvil = subprocess.Popen([tool('anvil'), '--host', '127.0.0.1', '--port', str(port), '--chain-id', str(SEPOLIA), '--silent',
                              '--accounts', '0', '--max-persisted-states', '0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        rpc = Rpc(f'http://127.0.0.1:{port}')
        for _ in range(100):
            try:
                rpc('eth_chainId')
                break
            except OSError:
                time.sleep(0.1)
        with tempfile.TemporaryDirectory(dir=work) as keys:  # throwaway: gone at the end, and the chain with them
            for role in RH.ROLES:
                (Path(keys) / f'{role}.key').write_text(secrets.token_bytes(32).hex())
            signers = RH.load_signers(keys)
        for sg in signers.values():
            rpc('anvil_setBalance', '0x' + sg.address.hex(), hex(10 ** 20))
        chain = Chain(rpc, SEPOLIA)
        cfg = json.loads((ROOT / 'deploy' / 'chains' / 'sepolia.json').read_text(encoding='utf-8'))
        cfg['token'] = '0x' + RH.deploy_token(chain, signers['deployer']).hex()
        cfg['dispute'] |= {'bond_wei': 10 ** 16, 'reward_wei': 5 * 10 ** 15, 'window': 3600, 'clock': 3600}
        path = work / 'config.json'
        path.write_text(json.dumps(cfg, indent=1), encoding='utf-8')

        def warp(sec):
            rpc('evm_increaseTime', hex(int(sec)))
            rpc('evm_mine')
        state = work / 'state'
        if state.exists():
            raise SystemExit('WORK_DIR_USED: a local run starts from nothing, its chain is gone')
        return finish(chain, signers, DP.load_config(path), state, work, warp, 0)
    finally:
        anvil.kill()
        anvil.wait(10)


def network(urls, cfg_path, work):
    work.mkdir(parents=True, exist_ok=True)
    build()
    cfg = DP.load_config(cfg_path)
    chain = RH._chain(urls, cfg, work / 'state')
    signers = RH.load_signers(os.environ['OMEGA_REHEARSAL_KEYS'])
    while True:
        try:
            return finish(chain, signers, cfg, work / 'state', work, None, 2)
        except OSError as e:  # every endpoint down: what was done is in the folder, and the same run goes on from there
            print(json.dumps({'rpc_down': type(e).__name__}), flush=True)
            time.sleep(60)


def check(run_path, urls, out):
    build()
    run = json.loads(Path(run_path).read_text(encoding='utf-8'))
    rpc = FailoverRpc(urls.split(','), run['chain_id'], allow_remote=True, timeout=60)
    got = E2E.transcript(ReadOnlyChain(rpc, run['chain_id']), run)
    Path(out).write_text(json.dumps(got, indent=1), encoding='utf-8')
    print(json.dumps({k: got[k] for k in ('economics_sha256', 'build_sha256', 'code_matches_build')}))
    return 0 if got['code_matches_build'] else 1


def compare(a, b):
    diff = E2E.compare(*(json.loads(Path(x).read_text(encoding='utf-8')) for x in (a, b)))
    print(json.dumps({'same': not diff, 'differences': diff}, indent=1))
    return 1 if diff else 0


def bundle(out):
    """the kit as one zip of the committed files, hashed and scanned for secrets (a hit stops it). Nothing is sent anywhere"""
    from omega_world import supply_chain as SC
    git = lambda *a: subprocess.run(['git', *a], cwd=ROOT, capture_output=True, check=True).stdout
    names = [p for p in git('ls-files', '-z', '--', *BUNDLE).decode().split('\0') if p and '__pycache__' not in p]
    head = git('rev-parse', 'HEAD').decode().strip()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    manifest, hits = {'head': head, 'files': {}}, []
    path = out / f'OMEGA_REPRO_KIT_{head[:8]}.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in names:
            data = git('show', f'HEAD:{p}')
            text = data.decode('utf-8', errors='replace')
            hits += [{'file': p, 'kind': kind} for kind, pat in SC.SECRET_PATTERNS.items() for m in re.finditer(pat, text)
                     if not (kind == 'email' and m.group(0) in SC.ALLOWED_EMAILS)]
            z.writestr(p, data)
            manifest['files'][p] = hashlib.sha256(data).hexdigest()
        z.writestr('KIT_MANIFEST.json', json.dumps(manifest, indent=1))
    if hits:
        path.unlink()
        raise SystemExit(f'SECRET_SCAN:{json.dumps(hits)}')
    print(json.dumps({'zip': path.name, 'files': len(names), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))
    return 0


def main(argv):
    cmd = argv[0] if argv else ''
    if cmd == 'bundle' and len(argv) == 2:
        return bundle(argv[1])
    if cmd == 'local' and len(argv) == 2:
        return local(Path(argv[1]).resolve())
    if cmd == 'network' and len(argv) == 4:
        return network(argv[1], argv[2], Path(argv[3]).resolve())
    if cmd == 'check' and len(argv) == 4:
        return check(*argv[1:])
    if cmd == 'compare' and len(argv) == 3:
        return compare(*argv[1:])
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
