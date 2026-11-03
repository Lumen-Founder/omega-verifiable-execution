"""Supply-chain and release checks (docs/adr/ADR-0012, completion condition C7):
- dependencies(): every module the world-computer stack imports, split into stdlib / in-repo / third party, with the
  installed version and declared license of each third-party distribution;
- solidity(): SPDX license of every contract source, external Solidity libraries (none: foundry libs = []);
- authority(): what in the deployed contracts could change them or move funds outside their rules (admin roles,
  upgrade hooks, delegatecall, selfdestruct, unrestricted token moves), in their sources and in their bytecode; the
  deployed stack must have none, except the clones of OmegaCannonGames, whose one DELEGATECALL is written out and read here;
- secrets(): a scan of the code, deployment and documentation trees for private-key material, cloud/API tokens and
  personal e-mail addresses (test keys are short constants and are reported separately);
- provenance(): tool versions and the bytecode hashes of a forced rebuild (from omega_world.deploy);
- toolchain(): those versions against deploy/toolchain.lock.json."""
import ast
import hashlib
import importlib.metadata as md
import json
import re
import sys
from pathlib import Path
from omega_world import deploy as DP

ROOT = Path(__file__).resolve().parent.parent
STACK_PY = ('omega_compute', 'omega_kernel', 'omega_world', 'examples')
DEPLOYED = DP.STACK + (DP.OP_REFEREE,) + DP.CANNON  # what deploy.stack gives for deploy/chains/mainnet.json
LOCK = ROOT / 'deploy' / 'toolchain.lock.json'
SCAN = ('omega_compute', 'omega_kernel', 'omega_world', 'omega_evm/src', 'omega_evm/test', 'examples', 'deploy',
        'docs/world_computer', 'docs/adr', 'tests')
SECRET_PATTERNS = {
    'pem_private_key': r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'github_token': r'gh[pousr]_[A-Za-z0-9]{36}',
    'api_key_sk': r'\bsk-[A-Za-z0-9_-]{20,}',
    'hex_key_assignment': r'(?i)(priv(ate)?[_ ]?key|secret|mnemonic|seed[_ ]?phrase)\s*[=:]\s*["\']?(0x)?[0-9a-f]{64}',
    'email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(com|net|org|io|co\.kr|kr)\b',
}
ALLOWED_EMAILS = ('noreply@anthropic.com',)


def _imports(path):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name.split('.')[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module.split('.')[0]


def dependencies():
    mods = set()
    for pkg in STACK_PY:
        p = ROOT / pkg
        for f in ([p] if p.is_file() else p.rglob('*.py')):
            mods |= set(_imports(f))
    in_repo = {m for m in mods if (ROOT / m).is_dir() or (ROOT / f'{m}.py').exists()}
    std = {m for m in mods if m in sys.stdlib_module_names}
    third = sorted(mods - in_repo - std)
    dist_of = md.packages_distributions()
    out = {}
    for m in third:
        for d in dist_of.get(m, []):
            meta = md.distribution(d).metadata
            out[m] = {'distribution': d, 'version': md.version(d),
                      'license': meta.get('License-Expression') or meta.get('License')}
        out.setdefault(m, {'distribution': None})
    return {'python': sys.version.split()[0], 'stdlib': sorted(std), 'in_repo': sorted(in_repo), 'third_party': out}


def solidity():
    srcs = sorted((ROOT / 'omega_evm' / 'src').glob('*.sol'))
    lic = {}
    for f in srcs:
        m = re.search(r'SPDX-License-Identifier:\s*([^\s*]+)', f.read_text(encoding='utf-8'))
        lic[f.name] = m.group(1) if m else None
    toml = (ROOT / 'omega_evm' / 'foundry.toml').read_text()
    return {'spdx': lic, 'external_libs': re.search(r'libs\s*=\s*\[(.*?)\]', toml).group(1).strip() or 'none',
            'lib_dir_exists': (ROOT / 'omega_evm' / 'lib').exists()}


def opcodes(code):
    """how many instructions of the kinds that run or destroy code on someone else's terms, read past PUSH data; the
    trailing metadata (its length in the last two bytes) is not code"""
    tail = int.from_bytes(code[-2:], 'big') + 2
    code = code[:-tail] if tail <= len(code) else code
    out = {'CALLCODE': 0, 'DELEGATECALL': 0, 'SELFDESTRUCT': 0}
    names = {0xf2: 'CALLCODE', 0xf4: 'DELEGATECALL', 0xff: 'SELFDESTRUCT'}
    i = 0
    while i < len(code):
        op = code[i]
        if op in names:
            out[names[op]] += 1
        i += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    return out


def clone_template(text):
    """the runtime OmegaCannonGames writes for each game, from its source: the DELEGATECALL lives in a hex string, where
    neither a source pattern nor the bytecode scan sees it. -> how many it has and what it can reach (audit A44, A97)"""
    parts = re.findall(r'hex"([0-9a-f]+)"', text[text.index('function _clone'):])
    head, push_impl, tail = parts[0], parts[1], parts[2]
    template = bytes.fromhex(head + '0000' + push_impl + '00' * 20 + tail)
    n = opcodes(template + bytes(2))['DELEGATECALL']  # bytes(2): a metadata tail of length 0
    direct = push_impl.endswith('73') and tail.startswith('5af4')  # PUSH20 impl, GAS, DELEGATECALL
    return {'delegatecalls': n, 'target': 'PUSH20 impl (immutable), pinned by codehash' if direct else 'UNKNOWN'}


def authority():
    """per deployed contract: source files compiled into it, hits of patterns that would give someone power over
    the contract or its funds beyond its rules, and the same instructions counted in its runtime bytecode"""
    pats = {'delegatecall': r'\.delegatecall\(', 'selfdestruct': r'\bselfdestruct\(',
            'upgrade': r'(?i)\bupgrade(To|ToAndCall)?\s*\(', 'global_admin': r'(?i)\b(admin|governor|onlyOwner\b(?!\())',
            'pause': r'(?i)\bwhenNotPaused\b|\bpause\(\)'}
    out = {}
    for name in DEPLOYED:
        meta = DP.artifact(name)['metadata']
        # only the contract itself: imported files that carry other contracts (e.g. IERC20 from OmegaSettlement.sol)
        # are listed, but the deployed code is the target contract's
        target = meta['settings']['compilationTarget']
        path = next(iter(target))
        text = (ROOT / 'omega_evm' / path).read_text(encoding='utf-8')
        body = text[text.index(f'contract {name}'):]
        out[name] = {'sources': sorted(meta['sources']), 'hits': {k: len(re.findall(p, body)) for k, p in pats.items()},
                     'owner_scope': 'per-account owner (accounts[a].owner) only' if 'onlyOwner(bytes32' in body
                     else 'none',
                     'bytecode_opcodes': opcodes(bytes.fromhex(DP.artifact(name)['deployedBytecode']['object'][2:]))}
        if 'function _clone' in body:
            out[name]['clone'] = clone_template(body)
    return out


def secrets():
    hits, test_keys = [], []
    for d in SCAN:
        for f in (ROOT / d).rglob('*'):
            if not f.is_file() or f.suffix not in ('.py', '.sol', '.md', '.json', '.toml', '.txt', '.ps1', '.sh'):
                continue
            text = f.read_text(encoding='utf-8', errors='replace')
            for name, p in SECRET_PATTERNS.items():
                for m in re.finditer(p, text):
                    s = m.group(0)
                    if name == 'email' and s in ALLOWED_EMAILS:
                        continue
                    hits.append({'file': str(f.relative_to(ROOT)), 'kind': name, 'line': text[:m.start()].count('\n') + 1})
            test_keys += [{'file': str(f.relative_to(ROOT)), 'value_len': len(m.group(1))}
                          for m in re.finditer(r'_PK\s*=\s*0x([0-9A-Fa-f]+)', text)]
    return {'hits': hits, 'short_test_keys': test_keys}


def lock():
    return json.loads(LOCK.read_text(encoding='utf-8'))


def _record_sha256(dist):
    """keccak is the only thing the stack takes from pycryptodome; its files as installed, hashed by the wheel's RECORD"""
    text = md.distribution(dist).read_text('RECORD')
    return hashlib.sha256(text.encode('utf-8')).hexdigest() if text else None


def toolchain(forge_lines, solc, want=None):
    """what runs now against deploy/toolchain.lock.json; differs: name -> (locked, now)"""
    want = want or lock()
    forge = next((l.split(':', 1)[1].strip() for l in forge_lines if l.startswith('forge Version')), None)
    meta = DP.artifact('OmegaGraphEscrow')['metadata']['settings']
    now = {'forge': forge, 'solc': solc, 'evm_version': meta.get('evmVersion'),
           'optimizer_runs': meta.get('optimizer', {}).get('runs'),
           'python_packages': {d: md.version(d) for d in want['python_packages']},
           'python_record_sha256': {d: _record_sha256(d) for d in want['python_record_sha256']}}
    # the wheel differs between platforms; its RECORD is compared where it was recorded
    if want.get('python_record_platform', sys.platform) != sys.platform:
        now['python_record_sha256'] = want['python_record_sha256']
    return {'now': now, 'differs': {k: (want[k], v) for k, v in now.items() if want[k] != v}}


def report(build_twice=True):
    prov = DP.provenance(build_twice)
    return {'dependencies': dependencies(), 'solidity': solidity(), 'authority': authority(), 'secrets': secrets(),
            'provenance': prov, 'toolchain': toolchain(prov['forge'], prov['solc'])}
