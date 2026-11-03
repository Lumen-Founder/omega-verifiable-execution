"""Mutation testing of the deployable contracts (docs/world_computer/SECURITY_REVIEW.md section 6): how many
deliberately broken versions the test suites reject. Works on a copy of omega_evm in a scratch folder; the
repository is never modified.

Operators, one mutant per (line, operator), first occurrence on the line, code lines only:
  drop-guard   `if (c) revert E(...)` -> `if (false) revert E(...)`   (a check removed)
  cmp          one comparison flipped: < <=, > >=, == !=
  drop-lock    the nonReentrant modifier removed from one function
  drop-owner   the onlyOwner modifier removed from one function
  status       a `Status.X` written in an assignment replaced by the next status
  arith        one arithmetic operator swapped (second family)
  branch       the condition of an `if` that does not revert replaced by false (third family, audit A27: `if (d.coverHeld)`
               or a `return _trap(...)` is a decision no drop-guard reaches)
A mutant is killed when a suite fails, stillborn when it does not compile (counted apart), survived otherwise.
The OVM-0 contracts decide by running real traces, which only the Python stack can produce, so their mutants face the
pytest differential and dispute suites first and their forge suites after (audit A27, A62, A72).

    python -X utf8 -B -m omega_world.mutation <work dir> <report.json> [--only <previous report.json>] [--ops a,b]
        [--shard k/n] [file ...]
    python -X utf8 -B -m omega_world.mutation --merge <report.json> <shard report.json> ..."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EVM = REPO / 'omega_evm'
SUITES = ('OmegaGraphEscrowTest|OmegaGraphEscrowInvariantTest|OmegaGraphEscrowAccessTest|OmegaGraphEscrowEdgesTest|OmegaReauditTest|'
          'OmegaSuperRootRefereeTest|OmegaCannonTest')
OVM0_FILES = ('src/OVM0Dispute.sol', 'src/OVM0Step.sol', 'src/OVM0Inbox.sol')
OVM0_SUITES = 'OVM0EdgesTest|OVM0DisputeReentryTest|OVM0DisputeInvariantTest|SmtFindingsTest'
OVM0_PYTEST = ('tests/test_omega_evm_dispute.py', 'tests/test_omega_evm_step.py', 'tests/test_omega_dispute_agent.py')
# what the pytest suites import, copied next to the mutated omega_evm so they build and read the mutant's artifacts
OVM0_COPY = ('omega_compute', 'omega_kernel', 'tests/__init__.py',
             'tests/test_omega_evm.py', 'tests/test_omega_compute.py') + OVM0_PYTEST
# mutants that cannot change behaviour, with the reason; reported apart and left out of the score
EQUIVALENT = {
    ('src/OmegaGraphEscrow.sol', 'cmp >->>=', 'for (uint256 w = size; w >= 1; w >>= 1) {'):
        'at w == 1 the inner loop runs i < w / 2 = 0 times: one extra empty pass',
    ('src/OmegaGraphEscrow.sol', 'cmp <-><=', 'if (pg <= g) g = pg;'): 'pg == g assigns the same value',
    ('src/OmegaGraphEscrow.sol', 'cmp >->>=',
     'd.expiry = e >= type(uint64).max ? type(uint64).max : uint64(e); // saturate: never wrap into the past (D8)'):
        'at e == 2^64-1 both branches store 2^64-1',
    ('src/OmegaGraphEscrow.sol', 'cmp >->>=',
     'if (claimId >= type(uint64).max) revert ClaimMismatch(); // stored as uint64; never truncated'):
        'claim id 2^64-1 would need 2^64-1 referee claims; either way the bind reverts',
    ('src/OmegaGraphEscrow.sol', 'cmp >->>=',
     'if (uint256(g.s) >= HALF_N || (g.v != 27 && g.v != 28)) return address(0);'):
        's == HALF_N exactly needs a signature with that s: not producible (probability about 2^-256)',
    ('src/OmegaCannonReferee.sol', 'cmp >->>=', 'for (uint256 w = size; w >= 1; w >>= 1) {'):
        'at w == 1 the inner loop runs i < w / 2 = 0 times: one extra empty pass (the escrow\'s same loop)',
    ('src/OVM0Inbox.sol', 'cmp >->>=', 'while (size >= 1) {'):
        'at size == 1 size becomes 0 and the inner loop runs 0 times: one extra empty pass, then 0 >= 1 stops',
    ('src/OmegaCannonGames.sol', 'drop-guard', 'if (false) revert CloneFailed();'):
        'a failed create2 leaves game = 0, and the initialize call that follows reverts too (a high-level call to an '
        'address without code reverts): the same outcome with another error',
}
# a lock removed from a function that makes no state-changing external call (its referee reads are view calls, run
# as STATICCALL, which cannot change state) cannot be observed; the token paths are covered by the access suite.
# settle joined the set when it stopped calling the token (audit A60); a token hook that re-enters it from withdrawBond
# or a deposit finds their effects done and nothing cached, so only the order of two independent steps changes
LOCK_ONLY_STATIC = {'reserve', 'bind', 'verify', 'settle', 'reject', 'voidNode', 'expire', 'release', 'slash'}


def equivalent(file, op, code):
    if EQUIVALENT.get((file, op, code)):
        return EQUIVALENT[(file, op, code)]
    m = re.match(r'function (\w+)\(', code)
    if op == 'drop-lock' and m and m.group(1) in LOCK_ONLY_STATIC:
        return 'the function makes only static calls: no re-entry can reach it with a state change'
    return None


STATUSES = ('Posted', 'Claimed', 'Verified', 'Final', 'Rejected', 'Voided', 'Expired')
CMP = [(' < ', ' <= '), (' <= ', ' < '), (' > ', ' >= '), (' >= ', ' > '), (' == ', ' != '), (' != ', ' == ')]
# second operator family (SECURITY_REVIEW 6-2): arithmetic, one per line, first match
ARITH = [(' += ', ' -= '), (' -= ', ' += '), (' + ', ' - '), (' - ', ' + '), (' * ', ' / ')]


def _condition(code):
    """span of the condition of the first `if (` on the line, parentheses balanced; None without a whole one"""
    m = re.search(r'\bif \(', code)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(code) and depth:
        depth += {'(': 1, ')': -1}.get(code[i], 0)
        i += 1
    return (m.end(), i - 1) if depth == 0 else None


def mutants(text):
    lines = text.split('\n')
    out = []
    for i, line in enumerate(lines):
        code = line.split('//')[0]
        s = code.strip()
        if not s or s.startswith(('*', 'error ', 'event ', 'import ', 'pragma ')):
            continue
        m = re.search(r'if \((.+?)\) revert (\w+)\(', code)
        if m:
            out.append((i, 'drop-guard', line.replace(m.group(0), f'if (false) revert {m.group(2)}(', 1)))
        for a, b in CMP:
            if a in code:
                out.append((i, f'cmp {a.strip()}->{b.strip()}', line.replace(a, b, 1)))
                break
        if s.startswith('function ') and ' nonReentrant' in code:
            out.append((i, 'drop-lock', line.replace(' nonReentrant', '', 1)))
        if s.startswith('function ') and ' onlyOwner(' in code:
            out.append((i, 'drop-owner', re.sub(r' onlyOwner\([^)]*\)', '', line, count=1)))
        for a, b in ARITH:
            if a in code and not s.startswith(('for ', 'function ')):
                out.append((i, f'arith {a.strip()}->{b.strip()}', line.replace(a, b, 1)))
                break
        m = re.search(r'= Status\.(\w+)', code)
        if m and m.group(1) in STATUSES:
            nxt = STATUSES[(STATUSES.index(m.group(1)) + 1) % len(STATUSES)]
            out.append((i, f'status {m.group(1)}->{nxt}', line.replace(f'Status.{m.group(1)}', f'Status.{nxt}', 1)))
        span = _condition(code)
        if span and not code[span[1] + 1:].lstrip().startswith('revert'):
            out.append((i, 'branch', line[:span[0]] + 'false' + line[span[1]:]))
    return out


def _run(cmd, cwd, timeout):
    """(returncode, text); on a timeout the whole process tree goes, because a pytest run would leave its anvil"""
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
    try:
        text = p.communicate(timeout=timeout)[0]
        return p.returncode, text
    except subprocess.TimeoutExpired:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/T', '/F', '/PID', str(p.pid)], capture_output=True)
        else:
            p.kill()
        p.communicate()
        return 1, f'TIMEOUT after {timeout} s'


def summarize(results, only=None):
    live = [r for r in results if r['verdict'] in ('killed', 'survived')]
    killed = sum(r['verdict'] == 'killed' for r in live)
    return {'suites': SUITES, 'ovm0_suites': OVM0_SUITES, 'ovm0_pytest': OVM0_PYTEST, 'only': str(only) if only else None,
            'mutants': len(results), 'stillborn': sum(r['verdict'] == 'stillborn' for r in results),
            'equivalent': sum(r['verdict'] == 'equivalent' for r in results), 'killed': killed,
            'survived': len(live) - killed, 'score': round(killed / len(live), 4) if live else None,
            'by_file': {f: {v: sum(r['file'] == f and r['verdict'] == v for r in results)
                            for v in ('killed', 'survived', 'equivalent', 'stillborn')}
                        for f in sorted({r['file'] for r in results})},
            'survivors': [r for r in live if r['verdict'] == 'survived'], 'all': results}


def merge(report, parts):
    """joins reports of shards; a later report overrides an earlier one on the same mutant (a rerun of the survivors)"""
    seen = {}
    for part in parts:
        for r in json.loads(Path(part).read_text(encoding='utf-8'))['all']:
            if r['verdict'] in ('survived', 'equivalent'):  # the reasons may have been written after the run
                eq = equivalent(r['file'], r['op'], r['code'])
                r = r | {'verdict': 'equivalent' if eq else 'survived', 'equivalent_because': eq}
            seen[(r['file'], r['line'], r['op'], r['code'])] = r
    summary = summarize(sorted(seen.values(), key=lambda r: (r['file'], r['line'], r['op'])))
    Path(report).write_text(json.dumps(summary, indent=1), encoding='utf-8')
    return summary


def run(work, report, files=('src/OmegaGraphEscrow.sol', 'src/OmegaSuperRootReferee.sol'), limit=None, only=None,
        ops=None, shard=None):
    """only: a previous report; then just its survivors (same file, line, operator, code) are run again.
    shard: (k, n), every n-th mutant from the k-th, so several processes can share one list"""
    forge = str(Path.home() / '.foundry' / 'bin' / ('forge.exe' if os.name == 'nt' else 'forge'))
    work = Path(work)
    if work.exists():
        shutil.rmtree(work)
    evm = work / 'omega_evm'
    shutil.copytree(EVM, evm, ignore=shutil.ignore_patterns('out', 'cache', 'broadcast'))
    if any(f in OVM0_FILES for f in files):
        for rel in OVM0_COPY:
            src, dst = REPO / rel, work / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__'))
            elif src.exists():
                shutil.copy2(src, dst)
    fast = lambda suites: _run([forge, 'test', '--offline', '--fail-fast', '--match-contract', suites], evm, 900)

    def test(rel):
        """(returncode, text) of the suites that face this file, the cheapest verdict first"""
        if rel not in OVM0_FILES:
            return fast(SUITES)
        rc, text = _run([forge, 'build', '--offline'], evm, 300)
        if rc:
            return rc, text
        rc, text = _run([sys.executable, '-X', 'utf8', '-B', '-m', 'pytest', '-x', '-q', '-p', 'no:cacheprovider', '-k',
                         'not DisputeMerkle', *OVM0_PYTEST], work, 900)
        return (rc, text) if rc else fast(OVM0_SUITES)

    base = test(files[0])
    if base[0] != 0:
        raise RuntimeError('BASELINE_FAILS:' + base[1][-2000:])
    results = []
    for rel in files:
        path = evm / rel
        orig = path.read_text(encoding='utf-8')
        lines = orig.split('\n')
        ms = [m for m in mutants(orig) if ops is None or m[1].split()[0] in ops][:limit]
        if only is not None:
            keep = {(x['file'], x['line'], x['op'], x['code'])
                    for x in json.loads(Path(only).read_text(encoding='utf-8'))['survivors']}
            ms = [(i, op, new) for i, op, new in ms if (rel, i + 1, op, new.strip()) in keep]
        if shard:
            ms = ms[shard[0]::shard[1]]
        for i, op, new in ms:
            mut = lines.copy()
            mut[i] = new
            path.write_text('\n'.join(mut), encoding='utf-8')
            t0 = time.monotonic()
            rc, text = test(rel)
            if rc == 0:
                verdict = 'survived'
            elif 'Compiler run failed' in text:
                verdict = 'stillborn'
            else:
                verdict = 'killed'
            failing = sorted(set(re.findall(r'\[FAIL[^\]]*\] (\w+)\(', text)
                                 + re.findall(r'(?:FAILED|ERROR) \S+::(\w+)', text)))[:5]
            eq = equivalent(rel, op, new.strip()) if verdict == 'survived' else None
            if eq:
                verdict = 'equivalent'
            results.append({'file': rel, 'line': i + 1, 'op': op, 'code': new.strip(), 'verdict': verdict,
                            'equivalent_because': eq, 'killed_by': failing, 'timed_out': text.startswith('TIMEOUT'),
                            'seconds': round(time.monotonic() - t0, 1)})
            print(f'{rel}:{i + 1} {op} -> {verdict}', flush=True)
            Path(report).write_text(json.dumps(summarize(results, only), indent=1), encoding='utf-8')
        path.write_text(orig, encoding='utf-8')
    summary = summarize(results, only)
    Path(report).write_text(json.dumps(summary, indent=1), encoding='utf-8')
    return summary


if __name__ == '__main__':
    args = sys.argv[1:]
    if args and args[0] == '--merge':
        s = merge(args[1], args[2:])
    else:
        only, ops, shard = None, None, None
        if '--ops' in args:
            k = args.index('--ops')
            ops = set(args[k + 1].split(','))
            del args[k:k + 2]
        if '--only' in args:
            k = args.index('--only')
            only = args[k + 1]
            del args[k:k + 2]
        if '--shard' in args:
            k = args.index('--shard')
            shard = tuple(int(x) for x in args[k + 1].split('/'))
            del args[k:k + 2]
        s = run(args[0], args[1], tuple(args[2:]) or ('src/OmegaGraphEscrow.sol', 'src/OmegaSuperRootReferee.sol'),
                only=only, ops=ops, shard=shard)
    print(json.dumps({k: v for k, v in s.items() if k not in ('all', 'survivors')}))
    for r in s['survivors']:
        print('SURVIVOR', r['file'], r['line'], r['op'], r['code'])
