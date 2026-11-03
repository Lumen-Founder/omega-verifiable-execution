"""Rule-based static analysis on solc's AST (docs/world_computer/SECURITY_REVIEW.md section 5).

Slither and SMTChecker's solvers are not installed (their download is a user decision, ADR-0012 X4). These checks
need nothing beyond forge: `forge build --ast` into a separate output folder, then this module walks the AST. They
are positive-controlled: tests/test_omega_static.py runs them on omega_evm/test/StaticFixtures.sol, which breaks
each rule once, and every rule must fire there. They are not a proof and not a substitute for an audit.

Rules (per deployable contract):
  S1 reentrancy-guard  every public/external function that can reach a state-changing external call (through its
                       internal callees) carries a reentrancy-guard modifier
  S2 effects-after-call no storage write on any path after a state-changing external call (path-sensitive over
                       if/else, loops scanned twice, internal callees that write count as writes)
  S3 unchecked-return  no external call returning bool whose result is dropped; every low-level call binds its
                       success flag and reads it
  S4 forbidden         no delegatecall, callcode, selfdestruct, tx.origin; inline assembly only without
                       sstore / call / delegatecall / staticcall / create / create2 / selfdestruct
  S5 mutating-targets  state-changing external calls only to the contract types allowed for that contract
  S6 no-admin          no mutable address-typed state variable (no owner, admin, implementation slot)
"""
import json
import subprocess
from pathlib import Path

EVM = Path(__file__).resolve().parent.parent / 'omega_evm'
GUARDS = {'nonReentrant'}
LOW_LEVEL = {'call', 'delegatecall', 'staticcall', 'callcode'}
ASM_FORBIDDEN = {'sstore', 'call', 'callcode', 'delegatecall', 'staticcall', 'create', 'create2', 'selfdestruct'}
# contract -> contract types it may call with state-changing calls, and why
MUTATING_ALLOWED = {
    'OmegaGraphEscrow': {'IERC20'},  # the settlement token only; referees are read with view calls
    'OVM0Dispute': set(),  # pays with ETH transfers (low-level call, checked), reads its referee and inbox
    'OVM0Step': set(),
    'OVM0Inbox': set(),
    'OmegaSuperRootReferee': set(),  # reads Optimism's factory, games and registry only
    'OmegaCannonGames': {'ICannonGame'},  # initializes the clone it has just created (forwarding the bond)
    'OmegaCannonReferee': set(),  # reads its games factory and the games only
    'OmegaBondVault': set(),  # pays ETH back to the calling game (low-level call, checked)
}


def build_ast(out_dir, cache_dir):
    import os
    forge = str(Path.home() / '.foundry' / 'bin' / ('forge.exe' if os.name == 'nt' else 'forge'))
    subprocess.run([forge, 'build', '--ast', '--out', str(out_dir), '--cache-path', str(cache_dir)], cwd=EVM,
                   check=True, capture_output=True, timeout=900)


def load(out_dir, file_name, contract):
    a = json.loads((Path(out_dir) / file_name / f'{contract}.json').read_text())
    return a['ast']


def _walk(n):
    if isinstance(n, dict):
        yield n
        for v in n.values():
            yield from _walk(v)
    elif isinstance(n, list):
        for v in n:
            yield from _walk(v)


def _off(n):
    return int(n['src'].split(':')[0])


class Analyzer:
    def __init__(self, unit, contract):
        self.unit = unit
        self.c = next(n for n in _walk(unit) if n.get('nodeType') == 'ContractDefinition' and n['name'] == contract)
        self.name = contract
        self.decls = {n['id']: n for n in _walk(unit) if 'id' in n}
        self.state = {n['id'] for n in self.c['nodes'] if n.get('nodeType') == 'VariableDeclaration'}
        self.funcs = {n['id']: n for n in self.c['nodes'] if n.get('nodeType') == 'FunctionDefinition'}
        self.mods = {n['id']: n for n in self.c['nodes'] if n.get('nodeType') == 'ModifierDefinition'}
        self.findings = []

    def add(self, rule, node, msg):
        self.findings.append({'rule': rule, 'contract': self.name, 'src': node.get('src'), 'msg': msg})

    # ---- classification ------------------------------------------------------------------------------------------
    def ext_call(self, call):
        """-> None, or (target type, mutating?) for an external call node"""
        if call.get('nodeType') != 'FunctionCall' or call.get('kind') != 'functionCall':
            return None
        e = call['expression']
        while e.get('nodeType') == 'FunctionCallOptions':
            e = e['expression']
        if e.get('nodeType') != 'MemberAccess':
            return None
        base = e['expression'].get('typeDescriptions', {}).get('typeString', '')
        if e['memberName'] in LOW_LEVEL and base.startswith('address'):
            return ('address', e['memberName'] != 'staticcall')
        if not base.startswith('contract ') and not base.startswith('type(contract'):
            return None
        if base.startswith('type('):
            return None  # a selector or interfaceId, not a call
        # the called function's own type says whether it is a static call (declarations in other source files are
        # not in this unit's AST; a public variable's getter is typed view too)
        ftype = e.get('typeDescriptions', {}).get('typeString', '')
        static = ' view ' in ftype + ' ' or ' pure ' in ftype + ' '
        target = base.split()[1]
        return (target, not static)

    def writes_here(self, n):
        """storage writes directly in node n (not through calls)"""
        t = n.get('nodeType')
        if t == 'Assignment':
            return self._storage(n['leftHandSide'])
        if t == 'UnaryOperation' and n['operator'] in ('++', '--', 'delete'):
            return self._storage(n['subExpression'])
        if t == 'FunctionCall' and n['expression'].get('nodeType') == 'MemberAccess' and \
                n['expression']['memberName'] in ('push', 'pop'):
            return self._storage(n['expression']['expression'])
        return False

    def _storage(self, e):
        while e.get('nodeType') in ('IndexAccess', 'MemberAccess', 'TupleExpression'):
            if e['nodeType'] == 'TupleExpression':
                return any(self._storage(x) for x in e['components'] if x)
            e = e.get('baseExpression') or e.get('expression')
        if e.get('nodeType') != 'Identifier':
            return False
        d = self.decls.get(e.get('referencedDeclaration'))
        return bool(d) and (d['id'] in self.state or d.get('storageLocation') == 'storage')

    def internal_callee(self, call):
        if call.get('nodeType') != 'FunctionCall':
            return None
        e = call['expression']
        if e.get('nodeType') == 'Identifier':
            return self.funcs.get(e.get('referencedDeclaration'))
        return None

    # ---- function summaries (fixed point over internal calls) ---------------------------------------------------
    def summaries(self):
        mut_call, writes = {}, {}
        for fid, f in self.funcs.items():
            nodes = list(_walk(f.get('body')))
            for m in f.get('modifiers', []):
                md = self.mods.get(m['modifierName'].get('referencedDeclaration'))
                if md:
                    nodes += list(_walk(md.get('body')))
            mut_call[fid] = any((self.ext_call(n) or (None, False))[1] for n in nodes)
            writes[fid] = any(self.writes_here(n) for n in nodes)
        changed = True
        while changed:
            changed = False
            for fid, f in self.funcs.items():
                for n in _walk(f.get('body')):
                    g = self.internal_callee(n)
                    if g is None:
                        continue
                    for table in (mut_call, writes):
                        if table[g['id']] and not table[fid]:
                            table[fid] = changed = True
        return mut_call, writes

    # ---- rules -----------------------------------------------------------------------------------------------------
    def run(self):
        mut_call, writes = self.summaries()
        self.mut_call, self.writes = mut_call, writes
        for fid, f in self.funcs.items():
            guarded = any(m['modifierName']['name'] in GUARDS for m in f.get('modifiers', []))
            if f['visibility'] in ('public', 'external') and mut_call[fid] and not guarded and f['kind'] != 'constructor':
                self.add('S1', f, f"{f['name']} reaches a state-changing external call without a reentrancy guard")
            if f.get('body'):
                self._flow(f['body'], False, f['name'])
            self._returns(f)
            for n in _walk(f.get('body')):
                c = self.ext_call(n)
                if c and c[1] and c[0] != 'address' and c[0] not in MUTATING_ALLOWED.get(self.name, set()):
                    self.add('S5', n, f"{f['name']}: state-changing call to {c[0]}")
        self._forbidden()
        for n in self.c['nodes']:
            if n.get('nodeType') == 'VariableDeclaration' and n.get('mutability') == 'mutable' and \
                    n['typeDescriptions']['typeString'].startswith(('address', 'contract ')):
                self.add('S6', n, f"mutable address state variable {n['name']}")
        return self.findings

    def _expr_events(self, n, after, fname):
        """walk an expression/statement in evaluation-ish order (source order); -> after-call flag"""
        events = []
        for x in _walk(n):
            c = self.ext_call(x)
            if c and c[1]:
                events.append((_off(x) + int(x['src'].split(':')[1]), 'call', x))  # effects after the call returns
            elif self.writes_here(x):
                events.append((_off(x), 'write', x))
            else:
                g = self.internal_callee(x)
                if g is not None:
                    if self.writes[g['id']]:
                        events.append((_off(x), 'write', x))
                    if self.mut_call[g['id']]:
                        events.append((_off(x) + int(x['src'].split(':')[1]), 'call', x))
        for _, kind, x in sorted(events, key=lambda e: e[0]):
            if kind == 'call':
                after = True
            elif after:
                self.add('S2', x, f'{fname}: storage write after a state-changing external call')
        return after

    def _flow(self, n, after, fname):
        t = n.get('nodeType')
        if t == 'Block' or t == 'UncheckedBlock':
            for s in n['statements']:
                after = self._flow(s, after, fname)
            return after
        if t == 'IfStatement':
            after = self._expr_events(n['condition'], after, fname)
            a = self._flow(n['trueBody'], after, fname)
            b = self._flow(n['falseBody'], after, fname) if n.get('falseBody') else after
            return a or b
        if t in ('ForStatement', 'WhileStatement', 'DoWhileStatement'):
            parts = [n.get(k) for k in ('initializationExpression', 'condition', 'loopExpression') if n.get(k)]
            for _ in range(2):  # a call late in one iteration precedes the writes of the next
                for p in parts:
                    after = self._expr_events(p, after, fname)
                after = self._flow(n['body'], after, fname) or after
            return after
        if t in ('Return', 'RevertStatement'):
            self._expr_events(n, after, fname)
            return after
        if t == 'TryStatement':
            after = self._expr_events(n['externalCall'], after, fname)
            res = after
            for cl in n['clauses']:
                res = self._flow(cl['block'], after, fname) or res
            return res
        return self._expr_events(n, after, fname)

    def _returns(self, f):
        body = f.get('body')
        if not body:
            return
        for st in _walk(body):
            if st.get('nodeType') == 'ExpressionStatement':
                e = st['expression']
                c = self.ext_call(e)
                if c and c[0] != 'address':
                    ref = self.decls.get(e['expression'].get('referencedDeclaration'))
                    rets = (ref or {}).get('returnParameters', {}).get('parameters', [])
                    if rets and rets[0]['typeDescriptions']['typeString'] == 'bool':
                        self.add('S3', st, f"{f['name']}: bool result of an external call dropped")
                elif c:
                    self.add('S3', st, f"{f['name']}: low-level call result dropped")
            if st.get('nodeType') == 'VariableDeclarationStatement' and st.get('initialValue') and \
                    (self.ext_call(st['initialValue']) or ('', ''))[0] == 'address':
                d0 = st['declarations'][0]
                if d0 is None or not any(x.get('nodeType') == 'Identifier' and x.get('referencedDeclaration') == d0['id']
                                         for x in _walk(body)):
                    self.add('S3', st, f"{f['name']}: low-level call success flag not read")

    def _forbidden(self):
        for n in _walk(self.c):
            t = n.get('nodeType')
            if t == 'MemberAccess' and n['memberName'] in ('delegatecall', 'callcode'):
                self.add('S4', n, n['memberName'])
            if t == 'MemberAccess' and n['memberName'] == 'origin' and \
                    n['expression'].get('name') == 'tx':
                self.add('S4', n, 'tx.origin')
            if t == 'Identifier' and n.get('name') in ('selfdestruct', 'suicide'):
                self.add('S4', n, n['name'])
            if t == 'YulFunctionCall' and n['functionName']['name'] in ASM_FORBIDDEN:
                self.add('S4', n, 'assembly ' + n['functionName']['name'])


def check(out_dir, targets):
    """targets: [(file name, contract)] -> findings (list of dicts)"""
    out = []
    for file_name, contract in targets:
        out += Analyzer(load(out_dir, file_name, contract), contract).run()
    return out


DEPLOYABLE = [('OmegaGraphEscrow.sol', 'OmegaGraphEscrow'), ('OVM0Dispute.sol', 'OVM0Dispute'),
              ('OVM0Step.sol', 'OVM0Step'), ('OVM0Inbox.sol', 'OVM0Inbox'),
              ('OmegaSuperRootReferee.sol', 'OmegaSuperRootReferee'), ('OmegaCannonGames.sol', 'OmegaCannonGames'),
              ('OmegaCannonReferee.sol', 'OmegaCannonReferee'), ('OmegaBondVault.sol', 'OmegaBondVault')]

# findings reviewed and accepted, with the reason (SECURITY_REVIEW section 5); any other finding fails the test
ACCEPTED = {
    ('OmegaGraphEscrow', 'S2', 'deposit'): 'pull then credit under nonReentrant; a failed pull reverts, so the order '
                                           'changes no outcome; read-only reentrancy needs a hook token (T16: '
                                           'standard ERC-20 only)',
    ('OmegaGraphEscrow', 'S2', 'depositBond'): 'same as deposit',
    ('OVM0Dispute', 'S1', 'withdraw'): 'pull payment, effects complete before the call (credit zeroed); a re-entry '
                                       'finds nothing to withdraw',
    ('OmegaCannonGames', 'S1', 'create'): 'isOurs/gameOf and the event are set before initialize, the last statement; '
                                          'initialize runs the Optimism implementation on the clone just made; the '
                                          'nonce is advanced before the clone, so a re-entry only makes another game '
                                          'under a fresh key, which anyone may do',
    ('OmegaBondVault', 'S1', 'withdraw'): 'pull payment to msg.sender (the game itself): the request amount and the '
                                          'balance are reduced before the call; a re-entry sees them reduced',
    ('OmegaCannonGames', 'S4', '_clone'): 'create2 of the Solady CWIA proxy init code (no value, no call); the only '
                                          'way to deploy the computed clone; a failed create reverts CloneFailed',
}

# forge lint (Foundry 1.5.1) medium findings reviewed: (file, line) -> why the cast cannot truncate
LINT_ACCEPTED = {
    ('src/OVM0Step.sol', 128): 'stack is uint64[]: ADD/SUB/MUL are mod 2^64, DIV and MOD do not exceed an operand, '
                               'LT/EQ are 0/1',
    ('src/OVM0Dispute.sol', 189): 'bytes4 of revert data is the selector by intent (short data compares unequal)',
    ('src/OmegaGraphEscrow.sol', 456): 'owed <= cover - liab <= cover < 2^128, checked on the line before',
    ('src/OmegaGraphEscrow.sol', 481): 'saturating: values above uint64 max are clamped first (D8)',
    ('src/OmegaGraphEscrow.sol', 512): 'claimId > uint64 max reverts in _claimFor (ClaimMismatch)',
    ('src/OmegaGraphEscrow.sol', 676): 'owed was reserved as uint128 on every ancestor still holding cover',
    ('src/OmegaGraphEscrow.sol', 678): 'same: cover >= liab >= owed',
    ('src/OmegaCannonReferee.sol', 73): 'bytes11 of the 11-character literal "OVM0-OUT-v2": exact, nothing cut',
}


def key_of(analyzer_findings, unit_funcs):
    """(contract, rule, function name) for each finding, the function found by source range"""
    out = []
    for f in analyzer_findings:
        off = int(f['src'].split(':')[0])
        fn = next((n['name'] for n in unit_funcs[f['contract']]
                   if int(n['src'].split(':')[0]) <= off < sum(map(int, n['src'].split(':')[:2]))), '')
        out.append((f['contract'], f['rule'], fn))
    return out


def run(out_dir, targets=DEPLOYABLE):
    funcs, findings = {}, []
    for file_name, contract in targets:
        a = Analyzer(load(out_dir, file_name, contract), contract)
        funcs[contract] = list(a.funcs.values())
        findings += a.run()
    return findings, key_of(findings, funcs)


def forge_lint(paths, severity):
    """-> [(file, line, lint id)] from `forge lint --severity <severity>`"""
    import os
    import re
    forge = str(Path.home() / '.foundry' / 'bin' / ('forge.exe' if os.name == 'nt' else 'forge'))
    r = subprocess.run([forge, 'lint', '--color', 'never', *paths, '--severity', severity], cwd=EVM,
                       capture_output=True, text=True, timeout=900)
    text = r.stdout + r.stderr
    out, lint = [], None
    for line in text.splitlines():
        m = re.match(r'^(?:warning|error|note)\[([a-z0-9-]+)\]', line)
        if m:
            lint = m.group(1)
        m = re.match(r'^\s*-->\s*(\S+?):(\d+):\d+', line)
        if m and lint:
            out.append((m.group(1).replace(chr(92), '/'), int(m.group(2)), lint))
            lint = None
    return out


# Slither 0.11.6 (installed in a separate venv with the user's approval, 2026-10-30) on the deployable contracts:
# every High / Medium / Low finding other than `timestamp`, reviewed. Key: (impact, check, contract, element name).
SLITHER_ACCEPTED = {
    ('High', 'uninitialized-state', 'OmegaGraphEscrow', '_anc'):
        'false positive: written through a storage reference (`stored.push` in post); ancestry tests read it back',
    ('Medium', 'divide-before-multiply', 'OVM0Inbox', '_root'):
        'a power-of-two size halved, then used as an index (2 * i): exact, no precision involved',
    ('Medium', 'incorrect-equality', 'OVM0Dispute', 'prove'): 'comparing two state hashes; equality is the rule',
    ('Medium', 'uninitialized-local', 'OVM0Dispute', 'defenderRight'): 'zero by default and set on every path',
    ('Medium', 'uninitialized-local', 'OmegaGraphEscrow', 'b'): 'zero by default: no bond when not bonded',
    ('Medium', 'uninitialized-local', 'OmegaGraphEscrow', 'honest'): 'false by default: comp to the account',
    ('Medium', 'uninitialized-local', 'OmegaGraphEscrow', 'toAccount'): 'zero by default, then summed',
    ('Medium', 'unused-return', 'OVM0Dispute', 'prove'): 'only the post-state hash of stepHash is needed',
    ('Medium', 'unused-return', 'OmegaSuperRootReferee', '_record'): 'only the proxy of factory.games is needed',
    ('Low', 'calls-loop', 'OmegaGraphEscrow', '_parent'):
        'at most MAX_PARENTS (8) view calls to referees the account itself allowed',
    ('Low', 'reentrancy-benign', 'OmegaGraphEscrow', 'deposit'): 'same as ACCEPTED S2 deposit (under nonReentrant)',
    ('Low', 'reentrancy-benign', 'OmegaGraphEscrow', 'depositBond'): 'same as deposit',
    ('Low', 'missing-zero-check', 'OmegaCannonGames', 'impl_'):
        'constructor arguments; deploy.verify checks that the implementation, VM and WETH have code',
    ('Low', 'missing-zero-check', 'OmegaCannonGames', 'vm_'): 'same as impl_',
    ('Low', 'missing-zero-check', 'OmegaCannonGames', 'weth_'): 'same as impl_',
    ('Informational', 'missing-inheritance', 'OmegaCannonGames', 'OmegaCannonGames'):
        'implements ICannonGames, declared in the referee file that imports this one (no import cycle)',
}
# whole categories reviewed: deadlines and windows are time rules by design (THREAT_MODEL T15); informational style
SLITHER_ACCEPTED_CHECKS = {('Low', 'timestamp'), ('Informational', 'assembly'), ('Informational', 'low-level-calls'),
                           ('Informational', 'cyclomatic-complexity'), ('Informational', 'naming-convention')}


def slither(slither_exe, work):
    """run Slither on a copy of omega_evm (its forge clean/build must not touch the deploy artifacts) -> findings on
    the deployable contracts as (impact, check, contract, element name)"""
    import os
    import shutil
    work = Path(work)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    for x in ('src', 'test'):
        shutil.copytree(EVM / x, work / x)
    shutil.copy(EVM / 'foundry.toml', work / 'foundry.toml')
    env = dict(os.environ, PATH=str(Path.home() / '.foundry' / 'bin') + os.pathsep + os.environ.get('PATH', ''))
    subprocess.run([str(slither_exe), '.', '--filter-paths', 'test', '--exclude-dependencies', '--json',
                    'slither.json'], cwd=work, env=env, capture_output=True, timeout=1800)
    d = json.loads((work / 'slither.json').read_text())
    if not d.get('success'):
        raise RuntimeError('SLITHER_FAILED:' + str(d.get('error')))
    deployable = {c for _, c in DEPLOYABLE}
    out = set()
    for x in d['results'].get('detectors', []):
        el = x['elements'][0]
        c = el.get('source_mapping', {}).get('filename_relative', '').replace(chr(92), '/').split('/')[-1][:-4]
        if c in deployable:
            out.add((x['impact'], x['check'], c, el.get('name')))
    return out
