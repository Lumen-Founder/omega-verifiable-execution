"""Event indexer and archive (docs/adr/ADR-0012, layers L6 and L8).

sync() reads every OmegaGraphEscrow event, every OVM0Inbox Published event (the programs and inputs: the data the
referee needs), every event of the referees it is given (the dispute's history) and every token Transfer to or from the
escrow, and appends the new ones to a JSONL archive. Each record keeps the raw log (topics, data, block hash, log index)
and a SHA-256 hash chain over all records; what the logs do not say is read once and kept with them: a Posted record holds
the node's commitments and ancestors, a Bound record the claim's result, a Transfer into the escrow who it was sent through.
So:
- verify_archive() detects any edit, deletion or reordering of the file; a tail cut by a crash is told apart (ArchiveTorn),
  and sync() and recover() put it aside in <archive>.torn and read those blocks again;
- check_on_chain() re-finds every archived log on the chain (same block hash, index, topics and data);
- rebuild() turns the archive alone into the node table (status, bound claim, stake flags, commitments, ancestors);
- da() turns the archive alone into the program/input registry, and replay() re-executes every OVM-0 claim from the file
  with no chain at all (logs are not guaranteed to be served forever by every node);
- disputes() turns it into each claim's game history;
- backup() copies a verified archive; reset() rebuilds a bad one from the chain, for as long as the chain's logs are served.
The archive is evidence and a restart aid, not a source of truth: the chain decides; a mismatch is an alert."""
import hashlib
import json
import os
from pathlib import Path
from omega_compute import evm_step as E
from omega_compute import vm
from omega_compute.dispute_agent import PUBLISHED_TOPIC, decode_arrays
from omega_compute.graph_escrow import NODE_FIELDS
from omega_kernel.settlement.evm import RpcError
from omega_kernel.settlement.evm_crypto import call_data, keccak, words

ESCROW_EVENTS = {  # name: (signature, indexed fields, data fields) with types 'b32', 'addr', 'uint', 'bool'
    'Opened': ('Opened(bytes32,address)', [('account', 'b32'), ('owner', 'addr')], []),
    'Posted': ('Posted(bytes32,bytes32,address,address,bytes32,uint8)', [('key', 'b32'), ('account', 'b32'),
               ('executor', 'addr')], [('referee', 'addr'), ('parents', 'b32'), ('grade', 'uint')]),
    'Reserved': ('Reserved(bytes32,uint256,uint256,uint64)', [('key', 'b32')],
                 [('bond', 'uint'), ('cover', 'uint'), ('claimFloor', 'uint')]),
    'Bound': ('Bound(bytes32,uint256)', [('key', 'b32'), ('claimId', 'uint')], []),
    'Verified': ('Verified(bytes32)', [('key', 'b32')], []),
    'Settled': ('Settled(bytes32,bool,uint256)', [('key', 'b32')], [('paid', 'bool'), ('price', 'uint')]),
    'Rejected': ('Rejected(bytes32,uint256,uint256)', [('key', 'b32')], [('bond', 'uint'), ('surplus', 'uint')]),
    'Voided': ('Voided(bytes32,bytes32,uint256,bool,uint256)', [('key', 'b32'), ('payer', 'b32')],
               [('comp', 'uint'), ('compToExecutor', 'bool'), ('ext', 'uint')]),
    'Expired': ('Expired(bytes32)', [('key', 'b32')], []),
    'Released': ('Released(bytes32,uint256)', [('key', 'b32')], [('bond', 'uint')]),
    'Slashed': ('Slashed(bytes32,uint256,uint256)', [('key', 'b32'), ('claimId', 'uint')], [('bond', 'uint')]),
}
TOPICS = {keccak(sig.encode()): name for name, (sig, _, _) in ESCROW_EVENTS.items()}
REFEREE_EVENTS = {  # the same form; other referees' events are archived raw, as 'RefereeLog'
    'Claimed': ('Claimed(uint256,address,uint64,bytes32)', [('id', 'uint'), ('defender', 'addr')],
                [('n', 'uint'), ('finalHash', 'b32')]),
    'Challenged': ('Challenged(uint256,uint256,address)', [('claimId', 'uint'), ('gameId', 'uint'), ('challenger', 'addr')], []),
    'Bisected': ('Bisected(uint256,uint64,bytes32)', [('gameId', 'uint')], [('mid', 'uint'), ('hMid', 'b32')]),
    'Responded': ('Responded(uint256,bool,uint64,uint64)', [('gameId', 'uint')], [('agree', 'bool'), ('lo', 'uint'), ('hi', 'uint')]),
    'GameResolved': ('GameResolved(uint256,uint8)', [('gameId', 'uint')], [('status', 'uint')]),
    'ClaimResolved': ('ClaimResolved(uint256,uint8)', [('id', 'uint')], [('status', 'uint')]),
}
REFEREE_TOPICS = {keccak(sig.encode()): name for name, (sig, _, _) in REFEREE_EVENTS.items()}
TRANSFER_TOPIC = keccak(b'Transfer(address,address,uint256)')
STATE_OF = {'Posted': 'posted', 'Bound': 'claimed', 'Verified': 'verified', 'Settled': 'final', 'Rejected': 'rejected',
            'Voided': 'voided', 'Expired': 'expired'}
GENESIS = '0' * 64


class ArchiveError(RuntimeError):
    pass


class ArchiveTorn(ArchiveError):
    """the file ends in a line that was not finished (a crash or a power loss while appending); everything before it
    verifies. records, head: that part; offset: where the unfinished line starts"""

    def __init__(self, records, head, offset):
        super().__init__(f'TORN_TAIL_AFTER:{len(records)}')
        self.records, self.head, self.offset = records, head, offset


def _word(hexstr, kind):
    b = bytes.fromhex(hexstr[2:] if hexstr.startswith('0x') else hexstr)
    if kind == 'addr':
        return '0x' + b[12:].hex()
    if kind == 'b32':
        return '0x' + b.hex()
    if kind == 'bool':
        return bool(int.from_bytes(b, 'big'))
    return int.from_bytes(b, 'big')


def decode(log):
    """-> (event name, args) for an escrow, inbox, referee or token log"""
    topic = bytes.fromhex(log['topics'][0][2:]) if log['topics'] else b''
    if topic in TOPICS or topic in REFEREE_TOPICS:
        name = TOPICS.get(topic) or REFEREE_TOPICS[topic]
        _, idx, dat = (ESCROW_EVENTS if topic in TOPICS else REFEREE_EVENTS)[name]
        args = {f: _word(t, k) for (f, k), t in zip(idx, log['topics'][1:])}
        data = log['data'][2:]
        args |= {f: _word(data[64 * i:64 * i + 64], k) for i, (f, k) in enumerate(dat)}
        return name, args
    if topic == PUBLISHED_TOPIC:
        return 'Published', {'prog': log['topics'][1], 'inputs': log['topics'][2]}
    if topic == TRANSFER_TOPIC:
        return 'Transfer', {'from': _word(log['topics'][1], 'addr'), 'to': _word(log['topics'][2], 'addr'),
                            'value': _word(log['data'], 'uint')}
    return 'Unknown', {}


def _record_hash(prev, body):
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(',', ':'))).encode()).hexdigest()


def _read(path):
    """-> (records, offset of an unfinished last line or None). A line a crash can have left is one at the end of the
    file: without its newline, or not a record and with nothing after it. Any other bad line is damage: ArchiveError."""
    p = Path(path)
    if not p.exists():
        return [], None
    data, recs, at = p.read_bytes(), [], 0
    lines = data.split(b'\n')
    for i, raw in enumerate(lines):
        line, start = raw.strip(), at
        at += len(raw) + 1
        if not line:
            continue
        try:
            r = json.loads(line.decode('utf-8'))
        except ValueError:  # JSONDecodeError and UnicodeDecodeError both are
            r = None
        if i == len(lines) - 1 or (not isinstance(r, dict) and not any(x.strip() for x in lines[i + 1:])):
            return recs, start
        if not isinstance(r, dict):
            raise ArchiveError(f'BROKEN_AT:{len(recs)}')
        recs.append(r)
    return recs, None


def load(path):
    recs, torn = _read(path)
    if torn is not None:
        raise ArchiveTorn(recs, None, torn)
    return recs


def verify_archive(path, must_exist=False):
    """-> (records, head hash); raises ArchiveError at the first record that does not chain, ArchiveTorn (one) if every
    record chains and the file ends in an unfinished line. No file: no records (an archive not started yet), or with
    must_exist ArchiveError NO_ARCHIVE_FILE: a check of a file that is not there passes nothing"""
    if must_exist and not Path(path).is_file():
        raise ArchiveError('NO_ARCHIVE_FILE')
    prev = GENESIS
    recs, torn = _read(path)
    for i, r in enumerate(recs):
        body = {k: v for k, v in r.items() if k not in ('prev', 'hash')}
        if r.get('i') != i or r.get('prev') != prev or _record_hash(prev, body) != r.get('hash'):
            raise ArchiveError(f'BROKEN_AT:{i}')
        prev = r['hash']
    if torn is not None:
        raise ArchiveTorn(recs, prev, torn)
    return recs, prev


def _line(record):
    return (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def _append(path, data):
    """on the disk when it returns: the block whose logs these are will not be read again"""
    with Path(path).open('ab') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _replace(path, data):
    """the whole file or nothing, for a process killed at any moment"""
    tmp = Path(str(path) + '.tmp')
    with tmp.open('wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def backup(path, dest_dir):
    """copy a verified archive to dest_dir under its head hash -> {file, records, head}. A copy of a damaged file is no
    backup: ArchiveError, and the last good copy stays. The same head is one file, so calling it often costs nothing."""
    recs, head = verify_archive(path, must_exist=True)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / f'archive-{len(recs):08d}-{head[:16]}.jsonl'
    if not out.exists():
        _replace(out, Path(path).read_bytes())
    verify_archive(out)
    return {'file': str(out), 'records': len(recs), 'head': head}


def record_of(lg):
    """the part of an archive record the log itself says, for logs not archived yet"""
    name, args = decode(lg)
    return {'block': int(lg['blockNumber'], 16), 'blockHash': lg['blockHash'], 'tx': lg['transactionHash'],
            'logIndex': int(lg['logIndex'], 16), 'address': lg['address'].lower(), 'event': name, 'args': args,
            'topics': lg['topics'], 'data': lg['data']}


def via_of(chain, tx_hash):
    """who a transaction was sent to and what it called, or None if the chain does not say"""
    tx = chain.rpc('eth_getTransactionByHash', tx_hash)
    if not tx or not tx.get('to'):
        return None
    return {'to': tx['to'].lower(), 'selector': tx['input'][:10]}


class Indexer:
    def __init__(self, chain, escrow, inboxes=(), token=None, archive_path=None, from_block=0, confirmations=0, referees=()):
        """from_block: the deployment block (log scans never start before it, ADR-0012 D15). confirmations: blocks
        are archived only once this deep, so a reorg shallower than that never reaches the archive. referees: whose
        events to keep too (only those the operator trusts: the file holds whatever they emit)."""
        self.chain, self.escrow, self.inboxes, self.token = chain, escrow, tuple(inboxes), token
        self.referees = tuple(dict.fromkeys(bytes(r) for r in referees))
        self.path = Path(archive_path) if archive_path else None
        self.from_block, self.confirmations = from_block, confirmations
        self.repairs = []  # what sync() and recover() put aside since the last take_repairs()

    def fetch(self, from_block=0, confirmations=None):
        """every log of the escrow, the inboxes and the escrow's token transfers from `from_block` to ONE head read
        once: with a head per scan, a later scan could end past an earlier one and its last block would move the
        archive cursor past logs the earlier scan never saw (D18). confirmations: this call's depth instead of the
        indexer's (0: to the chain's head)."""
        from_block = max(from_block, self.from_block)
        depth = self.confirmations if confirmations is None else confirmations
        head = int(self.chain.rpc('eth_blockNumber'), 16) - depth
        get = lambda address, topics=None: self.chain.logs(address, topics, from_block, head)
        logs = get(self.escrow)
        for ib in self.inboxes:
            logs += get(ib, ['0x' + PUBLISHED_TOPIC.hex()])
        for ref in self.referees:
            logs += get(ref)
        if self.token:
            pad = '0x' + bytes(12).hex() + self.escrow.hex()
            logs += get(self.token, ['0x' + TRANSFER_TOPIC.hex(), None, pad])
            logs += get(self.token, ['0x' + TRANSFER_TOPIC.hex(), pad])
        uniq = {(lg['blockHash'], int(lg['logIndex'], 16)): lg for lg in logs}
        return [uniq[k] for k in sorted(uniq, key=lambda k: (int(uniq[k]['blockNumber'], 16), k[1]))]

    def reorged(self, recs):
        """the last archived block is no longer on the chain"""
        if not recs:
            return False
        b = self.chain.rpc('eth_getBlockByNumber', hex(recs[-1]['block']), False)
        return b is None or b['hash'] != recs[-1]['blockHash']

    def _repair(self, torn):
        """put the unfinished line aside and cut it off; its block is read again, the chain still has it"""
        data = self.path.read_bytes()
        cut = data[torn.offset:]
        _append(str(self.path) + '.torn', cut)
        _replace(self.path, data[:torn.offset])
        self.repairs.append(f'{len(cut)} bytes after record {len(torn.records)}')

    def _verified(self):
        try:
            return verify_archive(self.path)
        except ArchiveTorn as torn:
            self._repair(torn)
        return verify_archive(self.path)

    def take_repairs(self):
        out, self.repairs = self.repairs, []
        return out

    def _enriched(self, lg, name, args):
        """what this log's record keeps beyond the log (module docstring). A referee that does not answer leaves None."""
        call = lambda to, sig, *a: self.chain.call(to, call_data(sig, *a))
        if name == 'Posted':
            w = words(call(self.escrow, 'getNode(bytes32)', bytes.fromhex(args['key'][2:])))
            anc = words(call(self.escrow, 'ancestorsOf(bytes32)', bytes.fromhex(args['key'][2:])))
            f = lambda n: w[NODE_FIELDS.index(n)]
            return {'node': {'prog': '0x' + f('prog').hex(), 'inputs': '0x' + f('inputs').hex(),
                             'maxSteps': int.from_bytes(f('maxSteps'), 'big'),
                             'ancestors': ['0x' + x.hex() for x in anc[2:2 + int.from_bytes(anc[1], 'big')]]}}
        if name == 'Bound':
            w = words(call(self.escrow, 'getNode(bytes32)', bytes.fromhex(args['key'][2:])))
            try:
                c = words(call(w[NODE_FIELDS.index('referee')][12:], 'getClaim(uint256)', args['claimId']))
            except RpcError:
                return {'claim': None}
            if len(c) < 11:
                return {'claim': None}
            u = lambda i: int.from_bytes(c[i], 'big')
            return {'claim': {'n': u(4), 'hN': '0x' + c[8].hex(), 'output': u(9), 'trap': u(10),
                              'defender': '0x' + c[0][12:].hex()}}
        if name == 'Transfer' and args['to'] == '0x' + self.escrow.hex():
            return {'via': via_of(self.chain, lg['transactionHash'])}
        return {}

    def sync(self):
        """append every log not yet archived; -> number of new records. Refuses to continue if an archived block is no
        longer on the chain (a reorg or a different chain)."""
        if self.path is None:
            raise ArchiveError('NO_ARCHIVE')
        recs, head = self._verified()
        seen = {(r['blockHash'], r['logIndex']) for r in recs}
        last = recs[-1]['block'] if recs else 0
        if self.reorged(recs):
            raise ArchiveError('REORG_OR_OTHER_CHAIN')
        new = []
        for lg in self.fetch(last):
            k = (lg['blockHash'], int(lg['logIndex'], 16))
            if k in seen:
                continue
            name, args = decode(lg)
            if name == 'Unknown' and bytes.fromhex(lg['address'][2:]) in self.referees:
                name = 'RefereeLog'
            body = {'i': len(recs) + len(new), 'block': int(lg['blockNumber'], 16), 'blockHash': lg['blockHash'],
                    'tx': lg['transactionHash'], 'logIndex': k[1], 'address': lg['address'].lower(), 'event': name,
                    'args': args, 'topics': lg['topics'], 'data': lg['data']} | self._enriched(lg, name, args)
            h = _record_hash(head, body)
            new.append(body | {'prev': head, 'hash': h})
            head = h
        if new:
            _append(self.path, b''.join(_line(r) for r in new))
        return len(new)

    def reset(self):
        """RUNBOOK_INCIDENT ARCHIVE_TAMPERED: keep the bad file aside and build the archive again from the chain's logs.
        Only as complete as the logs the provider still serves: prefer a backup when there is one. -> where the old one is,
        None if there was none"""
        i = 0
        while (kept := Path(f'{self.path}.bad{i}')).exists():
            i += 1
        had = self.path.exists()
        if had:
            self.path.replace(kept)
        self.sync()
        return str(kept) if had else None

    def recover(self):
        """after REORG_OR_OTHER_CHAIN: keep the archive up to the last block whose hash the chain still has, drop
        the records after it (the hash chain of the kept prefix stays valid), and sync again from there. What is dropped
        goes to <archive>.dropped first: it was on a chain once, and an endpoint that is only behind must not cost evidence.
        -> (records dropped, records added)"""
        recs, _ = self._verified()
        keep = 0
        for i in range(len(recs) - 1, -1, -1):
            b = self.chain.rpc('eth_getBlockByNumber', hex(recs[i]['block']), False)
            if b is not None and b['hash'] == recs[i]['blockHash']:
                keep = i + 1
                break
        dropped = len(recs) - keep
        if dropped:
            _append(Path(str(self.path) + '.dropped'), b''.join(_line(r) for r in recs[keep:]))
        _replace(self.path, b''.join(_line(r) for r in recs[:keep]))
        return dropped, self.sync()

    def check_on_chain(self, recs):
        """every archived log is on the chain as archived -> list of mismatching record indices. A block the node says
        it does not know is a mismatch; any other refusal raises (a rate limit says nothing about the file)."""
        bad = []
        cache = {}
        for r in recs:
            key = (r['blockHash'], r['address'])
            if key not in cache:
                try:
                    logs = self.chain.rpc('eth_getLogs', {'blockHash': r['blockHash'], 'address': r['address']})
                except RpcError as e:
                    if not any(w in str(e).lower() for w in ('not found', 'unknown block')):
                        raise
                    logs = []
                cache[key] = {int(lg['logIndex'], 16): lg for lg in logs}
            lg = cache[key].get(r['logIndex'])
            if lg is None or lg['topics'] != r['topics'] or lg['data'] != r['data']:
                bad.append(r['i'])
        return bad


def rebuild(recs):
    """the node table from archived escrow events alone"""
    nodes = {}
    for r in recs:
        a, ev = r['args'], r['event']
        if ev == 'Posted':
            nodes[a['key']] = {'state': 'posted', 'account': a['account'], 'executor': a['executor'],
                               'referee': a['referee'], 'parents': a['parents'], 'grade': a['grade'], 'claimId': 0,
                               'bonded': False, 'coverHeld': False, 'claim': None} | (r.get('node') or {})
            continue
        n = nodes.get(a.get('key'))
        if n is None:
            continue
        if ev in STATE_OF:
            n['state'] = STATE_OF[ev]
        if ev == 'Reserved':
            n['bonded'] = n['coverHeld'] = True
        elif ev == 'Bound':
            n['claimId'], n['claim'] = a['claimId'], r.get('claim')
        elif ev in ('Verified', 'Settled', 'Voided', 'Expired'):
            n['coverHeld'] = False  # the cover goes back; a REJECTED node keeps holding L for its descendants
        if ev in ('Released', 'Slashed', 'Rejected'):
            n['bonded'] = False
    return nodes


def da(recs):
    """(prog, inputs) commitments -> (program, inputs) from archived Published events whose data checks out"""
    out = {}
    for r in recs:
        if r['event'] != 'Published':
            continue
        got = decode_arrays(bytes.fromhex(r['data'][2:]))
        if got is None:
            continue
        key = (bytes.fromhex(r['topics'][1][2:]), bytes.fromhex(r['topics'][2][2:]))
        if (E.program_commit(got[0]).commitment, E.inputs_commit(got[1]).commitment) == key:
            out[key] = got
    return out


def recompute(program, inputs, max_steps, codec=E):
    """(steps, final state hash, output) of the honest run: what Trace gives without hashing every state"""
    program, inputs = [list(i) for i in program], list(inputs)
    pc, ic = E.program_commit(program), E.inputs_commit(inputs)
    s, n = vm.initial(program, inputs), 0
    while (nxt := vm.transition(program, inputs, s, max_steps)) is not None:
        s, n = nxt, n + 1
    return n, codec.evm_state_hash(s, pc, ic), (s['stack'][-1] if s['stack'] else 0)


def replay(recs, codec=E):
    """node key -> {output, claimed, matches}: every bound OVM-0 claim re-executed from this file alone. Nodes whose
    computation is not in the file (a Cannon prestate needs its rebuild, cannon.find_job) are not in the answer."""
    reg = da(recs)
    out = {}
    for key, n in rebuild(recs).items():
        known = reg.get((bytes.fromhex(n['prog'][2:]), bytes.fromhex(n['inputs'][2:]))) if n.get('prog') else None
        if known is None or not n['claim']:
            continue
        steps, final, output = recompute(known[0], known[1], n['maxSteps'], codec)
        out[key] = {'output': output, 'claimed': n['claim']['output'],
                    'matches': (steps, '0x' + final.hex()) == (n['claim']['n'], n['claim']['hN'])}
    return out


def disputes(recs):
    """claim id -> {claimed: its Claimed record's args and block, games: [{id, challenger, block, moves, resolved}], status}
    from the archived referee events of OVM0Dispute"""
    claims, games = {}, {}
    for r in recs:
        ev, a = r['event'], r['args']
        if ev == 'Claimed':
            claims[a['id']] = {'claimed': a | {'block': r['block']}, 'games': [], 'status': None}
        elif ev == 'Challenged':
            games[a['gameId']] = g = {'id': a['gameId'], 'challenger': a['challenger'], 'block': r['block'], 'moves': 0,
                                      'resolved': None}
            claims.setdefault(a['claimId'], {'claimed': None, 'games': [], 'status': None})['games'].append(g)
        elif ev in ('Bisected', 'Responded') and a['gameId'] in games:
            games[a['gameId']]['moves'] += 1
        elif ev == 'GameResolved' and a['gameId'] in games:
            games[a['gameId']]['resolved'] = a['status']
        elif ev == 'ClaimResolved' and a['id'] in claims:
            claims[a['id']]['status'] = a['status']
    return claims
