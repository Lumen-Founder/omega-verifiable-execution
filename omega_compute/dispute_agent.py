"""Honest players for OVM0Dispute: a defender that answers every game on its claims and a watchtower that re-executes
every open claim it can and challenges the false ones.

Both are stateless: each step() reads claims and games from the chain, recomputes the honest trace from the program
registry, and makes at most the moves that are due. The registry is rebuilt from the chain itself: a claim is only
accepted for a computation published in OVM0Inbox, whose event carries the program and inputs, and the watchtower
checks each one hashes to the commitments the inbox computed. A crashed or restarted player loses nothing but time; acting twice is refused by
the contract (WrongTurn / WrongStatus), so step() can be called as often as wanted.

Silence must not stop anything (READINESS_AUDIT A00): both players close the games whose deadline has passed in the
direction the contract decides (timeout), the defender finalizes its claim once the window is over, and what either
won is withdrawn from the game's credit, because it is the money for the next bond. A late challenger's game on a
claim already rejected is refunded.
"""
import re
import weakref
from collections import namedtuple
from omega_compute import dispute_econ as DE
from omega_compute import vm
from omega_compute import evm_step as E
from omega_kernel.settlement.evm import RpcError, TxOutcome
from omega_kernel.settlement.evm_crypto import keccak, selector, word, words

CLAIM_SIG = 'claim(bytes32,bytes32,uint64,uint64,bytes,bytes)'
PUBLISH_SIG = 'publish(uint256[],uint256[],uint256[])'
PUBLISHED_TOPIC = keccak(b'Published(bytes32,bytes32,address,uint256[],uint256[],uint256[])')
CLAIMED_TOPIC = keccak(b'Claimed(uint256,address,uint64,bytes32)')
NAMES = {i: op for op, i in E.OPCODES.items()}
CLAIMED, ACCEPTED, REJECTED = 1, 2, 3
ACTIVE = 1
DEFENDER, CHALLENGER, PROVE = 0, 1, 2
WITHDRAW = selector('withdraw()')
_URLISH = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://\S+|\b[\w-]+(?:\.[\w-]+)+(?::\d+)?/\S*")


def scrub(text):
    """what a player tells about a failure, without the URL a provider's key may sit in: an error text can quote its request"""
    return _URLISH.sub('<url>', str(text))


def contract_refused(e):
    """the contract said no (a call that is no longer due, which the next pass reads again), as opposed to anything
    between this process and the chain: a limit of the provider, a fee cap, no funds, a transaction not mined or failed"""
    return not isinstance(e, TxOutcome) and (e.revert is not None or 'revert' in str(e).lower())
_URLISH = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://\S+|\b[\w-]+(?:\.[\w-]+)+(?::\d+)?/\S*")


def scrub(text):
    """what a player tells about a failure, without the URL a provider's key may sit in: an error text can quote its request"""
    return _URLISH.sub('<url>', str(text))


def contract_refused(e):
    """the contract said no (a call that is no longer due, which the next pass reads again), as opposed to anything
    between this process and the chain: a limit of the provider, a fee cap, no funds, a transaction not mined or failed"""
    return not isinstance(e, TxOutcome) and (e.revert is not None or 'revert' in str(e).lower())


def _call(sig, *items):
    return selector(sig) + E.abi_encode(items)


def _u(w):
    return int.from_bytes(w, 'big')


def timeout_data(gid):
    return _call('timeout(uint256)', ('w', word(gid)))


def finalize_data(cid):
    return _call('finalize(uint256)', ('w', word(cid)))


def publish_data(program, inputs):
    vm.check_program(program)
    ops = [E.OPCODES[ins[0]] for ins in program]
    imms = [ins[1] if len(ins) > 1 else 0 for ins in program]
    return _call(PUBLISH_SIG, ('a', ops), ('a', imms), ('a', list(inputs)))


def decode_publish(data):
    """(program, inputs) from OVM0Inbox.publish calldata; None if it is not a well-formed publish call."""
    if data[:4] != selector(PUBLISH_SIG):
        return None
    return decode_arrays(data[4:])


def decode_arrays(body):
    """(program, inputs) from abi.encode(ops, imms, inputs) (publish arguments or Published event data)."""

    def array(head):
        off = _u(body[32 * head:32 * head + 32])
        n = _u(body[off:off + 32])
        return [_u(body[off + 32 + 32 * i:off + 64 + 32 * i]) for i in range(n)]
    try:
        ops, imms, inputs = array(0), array(1), array(2)
        program = [[NAMES[o]] + ([m] if vm.OPS[NAMES[o]] else []) for o, m in zip(ops, imms, strict=True)]
        vm.check_program(program)
    except (KeyError, ValueError, IndexError):  # vm.ProgramError is a ValueError
        return None
    return program, inputs


Publication = namedtuple('Publication', 'prog inputs publisher program values')
REORG_DEPTH = 64  # blocks read again on every read: past two epochs the chain does not change without saying so


class LogCursor:
    """One eth_getLogs query, read incrementally (re-audit B20: a pass from the deployment block cost 261 requests over 2.6
    million blocks, 2,084 on a provider capped at 2,000 blocks). Each read asks again for the last `depth` blocks, which
    is where a reorg changes the logs. A deeper one shows in the hash of the block under that window: everything is read
    again. rewind() does the same by hand. A restart starts over, or from state(): the logs come out the same."""

    def __init__(self, chain, address, topics=None, from_block=0, depth=REORG_DEPTH, state=None):
        self.chain, self.address, self.topics, self.start, self.depth = chain, address, topics, from_block, depth
        self.rows, self.next, self.anchor = [], from_block, None  # next: the first block not read yet
        if state is not None:
            self.rows, self.next = list(state['rows']), state['next']
            self.anchor = tuple(state['anchor']) if state['anchor'] else None

    def state(self):
        """what a later LogCursor(..., state=) continues from; JSON can hold it"""
        return {'rows': list(self.rows), 'next': self.next, 'anchor': list(self.anchor) if self.anchor else None}

    def rewind(self, block=None):
        """forget what was read from `block` on (default: everything); the next read gets it again"""
        block = self.start if block is None else max(block, self.start)
        self.rows = [r for r in self.rows if int(r['blockNumber'], 16) < block]
        self.next = min(self.next, block)
        if self.anchor and self.anchor[0] >= block:
            self.anchor = None

    def _hash(self, block):
        got = self.chain.rpc('eth_getBlockByNumber', hex(block), False)
        return got['hash'] if got else None  # a node behind says nothing about that block

    def read(self):
        """every log so far, oldest first. An error leaves the cursor as it was"""
        rows, nxt, anchor = self.rows, self.next, self.anchor
        try:
            head = int(self.chain.rpc('eth_blockNumber'), 16)
            if head + 1 < self.next:  # the head went back: a reorg, or a node behind; above it nothing can be claimed
                self.rewind(head + 1)
            if self.anchor and self._hash(self.anchor[0]) not in (self.anchor[1], None):
                self.rewind()
            lo = max(self.start, self.next - self.depth)
            if lo <= head:
                fresh = self.chain.logs(self.address, self.topics, lo, head)
                self.rows = [r for r in self.rows if int(r['blockNumber'], 16) < lo] + fresh
                self.next = head + 1
                below = self.next - self.depth - 1
                self.anchor = (below, self._hash(below)) if below >= self.start else None
        except Exception:
            self.rows, self.next, self.anchor = rows, nxt, anchor
            raise
        return self.rows


_CURSORS = weakref.WeakKeyDictionary()


def scan_logs(chain, address, topics=None, from_block=0):
    """Chain.logs for what is asked again and again: one LogCursor per query of a chain object, shared by whoever asks.
    A new object (a restart) starts over."""
    key = (address, tuple(topics or ()), from_block)
    cursors = _CURSORS.setdefault(chain, {})
    if key not in cursors:
        cursors[key] = LogCursor(chain, address, topics, from_block)
    return list(cursors[key].read())


def published_logs(chain, inbox, from_block=0, inputs=None, prog=None):
    """[Publication] of an OVM0Inbox whose event data checks out against its commitments, oldest first; `inputs`, `prog`:
    only those of this inputs commitment (the topic the node of a job carries), of this program commitment"""
    topics = ['0x' + PUBLISHED_TOPIC.hex(), '0x' + prog.hex() if prog is not None else None,
              '0x' + inputs.hex() if inputs is not None else None]
    while topics[-1] is None:
        topics.pop()
    out = []
    for log in scan_logs(chain, inbox, topics, from_block):
        got = decode_arrays(bytes.fromhex(log['data'][2:]))
        if got is None:
            continue
        key = (bytes.fromhex(log['topics'][1][2:]), bytes.fromhex(log['topics'][2][2:]))
        if (E.program_commit(got[0]).commitment, E.inputs_commit(got[1]).commitment) == key:
            out.append(Publication(key[0], key[1], bytes.fromhex(log['topics'][3][2:])[12:], got[0], got[1]))
    return out


class Trace:
    """The honest run of (program, inputs, max_steps) and its state hashes under one referee codec."""

    def __init__(self, codec, program, inputs, max_steps, states=None):
        self.codec, self.program, self.inputs, self.max_steps = codec, program, inputs, max_steps
        self.pc_, self.ic_ = E.program_commit(program), E.inputs_commit(inputs)
        if states is None:  # the honest run; tests pass other states to play a false defender
            s = vm.initial(program, inputs)
            states = [s]
            while (s := vm.transition(program, inputs, s, max_steps)) is not None:
                states.append(s)
        self.states = states
        self.hashes = [codec.evm_state_hash(x, self.pc_, self.ic_) for x in self.states]
        self.n = len(self.states) - 1

    def key(self):
        return self.pc_.commitment, self.ic_.commitment, self.max_steps

    def enc(self, i):
        return self.codec.encode_state(self.states[i], self.pc_, self.ic_)

    def aux(self, i):
        return self.codec.aux_for(self.program, self.inputs, self.states[i], self.pc_, self.ic_)

    def out(self, i):
        return self.codec.out_witness(self.states[i])


class Board:
    """Read-only view of an OVM0Dispute deployment and its inbox."""

    def __init__(self, chain, game, from_block=0):
        """from_block: the deployment block; log scans start there (real RPC providers refuse or cap scans from
        genesis, ADR-0012 D15)"""
        self.chain, self.game, self.from_block = chain, game, from_block
        self.inbox = self.view('inbox()')[12:32]

    def is_published(self, prog, inputs):
        return _u(self.chain.call(self.inbox, _call('isPublished(bytes32,bytes32)', ('w', prog), ('w', inputs)))) == 1

    def published(self):
        """(prog, inputs) commitments -> (program, inputs) for every publication whose calldata checks out."""
        return {(r.prog, r.inputs): (r.program, r.values) for r in published_logs(self.chain, self.inbox, self.from_block)}

    def view(self, sig, *args):
        return self.chain.call(self.game, _call(sig, *[('w', word(a)) for a in args]))

    def counts(self):
        return _u(self.view('claims()')), _u(self.view('games()'))

    def claim(self, cid):
        w = words(self.view('getClaim(uint256)', cid))
        return {'id': cid, 'defender': w[0][12:], 'prog': w[1], 'inputs': w[2], 'maxSteps': _u(w[3]), 'n': _u(w[4]),
                'deadline': _u(w[5]), 'open': _u(w[6]), 'status': _u(w[7]), 'hN': w[8], 'output': _u(w[9])}

    def game_(self, gid):
        w = words(self.view('getGame(uint256)', gid))
        return {'id': gid, 'claimId': _u(w[0]), 'challenger': w[1][12:], 'lo': _u(w[2]), 'hi': _u(w[3]),
                'deadline': _u(w[4]), 'status': _u(w[5]), 'turn': _u(w[6]), 'hMid': w[9]}

    def games_of(self, cid):
        _, ng = self.counts()
        return [g for g in (self.game_(i) for i in range(1, ng + 1)) if g['claimId'] == cid]

    def now(self):
        return int(self.chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)

    def credit(self, who):
        return _u(self.view('credit(address)', who))

    def fresh(self, prog, inputs, now):
        """a claim on this computation would pass the contract's data availability check right now"""
        at = _u(self.chain.call(self.inbox, _call('lastPublished(bytes32,bytes32)', ('w', prog), ('w', inputs))))
        return at != 0 and now - at <= _u(self.view('daMaxAge()'))


def _mid(g):
    return g['lo'] + (g['hi'] - g['lo']) // 2


class _Player:
    def __init__(self, board, signer, collect=True):
        """collect: withdraw what it won from the game's credit in every step"""
        self.board, self.signer, self.collect = board, signer, collect
        self.moves = []

    def _send(self, tag, data, value=0):
        try:
            self.board.chain.send(self.signer, self.board.game, data, value=value)
        except TxOutcome as e:  # not mined yet, or mined and failed: the next step reads the chain and decides again
            self.moves.append((tag, str(e)))
            if hasattr(self, '_failed'):
                self._failed[f'tx:{tag}'] = scrub(e)[:120]
            return False
        except RpcError as e:  # a move that is no longer due (raced, or already made before a restart)
            if e.revert not in ('WrongTurn', 'WrongStatus', 'TooLate', 'NotSingleStep', 'TooEarly', 'StillOpen',
                                'NothingToWithdraw', 'PayoutFailed'):
                raise
            self.moves.append((tag, 'refused:' + e.revert))
            return False
        self.moves.append((tag, 'ok'))
        return True

    def _prove(self, g, trace):
        lo = g['lo']
        return self._send('prove', _call('prove(uint256,bytes,bytes)', ('w', word(g['id'])), ('b', trace.enc(lo)),
                                         ('b', trace.aux(lo))))

    def _withdraw(self):
        if self.collect and self.board.credit(self.signer.address) > 0:
            self._send('withdraw', WITHDRAW)


class Defender(_Player):
    """Posts honest claims and answers every game on them with the honest trace."""

    def __init__(self, board, signer, bond, collect=True):
        super().__init__(board, signer, collect)
        self.bond, self.mine = bond, {}  # claim id -> Trace

    def post(self, trace):
        if not self.board.is_published(trace.pc_.commitment, trace.ic_.commitment):
            self.board.chain.send(self.signer, self.board.inbox, publish_data(trace.program, trace.inputs))
        rc = self.board.chain.send(self.signer, self.board.game,
                                   _call(CLAIM_SIG, ('w', trace.pc_.commitment), ('w', trace.ic_.commitment),
                                         ('w', word(trace.max_steps)), ('w', word(trace.n)), ('b', trace.enc(trace.n)),
                                         ('b', trace.out(trace.n))), value=self.bond)
        # from the receipt, not the claim count: another claim can land in the same or the next block
        cid = next(int(lg['topics'][1], 16) for lg in rc['logs'] if lg['topics'][0] == '0x' + CLAIMED_TOPIC.hex())
        self.mine[cid] = trace
        return cid

    def step(self):
        now = self.board.now()
        for cid, trace in self.mine.items():
            c = self.board.claim(cid)
            if c['status'] != CLAIMED:
                continue
            for g in self.board.games_of(cid) if c['open'] else ():
                if g['status'] != ACTIVE:
                    continue
                if now > g['deadline']:
                    if g['turn'] != DEFENDER:  # the challenger ran out of time: the game and its bond are ours
                        self._send('timeout', timeout_data(g['id']))
                elif g['turn'] == DEFENDER:
                    self._send('bisect', _call('bisect(uint256,bytes32)', ('w', word(g['id'])),
                                               ('w', trace.hashes[_mid(g)])))
                elif g['turn'] == PROVE:
                    self._prove(g, trace)  # the honest successor matches the disputed h_hi, so proving wins
            if now > c['deadline'] and self.board.claim(cid)['open'] == 0:
                self._send('finalize', finalize_data(cid))
        self._withdraw()


class Watchtower(_Player):
    """Re-executes every open claim whose program it knows and plays every game it opened against a false one. One claim's
    failure is that claim's (re-audit B9). The games it plays come first, and a new challenge takes only what is left after
    the gas of playing them and it: a liar's flood of false claims must not drain it out of the games it holds."""

    def __init__(self, board, signer, bond, codec, registry=None, collect=True, gas_reserve_wei=None):
        """gas_reserve_wei: the ether a challenge must leave; default: the worst game's gas (dispute_econ) at the fee of the
        chain's latest block, for each game it plays and for the new one"""
        super().__init__(board, signer, collect)
        self.gas_reserve_wei = gas_reserve_wei
        self._failed = {}
        self.bond, self.codec = bond, codec
        self.registry = dict(registry or {})  # (prog commitment, inputs commitment) -> (program, inputs)
        self.verdicts = {}  # claim id -> 'honest' | 'false' | 'unknown'
        self._traces = {}  # (prog, inputs, maxSteps) -> honest Trace; a cache, lost harmlessly on restart

    def _truth(self, c):
        known = self.registry.get((c['prog'], c['inputs']))
        if known is None:
            return None
        k = (c['prog'], c['inputs'], c['maxSteps'])
        if k not in self._traces:  # re-hashing the whole trace on every step made long games quadratic in practice
            self._traces[k] = Trace(self.codec, known[0], known[1], c['maxSteps'])
        return self._traces[k]

    def failing(self):
        """{kind: detail} of what the last pass swallowed, see GraphExecutor.failing; a claim it had to leave unchallenged too"""
        return dict(self._failed)

    def _one(self, kind, act):
        try:
            return act()
        except (RpcError, ValueError, ArithmeticError, LookupError) as e:
            self._failed[kind] = scrub(getattr(e, 'revert', None) or e)[:120]
            return None

    def step(self):
        self._failed = {}
        self._one('registry', lambda: self.registry.update(self.board.published()))
        nc, _ = self.board.counts()
        now = self.board.now()
        due = []  # false claims it has no game on; the games it plays come first
        self._playing = 0
        for cid in range(1, nc + 1):
            self._one(f'claim:{cid}', lambda i=cid: self._claim(i, now, due))
        for c, truth in due:
            self._one(f"claim:{c['id']}", lambda x=c, t=truth: self._challenge(x, t, now))
        self._one('withdraw', self._withdraw)

    def _claim(self, cid, now, due):
        me = self.signer.address
        c = self.board.claim(cid)
        if c['status'] == REJECTED and c['open']:  # another challenger won first: this bond only comes back by refund
            for g in self.board.games_of(cid):
                if g['status'] == ACTIVE and g['challenger'] == me:
                    self._send('refund', _call('refund(uint256)', ('w', word(g['id']))))
        if c['status'] != CLAIMED:
            return
        truth = self._truth(c)
        if truth is None:
            self.verdicts[cid] = 'unknown'
            return
        false = truth.n != c['n'] or truth.hashes[-1] != c['hN']
        self.verdicts[cid] = 'false' if false else 'honest'
        if not false:
            # a challenger out of time must not hold a true claim open past its window, whoever opened the game
            for g in self.board.games_of(cid) if c['open'] else ():
                if g['status'] == ACTIVE and now > g['deadline'] and g['turn'] != DEFENDER:
                    self._send('timeout', timeout_data(g['id']))
            return
        games = self.board.games_of(cid)
        self._playing += sum(g['challenger'] == me and g['status'] == ACTIVE for g in games)
        if not [g for g in games if g['challenger'] == me] and now <= c['deadline']:
            due.append((c, truth))
        self._play(games, truth, now)

    def _challenge(self, c, truth, now):
        chain = self.board.chain
        reserve = self.gas_reserve_wei
        if reserve is None:
            reserve = (self._playing + 1) * DE.honest_gas(c['maxSteps'])[0] * chain.fees()[1]
        if int(chain.rpc('eth_getBalance', '0x' + self.signer.address.hex(), 'latest'), 16) < self.bond + reserve:
            self._failed[f"challenge:{c['id']}"] = 'NO_FUNDS_FOR_BOND_AND_GAS'
            self.moves.append(('challenge', 'skipped:NO_FUNDS_FOR_BOND_AND_GAS'))
            return
        self._send('challenge', _call('challenge(uint256)', ('w', word(c['id']))), self.bond)
        self._playing += 1
        self._play(self.board.games_of(c['id']), truth, now)

    def _play(self, games, truth, now):
        me = self.signer.address
        for g in games:
            if g['status'] != ACTIVE:
                continue
            if now > g['deadline']:
                if g['turn'] == DEFENDER and self._send('timeout', timeout_data(g['id'])):
                    break  # the false claim is rejected: every other game can only be refunded now
                continue
            if g['challenger'] != me:
                continue
            if g['turn'] == CHALLENGER:
                m = _mid(g)
                agree = m <= truth.n and g['hMid'] == truth.hashes[m]
                self._send('respond', _call('respond(uint256,bool)', ('w', word(g['id'])), ('w', word(agree))))
            elif g['turn'] == PROVE:
                self._prove(g, truth)
