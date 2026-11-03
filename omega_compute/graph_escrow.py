"""Python side of OmegaGraphEscrow (W1, docs/adr/ADR-0011): EIP-712 job requests with parent links, calldata
encoders, the node view, and the players of the local tests:
- GraphExecutor: stakes (bond + cover), claims in an OVM0Dispute-like referee, binds the claim to the node, answers the
  games on it, closes the ones whose challenger went silent, finalizes, verifies (cover back as soon as its own claim is
  Accepted) and settles once every ancestor is final, then takes the bond back after the slash period, expires what
  nobody else ended, and withdraws what it won. `lie(trace) -> trace` plays a dishonest executor.
- GraphGuard: rejects nodes whose bound claim was defeated and voids their descendants (both callable by anyone).
Nothing here decides correctness: the escrow pays only for a claim its referee accepted."""
from dataclasses import dataclass
from omega_compute import evm_step as E
from omega_compute.dispute_agent import (ACTIVE, CLAIM_SIG, DEFENDER, PROVE, WITHDRAW, Trace, _call, _mid, _u,
                                         finalize_data, scan_logs, scrub, timeout_data)
from omega_kernel.settlement.evm import RpcError, TxOutcome
from omega_kernel.settlement.evm_crypto import call_data, domain_separator, keccak, selector, word, words

JOB_TYPE = (b'Job(bytes32 key,bytes32 account,address executor,address referee,bytes32 prog,bytes32 inputs,'
            b'uint64 maxSteps,uint128 price,uint128 comp,uint128 ext,uint128 cover,uint8 cond,uint64 condArg,'
            b'uint64 deadline,bytes32 parents)')
JOB_TUPLE = ('(bytes32,bytes32,address,address,bytes32,bytes32,uint64,uint128,uint128,uint128,uint128,uint8,uint64,'
             'uint64,bytes32)')
SIG_TUPLE = '(uint8,bytes32,bytes32)'
POST_SIG = f'post({JOB_TUPLE},bytes32[],uint256[],{SIG_TUPLE},{SIG_TUPLE})'
NO_SIG = (0, bytes(32), bytes(32))
POSTED_TOPIC = keccak(b'Posted(bytes32,bytes32,address,address,bytes32,uint8)')
COND = {'clean': 0, 'eq': 1, 'le': 2, 'ge': 3}
STATUS = {0: 'none', 1: 'posted', 2: 'claimed', 3: 'verified', 4: 'final', 5: 'rejected', 6: 'voided', 7: 'expired'}
NODE_FIELDS = ('status', 'grade', 'bonded', 'coverHeld', 'deadline', 'claimFloor', 'claimId', 'referee', 'cond',
               'condArg', 'executor', 'maxSteps', 'account', 'prog', 'inputs', 'price', 'comp', 'ext', 'cover', 'liab',
               'expiry')
CLAIMED, ACCEPTED, REJECTED = 1, 2, 3  # referee ClaimStatus


def account_key(account, salt):
    """a job key the escrow accepts for `account`: keccak(account)'s first 12 bytes, then 20 bytes of `salt`
    (ADR-0012 D10: no other account can take this account's keys)"""
    return keccak(word(account))[:12] + keccak(salt)[:20]


def parents_hash(keys, claims):
    if not keys:
        return bytes(32)
    return keccak(E.abi_encode([('a', [int.from_bytes(k, 'big') for k in keys]), ('a', list(claims))]))


@dataclass(frozen=True)
class GraphJob:
    key: bytes
    account: bytes
    executor: bytes
    referee: bytes
    program: tuple
    inputs: tuple
    max_steps: int
    price: int
    comp: int = 0
    ext: int = 0
    cover: int = 0
    cond: int = 0
    cond_arg: int = 0
    deadline: int = 0
    parent_keys: tuple = ()
    parent_claims: tuple = ()

    def commitments(self):
        return E.program_commit([list(i) for i in self.program]).commitment, E.inputs_commit(list(self.inputs)).commitment

    def fields(self):
        prog, inp = self.commitments()
        return (self.key, self.account, self.executor, self.referee, prog, inp, self.max_steps, self.price, self.comp,
                self.ext, self.cover, self.cond, self.cond_arg, self.deadline,
                parents_hash(self.parent_keys, self.parent_claims))

    def struct_hash(self):
        return keccak(keccak(JOB_TYPE) + b''.join(word(x) for x in self.fields()))

    def digest(self, domain):
        return keccak(b'\x19\x01' + domain + self.struct_hash())


def post_data(job, agent_sig, cosig=NO_SIG, parent_keys=None, inputs=None):
    """`parent_keys` / `inputs` override what is sent next to the signed request (tests of mismatches)"""
    keys = job.parent_keys if parent_keys is None else parent_keys
    vals = list(job.inputs if inputs is None else inputs)
    items = ([('w', word(x)) for x in job.fields()] + [('a', [int.from_bytes(k, 'big') for k in keys]), ('a', vals)]
             + [('w', word(x)) for x in tuple(agent_sig) + tuple(cosig)])
    return selector(POST_SIG) + E.abi_encode(items)


def key_call(name, key, *extra):
    sig = f'{name}(bytes32' + ',uint256' * len(extra) + ')'
    return call_data(sig, key, *extra)


class GraphEscrow:
    def __init__(self, chain, address):
        """ValueError ESCROW_DOMAIN_MISMATCH: the contract's EIP-712 domain is not this escrow's on this chain, as computed
        here. What an agent signs must not depend on what an RPC says (re-audit B14)"""
        self.chain, self.address = chain, address
        self.domain = chain.call(address, selector('DOMAIN_SEPARATOR()'))
        if self.domain != domain_separator('OmegaGraphEscrow', '1', chain.chain_id, address):
            raise ValueError('ESCROW_DOMAIN_MISMATCH')
        self._ended = set()  # nodes no later block changes

    def view(self, sig, *args):
        return self.chain.call(self.address, call_data(sig, *args))

    def node(self, key):
        w = words(self.view('getNode(bytes32)', key))
        n = {f: _u(x) for f, x in zip(NODE_FIELDS, w)}
        for f in ('referee', 'executor'):
            n[f] = w[NODE_FIELDS.index(f)][12:]
        for f in ('account', 'prog', 'inputs'):
            n[f] = w[NODE_FIELDS.index(f)]
        n['bonded'], n['coverHeld'] = bool(n['bonded']), bool(n['coverHeld'])
        n['state'] = STATUS[n['status']]
        return n

    def ancestors(self, key):
        w = words(self.view('ancestorsOf(bytes32)', key))
        return [x for x in w[2:2 + _u(w[1])]]

    def u(self, sig, *args):
        return _u(self.view(sig, *args))

    def balance(self, account):
        return self.u('balanceOf(bytes32)', account)

    def bond_of(self, who):
        return self.u('bondOf(address)', who)

    def expires_at(self, key):
        return self.u('expiresAt(bytes32)', key)

    def live_nodes(self, referee, from_block=0, account=None, executor=None):
        """[(key, node)] on this referee whose dispute can still ask for capital (posted or claimed), of this account or this
        executor, from the Posted events"""
        topics = ['0x' + POSTED_TOPIC.hex(), None, '0x' + account.hex() if account else None,
                  '0x' + bytes(12).hex() + executor.hex() if executor else None]
        while topics[-1] is None:
            topics.pop()
        out = []
        for log in scan_logs(self.chain, self.address, topics, from_block):
            key = bytes.fromhex(log['topics'][1][2:])
            if key in self._ended:
                continue
            n = self.node(key)
            if n['state'] in ('final', 'rejected', 'voided', 'expired'):
                self._ended.add(key)
            elif n['state'] in ('posted', 'claimed') and n['referee'] == referee:
                out.append((key, n))
        return out

    def totals(self):
        return {'locked': self.u('locked()'), 'bondsHeld': self.u('bondsHeld()'), 'coversHeld': self.u('coversHeld()')}


class GraphExecutor:
    """Runs the nodes it is given, in the order given (parents before children), on an OVM0Dispute referee."""
    ISOLATED = (RpcError, ValueError, ArithmeticError, LookupError)  # one job's, see _isolated

    def __init__(self, board, escrow, signer, bond, codec, lie=None, keep_stake=None, payout=None):
        """keep_stake: the free stake kept for new work; what is earned above it leaves as tokens to `payout` (default:
        this key) in every step. None: everything stays in the escrow until withdrawBond is called."""
        self.board, self.escrow, self.signer, self.bond, self.codec, self.lie = board, escrow, signer, bond, codec, lie
        self.keep_stake, self.payout = keep_stake, payout or signer.address
        self.jobs = []
        self.moves = []
        self.errors, self.refused = {}, {}  # what was last said about each job: a stuck job is reported once, not per pass
        self._failed = {}  # what the last pass swallowed: failing()

    def take(self, job):
        self.jobs.append(job)

    def _send(self, tag, to, data, value=0, ok=()):
        try:
            rc = self.board.chain.send(self.signer, to, data, value=value)
        except TxOutcome as e:  # not mined yet, or mined and failed: the next step reads the chain and decides again
            self.moves.append((tag, str(e)))
            self._note('tx', tag, e)
            return None
        except RpcError as e:
            if e.revert not in ok and e.revert not in {'REVERT_' + selector(n + '()').hex() for n in ok}:
                raise  # a custom error outside the kernel's table arrives as REVERT_<selector>
            self.moves.append((tag, 'refused:' + e.revert))
            return None
        self.moves.append((tag, 'ok'))
        return rc

    def trace(self, job):
        t = Trace(self.codec, [list(i) for i in job.program], list(job.inputs), job.max_steps)
        return self.lie(t) if self.lie else t

    def refusal(self, job, n, now):
        """why this posted job gets no stake, or None. This class runs the jobs it was handed with take()."""
        return None

    def _isolated(self, tag, name, act):
        """one job's failure stops that job only (READINESS_AUDIT A03): a refused call outside the expected ones, a run
        that cannot be computed. A transport error is about every job and still raises, so does a wiring error."""
        try:
            act()
        except self.ISOLATED as e:
            said = scrub(getattr(e, 'revert', None) or e)[:120]
            self._failed[(tag, name)] = said
            if self.errors.get((tag, name)) != said:
                self.errors[(tag, name)] = said
                self.moves.append((tag, name, 'error:' + said))
        else:
            self.errors.pop((tag, name), None)

    def _note(self, tag, name, said):
        """a failure the pass goes on after: failing() tells it"""
        self._failed[(tag, name)] = scrub(getattr(said, 'revert', None) or said)[:120]

    def failing(self):
        """{kind: detail} of what the last pass swallowed (B4): a refused call outside the expected ones, a transaction not
        mined or failed, a job that could not be computed. Empty: healthy. Another pass that works empties it."""
        return {f'{tag}:{name}' if name else tag: said for (tag, name), said in self._failed.items()}

    def _scan(self):
        """before the jobs: what a player finds on its own"""

    def step(self):
        self._failed = {}
        self._scan()
        now = self.board.now()
        for job in self.jobs:
            self._isolated('job', job.key.hex(), lambda j=job: self._advance(j, now))  # the whole key: the head is the account's
        self._isolated('collect', '', self._collect)

    def _advance(self, job, now):
        esc = self.escrow.address
        n = self.escrow.node(job.key)
        if n['state'] == 'posted' and not n['bonded'] and not n['coverHeld'] and now <= n['deadline']:
            why = self.refusal(job, n, now)
            if why is not None:
                if self.refused.get(job.key) != why:
                    self.refused[job.key] = why
                    self.moves.append(('refused', job.key.hex(), why))
                return
            self._send('reserve', esc, key_call('reserve', job.key), ok=('InsufficientBond',))
            n = self.escrow.node(job.key)
        if n['state'] == 'posted' and n['bonded'] and now <= n['deadline']:
            t = self.trace(job)
            cid = self._own_unbound_claim(n)  # e.g. the claim went through but this step crashed before bind
            if cid is None:
                self._send('claim', self.board.game, _call(
                    CLAIM_SIG, ('w', t.pc_.commitment), ('w', t.ic_.commitment), ('w', word(t.max_steps)),
                    ('w', word(t.n)), ('b', t.enc(t.n)), ('b', t.out(t.n))), value=self.bond)
                cid = self._own_unbound_claim(n)
            if cid is None:
                return  # the claim is not mined yet (or was refused): nothing to bind in this pass
            self._send('bind', esc, key_call('bind', job.key, cid))
            self.moves.append(('trace', job.key.hex()[:8], t.n))
            return
        if n['state'] not in ('claimed', 'verified'):
            if n['bonded'] and n['state'] in ('final', 'voided') and now > self.escrow.expires_at(job.key):
                self._send('release', esc, key_call('release', job.key), ok=('NotBonded',))
            self._expire(job, n, now)
            return
        c = self.board.claim(n['claimId'])
        if c['status'] == CLAIMED:
            if c['open']:
                self._defend(c, self.trace(job), now)
            if now > c['deadline'] and self.board.claim(c['id'])['open'] == 0:
                self._send('finalize', self.board.game, finalize_data(c['id']),
                           ok=('WrongStatus', 'StillOpen', 'TooEarly'))
        if self.board.claim(n['claimId'])['status'] == ACCEPTED:
            # anyone may settle: WrongStatus is a settle by someone else landing between the read and this call
            if self._send('settle', esc, key_call('settle', job.key), ok=('AncestorNotFinal', 'WrongStatus')) is None \
                    and self.escrow.node(job.key)['state'] == 'claimed':  # re-read: the settle may have lost a race
                self._send('verify', esc, key_call('verify', job.key), ok=('WrongStatus',))
        if now > n['expiry']:
            self._expire(job, self.escrow.node(job.key), now)

    def _expire(self, job, n, now):
        """an account that vanished must not hold the stake: past the node's expiry anyone may end it, and this is the
        party with money in it"""
        if n['state'] in ('posted', 'claimed', 'verified') and (n['bonded'] or n['coverHeld']) and now > n['expiry']:
            self._send('expire', self.escrow.address, key_call('expire', job.key),
                       ok=('ClaimRejected', 'Settleable', 'WrongStatus', 'TooEarly'))

    def _collect(self):
        """settling and winning games only credit: this is where the money reaches the executor. The game's credit
        always leaves (it is the next claim bond); the escrow's free stake leaves above keep_stake."""
        me = self.signer.address
        if self.board.credit(me) > 0:
            self._send('withdraw', self.board.game, WITHDRAW, ok=('NothingToWithdraw', 'PayoutFailed'))
        if self.keep_stake is not None:
            extra = self.escrow.bond_of(me) - self.keep_stake
            if extra > 0:
                self._send('collect', self.escrow.address, call_data('withdrawBond(address,uint256)', self.payout, extra),
                           ok=('InsufficientBond',))

    def _own_unbound_claim(self, n):
        """my live claim for exactly this node's computation, made after its reservation and not used by any node"""
        nc, _ = self.board.counts()
        for cid in range(n['claimFloor'] + 1, nc + 1):
            c = self.board.claim(cid)
            if (c['defender'], c['prog'], c['inputs'], c['maxSteps']) != (self.signer.address, n['prog'], n['inputs'],
                                                                          n['maxSteps']) or c['status'] not in (1, 2):
                continue
            used = self.board.chain.call(self.escrow.address, call_data('claimUsedBy(address,uint256)',
                                                                        self.board.game, cid))
            if used == bytes(32):
                return cid
        return None

    def _defend(self, c, t, now):
        for g in self.board.games_of(c['id']):
            if g['status'] != ACTIVE:
                continue
            if now > g['deadline']:
                if g['turn'] != DEFENDER:  # the challenger ran out of time: the game and its bond are ours
                    self._send('timeout', self.board.game, timeout_data(g['id']), ok=('WrongStatus', 'TooEarly'))
            elif g['turn'] == DEFENDER:
                self._send('bisect', self.board.game, _call('bisect(uint256,bytes32)', ('w', word(g['id'])),
                                                            ('w', t.hashes[min(_mid(g), t.n)])),
                           ok=('WrongTurn', 'WrongStatus', 'TooLate'))
            elif g['turn'] == PROVE:
                lo = g['lo']
                self._send('prove', self.board.game, _call('prove(uint256,bytes,bytes)', ('w', word(g['id'])),
                                                           ('b', t.enc(lo)), ('b', t.aux(lo))),
                           ok=('WrongTurn', 'WrongStatus', 'TooLate', 'NotSingleStep'))


class GraphGuard:
    """Rejects every node whose bound claim its referee rejected, then voids every node with a rejected ancestor
    (waiting while the node's own claim is undecided)."""

    def __init__(self, escrow, signer, referee_status):
        self.escrow, self.signer, self.referee_status = escrow, signer, referee_status  # (node) -> ClaimStatus
        self.keys = []
        self.moves = []

    def watch(self, key):
        self.keys.append(key)

    def step(self):
        chain = self.escrow.chain
        for k in self.keys:
            n = self.escrow.node(k)
            if n['state'] == 'claimed' and self.referee_status(n) == REJECTED:
                try:
                    chain.send(self.signer, self.escrow.address, key_call('reject', k))
                    self.moves.append(('reject', k))
                except TxOutcome as e:
                    self.moves.append(('reject', k, str(e)))
        for k in self.keys:
            n = self.escrow.node(k)
            if n['state'] in ('posted', 'claimed', 'verified', 'expired') and any(
                    self.escrow.node(a)['state'] == 'rejected' for a in self.escrow.ancestors(k)):
                try:
                    chain.send(self.signer, self.escrow.address, key_call('voidNode', k))
                    self.moves.append(('void', k))
                except TxOutcome as e:
                    self.moves.append(('void', k, str(e)))
                except RpcError as e:
                    if e.revert not in ('ClaimPending',):
                        raise
