"""Intent -> policy check -> execution -> verifiable result -> challenge/dispute -> conditional settlement, end to end
over OmegaJobEscrow + OVM0Dispute + OVM0Inbox on an EVM chain.

Roles (all stateless between calls except the kernel cosigner's spend journal, which is the policy state):
- Requester: the agent signs the job (EIP-712), the kernel cosigner checks its own policy and countersigns, the requester
  publishes the program and inputs (data availability) and any relayer posts the job; posting twice is a no-op.
- Executor: finds the jobs addressed to it from Posted logs and the programs from Published logs, stakes at least the
  price in the escrow (reserve), runs the program, claims the result with a dispute bond, answers every game on its
  claims, finalizes and settles, and takes the stake back after the slash period. It keeps nothing in memory that it
  cannot rebuild from the chain, so a restarted executor finishes what the previous one started.
- Watchtower (omega_compute.dispute_agent) re-executes every claim and defeats the false ones.
- Guard: the account's side; moves the stake of an executor whose claim for the job was defeated to the account.
Nothing here decides correctness: the escrow pays only for a claim OVM0Dispute accepted.
"""
import sqlite3
from dataclasses import dataclass
from omega_compute import vm
from omega_compute import evm_step as E
from omega_compute.dispute_agent import (ACTIVE, CLAIM_SIG, CLAIMED, DEFENDER, PROVE, Board, Trace, _call, _mid, _u,
                                         publish_data)
from omega_kernel.settlement.evm import RpcError, TxOutcome
from omega_kernel.settlement.evm_crypto import keccak, selector, sign_typed, word, words

JOB_TYPE = (b'Job(bytes32 key,bytes32 account,address executor,bytes32 prog,bytes32 inputs,uint64 maxSteps,'
            b'uint128 price,uint8 cond,uint64 condArg,uint64 deadline)')
JOB_TUPLE = '(bytes32,bytes32,address,bytes32,bytes32,uint64,uint128,uint8,uint64,uint64)'
SIG_TUPLE = '(uint8,bytes32,bytes32)'
POST_SIG = f'post({JOB_TUPLE},{SIG_TUPLE},{SIG_TUPLE})'
POSTED_TOPIC = keccak(b'Posted(bytes32,bytes32,address,bytes32,bytes32,uint64,uint128,uint8,uint64,uint64)')
SETTLE_SIG = f'settle({JOB_TUPLE},uint256)'
EXPIRE_SIG = f'expire({JOB_TUPLE})'
RESERVE_SIG = f'reserve({JOB_TUPLE})'
SLASH_SIG = f'slash({JOB_TUPLE},uint256)'
RELEASE_SIG = f'release({JOB_TUPLE})'
REJECTED = 3  # OVM0Dispute ClaimStatus
COND = {'clean': 0, 'eq': 1, 'le': 2, 'ge': 3}
OPEN, PAID, REFUNDED = 1, 2, 3  # JobStatus
NO_SIG = (0, bytes(32), bytes(32))

# sum 1..N of input 0: stack (acc, i); 9N + 6 transitions, output N(N+1)/2 mod 2^64
SUM_TO_N = [['PUSH', 0], ['LOAD', 0], ['DUP', 0], ['JZ', 11], ['DUP', 0], ['SWAP', 2], ['ADD'], ['SWAP', 1], ['PUSH', 1],
            ['SUB'], ['JMP', 2], ['POP'], ['HALT']]


def budget_check_program(k):
    """Checker for a non-deterministic producer's answer (e.g. a model's allocation of k amounts): inputs are
    [budget, cap, a_1..a_k] with the answer published as data; output 1 iff sum(a) <= budget and every a_i <= cap,
    else 0. The answer itself is not proven right, only that it meets these checkable constraints. mem[0] holds the
    sum, mem[1] the count of items over cap; sums wrap mod 2^64, so keep k * cap < 2^64 (then a wrap needs an item
    over cap, which already fails). 14k + 11 transitions."""
    p = []
    for i in range(k):
        p += [['PUSH', 0], ['MLOAD'], ['LOAD', 2 + i], ['ADD'], ['PUSH', 0], ['MSTORE'],
              ['PUSH', 1], ['MLOAD'], ['LOAD', 1], ['LOAD', 2 + i], ['LT'], ['ADD'], ['PUSH', 1], ['MSTORE']]
    return p + [['PUSH', 0], ['MLOAD'], ['LOAD', 0], ['SWAP', 1], ['LT'], ['PUSH', 1], ['MLOAD'], ['ADD'], ['PUSH', 0],
                ['EQ'], ['HALT']]


class PolicyDenied(Exception):
    pass


@dataclass(frozen=True)
class JobIntent:
    key: bytes
    account: bytes
    executor: bytes
    program: tuple
    inputs: tuple
    max_steps: int
    price: int
    cond: int
    cond_arg: int
    deadline: int

    def commitments(self):
        prog = [list(i) for i in self.program]
        return E.program_commit(prog).commitment, E.inputs_commit(list(self.inputs)).commitment

    def fields(self):
        prog, inp = self.commitments()
        return (self.key, self.account, self.executor, prog, inp, self.max_steps, self.price, self.cond, self.cond_arg,
                self.deadline)

    def struct_hash(self):
        return keccak(keccak(JOB_TYPE) + b''.join(word(x) for x in self.fields()))

    def digest(self, domain):
        return keccak(b'\x19\x01' + domain + self.struct_hash())


def intent(key, account, executor, program, inputs, max_steps, price, deadline, cond='clean', cond_arg=0):
    vm.check_program(program)
    return JobIntent(key, account, executor, tuple(tuple(i) for i in program), tuple(inputs), max_steps, price, COND[cond],
                     cond_arg, deadline)


def post_data(it, agent_sig, cosig=NO_SIG):
    return selector(POST_SIG) + b''.join(word(x) for x in it.fields() + tuple(agent_sig) + tuple(cosig))


def job_fields(job):
    """JobReq fields of a job dict from Escrow.job (the escrow checks them against the posted hash)."""
    return (job['key'], job['account'], job['executor'], job['prog'], job['inputs'], job['maxSteps'], job['price'],
            job['cond'], job['condArg'], job['deadline'])


def settle_data(fields, claim_id):
    return selector(SETTLE_SIG) + b''.join(word(x) for x in fields) + word(claim_id)


def expire_data(fields):
    return selector(EXPIRE_SIG) + b''.join(word(x) for x in fields)


def reserve_data(fields):
    return selector(RESERVE_SIG) + b''.join(word(x) for x in fields)


def slash_data(fields, claim_id):
    return selector(SLASH_SIG) + b''.join(word(x) for x in fields) + word(claim_id)


def release_data(fields):
    return selector(RELEASE_SIG) + b''.join(word(x) for x in fields)


class KernelCosigner:
    """The OMEGA kernel's policy key: countersigns a job only if its own (off-chain, stricter or equal) policy allows it.
    The spend journal is the policy state (window spend and call count) and survives restarts; the same job key always
    gets the same answer, a different job under a used key is refused."""

    def __init__(self, signer, journal_path, *, programs, executors, max_price, max_steps, window_seconds,
                 max_spend_per_window, max_calls_per_window, valid_until, clock):
        self.signer, self.clock = signer, clock
        self.programs, self.executors = set(programs), set(executors)
        self.max_price, self.max_steps, self.window = max_price, max_steps, window_seconds
        self.max_spend, self.max_calls, self.valid_until = max_spend_per_window, max_calls_per_window, valid_until
        self.db = sqlite3.connect(journal_path)
        self.db.execute('CREATE TABLE IF NOT EXISTS cosigned (key BLOB PRIMARY KEY, struct BLOB, price INTEGER, at INTEGER)')
        self.db.commit()

    def close(self):
        self.db.close()

    def approve(self, it, domain):
        row = self.db.execute('SELECT struct FROM cosigned WHERE key = ?', (it.key,)).fetchone()
        if row is not None:
            if row[0] != it.struct_hash():
                raise PolicyDenied('KEY_REUSE')
            return sign_typed(self.signer, it.digest(domain))  # same job: same answer (deterministic RFC 6979)
        now = self.clock()
        prog, _ = it.commitments()
        checks = [(now >= self.valid_until or it.deadline > self.valid_until, 'POLICY_EXPIRED'),
                  (prog not in self.programs, 'PROGRAM_DENIED'), (it.executor not in self.executors, 'EXECUTOR_DENIED'),
                  (it.max_steps > self.max_steps, 'TOO_MANY_STEPS'), (it.price > self.max_price, 'OVER_PER_JOB'),
                  (it.deadline <= now, 'DEADLINE_PASSED')]
        for bad, why in checks:
            if bad:
                raise PolicyDenied(why)
        spent, calls = self.db.execute('SELECT COALESCE(SUM(price), 0), COUNT(*) FROM cosigned WHERE at > ?',
                                       (now - self.window,)).fetchone()
        if spent + it.price > self.max_spend:
            raise PolicyDenied('OVER_WINDOW')
        if calls + 1 > self.max_calls:
            raise PolicyDenied('OVER_CALLS')
        self.db.execute('INSERT INTO cosigned VALUES (?, ?, ?, ?)', (it.key, it.struct_hash(), it.price, now))
        self.db.commit()
        return sign_typed(self.signer, it.digest(domain))


class Escrow:
    """Read-only view of an OmegaJobEscrow deployment."""

    def __init__(self, chain, address):
        self.chain, self.address = chain, address
        self.domain = chain.call(address, selector('DOMAIN_SEPARATOR()'))

    def view(self, sig, *args):
        return self.chain.call(self.address, selector(sig) + b''.join(word(a) for a in args))

    def job(self, key, log=None):
        """the posted fields (from the Posted log; the contract keeps only their hash) plus the one-slot state"""
        w = words(self.view('getJob(bytes32)', key))
        out = {'key': key, 'status': _u(w[0]), 'postedAt': _u(w[1]), 'claimFloor': _u(w[2]), 'claimId': _u(w[3]),
               'bonded': _u(w[4]) == 1}
        if log is None:
            logs = self.chain.rpc('eth_getLogs', {'address': '0x' + self.address.hex(), 'fromBlock': '0x0',
                                                  'toBlock': 'latest', 'topics': ['0x' + POSTED_TOPIC.hex(), '0x' + key.hex()]})
            log = logs[0] if logs else None
        if log is not None:
            d = words(bytes.fromhex(log['data'][2:]))
            out |= {'account': bytes.fromhex(log['topics'][2][2:]), 'executor': bytes.fromhex(log['topics'][3][2:])[12:],
                    'prog': d[0], 'inputs': d[1], 'maxSteps': _u(d[2]), 'price': _u(d[3]), 'cond': _u(d[4]),
                    'condArg': _u(d[5]), 'deadline': _u(d[6])}
        return out

    def balance(self, account):
        return _u(self.view('balanceOf(bytes32)', account))

    def locked(self):
        return _u(self.view('locked()'))

    def bond_of(self, executor):
        return _u(self.view('bondOf(address)', executor))

    def bonds_held(self):
        return _u(self.view('bondsHeld()'))

    def bond_for(self, price):
        return _u(self.view('bondFor(uint128)', price))

    def expires_at(self, deadline):
        return _u(self.view('expiresAt(uint64)', deadline))

    def claim_used(self, cid):
        return self.view('claimUsedBy(uint256)', cid) != bytes(32)

    def posted(self, executor=None):
        """job key -> Posted fields, optionally only the jobs addressed to `executor`."""
        topics = ['0x' + POSTED_TOPIC.hex(), None, None]
        if executor is not None:
            topics.append('0x' + word(executor).hex())
        logs = self.chain.rpc('eth_getLogs', {'address': '0x' + self.address.hex(), 'fromBlock': '0x0', 'toBlock': 'latest',
                                              'topics': topics})
        return {bytes.fromhex(g['topics'][1][2:]): g for g in logs}


class Requester:
    def __init__(self, chain, escrow, board, relayer, agent, cosigner=None):
        self.chain, self.escrow, self.board, self.relayer, self.agent = chain, escrow, board, relayer, agent
        self.cosigner = cosigner

    def sign(self, it):
        agent_sig = sign_typed(self.agent, it.digest(self.escrow.domain))
        cosig = self.cosigner.approve(it, self.escrow.domain) if self.cosigner else NO_SIG
        return agent_sig, cosig

    def publish(self, it):
        prog, inp = it.commitments()
        if not self.board.is_published(prog, inp):
            self.chain.send(self.relayer, self.board.inbox, publish_data([list(i) for i in it.program], list(it.inputs)))

    def submit(self, it):
        """-> receipt of the post (a repeat post of the same job succeeds and locks nothing)."""
        agent_sig, cosig = self.sign(it)
        self.publish(it)
        return self.chain.send(self.relayer, self.escrow.address, post_data(it, agent_sig, cosig))


class Executor:
    """Executes, claims, defends, finalizes and settles every job addressed to `signer`. `lie(trace) -> trace` lets a
    test play a dishonest executor."""

    def __init__(self, board, escrow, signer, bond, codec, lie=None, max_claims=None):
        self.board, self.escrow, self.signer, self.bond, self.codec, self.lie = board, escrow, signer, bond, codec, lie
        self.max_claims = max_claims  # per job and stake; tests use 1 so a dishonest player does not retry after losing
        self._staked = set()  # with max_claims only: jobs this instance staked once, never staked again
        self.moves = []
        self._traces = {}  # (prog, inputs, maxSteps) -> Trace; a cache, not state: a restart only recomputes it

    def _send(self, tag, to, data, value=0, ok=()):
        try:
            rc = self.board.chain.send(self.signer, to, data, value=value)
        except TxOutcome as e:  # not mined yet, or mined and failed: the next step reads the chain and decides again
            self.moves.append((tag, str(e)))
            return None
        except RpcError as e:
            if e.revert not in ok:
                raise
            self.moves.append((tag, 'refused:' + e.revert))
            return None
        self.moves.append((tag, 'ok'))
        return rc

    def trace(self, job, published):
        known = published.get((job['prog'], job['inputs']))
        if known is None:
            return None  # the requester has not published the computation: nothing can be claimed for it
        k = (job['prog'], job['inputs'], job['maxSteps'])
        if k not in self._traces:  # without this every step re-hashed the whole trace (9,006 Merkle states at N=1000)
            t = Trace(self.codec, known[0], known[1], job['maxSteps'])
            self._traces[k] = self.lie(t) if self.lie else t
        return self._traces[k]

    def step(self):
        """One pass over every job addressed to me. An open job is staked (reserve) before anything is claimed for it.
        Jobs asking for the same computation each get their own claim: staked jobs (oldest first) take my live, unused
        claims (oldest first) made after their reservation, and a job left without one gets a new claim. Rejected claims
        are never reused, so a job outlives a lost game (staked again after a slash). A held stake is released once the
        job's slash period is over."""
        now = self.board.now()
        me = self.signer.address
        nc, _ = self.board.counts()
        mine = [c for c in (self.board.claim(i) for i in range(1, nc + 1)) if c['defender'] == me]
        jobs = sorted(((self.escrow.job(k, g), k) for k, g in self.escrow.posted(me).items()),
                      key=lambda x: (x[0]['postedAt'], x[1]))
        published = self.board.published()
        taken = set()
        for job, key in jobs:
            if job['status'] != OPEN:
                if job['bonded'] and now > self.escrow.expires_at(job['deadline']):
                    self._send('release', self.escrow.address, release_data(job_fields(job)), ok=('NotBonded',))
                continue
            t = self.trace(job, published)
            if t is None:
                continue
            if not job['bonded']:
                if now > job['deadline'] or (self.max_claims is not None and key in self._staked):
                    continue
                if self.escrow.bond_of(me) < self.escrow.bond_for(job['price']):
                    continue  # too little free stake: the job is left to expire, never claimed unstaked
                if self._send('reserve', self.escrow.address, reserve_data(job_fields(job)), ok=('AlreadyBonded',)) is None:
                    continue
                self._staked.add(key)
                job = job | {'bonded': True, 'claimFloor': self.board.counts()[0]}
            comp = (job['prog'], job['inputs'], job['maxSteps'])
            ours = [c for c in mine if (c['prog'], c['inputs'], c['maxSteps']) == comp and c['id'] > job['claimFloor']]
            free = [c for c in ours if c['status'] in (CLAIMED, 2) and c['id'] not in taken
                    and not self.escrow.claim_used(c['id'])]
            if not free:
                if now <= job['deadline'] and (self.max_claims is None or len(ours) < self.max_claims):
                    self._send('claim', self.board.game, _call(CLAIM_SIG, ('w', t.pc_.commitment), ('w', t.ic_.commitment),
                                                               ('w', word(t.max_steps)), ('w', word(t.n)),
                                                               ('b', t.enc(t.n)), ('b', t.out(t.n))), value=self.bond)
                continue
            c = free[0]
            taken.add(c['id'])
            if c['status'] == CLAIMED:
                self._defend(c, t)
                if now > c['deadline'] and self.board.claim(c['id'])['open'] == 0:
                    self._send('finalize', self.board.game, _call('finalize(uint256)', ('w', word(c['id']))),
                               ok=('WrongStatus', 'StillOpen', 'TooEarly'))
            if self.board.claim(c['id'])['status'] == 2:  # Accepted: pays or refunds by the job's condition
                self._send('settle', self.escrow.address, settle_data(job_fields(job), c['id']),
                           ok=('JobNotOpen', 'ClaimUsed'))

    def _defend(self, c, t):
        for g in self.board.games_of(c['id']):
            if g['status'] != ACTIVE:
                continue
            if g['turn'] == DEFENDER:
                self._send('bisect', self.board.game, _call('bisect(uint256,bytes32)', ('w', word(g['id'])),
                                                            ('w', t.hashes[min(_mid(g), t.n)])),
                           ok=('WrongTurn', 'WrongStatus', 'TooLate'))
            elif g['turn'] == PROVE:
                lo = g['lo']
                self._send('prove', self.board.game, _call('prove(uint256,bytes,bytes)', ('w', word(g['id'])),
                                                           ('b', t.enc(lo)), ('b', t.aux(lo))),
                           ok=('WrongTurn', 'WrongStatus', 'TooLate', 'NotSingleStep'))


class Guard:
    """The account's watcher of stakes: for every staked job of `account` (every account if None), slashes a claim of the
    job's executor that OVM0Dispute rejected and that could have settled the job. The stake goes to the account, so the
    account is the party with a reason to run this (a defeated claim's dispute bond can be raced away by the liar's own
    challenger; the stake cannot). Stateless: everything comes from logs and views."""

    def __init__(self, board, escrow, signer, account=None):
        self.board, self.escrow, self.signer, self.account = board, escrow, signer, account
        self.slashed = []  # (job key, claim id)

    def step(self):
        now = self.board.now()
        nc, _ = self.board.counts()
        rejected = [c for c in (self.board.claim(i) for i in range(1, nc + 1)) if c['status'] == REJECTED]
        if not rejected:
            return
        for key, g in self.escrow.posted().items():
            job = self.escrow.job(key, g)
            if self.account is not None and job['account'] != self.account:
                continue
            if not job['bonded'] or now > self.escrow.expires_at(job['deadline']):
                continue
            comp = (job['executor'], job['prog'], job['inputs'], job['maxSteps'])
            for c in rejected:
                if (c['defender'], c['prog'], c['inputs'], c['maxSteps']) != comp or c['id'] <= job['claimFloor']:
                    continue
                try:
                    self.board.chain.send(self.signer, self.escrow.address, slash_data(job_fields(job), c['id']))
                except TxOutcome:
                    continue
                except RpcError as e:
                    if e.revert not in ('LateClaim', 'ClaimUsed', 'NotBonded', 'TooLate'):
                        raise
                    continue
                self.slashed.append((key, c['id']))
                break


def expected_output(it):
    """What the escrow will decide for this intent, computed off chain from the honest run."""
    s, _ = vm.run([list(i) for i in it.program], list(it.inputs), it.max_steps)
    top = s['stack'][-1] if s['stack'] else 0
    clean = s['trap'] is None
    ok = {0: True, 1: top == it.cond_arg, 2: top <= it.cond_arg, 3: top >= it.cond_arg}[it.cond]
    return top, clean and ok


__all__ = ['Board', 'Escrow', 'Executor', 'Guard', 'JobIntent', 'KernelCosigner', 'PolicyDenied', 'Requester',
           'SUM_TO_N', 'expected_output', 'intent', 'post_data']
