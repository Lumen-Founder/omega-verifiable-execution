"""The account side of a Plan on OmegaGraphEscrow (docs/adr/ADR-0012). tick():
- publishes each task's program and inputs (data availability) and posts it as soon as every parent has a live bound
  claim (early execution: the child runs on the parent's claimed result, payment waits for the parent to be final);
- rejects nodes whose bound claim the referee rejected, and voids every node built on a rejected one;
- expires nodes past their expiry;
- retries a task whose current attempt is REJECTED, VOIDED or EXPIRED as the next attempt (a new node), on the parents'
  current live attempts, up to the plan's max_attempts.
It keeps no state: every tick re-reads the chain, the keys and deadlines come from the plan, so a crash, a lost
acknowledgement or a repeated tick changes nothing (a repeated post of the same signed request is a no-op on chain).
Settlement itself (settle) is done by the executors and by anyone; tick() also closes the games past their deadline on
the plan's claims (timeout, in the direction the contract decides), finalizes the claims past their window and settles
what is settleable, on every referee it holds a Board for, so a plan completes even if an executor never comes back.
A task on a Cannon referee (OmegaCannonReferee) is posted only if the balances of its executor and of the watcher in
`capital` cover what omega_world.referee_policy requires; otherwise it is refused, never moved to another referee; a
referee that cannot be read is a refusal too and nothing about it is remembered. A task is posted only while the guard
(deploy.referee_guards: the pinned Optimism contracts are unchanged) of its referee and of every ancestor's referee
passes: its money is bound to what they decide.
A task's kind (plan.py) decides its commitments, so that the claim its referee reports binds: an OVM-0 commitment, a Cannon
prestate (rebuilt by `prestates`, never taken from anyone), or an Optimism question. Nothing is posted before what an
independent watcher needs is public: the program and inputs, or the question, in OVM0Inbox (docs/adr/ADR-0012 section 11)."""
from omega_compute import evm_step as E
from omega_compute.dispute_agent import (ACTIVE, CLAIMED, PUBLISHED_TOPIC, Board, finalize_data, published_logs, publish_data,
                                         scan_logs, timeout_data)
from omega_compute.graph_escrow import ACCEPTED, REJECTED, GraphJob, key_call, post_data
from omega_kernel.settlement.evm import RpcError, TxOutcome
from omega_world import cannon as CN
from omega_world import op_attest as OA
from omega_world import referee_policy as RP
from omega_kernel.settlement.evm_crypto import call_data, selector, sign_typed, words
from omega_world.plan import PUBLISH_MAX_BYTES, TX_GAS_CAP, PlanError, meets, publish_bytes

LIVE = ('claimed', 'verified', 'final')
FAILED = ('rejected', 'voided', 'expired')
EXPECTED = ('ClaimPending', 'ClaimRejected', 'WrongStatus', 'TooEarly', 'AncestorNotFinal', 'NoRejectedAncestor',
            'ClaimNotAccepted', 'ClaimNotRejected',  # races with other callers: the next tick decides again
            'ParentRejected', 'AncestorDead', 'AncestorExpired', 'ExposureExceeded', 'DeadlinePassed',  # post races
            'Settleable')


def revert_name(e):
    """the custom error of a revert, by name, whether or not the kernel's error table knows it"""
    r = e.revert
    for n in EXPECTED:
        if r == n or r == 'REVERT_' + selector(n + '()').hex():
            return n
    return r


SETTLE_MARGIN = 3600  # seconds a child must outlive its last ancestor's decision, for the settle transactions


def claim_view(chain, referee, cid):
    """the bound claim as the referee reports it, or None if the referee cannot be read: an answer too short to be a claim
    is that too (the escrow treats it the same way, ADR-0012 D9; READINESS_AUDIT A39)"""
    try:
        w = words(chain.call(referee, call_data('getClaim(uint256)', cid)))
    except RpcError:
        return None
    if len(w) < 11:
        return None
    return {'status': int.from_bytes(w[7], 'big'), 'output': int.from_bytes(w[9], 'big'),
            'deadline': int.from_bytes(w[5], 'big'), 'trap': int.from_bytes(w[10], 'big'),
            'open': int.from_bytes(w[6], 'big'), 'id': cid, 'n': int.from_bytes(w[4], 'big'), 'hN': w[8]}


def job_of(plan, t, attempt, vals, parents, prestates=None):
    """the escrow request of one attempt of a task, by its kind; parents: [(key, claim id)]"""
    head = (plan.key(t.name, attempt), bytes.fromhex(plan.account[2:]), plan.executor(t.name, attempt),
            bytes.fromhex(t.referee[2:]))
    terms = (t.price, t.comp, t.ext, plan.covers()[t.name], t.cond, t.cond_arg, plan.deadline(attempt),
             tuple(k for k, _ in parents), tuple(c for _, c in parents))
    if t.kind == 'op':
        return OA.AttestJob(*head, (), (), 1, *terms, l2_chain_id=t.l2_chain_id, l2_time=t.l2_time)
    inputs = tuple(vals) + tuple(t.inputs)
    if t.kind == 'cannon':
        return CN.CannonJob(*head, t.program, inputs, t.max_steps, *terms, prestate=prestates(t.program, inputs, t.max_steps))
    return GraphJob(*head, t.program, inputs, t.max_steps, *terms)


class Orchestrator:
    def __init__(self, chain, escrow, plan, agent, relayer, boards=None, cosign=None, capital=None, guards=None, inbox=None,
                 prestates=None, from_block=None):
        """boards: referee address -> Board for referees with an OVM0Inbox (programs are published there first);
        capital: referee address -> referee_policy.CannonCapital for Cannon referees;
        guards: referee address -> check(chain) -> bool, re-run before each post on it or on anything built on it
        (deploy.referee_guards);
        inbox: the OVM0Inbox of Cannon jobs and Optimism questions (default: the boards');
        prestates: (program, inputs, max_steps) -> prestate, cannon.Prestates, for Cannon tasks;
        from_block: the deployment block, where log scans start (default: the boards')"""
        self.chain, self.esc, self.plan, self.agent, self.relayer = chain, escrow, plan, agent, relayer
        self.boards = dict(boards or {})
        self.inbox = inbox if inbox is not None else next((b.inbox for b in self.boards.values()), None)
        self.prestates = prestates
        self.from_block = min((b.from_block for b in self.boards.values()), default=0) if from_block is None else from_block
        self._too_large = set()  # tasks whose publication the node says is over the limit of one transaction (F4)
        kinds = {t.kind for t in plan.tasks} if plan else set()
        if 'cannon' in kinds and prestates is None:
            raise PlanError('CANNON_NEEDS_PRESTATES')
        if kinds & {'cannon', 'op'} and self.inbox is None:
            raise PlanError('NEEDS_INBOX')
        self._prog_checked = {}  # node key -> this plan's job or not, for what took a rebuild to tell
        self.capital = {bytes(k): v for k, v in (capital or {}).items()}
        self._kinds = {}  # referee address -> FDG bond curve (a Cannon referee) or None (another referee)
        self.guards = {bytes(k): v for k, v in (guards or {}).items()}
        self.cosign = cosign  # optional (job, domain) -> Sig, e.g. a policy key that countersigns
        self.log = []

    # ---- reading ------------------------------------------------------------------------------------------------------
    def now(self):
        return int(self.chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)

    def attempts(self, name):
        """[(attempt, key, node)] of every attempt that exists on chain and is this plan's (same account, executor,
        referee and program): anything else under a plan key is ignored and reported by foreign()"""
        return [(a, k, n) for a, k, n in self._all(name) if self._ours(name, a, n)]

    def _all(self, name):
        out = []
        for a in range(self.plan.max_attempts):
            k = self.plan.key(name, a)
            n = self.esc.node(k)
            if n['status']:
                out.append((a, k, n))
        return out

    def _ours(self, name, attempt, n):
        t = self.plan.task(name)
        if (n['account'], n['executor'], n['referee']) != (bytes.fromhex(self.plan.account[2:]),
                                                           self.plan.executor(name, attempt), bytes.fromhex(t.referee[2:])):
            return False
        if t.kind == 'op':
            return (n['prog'], n['inputs']) == (OA.PROG, OA.inputs_of(t.l2_chain_id, t.l2_time))
        if t.kind == 'cannon':
            return self._ours_cannon(t, self.plan.key(name, attempt), n)
        return n['prog'] == GraphJob(b'', b'', b'', b'', t.program, (), 0, 0).commitments()[0]

    def _ours_cannon(self, t, key, n):
        """the prestate commits to the inputs, and a child's come from its parents' attempt under this node: read them and
        rebuild. Keys are bound to the account (D10), so if the chain cannot say now the answer is yes and is not kept."""
        if key not in self._prog_checked:
            try:
                anc = self.esc.ancestors(key)
                vals = []
                for p in t.parents:
                    pk = next(k for k in anc if k in {self.plan.key(p, a) for a in range(self.plan.max_attempts)})
                    pn = self.esc.node(pk)
                    vals.append(claim_view(self.chain, pn['referee'], pn['claimId'])['output'])
            except (RpcError, TypeError):
                return True
            except StopIteration:
                self._prog_checked[key] = False
                return False
            inputs = vals + list(t.inputs)
            try:
                self._prog_checked[key] = n['inputs'] == E.inputs_commit(inputs).commitment and n['prog'] == self.prestates(
                    t.program, inputs, t.max_steps)
            except ValueError:
                self._prog_checked[key] = False
        return self._prog_checked[key]

    def foreign(self):
        """plan keys holding nodes that are not this plan's (impossible on chain since ADR-0012 D10; checked anyway)"""
        return [(t.name, a) for t in self.plan.tasks for a, _, n in self._all(t.name) if not self._ours(t.name, a, n)]

    def current(self, name):
        att = self.attempts(name)
        return att[-1] if att else (None, None, None)

    def live_claim(self, node, task=None, key=None):
        """the node's bound claim if a child may be built on it: bound, not rejected, halted cleanly and meeting the
        task's condition (a trapped or failed result is final but useless, ADR-0012 D13), and no ancestor's claim
        rejected even if reject() was not called yet (D14)"""
        if node is None or node['state'] not in LIVE:
            return None
        c = claim_view(self.chain, node['referee'], node['claimId'])
        if c is None or c['status'] == REJECTED:
            return None
        if task is not None and not meets(task, c):
            return None
        if key is not None:
            for x in self.esc.ancestors(key):
                a = self.esc.node(x)
                ac = claim_view(self.chain, a['referee'], a['claimId']) if a['claimId'] else None
                if a['state'] in ('rejected', 'voided', 'expired') or (ac is not None and ac['status'] == REJECTED):
                    return None
        return c

    def status(self):
        out = {}
        for t in self.plan.tasks:
            a, k, n = self.current(t.name)
            c = claim_view(self.chain, n['referee'], n['claimId']) if n and n['claimId'] else None
            ok = bool(c and n['state'] == 'final' and meets(t, c))
            out[t.name] = {'attempt': a, 'key': k.hex() if k else None, 'state': n['state'] if n else 'unposted',
                           'output': c['output'] if ok else None, 'met': ok if n and n['state'] == 'final' else None,
                           'attempts_used': len(self.attempts(t.name))}
        return out

    def done(self):
        return all(v['state'] == 'final' and v['met'] for v in self.status().values())

    def stuck(self):
        """tasks that can never finish: a final result that trapped or missed its condition (deterministic: a retry
        gives the same), or no attempt left (all used and failed, or the remaining ones past their deadlines)"""
        out, now = [], self.now()
        for t in self.plan.tasks:  # plan order: a task under a stuck parent is stuck too
            if any(p in out for p in t.parents):
                out.append(t.name)
                continue
            a, _, n = self.current(t.name)
            if n is None and (t.name in self._too_large or (t.kind != 'op' and publish_bytes(t) > PUBLISH_MAX_BYTES)):
                out.append(t.name)  # it would never be posted: its publication does not fit a transaction (F4)
                continue
            if n is not None and n['state'] == 'final':
                c = claim_view(self.chain, n['referee'], n['claimId'])
                if c is not None and not meets(t, c):
                    out.append(t.name)
                continue
            if n is not None and n['state'] not in FAILED:
                continue
            nxt = 0 if a is None else a + 1
            if not any(self.plan.deadline(x) > now + 60 for x in range(nxt, self.plan.max_attempts)):
                out.append(t.name)
        return out

    def _word(self, to, sig):
        return int.from_bytes(self.chain.call(to, selector(sig))[:32], 'big')

    def _outlives(self, job, parent_keys):
        """a child must not expire before every ancestor's claim can be decided, plus SETTLE_MARGIN to get the
        settlements mined: a parent is final only once its own ancestors are (ADR-0013 D16, D19). Else the child's
        honest executor works and is never paid. An unreadable referee is a refusal too (post would revert on it):
        logged, not raised, so one failed referee does not stop the tick."""
        ref = job.referee
        try:  # the latest any ancestor's claim is decided: its deadline + both sides' game clocks
            due = 0
            for pk in parent_keys:
                for k in [pk] + self.esc.ancestors(pk):
                    n = self.esc.node(k)
                    c = claim_view(self.chain, n['referee'], n['claimId'])
                    if c is None:
                        raise RpcError('ANCESTOR_REFEREE_UNREADABLE')
                    due = max(due, c['deadline'] + 2 * self._word(n['referee'], 'clock()'))
            due += SETTLE_MARGIN
            expiry = job.deadline + self._word(ref, 'window()') + 2 * self._word(ref, 'clock()') + self._word(
                self.esc.address, 'grace()')
        except RpcError as e:
            self.log.append(('post', job.key.hex()[:8], 'refused:REFEREE_UNREADABLE:' + (revert_name(e) or str(e))))
            return False
        if expiry < due:
            self.log.append(('post', job.key.hex()[:8], 'refused:CHILD_EXPIRES_BEFORE_PARENT_DECIDED'))
            return False
        return True

    # ---- acting -------------------------------------------------------------------------------------------------------
    def _send(self, tag, key, data, to=None):
        try:
            self.chain.send(self.relayer, to or self.esc.address, data)
        except TxOutcome as e:  # not mined yet (the same call next tick waits for it) or mined and failed: read again
            self.log.append((tag, key.hex()[:8], str(e)))
            return False
        except RpcError as e:  # a refused call changes nothing on chain; transport errors (OSError) still raise
            self.log.append((tag, key.hex()[:8], 'refused:' + (revert_name(e) or str(e))))
            return False
        self.log.append((tag, key.hex()[:8], 'ok'))
        return True

    def tick(self):
        """one pass; returns the actions taken"""
        start = len(self.log)
        now = self.now()
        for t in self.plan.tasks:
            a, key, n = self.current(t.name)
            if n is not None:
                self._care(t, key, n, now)
                n = self.esc.node(key)
            if n is None or n['state'] in FAILED:
                self._try_post(t, 0 if a is None else a + 1, now)
        return self.log[start:]

    def _care(self, t, key, n, now):
        st = n['state']
        if st == 'posted' and t.kind == 'ovm0':
            self._keep_public(t, key, n, now)
        if st == 'claimed':
            c = claim_view(self.chain, n['referee'], n['claimId'])
            if c and c['status'] == REJECTED:
                self._send('reject', key, key_call('reject', key))
                return
            if c and c['status'] == CLAIMED:
                self._close(key, n, c, now, t)
        if st in ('posted', 'claimed', 'verified', 'expired'):
            if any(self.esc.node(x)['state'] == 'rejected' for x in self.esc.ancestors(key)):
                self._send('void', key, key_call('voidNode', key))
                return
        if st in ('claimed', 'verified'):
            c = claim_view(self.chain, n['referee'], n['claimId'])
            if c and c['status'] == ACCEPTED and all(self.esc.node(x)['state'] == 'final'
                                                      for x in self.esc.ancestors(key)):
                self._send('settle', key, key_call('settle', key))
                return
        if st in ('posted', 'claimed', 'verified') and now > n['expiry']:
            self._send('expire', key, key_call('expire', key))

    def _close(self, key, n, c, now, t):
        """calls anyone may make, so that no silent party and no vanished executor stops the plan (READINESS_AUDIT A00):
        a game past its deadline ends as the contract decides, a claim past its window with no game open is accepted"""
        board = self.boards.get(n['referee'])
        try:
            if t.kind != 'ovm0':  # a fault dispute game: resolved as its clocks allow, then the referee reads it
                sig = 'gameOf(uint256)' if t.kind == 'cannon' else 'rootOf(uint256)'
                OA.resolve_game(self.chain, self.relayer, self.chain.call(n['referee'], call_data(sig, c['id']))[12:32])
                return
            if board is None:
                return  # not an OVM0Dispute: its games are not played through this Board
            if c['open']:
                for g in board.games_of(c['id']):
                    if g['status'] == ACTIVE and now > g['deadline']:
                        self._send('timeout', key, timeout_data(g['id']), to=board.game)
                c = board.claim(c['id'])
            if c['status'] == CLAIMED and now > c['deadline'] and c['open'] == 0:
                self._send('finalize', key, finalize_data(c['id']), to=board.game)
        except RpcError as e:  # the referee cannot be read: the next tick looks again
            self.log.append(('close', key.hex()[:8], 'refused:' + (revert_name(e) or str(e))))

    def _cannon_bonds(self, ref):
        """referee_policy.cannon_bonds, once per referee; raises RpcError, and remembers nothing, if it cannot tell"""
        if ref not in self._kinds:
            self._kinds[ref] = RP.cannon_bonds(self.chain, ref)
        return self._kinds[ref]

    def _referees_under(self, job):
        """the job's referee and each ancestor's: all of them decide whether the job's money is ever paid"""
        refs = [job.referee]
        for pk in job.parent_keys:
            for k in [pk] + self.esc.ancestors(pk):
                r = self.esc.node(k)['referee']
                if r not in refs:
                    refs.append(r)
        return refs

    def _admitted(self, job):
        """the external contracts of the job's and its ancestors' referees pass their guards and its dispute capital is
        covered (referee_policy); a refusal is logged and the task waits"""
        try:
            for ref in (self._referees_under(job) if self.guards else ()):
                guard = self.guards.get(ref)
                if guard is not None and not guard(self.chain):
                    self.log.append(('post', job.key.hex()[:8], 'refused:REFEREE_CONTRACTS_CHANGED'))
                    return False
            bonds = self._cannon_bonds(job.referee)
            if bonds is not None:
                RP.admit_on_chain(self.chain, bonds, self.capital.get(job.referee), job.executor, job.referee,
                                  *self._in_flight(job))
        except RP.Refused as e:
            self.log.append(('post', job.key.hex()[:8], 'refused:' + str(e)))
            return False
        except RpcError as e:
            self.log.append(('post', job.key.hex()[:8], 'refused:REFEREE_UNREADABLE:' + (revert_name(e) or str(e))))
            return False
        return True

    def _in_flight(self, job):
        """(what the job's executor answers for, what the account's watcher answers for), as nodes (re-audit B18). The
        executor's: where it holds a stake, for any account, and this account's jobs it has not taken yet. Anyone can name it
        as the executor of a job: another account's offer it has not taken ties up nothing, or a stranger could use up its
        capital here. The watcher's: this account's."""
        if job.referee not in self.capital:
            return (), ()
        ref, acct = job.referee, job.account
        his = self.esc.live_nodes(ref, self.from_block, executor=job.executor)
        return ([n for k, n in his if k != job.key and (n['state'] == 'claimed' or n['bonded'] or n['account'] == acct)],
                [n for k, n in self.esc.live_nodes(ref, self.from_block, account=acct) if k != job.key])

    def _public(self, t, job):
        """what an independent watcher needs is in the inbox before the money is (READINESS_AUDIT A17, A42, A61). A
        publication that did not go through leaves the task waiting. An OVM-0 job on a referee without a Board has no
        inbox to go to."""
        board = self.boards.get(job.referee)
        if t.kind == 'ovm0' and board is None:
            return True
        inbox = board.inbox if t.kind == 'ovm0' else self.inbox
        if t.kind == 'op':
            try:
                if self._word(job.referee, 'l2ChainId()') != t.l2_chain_id:
                    self.log.append(('post', job.key.hex()[:8], 'refused:OP_WRONG_CHAIN'))
                    return False
            except RpcError as e:
                self.log.append(('post', job.key.hex()[:8], 'refused:REFEREE_UNREADABLE:' + (revert_name(e) or str(e))))
                return False
            prog, inp = OA.question_commitments(t.l2_chain_id, t.l2_time)
            data = OA.question_data(t.l2_chain_id, t.l2_time)
        else:
            program = [list(i) for i in job.program]
            prog, inp = E.program_commit(program).commitment, E.inputs_commit(list(job.inputs)).commitment
            data = publish_data(program, list(job.inputs))
        if len(data) > PUBLISH_MAX_BYTES:
            self.log.append(('publish', job.key.hex()[:8], 'refused:PUBLISH_TOO_LARGE'))
            return False
        try:
            if self._published(inbox, board if t.kind == 'ovm0' else None, prog, inp, job.deadline):
                return True
            gas = int(self.chain.rpc('eth_estimateGas', {'from': '0x' + self.relayer.address.hex(), 'to': '0x' + inbox.hex(),
                                                         'data': '0x' + data.hex()}), 16)
        except RpcError as e:
            self.log.append(('publish', job.key.hex()[:8], 'refused:' + (revert_name(e) or str(e))))
            return False
        if gas > TX_GAS_CAP:
            self._too_large.add(t.name)
            self.log.append(('publish', job.key.hex()[:8], 'refused:PUBLISH_TOO_LARGE'))
            return False
        return self._send('publish', job.key, data, to=inbox)

    def _published(self, inbox, board, prog, inp, deadline):
        """the relayer's own publication is there, and it lasts. Own: someone else's may come first and costs nothing to make,
        and find_job looks at the poster's publication first, so that a flood of look-alikes cannot hide this job from a
        watcher (re-audit B3). Lasting: isPublished stays true for ever, a claim only passes within daMaxAge (B15)."""
        last = int.from_bytes(self.chain.call(inbox, call_data('lastPublished(bytes32,bytes32)', prog, inp))[:32], 'big')
        if last == 0 or (board is not None and self._runs_out(board, last, deadline)):
            return False
        return bool(scan_logs(self.chain, inbox, ['0x' + PUBLISHED_TOPIC.hex(), '0x' + prog.hex(), '0x' + inp.hex(),
                                                  '0x' + bytes(12).hex() + self.relayer.address.hex()], self.from_block))

    def _runs_out(self, board, last, deadline):
        """the publication would not last to the deadline, or for half its age if the deadline is further than one
        publication lasts (then this comes back for it, _keep_public). A publication just made never runs out"""
        age = int.from_bytes(board.view('daMaxAge()')[:32], 'big')
        return last + age < min(deadline, self.now() + age // 2)

    def _keep_public(self, t, key, n, now):
        """a node waiting for its claim: the executor cannot claim on a publication past daMaxAge (B15). Published again with
        the values of an earlier publication: a child's inputs are not in the plan"""
        board = self.boards.get(n['referee'])
        if board is None or now > n['deadline']:
            return
        try:
            last = int.from_bytes(self.chain.call(board.inbox, call_data('lastPublished(bytes32,bytes32)', n['prog'], n['inputs']))[:32], 'big')
            if not self._runs_out(board, last, n['deadline']):
                return
            rows = published_logs(self.chain, board.inbox, self.from_block, n['inputs'], n['prog'])
        except RpcError as e:
            self.log.append(('publish', key.hex()[:8], 'refused:' + (revert_name(e) or str(e))))
            return
        if rows:
            self._send('publish', key, publish_data(rows[0].program, rows[0].values), to=board.inbox)

    def _try_post(self, t, attempt, now):
        while attempt < self.plan.max_attempts and self.plan.deadline(attempt) <= now + 60:
            attempt += 1  # this attempt's deadline is gone: its key is never used
        if attempt >= self.plan.max_attempts:
            return
        parents, vals, decided = [], [], []
        for p in t.parents:
            _, pk, pn = self.current(p)
            c = self.live_claim(pn, self.plan.task(p), pk)
            if c is None:
                return  # wait for a live, useful parent (possibly its own retry)
            parents.append((pk, pn['claimId']))
            vals.append(c['output'])
            decided.append(pk)
        job = job_of(self.plan, t, attempt, vals, parents, self.prestates)
        if not self._admitted(job):
            return
        if parents and not self._outlives(job, decided):
            return
        if not self._public(t, job):
            return
        digest = job.digest(self.esc.domain)
        cos = self.cosign(job, self.esc.domain) if self.cosign else (0, bytes(32), bytes(32))
        self._send('post', job.key, post_data(job, sign_typed(self.agent, digest), cos))
