"""Developer SDK (docs/adr/ADR-0012 L9): one object to submit plans, drive them, read results and health.

    client = WorldClient(chain, escrow_address, agent, relayer, token=..., boards={referee: Board}, archive=path)
    plan = client.plan(account, tasks, ttl=6 * 3600)          # fixes the anchor time and validates the DAG
    client.allow_programs(owner, plan)                          # the owner's once: what the honest run posts
    client.submit(plan)                                         # posts every task whose parents are ready
    client.tick(plan)                                           # call periodically (or run_local on a dev chain)
    client.status(plan); client.result(plan, 'task'); client.health(); client.lineage(key)

Accounts and stakes take their owner's signer: client.open_account(owner, account, deposit=, mandate=, programs=, executors=,
referees=, agent=), deposit, set_mandate, allow_program, set_executor, set_referee, set_agent, revoke, withdraw; client.stake(
executor, amount), unstake. omega_world/daemon.py is what runs tick and the players for a long time.

The client holds the agent's signing key only in the signer object it is given (keys are never read from files here)
and keeps no state besides the archive file: plans are JSON (Plan.to_json) and everything else is re-read from chain.
health() always answers: what cannot be read is an alert, not an exception; a broken archive never stops tick().

A task's kind is its referee's (plan.py): Cannon tasks need `prestates` (cannon.Prestates), Cannon tasks and Optimism
questions an inbox, by default the boards'. The players that serve them are omega_world/cannon_agent.py and
omega_world/op_attest.py."""
from omega_compute.graph_escrow import GraphEscrow
from omega_compute import evm_step as E
from omega_kernel.settlement.evm import DEFAULT_CONFIRMATIONS, TEST_CHAIN_IDS, RpcError, until_mined
from omega_kernel.settlement.evm_crypto import call_data
from omega_world import indexer as IX
from omega_world import monitor as MON
from omega_world.orchestrator import Orchestrator, claim_view
from omega_world.plan import PUBLISH_MAX_BYTES, Plan, PlanError, Task, publish_bytes


class AccountError(ValueError):
    pass


class WorldClient:
    def __init__(self, chain, escrow_address, agent, relayer, token=None, boards=None, archive=None, cosign=None,
                 from_block=None, capital=None, guards=None, confirmations=None, inbox=None, prestates=None, referees=()):
        """capital, guards, inbox, prestates: as Orchestrator (Cannon dispute capital; deploy.referee_guards for
        production; the inbox and the rebuild of Cannon jobs);
        confirmations: the archive holds blocks this deep (default 0 on a test chain, DEFAULT_CONFIRMATIONS elsewhere);
        referees: more referees whose events the archive keeps, besides the boards'"""
        self.chain, self.agent, self.relayer, self.token = chain, agent, relayer, token
        self.capital, self.guards = capital, guards
        self.esc = GraphEscrow(chain, escrow_address)
        self.boards = dict(boards or {})
        self.archive = archive
        self.cosign = cosign
        self.inbox, self.prestates = inbox, prestates
        inboxes = [b.inbox for b in self.boards.values()]
        if inbox is not None and inbox not in inboxes:
            inboxes.append(inbox)
        if from_block is None:  # default: the boards' deployment block (0 on a fresh dev chain)
            from_block = min((b.from_block for b in self.boards.values()), default=0)
        self.from_block = from_block
        if confirmations is None:
            confirmations = 0 if chain.chain_id in TEST_CHAIN_IDS else DEFAULT_CONFIRMATIONS
        self.ix = IX.Indexer(chain, escrow_address, inboxes, token, archive, from_block, confirmations,
                             list(self.boards) + list(referees))
        self._monitor_cache = {}

    def now(self):
        return int(self.chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)

    def plan(self, account, tasks, ttl=6 * 3600, max_attempts=3):
        """PlanError PUBLISH_TOO_LARGE:<task>: a job whose publication does not fit a transaction of a public mempool (F4), said
        before the owner allows anything for it. The contract's own limits are higher, and low-level calls can still use them."""
        plan = Plan('0x' + account.hex(), self.now(), ttl, tuple(t if isinstance(t, Task) else Task(**t) for t in tasks),
                    max_attempts)
        for t in plan.tasks:
            if t.kind != 'op' and publish_bytes(t) > PUBLISH_MAX_BYTES:
                raise PlanError(f'PUBLISH_TOO_LARGE:{t.name}')
        return plan

    def orchestrator(self, plan):
        return Orchestrator(self.chain, self.esc, plan, self.agent, self.relayer, self.boards, self.cosign,
                            self.capital, self.guards, self.inbox, self.prestates, self.from_block)

    def allow_programs(self, owner, plan, outputs=None):
        """the owner's setProgram for what the plan's honest run posts (Plan.programs); `outputs` for what is not computed
        here. -> the tasks a transaction was sent for. An agent cannot do this: the allow list is what binds it."""
        account, sent = bytes.fromhex(plan.account[2:]), []
        for name, prog in plan.programs(self.prestates, outputs).items():
            if not self.esc.u('programAllowed(bytes32,bytes32)', account, prog):
                self.chain.send(owner, self.esc.address, call_data('setProgram(bytes32,bytes32,bool)', account, prog, True))
                sent.append(name)
        return sent

    def submit(self, plan):
        return self.tick(plan)

    def _sync(self):
        """the archive is evidence: a broken file is reported by health() and must not stop settlement (A35). -> what went
        wrong, or None. A lost connection still raises, as everywhere: the same call again is safe."""
        if self.archive:
            try:
                self.ix.sync()
            except (IX.ArchiveError, RpcError) as e:
                return str(e)[:160]
        return None

    def tick(self, plan):
        acts = self.orchestrator(plan).tick()
        why = self._sync()
        return acts + [('archive', 'error:' + why)] if why else acts

    def status(self, plan):
        return self.orchestrator(plan).status()

    def result(self, plan, name):
        return self.status(plan)[name]['output']

    def alerts(self, **scope):
        """monitor.check with this client's contracts, after syncing the archive; `scope`: its options. Raises if the
        chain cannot be read: the daemon decides when that becomes an alert."""
        self._sync()
        said = [MON.Alert('ARCHIVE_TORN', detail=w) for w in self.ix.take_repairs()]
        scope.setdefault('cache', self._monitor_cache)
        return said + MON.check(self.chain, self.esc, self.token, self.archive, self.ix, **scope)

    def health(self, **scope):
        """-> (overall, alerts), whatever happens (A35, A65, A80): what cannot be read is an alert"""
        try:
            alerts = self.alerts(**scope)
        except (RpcError, OSError, ValueError) as e:
            alerts = [MON.Alert('MONITOR_FAILED', detail=f'{type(e).__name__}:{e}'[:200])]
        return MON.health(alerts), alerts

    # ---- accounts and stakes (READINESS_AUDIT A69): each is the contract's call and nothing else; the signer is the owner's -
    def _send(self, signer, to, data):
        """a slow block is not a failure of these one-shot calls: wait for the same transaction, sending nothing twice"""
        return until_mined(lambda: self.chain.send(signer, to, data))

    def _owner_call(self, owner, sig, *args):
        return self._send(owner, self.esc.address, call_data(sig, *args))

    def _allow_token(self, signer, amount):
        have = self.chain.call(self.token, call_data('allowance(address,address)', signer.address, self.esc.address))
        if int.from_bytes(have, 'big') < amount:
            self._send(signer, self.token, call_data('approve(address,uint256)', self.esc.address, amount))

    def owner_of(self, account):
        return self.esc.view('accounts(bytes32)', account)[12:32]

    def open_account(self, owner, account, deposit=0, mandate=None, programs=(), executors=(), referees=None, agent=None):
        """open the account and set what is given, in the contract's order; safe to call again after a crash: an account of
        this owner is not opened twice and `deposit` is the balance to reach, not an amount to add. An id someone else opened
        first is refused (AccountError ACCOUNT_TAKEN), before any token moves: pick another (READINESS_AUDIT A58).
        mandate: {max_per_job, max_per_window, window, valid_until, max_steps}; programs: OVM-0 programs or prog commitments;
        executors: addresses; referees: address -> grade; agent: address"""
        who = self.owner_of(account)
        if who == bytes(20):
            self._owner_call(owner, 'open(bytes32)', account)
        elif who != owner.address:
            raise AccountError('ACCOUNT_TAKEN')
        short = deposit - self.esc.balance(account)
        if short > 0:
            self.deposit(owner, account, short)
        if mandate:
            self.set_mandate(owner, account, **mandate)
        for p in programs:
            self.allow_program(owner, account, p)
        for x in executors:
            if not self.esc.u('executorAllowed(bytes32,address)', account, x):
                self.set_executor(owner, account, x, True)
        for ref, grade in (referees or {}).items():
            if self.esc.u('refereeGrade(bytes32,address)', account, ref) != grade:
                self.set_referee(owner, account, ref, grade)
        if agent is not None:
            self.set_agent(owner, account, agent)

    def deposit(self, owner, account, amount):
        self._allow_token(owner, amount)
        return self._owner_call(owner, 'deposit(bytes32,uint256)', account, amount)

    def withdraw(self, owner, account, amount, to=None):
        return self._owner_call(owner, 'withdraw(bytes32,address,uint256)', account, to or owner.address, amount)

    def set_mandate(self, owner, account, max_per_job, max_per_window, window, valid_until, max_steps):
        return self._owner_call(owner, 'setMandate(bytes32,uint128,uint128,uint64,uint64,uint64)', account, max_per_job,
                                max_per_window, window, valid_until, max_steps)

    def allow_program(self, owner, account, program, allowed=True):
        prog = program if isinstance(program, bytes) else E.program_commit([list(i) for i in program]).commitment
        if bool(self.esc.u('programAllowed(bytes32,bytes32)', account, prog)) != allowed:
            self._owner_call(owner, 'setProgram(bytes32,bytes32,bool)', account, prog, allowed)

    def set_executor(self, owner, account, executor, allowed=True):
        return self._owner_call(owner, 'setExecutor(bytes32,address,bool)', account, executor, allowed)

    def set_referee(self, owner, account, referee, grade):
        """grade 0 denies it for new jobs; posted jobs keep theirs"""
        return self._owner_call(owner, 'setReferee(bytes32,address,uint8)', account, referee, grade)

    def set_agent(self, owner, account, agent):
        return self._owner_call(owner, 'setAgent(bytes32,address)', account, agent)

    def revoke(self, owner, account):
        return self._owner_call(owner, 'revoke(bytes32)', account)

    def stake(self, executor, amount):
        """the executor's free stake, from its own tokens"""
        self._allow_token(executor, amount)
        return self._send(executor, self.esc.address, call_data('depositBond(uint256)', amount))

    def unstake(self, executor, amount, to=None):
        return self._send(executor, self.esc.address, call_data('withdrawBond(address,uint256)', to or executor.address, amount))

    def lineage(self, key):
        """a node and every ancestor, as the chain has them: {key, state, account, executor, referee, claim_id, output,
        ancestors: [the same without ancestors]}"""
        def one(k):
            n = self.esc.node(k)
            c = claim_view(self.chain, n['referee'], n['claimId']) if n['claimId'] else None
            return {'key': k.hex(), 'state': n['state'], 'account': n['account'].hex(), 'executor': n['executor'].hex(),
                    'referee': n['referee'].hex(), 'claim_id': n['claimId'], 'output': c['output'] if c else None}
        return one(key) | {'ancestors': [one(a) for a in self.esc.ancestors(key)]}

    def run_local(self, plan, players=(), rounds=400, warp=None):
        """test chains only: tick, step the players (executors, watchtowers), and advance time only when a whole round
        got no transaction mined and has none in flight (so no game in progress is timed out by the clock). `warp(seconds)`
        advances the chain clock (anvil evm_increaseTime) or sleeps. -> final status"""
        if self.chain.chain_id not in TEST_CHAIN_IDS and not self.chain.armed:
            raise RuntimeError('run_local is for test chains')
        orch = self.orchestrator(plan)
        for _ in range(rounds):
            before = int(self.chain.rpc('eth_blockNumber'), 16)
            orch.tick()
            for p in players:
                p.step()
            if orch.done() or orch.stuck():
                break
            if warp and not self.chain.open_transactions() and not self._txs_after(before):
                warp(self._next_due(orch))
        self._sync()
        return orch.status()

    def _txs_after(self, block):
        """transactions mined after `block`: an idle chain can keep making blocks, so the block number says nothing"""
        head = int(self.chain.rpc('eth_blockNumber'), 16)
        return sum(int(self.chain.rpc('eth_getBlockTransactionCountByNumber', hex(b)), 16)
                   for b in range(block + 1, head + 1))

    def _next_due(self, orch):
        """seconds to the next deadline that can unblock something: a claim window end, an active game's deadline or a
        node expiry (at least 1)"""
        now = self.now()
        due = []
        for t in orch.plan.tasks:
            _, key, n = orch.current(t.name)
            if n is None:
                continue
            if n['claimId']:
                c = claim_view(self.chain, n['referee'], n['claimId'])
                if c and c['status'] == 1 and c['deadline'] >= now:
                    due.append(c['deadline'] + 1)
            if n['state'] in ('posted', 'claimed', 'verified'):
                due.append(n['expiry'] + 1)
        for b in self.boards.values():
            _, ng = b.counts()
            due += [g['deadline'] + 1 for g in (b.game_(i) for i in range(1, ng + 1))
                    if g['status'] == 1 and g['deadline'] >= now]
        return max(1, min(due) - now) if due else 60
