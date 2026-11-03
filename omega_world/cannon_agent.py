"""The players of the Cannon referee path at runtime (READINESS_AUDIT A02, A17, A57; docs/adr/ADR-0012 section 11).

- CannonExecutor: finds the jobs addressed to its key from the escrow's Posted events, takes each job from OVM0Inbox and
  rebuilds its prestate (D25); before staking, reserve_cannon (the account is one it trusts, its balance read now covers
  the attacker it means to withstand, A12). Then it opens and registers its own game, binds, answers every branch,
  resolves what the clocks allow, verifies and settles, voids what stands on a rejected ancestor, releases its stake and
  claims its game bonds.
- CannonWatcher: needs nothing from the account: from the referee's Registered events and the inbox it recomputes each
  game's output, attacks a false root, answers every branch against a true one, resolves, and rejects a node whose game
  was lost. A game whose job it cannot rebuild is reported (`unknown`), it cannot be judged.

Both keep no state: a restart finds everything again on chain, and what they built stays in Prestates' folder."""
from collections import namedtuple
from omega_compute.dispute_agent import contract_refused, scan_logs
from omega_compute.graph_escrow import ACCEPTED, REJECTED, GraphExecutor, key_call
from omega_kernel.settlement.evm import RpcError
from omega_kernel.settlement.evm_crypto import call_data, keccak, selector, words
from omega_world import cannon as CN
from omega_world import referee_policy as RP
from omega_world.executor import POSTED_TOPIC, reserve_cannon
from omega_world.op_attest import IN_PROGRESS, resolve_game

REGISTERED_TOPIC = keccak(b'Registered(uint256,address,address,bytes32)')
GAME_CREATED_TOPIC = keccak(b'GameCreated(address,bytes32,bytes32,address)')
CannonWork = namedtuple('CannonWork', 'key program inputs max_steps prestate')
Watched = namedtuple('Watched', 'key cid')  # key: the game's address, one job of GraphExecutor.step


def _u(w):
    return int.from_bytes(w[:32], 'big')


class CannonReferee:
    """Read side of an OmegaCannonReferee and its OmegaCannonGames. It stands where GraphExecutor expects its board:
    `game` is the referee's address there, a game's own credit is claimed per game (claim_credit)."""

    def __init__(self, chain, address, from_block=0):
        self.chain, self.game, self.from_block = chain, address, from_block
        self.games = chain.call(address, selector('games()'))[12:32]

    def now(self):
        return int(self.chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)

    def credit(self, who):
        return 0

    def claim(self, cid):
        w = words(self.chain.call(self.game, call_data('getClaim(uint256)', cid)))
        return {'id': cid, 'defender': w[0][12:], 'prog': w[1], 'inputs': w[2], 'maxSteps': _u(w[3]), 'deadline': _u(w[5]),
                'status': _u(w[7]), 'output': _u(w[9]), 'trap': _u(w[10])}

    def game_of(self, cid):
        return self.chain.call(self.game, call_data('gameOf(uint256)', cid))[12:32]

    def id_of(self, game):
        return _u(self.chain.call(self.game, call_data('idOf(address)', game)))

    def register_grace(self):
        return _u(self.chain.call(self.game, selector('registerGrace()')))

    def registered(self, defender=None):
        """[(claim id, game)] oldest first"""
        topics = ['0x' + REGISTERED_TOPIC.hex()] + ([None, None, '0x' + bytes(12).hex() + defender.hex()] if defender else [])
        return [(int(g['topics'][1], 16), bytes.fromhex(g['topics'][2][2:])[12:])
                for g in scan_logs(self.chain, self.game, topics, self.from_block)]

    def init_bond(self):
        return _u(self.chain.call(self.games, selector('initBond()')))

    def nonces(self, who):
        return _u(self.chain.call(self.games, call_data('nonces(address)', who)))

    def created_by(self, who):
        """the games `who` opened, oldest first (registered or not)"""
        logs = scan_logs(self.chain, self.games, ['0x' + GAME_CREATED_TOPIC.hex()], self.from_block)
        return [bytes.fromhex(g['topics'][1][2:])[12:] for g in logs if bytes.fromhex(g['data'][2:])[44:64] == who]

    def game_by(self, prestate, root, who, nonce):
        key = self.chain.call(self.games, call_data('keyOf(bytes32,bytes32,address,uint256)', prestate, root, who, nonce))
        return self.chain.call(self.games, call_data('gameOf(bytes32)', key))[12:32]

    def created_at(self, game):
        return _u(self.chain.call(game, selector('createdAt()')))

    def finalized(self, game):
        return _u(self.chain.call(self.games, call_data('isGameFinalized(address)', game))) == 1


def poster_of(chain, escrow, key, from_block):
    """who sent the node's post (find_job looks at that key's publication first), or None"""
    logs = chain.logs(escrow, ['0x' + POSTED_TOPIC.hex(), '0x' + key.hex()], from_block)
    if not logs:
        return None
    tx = chain.rpc('eth_getTransactionByHash', logs[0]['transactionHash'])
    return bytes.fromhex(tx['from'][2:]) if tx else None


def false_claim_judge(view, inbox, prestates, max_rebuilds=CN.MAX_REBUILDS, known_programs=()):
    """monitor.check's judge for a Cannon referee, by the watcher's own means: rebuild the job from the inbox and compare the
    game's root. True, False, 'contested' (false, and the true output stands against the root: anyone's other move may be
    the liar's own, re-audit B2) or 'unknown' (nothing rebuilds to its prestate, or the build failed: nobody here can tell,
    T13, and the bound claim is judged by nobody, B3). monitor gives a node its key and escrow: the poster's publication
    goes first; known_programs: find_job"""
    found = {}

    def judge(n, c):
        k = (n['prog'], n['inputs'], n['maxSteps'])
        if k not in found:
            prefer = poster_of(view.chain, n['escrow'], n['key'], view.from_block) if 'key' in n else None
            try:
                got = CN.find_job(view.chain, inbox, prestates, n['prog'], n['inputs'], n['maxSteps'], view.from_block, prefer,
                                  max_rebuilds, known=tuple(known_programs))
            except CN.ToolFailed:
                return 'unknown'
            if got is None:
                return 'unknown'
            found[k] = CN.commit(tuple(got[1]), n['maxSteps'], *CN.claim_of(got[0], tuple(got[1]), n['maxSteps']))
        game = view.game_of(n['claimId'])
        g = CN.Game(view.chain, game)
        if g.chain.call(game, selector('rootClaim()'))[:32] == found[k]:
            return True
        return 'contested' if any(x.parent == 0 and x.pos == 2 and x.value == found[k] for x in g.claims()[1:]) else False
    return judge


class _Party(GraphExecutor):
    """what both players do with a finished game. Its bonds take two calls: closeGame and the vault's unlock, then the
    payment after the vault's delay; a call that is refused (not final yet, the delay is running, nothing to claim) comes
    again next pass, and nothing depends on it."""
    ISOLATED = GraphExecutor.ISOLATED + (CN.ToolFailed,)

    def __init__(self, view, escrow, inbox, signer, prestates, max_rebuilds, keep_stake=None, payout=None, known_programs=()):
        super().__init__(view, escrow, signer, None, None, keep_stake=keep_stake, payout=payout)
        self.inbox, self.prestates, self.max_rebuilds = inbox, prestates, max_rebuilds
        self.known_programs = tuple(known_programs)  # program commitments it knows: find_job asks for them by their topic
        self.unknown = {}  # what cannot be rebuilt and is therefore not played, as of the last pass
        self.gave_up = set()  # (game, claim index): the contract's ValidStep, nothing it could send proves that side
        self._lost = []  # games of this key that can no longer serve a job: CannonExecutor._strays
        self.game_log, self._found, self._credits = [], {}, {}

    def failing(self):
        out = super().failing()
        out.update({f'unknown:{k}': why for k, why in self.unknown.items()})
        out.update({f'gave_up:{g.hex()}:{i}': 'ValidStep' for g, i in self.gave_up})
        return out

    def _play(self, game, actor):
        """respond, with what it tells kept: what the contract refused for good, what the next pass tries again. -> the log
        entries of this play"""
        start = len(self.game_log)
        CN.respond(game, actor, self.game_log, {i for g, i in self.gave_up if g == game.address})
        new = self.game_log[start:]
        for e in new:
            if 'step_refused' in e:
                self.gave_up.add((game.address, e['claim']))
            elif 'late' in e:
                self._note('late', f"{game.address.hex()}:{e['claim']}", e['error'])
            elif 'retry' in e:
                self._note('move', f"{game.address.hex()}:{e['claim']}", e['revert'] or e['error'])
        return new

    def _resolve(self, game):
        return resolve_game(self.board.chain, self.signer, game, lambda e: self._note('resolve', game.hex(), e))

    def _job(self, prestate, inputs, max_steps, key=None):
        """the job behind a prestate from the inbox, by this party's own rebuild, once found"""
        k = (prestate, inputs, max_steps)
        if k not in self._found:
            prefer = poster_of(self.board.chain, self.escrow.address, key, self.board.from_block) if key else None
            got = CN.find_job(self.board.chain, self.inbox, self.prestates, prestate, inputs, max_steps,
                              self.board.from_block, prefer, self.max_rebuilds, known=self.known_programs)
            if got is None:
                return None
            self._found[k] = got
        return self._found[k]

    def _collect(self):
        super()._collect()
        me = self.signer.address
        for game in self._games():
            if self._credits.get(game, 0) >= 2 or not self.board.finalized(game):
                continue
            try:
                self.board.chain.send(self.signer, game, call_data('claimCredit(address)', me))
            except RpcError as e:
                if not contract_refused(e):
                    self._note('credit', game.hex(), e)
                continue
            self._credits[game] = self._credits.get(game, 0) + 1
            self.moves.append(('credit', game.hex()[:8], self._credits[game]))

    def _games(self):
        return ()

    def _scan(self):
        self.unknown = {}
        self._isolated('discover', '', self.discover)


class CannonExecutor(_Party):
    def __init__(self, view, escrow, inbox, signer, prestates, policy=None, withstand_wei=0, lie=None, keep_stake=None,
                 payout=None, gas_price_wei=RP.GAS_PRICE_WEI, max_rebuilds=CN.MAX_REBUILDS, known_programs=(), gas=RP.MAINNET_GAS):
        """policy: executor.AcceptPolicy, what it stakes for; without one it finishes what it holds and takes nothing new.
        withstand_wei: the attacker capital it means to withstand (the user's value, reserve_cannon). A job on this
        referee is an offer from someone who may be the attacker (A12). lie(job, true claim) -> (claim, lie_from) plays a
        dishonest executor in tests. keep_stake, payout: GraphExecutor"""
        super().__init__(view, escrow, inbox, signer, prestates, max_rebuilds, keep_stake, payout, known_programs)
        self.policy, self.withstand, self.lie, self.gas_price = policy, withstand_wei, lie, gas_price_wei
        self.gas = gas  # the chain's table: referee_policy.gas_table
        self._beliefs = {}

    def discover(self):
        chain, me = self.board.chain, self.signer.address
        logs = scan_logs(chain, self.escrow.address, ['0x' + POSTED_TOPIC.hex(), None, None, '0x' + bytes(12).hex() + me.hex()],
                         self.board.from_block)
        held = {j.key: j for j in self.jobs}
        jobs, now = [], self.board.now()
        for log in logs:
            key = bytes.fromhex(log['topics'][1][2:])
            try:
                n = self.escrow.node(key)
                if n['referee'] != self.board.game:
                    continue  # another referee: not this executor's game
                if not n['bonded'] and (self.policy is None or n['state'] != 'posted'
                                        or self.policy.refusal(self.escrow, key, n, now) is not None):
                    continue  # no stake at risk and no offer it would take: no rebuild for it, that would be free work
                got = self._job(n['prog'], n['inputs'], n['maxSteps'], key)
            except (RpcError, CN.ToolFailed) as e:  # not this pass: a job it holds stays
                self._note('discover', key.hex(), e)
                if key in held:
                    jobs.append(held[key])
                continue
            if got is None:
                self.unknown[key.hex()] = 'NO_PUBLICATION_REBUILDS_TO_ITS_PRESTATE'  # D25: never a stake on it
                continue
            jobs.append(CannonWork(key, got[0], tuple(got[1]), n['maxSteps'], n['prog']))
        self.jobs = jobs

    def _staked(self, job, referee):
        """the nodes in flight on this referee this key holds a stake in, besides this job"""
        nodes = (self.escrow.node(j.key) for j in self.jobs if j.key != job.key)
        return [n for n in nodes if n['referee'] == referee and (n['state'] == 'claimed' or (n['state'] == 'posted' and n['bonded']))]

    def _claim(self, job):
        """(claim in the guest's text form, lie_from)"""
        if job.key not in self._beliefs:
            true = CN.claim_of(job.program, job.inputs, job.max_steps)
            self._beliefs[job.key] = self.lie(job, true) if self.lie else (true, None)
        return self._beliefs[job.key]

    def _advance(self, job, now):
        esc = self.escrow.address
        n = self.escrow.node(job.key)
        if n['state'] in ('posted', 'claimed', 'verified') and any(
                self.escrow.node(x)['state'] == 'rejected' for x in self.escrow.ancestors(job.key)):
            self._send('void', esc, key_call('voidNode', job.key), ok=('ClaimPending', 'WrongStatus'))
            n = self.escrow.node(job.key)
        if n['state'] == 'posted' and not n['bonded'] and not n['coverHeld'] and now <= n['deadline']:
            why = reserve_cannon(self.escrow, self.signer, job.key, self.policy, self.withstand, now, self.gas_price, self.gas,
                                 self._staked(job, n['referee']))
            if why is not None:
                if self.refused.get(job.key) != why:
                    self.refused[job.key] = why
                    self.moves.append(('refused', job.key.hex(), why))
                return
            self.moves.append(('reserve', 'ok'))
            n = self.escrow.node(job.key)
        if n['state'] == 'posted' and n['bonded'] and now <= n['deadline']:
            cid = self._open(job, n, now)
            if cid is not None:
                self._send('bind', esc, key_call('bind', job.key, cid))
            return
        if n['state'] not in ('claimed', 'verified'):
            if n['bonded'] and n['state'] in ('final', 'voided') and now > self.escrow.expires_at(job.key):
                self._send('release', esc, key_call('release', job.key), ok=('NotBonded',))
            self._expire(job, n, now)
            return
        g = CN.Game(self.board.chain, self.board.game_of(n['claimId']))
        if g.status() == IN_PROGRESS:
            def play():
                claim, lie_from = self._claim(job)
                self._play(g, CN.Actor(self.signer.address.hex()[:8], self.signer,
                                       self.prestates.driver(job.program, job.inputs, job.max_steps),
                                       CN.commit(job.inputs, job.max_steps, *claim), lie_from))
            self._isolated('play', job.key.hex(), play)  # whatever happened to the moves, what the clocks allow is resolved
            self._resolve(g.address)
        status = self.board.claim(n['claimId'])['status']
        if status == ACCEPTED:
            if self._send('settle', esc, key_call('settle', job.key), ok=('AncestorNotFinal', 'WrongStatus')) is None \
                    and self.escrow.node(job.key)['state'] == 'claimed':  # re-read: the settle may have lost a race
                self._send('verify', esc, key_call('verify', job.key), ok=('WrongStatus',))
        elif now > n['expiry']:
            self._expire(job, self.escrow.node(job.key), now)

    def _open(self, job, n, now):
        """the claim id of my game for this job, a game opened and registered if none can serve: every step can run again
        after a crash between any two transactions, so an existing game is reused and only one past its registration
        grace is replaced. None: not mined yet, or refused (reported, the next pass reads again)"""
        view, me = self.board, self.signer.address
        claim, _ = self._claim(job)
        root = CN.commit(job.inputs, job.max_steps, *claim)
        grace = view.register_grace()
        for i in range(view.nonces(me)):
            game = view.game_by(job.prestate, root, me, i)
            if game == bytes(20):
                continue
            cid = view.id_of(game)
            if cid == 0:
                if now > view.created_at(game) + grace:
                    continue
                return self._register(job, game, claim)
            used = view.chain.call(self.escrow.address, call_data('claimUsedBy(address,uint256)', view.game, cid))
            if cid > n['claimFloor'] and used == bytes(32):
                return cid
        if self._send('create', view.games, call_data('create(bytes32,bytes32)', job.prestate, root),
                      value=view.init_bond()) is None:
            return None
        return self._register(job, view.game_by(job.prestate, root, me, view.nonces(me) - 1), claim)

    def _register(self, job, game, claim):
        self._send('register', self.board.game, CN.register_data(game, job.inputs, job.max_steps, *claim))
        return self.board.id_of(game) or None

    def _strays(self, now):
        """games this key opened and did not register within the grace (a crash, a mempool slower than the grace): nobody
        watches them or resolves them, and the initial bond is in there (re-audit B24)"""
        out = []
        for game in self.board.created_by(self.signer.address):
            if self._credits.get(game, 0) < 2 and self.board.id_of(game) == 0 \
                    and now > self.board.created_at(game) + self.board.register_grace():
                out.append(game)
        return out

    def _collect(self):
        self._isolated('strays', '', self._resolve_strays)
        super()._collect()

    def _resolve_strays(self):
        self._lost = self._strays(self.board.now())
        for game in self._lost:
            self._resolve(game)

    def _games(self):
        return [g for _, g in self.board.registered(self.signer.address)] + list(self._lost)


class CannonWatcher(_Party):
    def __init__(self, view, escrow, inbox, signer, prestates, max_rebuilds=CN.MAX_REBUILDS, known_programs=()):
        super().__init__(view, escrow, inbox, signer, prestates, max_rebuilds, known_programs=known_programs)
        self.verdicts = {}  # claim id -> 'honest' | 'false' | 'unknown'
        self._played = set()

    def discover(self):
        self.jobs = [Watched(game, cid) for cid, game in self.board.registered()]

    def _advance(self, w, now):
        view, chain = self.board, self.board.chain
        c = view.claim(w.cid)
        node_key = chain.call(self.escrow.address, call_data('claimUsedBy(address,uint256)', view.game, w.cid))[:32]
        bound = node_key if node_key != bytes(32) else None
        if c['status'] == REJECTED:
            if bound and self.escrow.node(bound)['state'] == 'claimed':
                self._send('reject', self.escrow.address, key_call('reject', bound), ok=('WrongStatus', 'ClaimNotRejected'))
            return
        g = CN.Game(chain, w.key)
        if g.status() != IN_PROGRESS:
            return
        # a game that is not bound yet is watched as well: its executor can bind it late, with a clock already run down
        self._isolated('play', w.key.hex(), lambda: self._watch(w, c, g, bound))  # what the clocks allow is resolved anyway
        self._resolve(w.key)

    def _watch(self, w, c, g, bound):
        job = self._job(c['prog'], c['inputs'], c['maxSteps'], bound)
        if job is None:
            self.verdicts[w.cid] = 'unknown'
            self.unknown[w.key.hex()] = 'NO_PUBLICATION_REBUILDS_TO_ITS_PRESTATE ' + ('bound' if bound else 'unbound')
            return
        program, inputs = job[0], tuple(job[1])
        truth = CN.commit(inputs, c['maxSteps'], *CN.claim_of(program, inputs, c['maxSteps']))
        claims = g.claims()
        self.verdicts[w.cid] = 'honest' if claims[0].value == truth else 'false'
        actor = CN.Actor('watcher', self.signer, self.prestates.driver(program, inputs, c['maxSteps']), truth)
        if any('pos' in e or 'step' in e for e in self._play(g, actor)):
            self._played.add(w.key)

    def _games(self):
        return self._played | {w.key for w in self.jobs if self._credits.get(w.key, 0) < 2 and self.board.finalized(w.key)
                               and any(c.claimant == self.signer.address for c in CN.Game(self.board.chain, w.key).claims())}
