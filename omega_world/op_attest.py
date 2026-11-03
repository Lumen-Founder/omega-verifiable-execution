"""OMEGA jobs judged by Optimism's own fault proof system (docs/adr/ADR-0013, contract OmegaSuperRootReferee).

A job asks "what is the output root of L2 chain c at L2 time t?". Its executor computes the answer from public L2
data, creates an Optimism super-root dispute game that states it (extraData = 0x01 || t || c || outputRoot,
rootClaim = keccak256(extraData), bond = the factory's initBonds), registers the game with the referee and binds
it to the node. The game is then judged by Optimism's FaultDisputeGame and AnchorStateRegistry: a false root is
attacked by honest challengers (on mainnet: Optimism's own op-challenger and anyone else); the escrow pays only when
the registry calls the claim valid.

- output_root(l2_rpc, t): the L2 output root at time t, version 0: keccak(0^32 || stateRoot || messagePasserStorageRoot
  || blockHash). The storage root is the block header's withdrawalsRoot (the Isthmus header rule, live on OP Mainnet),
  so one header read is enough and no archive proof is needed; checked equal to a real mainnet game on 2026-10-30.
- AttestJob: an OmegaGraphEscrow job request for such a question.
- question_data / question_of: the question in OVM0Inbox. A node carries only inputs_of(chain, t), a hash; the executor
  reads the question back from the inbox (no plan JSON has to reach it). Any publication may claim any question, and that
  is harmless: it counts only if its values hash to the node's inputs.
- OpGames: the factory and game calls (create, attack, resolve); resolve_game: anyone's resolution of a fault dispute game.
- AttestExecutor / OpChallenger: the players. The challenger here stands in for Optimism's op-challenger on a fork; it
  only plays the opening move and lets the chess clock decide (the bisection down to the MIPS step needs Cannon
  traces, which are not run here: ADR-0013 section 4). AttestExecutor has no defence either: a true root attacked and
  not defended by someone else is lost on the clock (tests/test_omega_referee_sdk.py pins that, READINESS_AUDIT A19)."""
import json
import urllib.request
from dataclasses import dataclass
from omega_compute import evm_step as E
from omega_compute.dispute_agent import _u, contract_refused, published_logs, publish_data, scan_logs, scrub
from omega_compute.graph_escrow import GraphJob, key_call
from omega_kernel.settlement.evm import RpcError, TxOutcome
from omega_kernel.settlement.evm_crypto import call_data, keccak, selector, word, words

PROG = keccak(b'omega.op-super-root-output.v1')
POSTED_TOPIC = keccak(b'Posted(bytes32,bytes32,address,address,bytes32,uint8)')
IN_PROGRESS, CHALLENGER_WINS, DEFENDER_WINS = 0, 1, 2
CLAIMED, ACCEPTED, REJECTED = 1, 2, 3
RESOLVE_PAGE = 512  # children of a claim one resolveClaim checks. 0 would ask for all at once, whatever that costs (re-audit B23)
MAX_PAGES = 64  # of one claim in one pass; what is checked stays checked in the contract


def _l2(url, method, *params):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                                                  'params': list(params)}).encode(),
                                 {'Content-Type': 'application/json', 'User-Agent': 'omega-world/1'})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.load(r)
    if 'error' in out:
        raise RpcError(out['error'].get('message', 'rpc error'), out['error'].get('data'))
    return out['result']


class NotSafeYet(ValueError):
    """t is past the L2 safe head: its block may not be derivable from L1 yet, and Optimism's challengers judge a
    claim against L1 data, so even the true root could lose (D20). Wait and ask again."""


def l2_block_at(url, t, block_time=2, tag='safe'):
    """the L2 block whose timestamp is exactly t (fixed block time), its header; only up to the `tag` head"""
    head = _l2(url, 'eth_getBlockByNumber', tag, False)
    if t > int(head['timestamp'], 16):
        raise NotSafeYet(f'NOT_SAFE_YET:{t}>{int(head["timestamp"], 16)}')
    n = int(head['number'], 16) - (int(head['timestamp'], 16) - t) // block_time
    b = _l2(url, 'eth_getBlockByNumber', hex(n), False)
    if int(b['timestamp'], 16) != t:
        raise ValueError(f'NO_BLOCK_AT:{t}')
    return b


def output_root(url, t):
    b = l2_block_at(url, t)
    wr = b.get('withdrawalsRoot')
    if not wr:
        raise ValueError('PRE_ISTHMUS_HEADER')  # would need eth_getProof of the message passer instead
    h = lambda x: bytes.fromhex(x[2:])
    return int(b['number'], 16), keccak(bytes(32) + h(b['stateRoot']) + h(wr) + h(b['hash']))


def super_extra(t, chain_id, root):
    return b'\x01' + t.to_bytes(8, 'big') + word(chain_id) + root


def inputs_of(chain_id, t):
    return keccak(word(chain_id) + word(t))


QUESTION_PROGRAM = [['HALT']]  # the inbox takes a program with its values; a question needs only the values


def question_data(chain_id, t):
    """calldata of the OVM0Inbox publication of a question"""
    return publish_data(QUESTION_PROGRAM, [chain_id, t])


def question_commitments(chain_id, t):
    return E.program_commit(QUESTION_PROGRAM).commitment, E.inputs_commit([chain_id, t]).commitment


def question_of(chain, inbox, inputs, from_block=0):
    """(l2 chain id, l2 time) of the publication whose values hash to a node's inputs, or None"""
    prog = E.program_commit(QUESTION_PROGRAM).commitment
    for r in published_logs(chain, inbox, from_block):
        if r.prog == prog and len(r.values) == 2 and inputs_of(*r.values) == inputs:
            return tuple(r.values)
    return None


def resolve_game(chain, signer, game, report=None):
    """resolve what the clocks allow, children first, then the game. Anyone may call, so that no silent party stops the
    plan (READINESS_AUDIT A00, A02); a refused call (a branch still open, someone faster) waits for the next pass.
    report(error): told what stopped a call and is not the contract refusing it. -> the game status"""

    def u(sig, *a):
        return _u(chain.call(game, call_data(sig, *a))[:32])

    def send(data):
        try:
            chain.send(signer, game, data)
            return True
        except RpcError as e:
            if report is not None and not contract_refused(e):
                report(e)
            return False
    if u('status()') != IN_PROGRESS:
        return u('status()')
    clock, n = u('maxClockDuration()'), u('claimDataLen()')
    # every party calls this on every pass: while the newest claim's clock runs the game cannot end, and a deep game is
    # hundreds of calls to find that out (measured: half of all reads of a pass)
    if not u('resolvedSubgames(uint256)', n - 1) and u('getChallengerDuration(uint256)', n - 1) < clock:
        return IN_PROGRESS
    for i in reversed(range(n)):
        if u('resolvedSubgames(uint256)', i) or u('getChallengerDuration(uint256)', i) < clock:
            continue
        for _ in range(MAX_PAGES):
            if not send(call_data('resolveClaim(uint256,uint256)', i, RESOLVE_PAGE)) or u('resolvedSubgames(uint256)', i):
                break
    if u('resolvedSubgames(uint256)', 0):
        send(call_data('resolve()'))
    return u('status()')


@dataclass(frozen=True)
class AttestJob(GraphJob):
    """program/inputs of GraphJob stay empty: the request carries PROG and inputs_of(chain, t), maxSteps 1"""
    l2_chain_id: int = 0
    l2_time: int = 0

    def commitments(self):
        return PROG, inputs_of(self.l2_chain_id, self.l2_time)


class OpGames:
    def __init__(self, chain, factory, game_type):
        self.chain, self.factory, self.game_type = chain, factory, game_type
        self.gas = {}  # last gasUsed per call kind (cost evidence)

    def bond(self):
        return _u(self.chain.call(self.factory, call_data('initBonds(uint32)', self.game_type))[:32])

    def _args(self, extra):
        return E.abi_encode([('w', word(self.game_type)), ('w', keccak(extra)), ('b', extra)])

    def game_of(self, extra):
        return self.chain.call(self.factory, selector('games(uint32,bytes32,bytes)') + self._args(extra))[12:32]

    def create(self, signer, extra):
        rc = self.chain.send(signer, self.factory, selector('create(uint32,bytes32,bytes)') + self._args(extra),
                             value=self.bond())
        self.gas['create'] = int(rc['gasUsed'], 16)
        return self.game_of(extra)

    def view(self, game, sig, *a):
        return _u(self.chain.call(game, call_data(sig, *a))[:32])

    def status(self, game):
        return self.view(game, 'status()')

    def claims_in(self, game):
        return self.view(game, 'claimDataLen()')

    def root_attacks(self, game):
        """the values of the moves directly against the root"""
        out = []
        for i in range(1, self.claims_in(game)):
            w = self.chain.call(game, call_data('claimData(uint256)', i))
            if _u(w[:32]) == 0:
                out.append(w[128:160])
        return out

    def attack(self, signer, game, disputed, counter):
        bond = self.view(game, 'getRequiredBond(uint128)', 2)  # the first move sits at position 2
        rc = self.chain.send(signer, game, call_data('attack(bytes32,uint256,bytes32)', disputed, 0, counter),
                             value=bond)
        self.gas['attack'] = int(rc['gasUsed'], 16)

    def resolve(self, signer, game, report=None):
        return resolve_game(self.chain, signer, game, report)


class SuperRootReferee:
    def __init__(self, chain, address):
        self.chain, self.address = chain, address
        self.gas = {}

    def claims(self):
        return _u(self.chain.call(self.address, call_data('claims()'))[:32])

    def status(self, cid):
        return _u(words(self.chain.call(self.address, call_data('getClaim(uint256)', cid)))[7])

    def root_of(self, cid):
        w = words(self.chain.call(self.address, call_data('rootOf(uint256)', cid)))
        return w[0][12:], _u(w[1]), w[2]

    def id_of(self, game):
        return _u(self.chain.call(self.address, call_data('idOf(address)', game))[:32])

    def adopted_id(self, game, defender):
        return _u(self.chain.call(self.address, call_data('adoptedId(address,address)', game, defender))[:32])

    def registry(self):
        return self.chain.call(self.address, call_data('registry()'))[12:32]

    def l2_chain_id(self):
        return _u(self.chain.call(self.address, call_data('l2ChainId()'))[:32])

    def register(self, signer, game):
        rc = self.chain.send(signer, self.address, call_data('register(address)', game))
        self.gas['register'] = int(rc['gasUsed'], 16)
        return self.id_of(game)

    def adopt(self, signer, game):
        rc = self.chain.send(signer, self.address, call_data('adopt(address)', game))
        self.gas['adopt'] = int(rc['gasUsed'], 16)
        return self.adopted_id(game, signer.address)


class AttestExecutor:
    """Takes attestation nodes, handed over with take() or found by discover() from the escrow's Posted events and the
    question in the inbox; for each: reserve, compute the root, create the game, register it, bind. Then resolves the
    game when its clocks allow, verifies/settles once the referee accepts and releases its stake. `lie(root) -> root`
    plays a dishonest executor."""

    def __init__(self, escrow, referee, games, signer, source, lie=None, policy=None, inbox=None, from_block=0):
        """policy (executor.AcceptPolicy), inbox: what it finds on its own and stakes for; a found job gets stake only if
        the policy takes it (a named job is an offer, READINESS_AUDIT A03). Without a policy it serves what it was given."""
        self.escrow, self.ref, self.games, self.signer, self.source, self.lie = (escrow, referee, games, signer,
                                                                               source, lie)
        self.policy, self.inbox, self.from_block = policy, inbox, from_block
        self.jobs, self.moves, self.game = [], [], {}
        self._credits = {}  # game -> claimCredit calls that went through
        self._failed = {}  # what the last pass swallowed: failing()

    def failing(self):
        """{kind: detail} of what the last pass swallowed, see GraphExecutor.failing. Waiting for the L2 to be safe is no
        failure: it is in moves, and anyone can open a job far ahead of the L2"""
        return dict(self._failed)

    def _note(self, kind, said):
        self._failed[kind] = scrub(getattr(said, 'revert', None) or said)[:120]

    def take(self, job):
        self.jobs.append(job)

    def discover(self):
        """the jobs addressed to this key on this referee whose question is in the inbox; a job it holds stays"""
        if self.policy is None or self.inbox is None:
            return
        chain, me = self.escrow.chain, self.signer.address
        held = {j.key for j in self.jobs}
        logs = scan_logs(chain, self.escrow.address, ['0x' + POSTED_TOPIC.hex(), None, None, '0x' + bytes(12).hex() + me.hex()],
                         self.from_block)
        now = int(chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)
        for log in logs:
            key = bytes.fromhex(log['topics'][1][2:])
            if key in held:
                continue
            n = self.escrow.node(key)
            if n['referee'] != self.ref.address or n['prog'] != PROG or (not n['bonded'] and (
                    n['state'] != 'posted' or self.policy.refusal(self.escrow, key, n, now) is not None)):
                continue
            q = question_of(chain, self.inbox, n['inputs'], self.from_block)
            if q is not None:
                self.jobs.append(AttestJob(key, n['account'], n['executor'], n['referee'], (), (), 1, n['price'],
                                           l2_chain_id=q[0], l2_time=q[1]))

    def _try(self, tag, to, data, value=0):
        try:
            self.escrow.chain.send(self.signer, to, data, value=value)
            self.moves.append((tag, 'ok'))
            return True
        except RpcError as e:
            self.moves.append((tag, 'refused:' + str(e.revert or e)))
            if isinstance(e, TxOutcome):
                self._note('tx:' + tag, e)
            elif tag in ('reserve', 'bind') or not contract_refused(e):  # settle, verify, release, expire: often not due yet
                self._note(tag, e)
            return False

    def step(self):
        """one pass over the jobs; an error on one job is recorded and does not stop the others (D21)"""
        self._failed = {}
        try:
            self.discover()
        except (RpcError, ValueError) as e:  # a failed scan must not stop the jobs it holds
            self.moves.append(('discover', 'error:' + str(e)[:120]))
            self._note('discover', e)
        for job in self.jobs:
            try:
                self._step(job)
            except (RpcError, ValueError) as e:
                self.moves.append(('job', job.key.hex()[:8], 'error:' + str(e)[:120]))
                if not isinstance(e, NotSafeYet):
                    self._note(f'job:{job.key.hex()}', e)

    def _step(self, job):
        """every step can run again after a crash between any two transactions (D21): an existing game is reused and an
        existing registration is reused. A game someone else opened for the same answer is adopted (T29): its root is
        the one computed here, so this key defends what it would have claimed anyway."""
        esc = self.escrow.address
        n = self.escrow.node(job.key)
        if n['state'] == 'posted' and not n['bonded']:
            self._try('reserve', esc, key_call('reserve', job.key))
            n = self.escrow.node(job.key)
        if n['state'] == 'posted' and n['bonded']:
            _, root = self.source(job.l2_time)  # NotSafeYet: wait for the next pass
            if self.lie:
                root = self.lie(root)
            extra = super_extra(job.l2_time, job.l2_chain_id, root)
            game = self.games.game_of(extra)
            if game == bytes(20):
                reg = self.ref.registry()
                if _u(self.games.chain.call(reg, call_data('respectedGameType()'))[:32]) != self.games.game_type:
                    raise ValueError('GAME_TYPE_NOT_RESPECTED')  # its games could never be valid claims
                game = self.games.create(self.signer, extra)
            mine = self.games.chain.call(game, call_data('gameCreator()'))[12:32] == self.signer.address
            if not mine:
                self.moves.append(('game', job.key.hex()[:8], 'GAME_OPENED_BY_ANOTHER'))
            self.game[job.key] = game
            cid = self.ref.id_of(game) if mine else self.ref.adopted_id(game, self.signer.address)
            if cid == 0:
                try:
                    cid = self.ref.register(self.signer, game) if mine else self.ref.adopt(self.signer, game)
                except RpcError as e:
                    self.moves.append(('register', job.key.hex()[:8], 'refused:' + str(e.revert)))
                    self._note('register', e)
                    return  # StaleGame: this game can no longer count; the job runs out (refund, stake back)
            self._try('bind', esc, key_call('bind', job.key, cid))
            return
        game = self.game.get(job.key) or (self.ref.root_of(n['claimId'])[0] if n['claimId'] else None)
        if game is not None and self.games.status(game) == IN_PROGRESS:
            self.games.resolve(self.signer, game, lambda e: self._note(f'resolve:{game.hex()}', e))
        if n['state'] in ('claimed', 'verified') and self.ref.status(n['claimId']) == ACCEPTED:
            if not self._try('settle', esc, key_call('settle', job.key)) and n['state'] == 'claimed':
                self._try('verify', esc, key_call('verify', job.key))
        if game is not None and self.games.status(game) != IN_PROGRESS and self._credits.get(game, 0) < 2:
            self._collect(game)
        now = int(self.escrow.chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)
        if n['bonded'] and n['state'] in ('final', 'voided') and now > self.escrow.expires_at(job.key):
            self._try('release', esc, key_call('release', job.key))
        if n['state'] in ('posted', 'claimed', 'verified') and (n['bonded'] or n['coverHeld']) and now > n['expiry']:
            self._try('expire', esc, key_call('expire', job.key))  # an account that vanished must not hold the stake


    def _collect(self, game):
        """the game's bond takes two calls, as in cannon_agent: claimCredit once the game is finalized opens the DelayedWETH
        unlock, again after its delay pays. A game this key lost has nothing for it: the call reverts and costs nothing."""
        chain = self.escrow.chain
        try:
            chain.send(self.signer, game, call_data('claimCredit(address)', self.signer.address))
        except RpcError as e:
            if not contract_refused(e):
                self._note(f'credit:{game.hex()}', e)
            return
        self._credits[game] = self._credits.get(game, 0) + 1
        self.moves.append(('credit', game.hex()[:8], self._credits[game]))


def false_claim_judge(referee, games, source):
    """monitor.check's judge for an OmegaSuperRootReferee: the registered root against the output root from `source` (the
    same as OpChallenger). True, False, 'contested' (false, and an attack on the root that this file can tell is the
    truth: the super root of the true output, or OpChallenger's own) or None (the L2 cannot say yet). Any other attack may be
    the liar's own (re-audit B2), so it counts for nothing. That includes a real op-challenger's where the value is not the
    super root above (seen on Sepolia, game 89730): a false root here alerts even so, and an alert that was not needed is
    the side this errs on."""
    def judge(n, c):
        game, t, root = referee.root_of(n['claimId'])
        try:
            _, truth = source(t)
        except (ValueError, OSError):  # NotSafeYet is a ValueError
            return None
        if root == truth:
            return True
        honest = {keccak(super_extra(t, referee.l2_chain_id(), truth)), keccak(b'omega-challenger' + truth)}
        return 'contested' if honest & set(games.root_attacks(game)) else False
    return judge


class OpChallenger:
    """Attacks every registered game whose root differs from the true one; resolves games when the clocks allow. One game's
    failure is that game's (re-audit B8), and several registrations of one game (adopt) are one game. It attacks unless its
    own attack is there: any other move may be the liar's own (B2)."""

    def __init__(self, referee, games, signer, source):
        self.ref, self.games, self.signer, self.source = referee, games, signer, source
        self.attacked, self.moves = set(), []
        self.waiting, self._failed = {}, {}  # claim id -> not safe yet: nothing failed, and anyone can open a game ahead of the L2

    def failing(self):
        """{kind: detail} of what the last pass swallowed, see GraphExecutor.failing"""
        return dict(self._failed)

    def step(self):
        self.waiting, self._failed = {}, {}
        seen = set()
        for cid in range(1, self.ref.claims() + 1):
            try:
                self._one(cid, seen)
            except NotSafeYet as e:
                self.waiting[cid] = str(e).split(':')[0]
            except (RpcError, ValueError) as e:
                self._failed[f'game:{cid}'] = scrub(getattr(e, 'revert', None) or e)[:120]

    def _one(self, cid, seen):
        game, t, root = self.ref.root_of(cid)
        if game in seen or self.games.status(game) != IN_PROGRESS:
            return
        seen.add(game)
        try:
            _, truth = self.source(t)
        except OSError as e:  # the L2's endpoint, about this game's answer
            raise ValueError(f'L2_UNREADABLE:{type(e).__name__}') from e
        if root == truth:
            return
        mine = keccak(b'omega-challenger' + truth)
        if game in self.attacked or mine in self.games.root_attacks(game):  # the chain remembers it across a restart
            self.games.resolve(self.signer, game)
            return
        disputed = self.games.chain.call(game, call_data('rootClaim()'))[:32]
        self.games.attack(self.signer, game, disputed, mine)
        self.attacked.add(game)
        self.moves.append(('attack', cid))
