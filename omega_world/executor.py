"""Executor side (docs/adr/ADR-0012): the executor interface and a self-discovering OVM-0 executor.

An executor is anything that, given a deterministic OVM-0 program and inputs, produces the run the referee will judge:
`run(program, inputs, max_steps) -> Trace`. WorldExecutor finds the jobs addressed to its key from the escrow's Posted
events, takes each job's program and inputs from the referee inbox (data availability), and then stakes, claims,
binds, defends, finalizes, verifies, settles and releases exactly like omega_compute.graph_escrow.GraphExecutor. It
keeps no state, so a restarted executor finishes what the previous one started.

Anyone can name any executor: setExecutor is the account's alone. So a named job is an offer, and a job gets stake only
if an AcceptPolicy says so (default: nothing; READINESS_AUDIT A03, A59). A job it already staked is served whatever the
policy says now: the stake is at risk. One job's failure is that job's (GraphExecutor.step)."""
from collections import namedtuple
from dataclasses import dataclass, field
from omega_compute import evm_step as E
from omega_compute.dispute_agent import Trace, scan_logs
from omega_compute.graph_escrow import POSTED_TOPIC, GraphExecutor, key_call
from omega_kernel.settlement.evm import RpcError
from omega_world import referee_policy as RP

Job = namedtuple('Job', 'key program inputs max_steps')


class OVM0Run:
    """the honest executor interface implementation: run the program in the reference VM"""
    codec = E

    def run(self, program, inputs, max_steps):
        return Trace(self.codec, [list(i) for i in program], list(inputs), max_steps)


@dataclass(frozen=True)
class AcceptPolicy:
    """What an executor stakes for. Nothing here has an accept-all value: an account or a referee is either listed or
    refused. The referees cover the job's and every ancestor's (an untrusted referee over a parent voids the child's
    honest work unpaid), and `guards` are deploy.referee_guards, so that a pin that changed also stops the stake."""
    accounts: frozenset  # bytes32 account ids it works for
    referees: frozenset  # addresses it trusts to decide the job and its ancestors
    min_price: int  # below it the work does not pay its gas and the capital it ties up
    max_cover: int  # the most stake one job may tie up besides its bond
    max_lock_s: int = 45 * 86_400  # the longest until the node's expiry frees the stake
    min_eth_wei: int = 0  # gas money to hold on top of the claim bond (RUNBOOK_DEPLOY: parallel games)
    guards: dict = field(default_factory=dict)
    min_comp: int = 0  # the least compensation of a job under a parent, in the price's token (re-audit F6): if the parent
    min_comp_bps: int = 0  # falls this is all the work is paid; the same as a share of the price. 0: no such rule

    def refusal(self, escrow, key, n, now):
        """why this node gets no stake, or None. RpcError if the chain cannot say: no stake either"""
        if n['account'] not in self.accounts:
            return 'UNTRUSTED_ACCOUNT'
        if n['price'] < self.min_price:
            return 'PRICE_TOO_LOW'
        if n['cover'] > self.max_cover:
            return 'COVER_TOO_HIGH'
        if n['expiry'] - now > self.max_lock_s:
            return 'LOCK_TOO_LONG'
        ancestors = escrow.ancestors(key)
        if ancestors and n['comp'] < max(self.min_comp, -(-n['price'] * self.min_comp_bps // 10_000)):
            return 'COMP_TOO_LOW'  # without a parent no void can come: comp is never paid and means nothing
        refs = {n['referee']} | {escrow.node(a)['referee'] for a in ancestors}
        if not refs <= self.referees:
            return 'UNTRUSTED_REFEREE'
        if any(r in self.guards and not self.guards[r](escrow.chain) for r in refs):
            return 'REFEREE_CONTRACTS_CHANGED'
        return None


def reserve_cannon(escrow, signer, key, policy, withstand_wei, now, gas_price_wei=RP.GAS_PRICE_WEI, gas=RP.MAINNET_GAS, live=()):
    """The only way a Cannon executor stakes (READINESS_AUDIT A12): the publisher can be the attacker, and its own
    orchestrator would never run referee_policy for it. So before the reservation: the account is one it trusts, and
    this key's balance read now covers the attacker capital it means to withstand (a policy value, the user's), for this job
    and for those in flight it holds a stake in (`live`: their nodes; B18). -> None if reserved, or the reason for not doing
    so. Called by cannon_agent.CannonExecutor, after its rebuild of the job (D25)."""
    chain = escrow.chain
    n = escrow.node(key)
    try:
        why = policy.refusal(escrow, key, n, now)
        if why is not None:
            return why
        bonds = RP.cannon_bonds(chain, n['referee'])
        if bonds is None:
            return 'NOT_A_CANNON_REFEREE'
        RP.check_side(bonds, withstand_wei, 'defender', RP.balance(chain, signer.address), gas_price_wei, len(live) + 1,
                      lambda: RP.locked_in_games(chain, RP.games_of(chain, n['referee'], live), signer.address), gas)
    except RP.Refused as e:
        return str(e)
    except RpcError as e:
        return 'REFEREE_UNREADABLE:' + (e.revert or str(e))
    chain.send(signer, escrow.address, key_call('reserve', key))
    return None


class WorldExecutor(GraphExecutor):
    def __init__(self, board, escrow, signer, bond, runner=None, lie=None, policy=None, keep_stake=None, payout=None):
        """policy: what it stakes for (AcceptPolicy); without one it finishes what it holds and takes nothing new.
        keep_stake, payout: GraphExecutor"""
        super().__init__(board, escrow, signer, bond, E, lie=lie, keep_stake=keep_stake, payout=payout)
        self.runner, self.policy = runner or OVM0Run(), policy

    def trace(self, job):
        t = self.runner.run(job.program, job.inputs, job.max_steps)
        return self.lie(t) if self.lie else t

    def refusal(self, job, n, now):
        if self.policy is None:
            return 'NO_POLICY'
        why = self.policy.refusal(self.escrow, job.key, n, now)
        if why is not None:
            return why
        if not self.board.fresh(n['prog'], n['inputs'], now):
            return 'STALE_PUBLICATION'  # the escrow posts it, the referee would refuse the claim: only the stake would move
        have = RP.balance(self.board.chain, self.signer.address)
        if have is None or have < self.bond + self.policy.min_eth_wei:
            return 'NO_GAS_MONEY'  # same: the claim could not be sent after the reservation
        return None

    def discover(self):
        logs = scan_logs(self.board.chain, self.escrow.address, [
            '0x' + POSTED_TOPIC.hex(), None, None, '0x' + bytes(12).hex() + self.signer.address.hex()],
            self.board.from_block)
        published = self.board.published()
        held = {j.key: j for j in self.jobs}
        jobs = []
        for log in logs:
            key = bytes.fromhex(log['topics'][1][2:])
            try:
                n = self.escrow.node(key)
            except RpcError:  # not this pass: a job it holds stays
                if key in held:
                    jobs.append(held[key])
                continue
            if n['referee'] != self.board.game:
                continue  # another referee: not this executor's game
            known = published.get((n['prog'], n['inputs']))
            if known is None:
                continue  # not published: nothing can be claimed for it
            jobs.append(Job(key, tuple(tuple(i) for i in known[0]), tuple(known[1]), n['maxSteps']))
        self.jobs = jobs

    def _scan(self):
        self._isolated('discover', '', self.discover)  # a failed scan must not stop the defence of the jobs it holds
