"""Dispute capital of each referee path, and the rule that a job is posted only on a path its capital can defend.

Two paths judge OVM0 jobs (SECURITY_REVIEW sections 4, 10-1):
- OVM0Dispute: OMEGA's bisection game with OVM0Step as the one-step judge. One claim bond (0.22 ETH on the mainnet
  proposal); each challenger posts its own bond per game, the defender posts nothing more. There is no bond race, but
  any number of challengers may open games, and every game needs the defender's gas in time (READINESS_AUDIT A34,
  RUNBOOK_DEPLOY): it costs the attacker a bond per game, not the defender's capital, and an executor without gas money
  still loses on the clock. Trust: OVM0Step (OMEGA's code, not externally audited).
- OmegaCannonReferee: Optimism's deployed FaultDisputeGame 2.2.0 + MIPS64 (Optimism's audited production VM, our
  small guest). Every move posts a bond that grows with depth (FaultDisputeGame.getRequiredBond), and a side may open
  any number of branches, each of which the other side must answer down to the leaf with its own bonds. Whoever runs
  out of liquidity loses on the clock and loses its bonds: the honest side is safe only against an attacker with less
  capital than what it can match.

Per branch an attacker opens at depth d (it posts the claims at depths d, d+2, ... and the honest side answers at
d+1, d+3, ...), honest cost / attacker cost = sum(bonds of the honest depths) / sum(bonds of the attacker depths).
R = the largest such ratio over every depth and both roles. An honest side with liquidity L therefore withstands any
attacker with capital below L / R, provided L covers at least one full branch. Bonds come back to the winner only
after the game, the finality delay and the bond vault delay.

The rule (Orchestrator._try_post): a job whose referee is a Cannon referee is posted only if the balances read from
the chain give the job's executor and the account's watcher each a liquidity >= requirement(withstand). Otherwise the
job is refused with a reason; it is never moved to another referee (that would change its security silently). The
rule compares with W: W is a policy value, the attacker is not known, and with W set low the capital that lost a true
node on the fork passes (SECURITY_REVIEW section 10-2). W is the user's. The publisher can be the attacker
(READINESS_AUDIT A12): a Cannon executor therefore applies the same comparison to itself before staking and works only
for accounts it trusts (omega_world.executor.reserve_cannon).
"""
from dataclasses import dataclass
from fractions import Fraction
from omega_compute.dispute_agent import contract_refused
from omega_kernel.settlement.evm import RpcError
from omega_kernel.settlement.evm_crypto import call_data, selector

GAS_PRICE_WEI = 50 * 10 ** 9  # the mainnet proposal's reward floor assumes it too (deploy/chains/mainnet.json)
# Assumed gas per action, above what was measured: an attack 254,118 (READINESS_AUDIT A31). resolveClaim and step are
# assumptions until they are measured on the fork (WORKLIST T7).
MOVE_GAS, RESOLVE_GAS, STEP_GAS = 300_000, 200_000, 1_500_000


@dataclass(frozen=True)
class GasTable:
    """what the honest side's moves cost on one chain, and the gas price it plans for. These defaults are mainnet's rules
    today. A chain with others (Sepolia's Glamsterdam reprices state creation) says so in its config: gas_table"""
    move: int = MOVE_GAS
    resolve: int = RESOLVE_GAS
    step: int = STEP_GAS
    price_wei: int = GAS_PRICE_WEI


MAINNET_GAS = GasTable()


def gas_table(config):
    """the GasTable of a chain's config (deploy/chains): its "referee_gas" section {move, resolve, step, price_wei}, what is
    not there as on mainnet. ValueError for anything else in it: a typo must not quietly price a dispute at mainnet's."""
    try:
        return GasTable(**config.get('referee_gas', {}))
    except TypeError as e:
        raise ValueError('BAD_REFEREE_GAS') from e


def bonds_from_chain(chain, impl, max_depth=73):
    """getRequiredBond(2^d) for d = 0..max_depth of a FaultDisputeGame implementation (its bond curve is fixed in
    its bytecode)"""
    return [int.from_bytes(chain.call(impl, call_data('getRequiredBond(uint128)', 1 << d))[:32], 'big')
            for d in range(max_depth + 1)]


def cannon_bonds(chain, ref):
    """the bond curve of a Cannon referee's FaultDisputeGame implementation, or None for any other referee. A Cannon
    referee has games() (its OmegaCannonGames) and registerGrace(); OVM0Dispute has games() (a count) but no
    registerGrace(), OmegaSuperRootReferee registerGrace() but no games(). Only a revert says "not this function"
    (READINESS_AUDIT A05): a rate limit, a node behind the chain answering 0x, any other answer raises RpcError, which is
    a refusal of this post and no verdict on the referee. A node whose reverts read otherwise refuses too: closed."""

    def read(to, sig):
        w = chain.call(to, selector(sig))
        if len(w) != 32:
            raise RpcError(f'NO_ANSWER:{sig}')
        return w
    try:
        read(ref, 'registerGrace()')
        w = read(ref, 'games()')
        games = w[12:32] if w[:12] == bytes(12) and w[12:32] != bytes(20) else None
        impl = read(games, 'impl()')[12:32] if games else None
    except RpcError as e:
        if 'execution reverted' in str(e).lower():
            return None
        raise
    return bonds_from_chain(chain, impl) if impl else None


def balance(chain, who):
    """the wei `who` holds, or None if the chain does not say (admit refuses None)"""
    try:
        return int(chain.rpc('eth_getBalance', '0x' + who.hex(), 'latest'), 16)
    except (RpcError, OSError, ValueError, TypeError):
        return None


def branch_cost(bonds, start):
    """bonds posted at depths start, start + 2, ... up to the maximum depth (the leaf is countered by a step, which
    posts no bond)"""
    return sum(bonds[d] for d in range(start, len(bonds), 2))


def worst_ratio(bonds):
    """R = max over branching depth d >= 1 of honest cost / attacker cost. The attacker posts at d, d+2, ...; the
    honest side answers at d+1, d+3, ... (when d is the maximum depth the honest side steps: cost 0)."""
    top = len(bonds) - 1
    r = Fraction(0)
    for d in range(1, top + 1):
        att = branch_cost(bonds, d)
        hon = branch_cost(bonds, d + 1) if d < top else 0
        if att == 0:
            raise Refused('CANNON_BOND_CURVE_INVALID')  # a free attacker branch: no capital bound exists
        r = max(r, Fraction(hon, att))
    return r


def full_branch(bonds, role):
    """what one whole branch costs a side: the defender of the root posts the even depths below it (2, 4, ...),
    the challenger the odd depths (1, 3, ...)"""
    return branch_cost(bonds, 2) if role == 'defender' else branch_cost(bonds, 1)


def gas_wei(bonds, withstand_wei, role, gas_price_wei, gas=MAINNET_GAS):
    """the gas of the honest side's moves (READINESS_AUDIT A31): one whole branch at least, and one answer plus its
    resolve for every move the attacker can pay for at the cheapest depth; a step at each leaf it can reach"""
    moves = max(len(range(2 if role == 'defender' else 1, len(bonds), 2)), -(-withstand_wei // bonds[1]))
    steps = max(1, -(-withstand_wei // bonds[-2]))
    return (moves * (gas.move + gas.resolve) + steps * gas.step) * gas_price_wei


def requirement(bonds, withstand_wei, role, gas_price_wei=GAS_PRICE_WEI, gas=MAINNET_GAS):
    """the liquidity a side needs to withstand an attacker holding `withstand_wei`: the bonds, the gas of playing them,
    and the root bond of the side that opens the game (the defender)"""
    need = -(-Fraction(withstand_wei) * worst_ratio(bonds) // 1)
    root = bonds[0] if role == 'defender' else 0
    return max(int(need), full_branch(bonds, role)) + root + gas_wei(bonds, withstand_wei, role, gas_price_wei, gas)


@dataclass(frozen=True)
class CannonCapital:
    """an account's policy for jobs on one Cannon referee: the attacker capital it wants to withstand, its watcher's
    address and the gas price it plans for. The liquidity is what the chain says these keys hold, never a declared
    number (READINESS_AUDIT A07); the defender is each job's executor. gas: the chain's table (gas_table)."""
    withstand_wei: int
    watcher: bytes
    gas_price_wei: int = GAS_PRICE_WEI
    gas: GasTable = MAINNET_GAS


class Refused(Exception):
    pass


def check_side(bonds, withstand_wei, role, have, gas_price_wei=GAS_PRICE_WEI, jobs=1, locked=None, gas=MAINNET_GAS):
    """None, or raise Refused: one side's balance (None: unknown) against the requirement. role: defender or watcher.
    Each job in flight can be attacked at once, so `jobs` of them need the requirement `jobs` times (re-audit B18: three jobs
    passed on a balance that could defend one). locked() -> what this side already holds in their games, which counts as
    held for them: read only if the balance alone is not enough."""
    if len(bonds) < 2 or not all(b > 0 for b in bonds):
        raise Refused('CANNON_BOND_CURVE_INVALID')
    if withstand_wei <= 0:
        raise Refused('CANNON_WITHSTAND_UNSET')
    if have is None:
        raise Refused('CANNON_BALANCE_UNKNOWN:' + role)
    need = jobs * requirement(bonds, withstand_wei, 'defender' if role == 'defender' else 'challenger', gas_price_wei, gas)
    if have < need and (locked is None or have + locked() < need):
        raise Refused('CANNON_CAPITAL_SHORT:' + role)


def admit(bonds, capital, defender_balance=None, watcher_balance=None, load=None):
    """None, or raise Refused with the reason. load: role -> (jobs, locked), check_side's, for what is in flight"""
    if len(bonds) < 2 or not all(b > 0 for b in bonds):
        raise Refused('CANNON_BOND_CURVE_INVALID')
    if capital is None:
        raise Refused('CANNON_NEEDS_CAPITAL_POLICY')
    for role, have in (('defender', defender_balance), ('watcher', watcher_balance)):
        jobs, locked = (load or {}).get(role, (1, None))
        check_side(bonds, capital.withstand_wei, role, have, capital.gas_price_wei, jobs, locked, capital.gas)


def locked_in_games(chain, games, who):
    """the bonds `who` has posted in these games, while they are in progress (FaultDisputeGame claimData)"""
    total = 0
    for game in games:
        if int.from_bytes(chain.call(game, selector('status()'))[:32], 'big') != 0:
            continue
        for i in range(int.from_bytes(chain.call(game, selector('claimDataLen()'))[:32], 'big')):
            w = chain.call(game, call_data('claimData(uint256)', i))
            bond = int.from_bytes(w[96:128], 'big')
            if w[76:96] == who and bond < (1 << 128) - 1:  # that value: the flag of a bond already paid out
                total += bond
    return total


def games_of(chain, referee, nodes):
    """the games of the nodes that have one. A referee that has no gameOf holds no game capital: counted as none, the side
    of the refusal, while a failed read stays the caller's"""
    out = []
    for n in nodes:
        if n['claimId']:
            try:
                out.append(chain.call(referee, call_data('gameOf(uint256)', n['claimId']))[12:32])
            except RpcError as e:
                if not contract_refused(e):
                    raise
    return out


def admit_on_chain(chain, bonds, capital, executor, referee=None, defended=(), watched=(), new=1):
    """admit with the balances read now: the executor's and the policy's watcher's. defended, watched: the nodes in flight
    on `referee` that each of them answers for already; new: the jobs this asks about, 1 or, for a job already in flight, 0"""
    if capital is None:
        return admit(bonds, None)

    def of(nodes, who):
        return len(nodes) + new, lambda: locked_in_games(chain, games_of(chain, referee, nodes), who)
    return admit(bonds, capital, balance(chain, executor), balance(chain, capital.watcher),
                 {'defender': of(defended, executor), 'watcher': of(watched, capital.watcher)})
