"""Bond and delay bounds for OVM0Dispute from measured gas (anvil, tests/test_omega_evm_dispute.py, OVM0Step).

A game over a claim of n transitions bisects [0, n] down to one step, so it lasts at most R = ceil(log2(n)) rounds,
and the contract caps n <= maxSteps + 1 <= stepCap + 1. The bond is the only thing that repays an honest party's gas,
so it must cover the most an honest party can be made to spend in one game; the claim's finality is delayed by at
most the challenge window plus one game, because games run in parallel.

A rejected claim's bond is split (S-3): the first winning challenger gets `reward` on top of its own bond and the rest,
bond - reward, burns. The defender can challenge its own claim with another key and win that race, so the burn is the
least a defeated false claim costs; the reward is what repays an honest winner's gas. So reward >= reward_floor_wei and
bond > reward. The dispute contract cannot know what a lie could win elsewhere (a job price, a downstream payment):
the burn deters only up to its own size, and OmegaJobEscrow adds a stake in the price token for that (ADR-0004 6-1).
"""
import math

# measured on the deployed referee OVM0Step, 2026-11-03: a claim of stepCap transitions over a 4096-instruction program,
# 14 rounds, ending in a prove of the costliest step found (MSTORE inserting past 255 memory cells on a full stack,
# tests/test_omega_evm_dispute.py test_a_full_state_dispute_..., which fails if a value is exceeded or goes stale).
# The earlier values priced prove with OVM0StepM, which the stack does not deploy (audit A29). Those of bisect and respond
# came from moves inside one second: the chess clock then writes the value it holds (100 gas instead of 2,900), which no
# real chain does. The test now lets time pass before each move (Sepolia rehearsal, 2026-11-03).
# These are the gas rules of mainnet today. Glamsterdam, live on Sepolia since 2026-10-06 and not yet dated on mainnet,
# reprices state creation (EIP-8037) and calldata (EIP-7976: a floor of 64 gas per byte): see GLAMSTERDAM.
CHALLENGE = 198_500
BISECT_MAX = 68_000
RESPOND_MAX = 54_900
PROVE_MAX = 660_500
WITHDRAW = 28_600  # pull payout to an account without code
MAINNET_TODAY = {'challenge': CHALLENGE, 'bisect': BISECT_MAX, 'respond': RESPOND_MAX, 'prove': PROVE_MAX, 'withdraw': WITHDRAW}
# The same game on Sepolia's rules, 2026-11-03. challenge, first bisect and respond: the rehearsal's measurements. prove: a
# full-state step is 25,860 bytes of calldata, so the floor sets the price, 21,000 + 64 x 25,860 = 1,676,040; eth_estimateGas
# of the referee's stepHash with that state on Sepolia said 1,684,462 (world_final_v10/reaudit/probe_gas.py), rounded up for
# prove's own storage writes. Not a full game on those rules; withdraw is today's value, not measured there. An estimate to
# measure again before arming on a chain with those rules: the earlier one left out the floor and was 30 % low (re-audit F2).
GLAMSTERDAM = {'challenge': 821_858, 'bisect': 164_288, 'respond': 77_502, 'prove': 1_690_000, 'withdraw': WITHDRAW}


def rounds(n):
    return max(0, math.ceil(math.log2(n))) if n > 1 else 0


def honest_gas(step_cap, rules=MAINNET_TODAY):
    """Most gas an honest party spends in one game, as defender or as challenger, for claims up to step_cap + 1."""
    r = rounds(step_cap + 1)
    defender = r * rules['bisect'] + rules['prove'] + rules['withdraw']
    return max(defender, challenger_gas(step_cap, rules)), r


def challenger_gas(step_cap, rules=MAINNET_TODAY):
    return rules['challenge'] + rounds(step_cap + 1) * rules['respond'] + rules['prove'] + rules['withdraw']


def bond_floor_wei(step_cap, gas_price_wei, margin=1.5, rules=MAINNET_TODAY):
    gas, _ = honest_gas(step_cap, rules)
    return math.ceil(gas * gas_price_wei * margin)


def reward_floor_wei(step_cap, gas_price_wei, margin=1.5, rules=MAINNET_TODAY):
    """Least reward that repays an honest winning challenger's worst-case gas in one game."""
    return math.ceil(challenger_gas(step_cap, rules) * gas_price_wei * margin)


def max_finality_delay(window, clock):
    """Claim -> accepted: games open within the window and each runs on a chess clock of `clock` per side, so
    finality is at most window + 2 * clock whatever the number of rounds; parallel games do not add up."""
    return window + 2 * clock


def per_move_finality_delay(window, step_cap):
    """The bound before the chess clock, when every move got a fresh window: (2r + 2) * window."""
    return window + (2 * rounds(step_cap + 1) + 1) * window


def watcher_log_horizon(da_max_age, window, clock):
    """Oldest publication log a watcher may still need: a claim can come da_max_age after publication and stay open
    window + 2 * clock; keep this inside the history every node retains (EIP-4444)."""
    return da_max_age + window + 2 * clock
