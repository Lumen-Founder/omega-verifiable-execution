# OMEGA — one page

**What it is.** Open infrastructure that turns work done outside the chain, by independent computers and AI agents, into verifiable
results and accountable state changes on Ethereum. A job names its inputs, its program, the jobs it depends on and the referee that
judges it. A false result is disputed and rejected on chain; every job built on it is voided before it pays, the honest executors
downstream are compensated from the faulty executor's stake, and the plan retries. Payment happens only for results that are final
all the way up the dependency graph.

**What it is not, today.** Not a general compute platform, and not a verifier of real-world work. The referees judge deterministic
computation only: our bisection game (`OVM0Dispute`), Optimism output roots (Optimism's fault dispute games), and MIPS64 programs
(the Cannon game). AI output quality and physical work have no referee here.

## Evidence (measured)

| | |
| --- | --- |
| Sepolia, 2026-11-03 | All 8 contracts deployed and bytecode-verified. A false claim was challenged 36 s (chain time) after it appeared, lost a 14-move game and was rejected 504 s after it was made. Two dependent jobs were voided, the honest executor was compensated, the retried plan settled (55, 56, 112) and paid out. A restart in the middle of the game recovered without re-posting anything. 89 transactions, mean inclusion 12.6 s, p90 23.1 s. At the close the escrow held no token and nothing locked or bonded. A local run of the same sources and a keyless re-read from a public RPC both give the same transcript (`runs/sepolia/`) |
| Gas per job, no dispute | 2,856,423 on Sepolia's rules (Glamsterdam), from posting to the bond's return |
| Reproducibility | A zip of committed files runs the whole job locally in about two minutes; Windows and Linux builds give the same bytecode digest and the same accounting digest. Not yet repeated by anyone outside the project |
| Tests | Unit, integration, invariant fuzzing, exhaustive small graphs, fork tests against mainnet Optimism contracts; mutation testing of all 8 contracts: 577 mutants, 0 survivors (17 equivalent) |

## Not done

- No external security audit. Our own reviews, AI-assisted reviews, static analysis, Halmos and SMTChecker are not one.
- No mainnet deployment; it waits for the audit and a validated business model.
- No customers and no revenue. The contracts have no fee, treasury or admin key, and are MIT-licensed: they earn us nothing.
- The Optimism and Cannon referees have not run a real dispute on a public network.

## Business model under test

The protocol stays free and permissionless. Revenue would come from operating it for teams: execution, monitoring, dispute response,
capital for disputes, and integration. That only works if running it yourself costs more than paying us. We are looking for teams
whose multi-step jobs can be recomputed deterministically and who have lost money when an early step was wrong.

## Check it yourself

`docs/world_computer/REPRODUCE.md`: a local run with no funds, a key-free check of our Sepolia run from your own RPC, and your own
testnet run.
