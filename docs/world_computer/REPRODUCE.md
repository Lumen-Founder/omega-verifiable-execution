# Reproducing the OMEGA end-to-end run

For an independent team. You should not have to take our word for anything here, and you should not need to talk to us to run it.
Status of this document's numbers is at the end.

## What the run does

Three jobs, each using the previous one's output, on the contracts in `omega_evm/src`:

1. An executor posts a false result for job A. A watchtower disputes it; the bisection game ends in a one-step proof on chain and
   the claim is rejected.
2. Jobs B and C were already running on A's false output, by an honest executor. They are voided, and the honest executor is
   compensated out of the false executor's cover.
3. The plan retries. A, B and C give 55, 56 and 112 and are paid.
4. A fourth job nobody takes expires, and its price returns to the account.
5. After every job's expiry the bonds are released and everyone withdraws. The escrow must end holding no tokens.

The kit then rebuilds a transcript from the chain's logs alone: each job's events and amounts, each claim's outcome, the moves of
each game, tokens in and out per role. Addresses are replaced by roles and times are left out, so independent runs of this plan
give the same `economics_sha256`.

## What it does not show

- **Safety against an attacker.** The false executor here follows a script. This is not a security result. No external audit has
  been done.
- **The Optimism and Cannon referees' dispute paths.** The run's disputes go through `OVM0Dispute` only.
- **Costs.** Ether is out of the digest because gas differs by chain and fork.
- **That anyone needs this.** There are no customers yet, and the contracts earn their authors nothing: they have no fee, treasury
  or admin path.

Tell us if you find any of the above misrepresented.

## Requirements

- Foundry `1.5.1-stable` (`forge`, `anvil`). It installs solc `0.8.28` itself. A different version may change the build digest.
- Python 3.12 or newer, with `pycryptodome==3.23.0`.

```bash
python3 -m venv .venv
.venv/bin/pip install pycryptodome==3.23.0
```

Use `.venv/bin/python` below (on Windows, `.venv\Scripts\python`). A bare Ubuntu needs `sudo apt install python3-venv` first.

## A. Local run: about two minutes, no funds, nothing leaves your machine

```bash
.venv/bin/python -X utf8 -B tools/world/repro_kit.py local work-a
```

It starts its own loopback anvil, makes throwaway keys and advances the clock. Exit code 0 means the checks in `RESULT.json` passed.
Then compare with ours:

```bash
.venv/bin/python -X utf8 -B tools/world/repro_kit.py compare work-a/TRANSCRIPT.json runs/sepolia/TRANSCRIPT.json
```

Exit code 0 and `"same": true` means the same contract code did the same accounting. A difference is printed by job. Please send it
to us as it is: a difference is a result.

## B. Check our Sepolia run: no key, no funds

```bash
.venv/bin/python -X utf8 -B tools/world/repro_kit.py check runs/sepolia/RUN.json <rpc-url>[,<rpc-url>] work-b.json
```

This builds the contracts, reads the logs from your RPC and rewrites the transcript without using anything we computed.
`code_matches_build: true` means the bytecode at those addresses is what your own compiler produced from these sources, with the
constructor arguments in `RUN.json`. Use an RPC you trust, or two.

## C. Your own run on a public test chain: hours, test ether only

Never use a key that holds real assets. The tool refuses chains outside its test list.

1. Make seven new keys, one 32-byte hex secret per file, in a folder outside this tree: `deployer.key`, `owner.key`, `agent.key`,
   `relayer.key`, `executor.key`, `liar.key`, `watcher.key`. Fund each with test ether.
2. Fill the `REQUIRED` values of `deploy/chains/sepolia.json` in a copy (4 contracts), or use `deploy/chains/sepolia_full.json`
   (all 8, the configuration of our run). A new `token` comes from:

   ```bash
   OMEGA_REHEARSAL_KEYS=<keys> .venv/bin/python -X utf8 -B -m omega_world.rehearsal deploy-token <rpc-url> <copy.json>
   ```

3. Run it, and run the same command again if it stops. The folder holds the progress:

   ```bash
   OMEGA_REHEARSAL_KEYS=<keys> .venv/bin/python -X utf8 -B tools/world/repro_kit.py network <rpc-url>[,<rpc-url>] <copy.json> work-c
   ```

4. Compare `work-c/TRANSCRIPT.json` as in A.

It really waits: the claim windows and then every job's expiry. With a window of 1,800 s, a clock of 600 s and a grace of 3,600 s
expect about six hours. Publish `work-c/RUN.json` if you want others to check you; it holds addresses and no secret.

## What we would like back

Your environment (`RESULT.json` has it, with no host name or user), the two digests, any difference, and every step of this
document that was wrong or missing.

## Status of the numbers in this document

Filled from measured runs only; see `runs/sepolia/` and `docs/adr/ADR-0015-verifiable-execution-identity.md`.

On 2026-11-03 we ran A and B ourselves on Windows (Python 3.14, forge 1.5.1) against `runs/sepolia/`: A gave `"same": true`, and B,
reading from `https://sepolia.gateway.tenderly.co`, gave `code_matches_build: true` and `"same": true`. That is our own check, not
an independent one: yours is the one that counts.
