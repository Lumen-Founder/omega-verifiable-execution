# Run the ERC-8183 Evaluator Verdicts conformance suite in your own CI

The suite checks an evaluator against requirements V1–V15 of the Evaluator Verdicts draft (`../../spec/`), on the real
erc-8183/base-contracts escrow (142e669c, deployed behind a proxy inside the test). 27 tests. You write four small
adapter functions; nothing else in your repository changes.

## Steps

1. Add this repository as a dependency, pinned to a commit:
   ```
   git submodule add https://github.com/Lumen-Founder/omega-verifiable-execution lib/omega-verifiable-execution
   git -C lib/omega-verifiable-execution checkout <commit>
   ```
   (`forge install Lumen-Founder/omega-verifiable-execution@<commit>` works too.)
2. Merge `foundry.toml` from this folder into yours. The suite needs solc 0.8.28 and the four remappings.
3. Install OpenZeppelin 5.6.1 from the lockfile, without install scripts:
   ```
   (cd lib/omega-verifiable-execution/omega_adapters/third_party/oz && npm ci --ignore-scripts)
   ```
4. Copy `MyEvaluator.conformance.t.sol` to your `test/`. As shipped it runs the reference evaluator, so it should pass
   unchanged. Then point the import and the four functions (`_deploy`, `_setKey`, `_retireKey`, `_revokeKey`) at your
   evaluator.
5. Copy `github-workflow.yml` to `.github/workflows/`. Run locally with
   `forge test --match-contract MyEvaluatorConformance`.

## What we checked

From an empty project with the dependency pinned to commit `cd053d2` (already public), steps 1–4 unchanged gave
25/25 with forge 1.5.1-stable on Windows. The GitHub workflow itself has not run yet; it uses the standard
`foundry-rs/foundry-toolchain` action.

V13 changed on 2026-11-12: a key's window is now judged at `block.timestamp`, not at the signer-written `signedAt`
(see the spec). The suite went from 25 to 27 tests. A CI pinned to `cd053d2` or `795ac2f` still runs the old V13, which
accepts a retired key's backdated verdict; move the pin forward.

## If your evaluator differs

- No key registry, or another key model: implement the four functions as no-ops where they do not apply and tell us
  which tests then fail; we would rather fix the suite than force a key model on you.
- Two-argument `complete(jobId, reason)` escrows: the suite targets base-contracts (three arguments). See the escrow
  layout notes in the spec.

Results you report (pass, fail, or "this test is wrong") go into the public comparison only with your consent.
