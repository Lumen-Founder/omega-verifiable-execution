# OmegaEscrowXD — ERC-8183 escrow extension (reference implementation, stages 1-3, pre-audit)

An ERC-8183 escrow in which nobody can change a job's economic terms on their own after the client funds it.
It is built on erc-8183/base-contracts@142e669c. Pre-audit, local tests only, not deployed anywhere.

## What it adds to base-contracts

| Rule | How |
|---|---|
| Fee terms are fixed per job | Both fee rates and both fee recipients are read once in `createJob`. Later admin changes reach only later jobs. `createJobWithTerms` lets the creator cap the rates; above the cap, creation reverts. |
| Commitment boundary | The provider confirms the full terms hash (`confirmTerms`). The client funds with the same hash (`fundWithTermsHash`). The escrow recomputes the hash from live state before and after the fund hook. The plain `fund` reverts (`TermsHashRequired`). |
| What the hash covers | `CommitmentTermsV2`, 22 fields: parties, provider recipient, token, budget, expiry, hook address, hook code hash, hook config hash, hook class, fault policy, the four fee terms, gas and time limits. EIP-712 domain `ERC8183CommitmentTerms`, version `2`. |
| Committed hooks | After funding, `batchDetachHook` reverts for that job (`HookBoundToCommittedJob`). Every hook call on a committed job first checks that the hook's code hash and config hash are still the committed ones (`HookBindingChanged`). |
| Changing a committed hook | `amendHook`, signed by client, provider and evaluator, plus the platform fee recipient when the job's platform fee is above 0. Only the four hook fields may change: the escrow rebuilds the new terms from storage and compares. Nonce, deadline and a hash-chained audit log. Neither the old nor the new hook is called. No allowlist for the new hook: the signers agreed to its code hash. |
| No partial settlement | `submitClaim`, `settleClaim`, `approveClaim`, `rejectClaim` revert. |
| Settlement mode, fixed at creation | IMMEDIATE (0) pays at completion and refunds at rejection or expiry, as upstream does. DEFERRED (1) records payout rights instead: completion fixes the provider, evaluator and platform shares, rejection or expiry of a funded job fixes the client refund. No transfer and no IDisburser callback happen then, so no recipient can block completion. |
| Claims | `claimPayout(jobId, kind, disburserData)`: kind 0 provider, 1 evaluator, 2 platform, 3 client refund. Anyone may call, also while paused. The tokens go to the job's fixed recipient only; no function takes a destination. A claim of a right that is NONE or already CLAIMED returns 0. A failed transfer or callback reverts the claim and the right stays ENTITLED. The provider share calls IDisburser with the `complete` selector and the exact `optParams` given to `complete` (the claimer cannot choose them). The upstream payment events are emitted at claim time. |
| Hook classes, fixed at creation | REQUIRED hooks gate the core call as upstream does. AUXILIARY hooks run with the gas cap fixed in the terms (`auxHookGas`, default 100,000); a revert, an out-of-gas or a changed binding only emits `AuxHookFailed` and the core call goes on. If the caller leaves too little gas for the cap, the core call reverts (`InsufficientGasForHook`), so nobody can starve a hook on purpose. At most 256 bytes of a hook's revert data are copied. |
| REQUIRED-hook faults | `declareHookFault(jobId, selector, phase, data)`: client or provider. The escrow probes the hook with that call itself and records a fault only if the probe reverts or the hook's code or config changed. `clearHookFault`: anyone, once the same probe passes. A successful hooked core call or an `amendHook` also clears it. `resolveHookFault`: anyone, after `faultWindow` (default 72 h); runs the policy fixed at creation: EXPIRE_ONLY (nothing; the expiry refund stays), REFUND_ON_FAULT (refund now, no fees), EVALUATOR_ON_FAULT (the evaluator may complete or reject once without the hook). No admin role can declare, clear or resolve, and pause does not block these. Probes run in a self-call that always reverts, so a probe never leaves state in the hook. |
| Solvency | Per token, `totalEscrowed` (funded budgets) and `totalUnclaimed` (rights). `emergencyWithdraw` can take only the balance above both. `claimRefund` is not blocked by pause. |

The client can always get its money back: `claimRefund` after expiry calls no hook and is not blocked by pause. So a broken committed hook can block payment to the provider, but it cannot lock the client's funds. Claims call no hook either.

## Files

- `ERC8183Virtual.sol`: base-contracts `ERC8183.sol` with the contract renamed and `virtual` added to 17 functions. Nothing else differs. `node src/escrow-xd/check_dev_copy.mjs` undoes these edits and compares the result with the pinned upstream hash.
- `IERC8183Hook.sol`, `IDisburser.sol`: unmodified upstream copies, checked by the same script.
- `OmegaEscrowXD.sol`: the escrow. It contains the entry points and the token movements.
- `XDLogic.sol`: external library: terms, commitment, binding and amendment logic. Delegatecalled, no state, moves no tokens.
- `XDPayout.sol`: external library: settlement, payout rights, claims and the solvency books. Delegatecalled, no state of its own; it moves the escrow's tokens only to a job's fixed recipients.
- `XDHooks.sol`: external library: hook calls by class, auxiliary isolation, fault declare / clear / resolve and the probe.
- `XDFlow.sol`: external library: the settling transitions (complete, reject, expiry refund), upstream checks and order.
- The four libraries keep the escrow under the EIP-170 size limit: the escrow is 23,990 bytes, the limit is 24,576. Deployment links all four; the link graph has no cycle (XDFlow -> XDHooks -> XDPayout; XDLogic alone).
- `CommitmentTermsLib.sol`: EIP-712 type strings and hashing.

## Tests

From `omega_adapters/`:

```
node src/escrow-xd/check_dev_copy.mjs
(cd third_party/oz && npm ci --ignore-scripts) && forge test --match-path "test/escrow-xd/*"
```

- `test/escrow-xd/OmegaEscrowXD.t.sol` has 37 tests: commitment boundary, committed hooks, amendment, locked fee terms and stage-1 limits. It includes a fuzz test of admin calls after commitment. The terms hash and the amendment digest are recomputed in the test without the library.
- `test/escrow-xd/OmegaEscrowXDPayout.t.sol` has 27 tests for stage 2: deferred rights and claims, blocked and reverting recipients, disburser data, reentrancy, false-returning tokens, refund rights, pause, excess-only withdrawal, a fuzz test of random call orders that checks both books against the job states after every step, and two gas scenarios.
- `test/escrow-xd/OmegaEscrowXDHooks.t.sol` has 28 tests for stage 3: auxiliary hooks that revert, burn gas, return large revert data, re-enter or change their binding; the low-gas guard; fault declare / clear / resolve under each policy; probes leaving no state; amendment during a fault; pause; and three gas scenarios.
- `test/escrow-xd/TermsVectors.t.sol` (generated by `sdk/scripts/make_terms_vectors.mjs`) recomputes 40 terms and amendment digests that the SDK, viem and ethers agree on.
- `test/escrow-xd/XD8183Conformance.t.sol` runs the same 25 V1–V15 evaluator conformance tests that run on base-contracts, here on XD.
- Mutation check: we removed each of 8 stage-1 guards one at a time (second hash check, detach block, binding check, structural recompute, evaluator signature, locked fee rate, provider confirmation, nonce), then 13 stage-2 guards (claim status, disburser data hash, CLAIMED mark, both book updates, excess-only withdrawal, unpausable claim and refund, escrowed on fund, provider recipient, stored disburser data, claim reentrancy guard, refund right). At least one test failed every time.

## Gas (implementation, `forge test --isolate`)

| Call | base-contracts | XD |
|---|---|---|
| `createJob` | 117,547 | 203,576 (3 more storage slots for the fee terms) |
| `confirmTerms` | — | 60,438 |
| `fund` / `fundWithTermsHash` (no hook) | 63,280 | 104,169 (stage 1); 143,773 in the stage-2 scenario, with the first write of `totalEscrowed` for the token |
| `complete` (no fees) | 70,676 | 66,801 (stage 1) |
| `complete`, IMMEDIATE, both fees | — | 137,884 |
| `complete`, DEFERRED, both fees | — | 78,983 |
| `claimPayout` (one right) | — | 64,352 – 71,674 |
| `submit`, no hook | — | 25,357 |
| `submit`, REQUIRED hook | — | 51,533 |
| `submit`, AUXILIARY hook (two capped calls) | — | 52,699 |
| `declareHookFault` (one probe in a self-call) | — | 55,970 |
| `amendHook` (3 signatures) | — | 83,269 – 164,829 |

## Limits

- **New deployments only.** Upgrading a live base-contracts proxy that has jobs in flight is not supported. Those jobs would change behaviour mid-flight (decision D-25).
- **Upgrade trust boundary.** The escrow is UUPS, as upstream is. Whoever holds `DEFAULT_ADMIN_ROLE` can replace the logic, and with it every rule above. Use a timelock or renounce upgrades before you rely on committed terms.
- **Faults are not judged, only routed.** On chain the escrow cannot tell a hook that enforces a condition from a broken one. A probe runs in a different context from the real call (inside a reverting self-call, not in the middle of the action), so a hook can pass the probe and fail the real call, or the reverse. In the first case no fault can be declared and the job falls back to expiry; in the second a fault is declared but the first successful real call clears it.
- **EVALUATOR_ON_FAULT skips the hook only for `complete` and `reject`.** If the broken hook blocks `submit`, a Funded job can only be rejected (refund), not completed.
- **Probe gas.** A REQUIRED hook that needs more than 1,000,000 gas per call can be declared faulty.
- There is no batch claim.
- **A recipient that never accepts.** If a fixed recipient can never receive (a permanent blacklist, a receiver contract that always reverts), its right stays ENTITLED forever. Nothing moves it to another address; that would bypass the token issuer's restriction (design S10). Recovery is a separate design and a legal question.
- **Token behaviour.** The books assume the escrow's balance changes only by its own transfers. Tokens whose balances change without a transfer (rebasing, fee-on-transfer, admin seizure) must not be allowed. Fee-on-transfer is already refused at funding.
- **The hash covers code, not proxies.** For a hook behind a proxy, the code hash covers only the proxy, not its implementation. The config hash is whatever the hook reports. Parties should check a hook before they confirm it.
- **Fee recipient.** An evaluator contract that wants its fees sent elsewhere must call `setEvaluatorDefaultRecipient` itself. Otherwise fees go to the evaluator address.
