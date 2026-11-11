# Evaluator measurement for ERC-8183 (reference, pre-audit, MIT)

This follows the discussion on the ERC-8183 thread (ethereum-magicians, topic 27902):
- #436-#438: evaluator verdicts that are signed and bound to the job
- #441: rater severity on one scale with a many-facet Rasch model, proposed by drmattbarney
- #442: our reply, committing to this reference

Everything here runs locally and is synthetic. No chain data is used. Nothing is deployed.

## M1 — signed verdict evaluator (`../src/SignedVerdictEvaluator8183.sol`)

The evaluator acts only on an EIP-712 verdict signed by a registered rater key.

What the verdict binds:
- **Job:** chain id and this contract (domain), escrow, job id, deliverable hash, criteria/schema hash, decision, expiry, `signedAt`.
- **Key:** key id.
- **Measurement:** model id, severity and its standard error (logits × 1e4), and the calibration run they came from.
- **Detail:** a `detailHash` of the full signed verdict document (RFC 8785 JSON).

How the evaluator acts:
- `COMPLETE` and `REJECT` call the escrow with the verdict digest as `reason`.
- `COULD_NOT_CHECK` is recorded and changes nothing. The job can still expire to a refund, so silence stays the evaluator's own failure.

How keys work:
- `retireKey` stops the key from settling anything new, whatever date its verdicts carry. Verdicts recorded on chain before the retirement stay valid, judged by the block that recorded them, so disputes over old jobs remain checkable after rotation.
- `revokeKey` (compromise) refuses every signature by that key.
- A key id is never reused for another signer.

Tests (`../test/SignedVerdictEvaluator8183.t.sol`, 24 tests). Each of these is refused:
- the same verdict a second time
- a second decision on a decided job
- a verdict replayed to another job
- a verdict replayed to another escrow
- a verdict replayed to another evaluator deployment on the same escrow
- a tampered severity or deliverable hash
- an unregistered signer
- a high-s signature
- an expired verdict
- a verdict with `signedAt` in the future
- a key that is not yet valid, retired, compromised or unknown

Limit: ERC-8183's `getJob` has no deliverable field. The deliverable hash in a verdict is therefore checked against the escrow's `JobSubmitted` event off chain, not inside this contract.

```
cd omega_adapters && forge test --offline --match-contract SignedVerdictEvaluator8183Test
```

## M2 — many-facet Rasch estimator (`mfrm.py`)

The model is dichotomous: P(complete) = sigmoid(quality_job − severity_rater).

Estimation:
- Joint MAP with weak priors. The quality prior is centred on the current mean, so shrinkage does not shift the scale.
- Standard errors come from model information.

Identification:
- Anchor jobs with known quality fix an absolute scale.
- Otherwise each connected rater group is centred on its own. The estimator reports when groups are disconnected, because their severities are then not on one scale.

Fit:
- With few raters per job, joint estimation deflates infit toward (L−1)/L, about 0.78 at four raters.
- `fit_null()` therefore reports infit relative to data simulated from the fitted model.
- When the model holds, that ratio is about 1. A rater answering at random stands out above 1.1.

Tests: `python test_mfrm.py` (recovery, disconnection detection, anchor scale, fit calibration).

This is a plain reference. Many-facet Rasch measurement is Linacre's method, and its use for 8183 evaluator panels was drmattbarney's proposal.

## M3 — committee design simulation (`simulate_design.py`, `simulate_design_result.json`)

Setup:
- 21 raters, severities ~ N(0, 0.7), job quality ~ N(0.5, 1).
- 20 replications per cell.

Designs:
- **fixed:** the raters are split into committees and each job goes to one committee. There are no shared ratings across committees.
- **rotate:** each job draws a random committee.
- **anchors:** fixed committees, plus 6 calibration jobs of known quality that every committee rates. Error is measured on the absolute scale, with no centring.

Severity error vs the truth, and the reported standard error (mean of 20 replications):

| committee | design | jobs | ratings/rater | reported SE | actual RMSE | rater groups |
|---|---|---|---|---|---|---|
| 3 | fixed | 252 | 36 | 0.402 | 0.532 | 7 |
| 3 | fixed | 1008 | 144 | 0.196 | **0.408** | 7 |
| 3 | rotate | 252 | 36 | 0.396 | 0.445 | 1 |
| 3 | rotate | 1008 | 144 | 0.198 | 0.212 | 1 |
| 3 | anchors | 1008 | 150 | 0.192 | 0.275 | 1 |
| 7 | fixed | 1008 | 336 | 0.128 | **0.260** | 3 |
| 7 | rotate | 1008 | 336 | 0.128 | 0.135 | 1 |
| 7 | anchors | 1008 | 342 | 0.127 | 0.223 | 1 |

Findings:
1. **With fixed committees, the reported standard error understates the real error and stops being informative.** At 1008 jobs with committees of 3, the reported SE is 0.20 but the actual error stays at about 0.41 logits. The scale gap between disconnected groups never shrinks. A client reading severity ± SE from such verdicts would be misled. This is the connectivity point in #442.
2. **Rotation makes the reported SE honest.** The actual error tracks the SE: 0.21 vs 0.20 at committees of 3, and 0.135 vs 0.128 at committees of 7.
3. **Calibration jobs connect fixed committees and add an absolute origin.** With only 6 of them, a residual error of about 0.2–0.28 logits remains. More anchors, or anchors combined with partial rotation, would close it. Not simulated yet.
4. Ratings needed for a reported SE ≤ 0.3 logits: about 72 per rater (committees of 3) or 84 per rater (committees of 7). For SE ≤ 0.2: about 144–168.

Not covered:
- No rating-scale (polytomous) model.
- No rater drift over time.
- No collusion or strategic raters.
- No real chain data. Today's deployments have almost no shared third-party ratings, per the census in #430.

## Calibration runs (`calibrate.py`)

This turns verdicts into a severity table that anyone can recompute. Each verdict then points at that table through `calibrationRun`.

1. `sdk/scripts/collect_ratings.mjs` builds a ratings file (`erc8183-ratings/0.1`).
   - Inputs: signed verdict records, such as committee ratings or calibration jobs that never touch the chain, together with the raters' key records. It can also read an evaluator's `VerdictRecorded` logs.
   - Every record is verified first: signature, key window, revocation, decision.
   - The output is one rating per rater and item, where the item is `escrow:jobId:deliverableHash`. COMPLETE counts 1 and REJECT counts 0. COULD_NOT_CHECK is counted but not rated.
   - Forged records, unknown keys and conflicting duplicates are excluded, and each exclusion is listed with its reason.
2. `python calibrate.py ratings.json --out run.json [--anchors anchors.json]` writes `erc8183-calibration-run/0.1`.
   - `runId` is the sha256 of the canonical JSON of {estimator file hash, options, sorted ratings}.
   - The output also holds, per rater: severity, SE, `severityE4`/`severitySeE4`, infit, outfit, the infit ratio against a bootstrap null, and the rater's connected group.
   - `design.comparableAcrossAllRaters` is false when raters fall into disconnected groups and no anchors tie them together.
3. A rater's next verdict carries `severityE4`, `severitySeE4` and `calibrationRun = runId`. Anyone holding the published ratings file can recompute the same `runId` and table.

End-to-end check: `node sdk/scripts/e2e_calibration.mjs`, with `PYTHON` set to a Python that has numpy. The setup is 21 simulated raters and 300 items with 3 ratings each, all signed with the SDK and collected. Three bad records are added.

| Check | Result |
|---|---|
| Collection | 900 ratings, 2 records excluded with reasons, 1 COULD_NOT_CHECK counted |
| Reproducibility | the same `runId` and table on a second run; one changed rating gives a new `runId` |
| Rotating committees | one connected group |
| Severity recovery | correlation 0.887 against an attainable ~0.90 for 43 ratings per rater; RMSE 0.375 against a reported SE of 0.363 |
| Fixed committees | flagged as 7 groups that cannot be compared |
| Use in a verdict | a verdict carrying the run's severity and `runId` verifies |

An earlier draft of this test used committees {5j, 5j+7, 5j+14} mod 21. Their members always share a residue mod 7, so the design splits into 7 groups. `calibrate.py` reported exactly that, which is the failure it exists to catch.
