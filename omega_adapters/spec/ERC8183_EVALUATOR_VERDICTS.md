---
title: ERC-8183 Evaluator Verdicts
description: Signed, job-bound evaluator verdicts with key lifecycle, a "could not check" outcome and optional rater measurement for ERC-8183 evaluators
status: Draft (pre-proposal, for discussion on ethereum-magicians topic 27902)
type: Standards Track
category: ERC
requires: 712, 5267, 8183
---

## Abstract

ERC-8183 lets one evaluator address complete or reject a job, with a `bytes32 reason`. This extension makes that decision checkable. The evaluator contract acts only on an EIP-712 verdict that a registered rater key signed. The verdict binds the job it decides, which prevents replay. Rater keys have a published lifecycle, so old verdicts stay checkable after rotation. "Could not check" is its own outcome and is not treated as a reject. A verdict can optionally carry the rater's measured severity and its standard error, so clients can compare evaluators. The verdict digest becomes the 8183 `reason`. No change to ERC-8183 itself is needed.

## Motivation

Points raised on the ERC-8183 discussion thread, which this document collects:
- #436 (teppi-xyz): the evaluator should commit to its own ruling with a signed verdict anyone can fetch and rerun.
- #437 (ted0x): bind the verdict to chain id, escrow, job id, deliverable hash, criteria hash, decision and expiry; a verdict replayed to another job or escrow must be refused.
- #438 (AgenticFinanceGraph): put the key id in the signed body and publish when each key starts and stops signing; give "could not check" its own outcome, separate from reject.
- #431, #435 (vijaygopalbalasa, apexfaucet-hub): under settle-on-silence, provider-side failures must become explicit rejects, and silence stays the evaluator's own failure.
- #441 (drmattbarney): for deliverables a program cannot recompute, the evaluator is a rater. Rater severity on a common many-facet Rasch scale, with its standard error, lets clients compare harshness across committees.
- #442, #443: such a scale exists only if ratings are connected. A simulation shows that with disconnected committees, the reported standard error understates the real error.

## Specification

The key words "MUST", "MUST NOT", "SHOULD" and "MAY" are to be interpreted as described in RFC 2119 and RFC 8174. Requirements are numbered `V1`–`V14`, and the conformance suite tests them by number.

### Verdict

```solidity
struct Verdict {
    address escrow;          // the ERC-8183 contract holding the job
    uint256 jobId;
    bytes32 deliverableHash; // the hash the provider submitted (JobSubmitted)
    bytes32 criteriaHash;    // hash of the evaluation criteria / output schema
    uint8   decision;        // 1 COMPLETE, 2 REJECT, 3 COULD_NOT_CHECK
    bytes32 detailHash;      // keccak256 of the full verdict document (RFC 8785 JSON)
    uint64  signedAt;
    uint64  expiresAt;
    bytes32 keyId;
    bytes32 modelId;         // 0 = no measurement
    int32   severityE4;      // rater severity in logits x 1e4
    uint32  severitySeE4;    // its standard error in logits x 1e4
    bytes32 calibrationRun;  // id/hash of the calibration run the measurement comes from
}
```

- **V1.** The EIP-712 type string MUST be exactly:
  `Verdict(address escrow,uint256 jobId,bytes32 deliverableHash,bytes32 criteriaHash,uint8 decision,bytes32 detailHash,uint64 signedAt,uint64 expiresAt,bytes32 keyId,bytes32 modelId,int32 severityE4,uint32 severitySeE4,bytes32 calibrationRun)`
- **V2.** The EIP-712 domain MUST include `chainId` and `verifyingContract` (the evaluator). The evaluator MUST implement EIP-5267 `eip712Domain()` so wallets and verifiers read the domain from chain.

### Interface

```solidity
interface IERC8183VerdictEvaluator {
    event KeySet(bytes32 indexed keyId, address signer, uint64 validFrom, uint64 validUntil);
    event KeyRevoked(bytes32 indexed keyId);
    event VerdictRecorded(uint256 indexed jobId, bytes32 indexed digest, bytes32 indexed keyId, uint8 decision,
        bytes32 deliverableHash, bytes32 criteriaHash);
    event RaterMeasurement(bytes32 indexed digest, bytes32 indexed modelId, int32 severityE4, uint32 severitySeE4,
        bytes32 calibrationRun);

    function escrow() external view returns (address);
    function digestOf(Verdict calldata v) external view returns (bytes32);
    function submitVerdict(Verdict calldata v, uint8 sigV, bytes32 r, bytes32 s) external returns (bytes32 digest);
    function keys(bytes32 keyId) external view returns (address signer, uint64 validFrom, uint64 validUntil, bool compromised);
    function decided(uint256 jobId) external view returns (bytes32 digest);
    function seen(bytes32 digest) external view returns (bool);
}
```

### Acceptance rules for `submitVerdict`

- **V3.** It MUST revert if `v.escrow` is not the evaluator's escrow.
- **V4.** It MUST revert unless the signature recovers the signer of `keys[v.keyId]`. It MUST revert on `s > secp256k1n/2` or `sigV` ∉ {27, 28}.
- **V5.** It MUST revert unless all of the following hold:
  - `validFrom <= v.signedAt < validUntil`
  - the key is not compromised
  - `v.signedAt <= block.timestamp`
  - `block.timestamp <= v.expiresAt`
- **V6.** It MUST revert unless the job's `evaluator` is this contract.
- **V7.** It MUST NOT accept the same digest twice.
- **V8.** On `COMPLETE` it MUST call the escrow's `complete(jobId, digest, ...)`. On `REJECT` it MUST call `reject(jobId, digest, ...)`. At most one of these may happen per job. It MUST revert if the job is not `Submitted`.
- **V9.** `COULD_NOT_CHECK` MUST NOT change escrow state. It MUST still be recorded. A later `COMPLETE` or `REJECT` for the same job remains possible.
- **V10.** It MUST revert on any decision other than 1, 2 or 3.
- **V11.** Every accepted verdict MUST emit `VerdictRecorded` and `RaterMeasurement` with the verdict's fields.
- Anyone MAY relay a signed verdict. The signature, not `msg.sender`, carries the authority.

### Keys

- **V12.** A `keyId` MUST NOT be reassigned to another signer.
- **V13.** Retiring a key (lowering `validUntil`) MUST keep verdicts signed before the new `validUntil` acceptable. Revoking a key (compromise) MUST make every verdict signed by it unacceptable.

### Measurement fields

- **V14.** If `modelId == 0`, the measurement fields carry no meaning and clients MUST ignore them.
- A non-zero `modelId` SHOULD identify a published model and estimator version. `calibrationRun` SHOULD identify a published run whose input verdicts and output are retrievable, so anyone can recompute the severity.
- Severity and its standard error SHOULD be the values estimated when the verdict was signed. The rater's fit statistics and severity history belong in the rater profile, which is off chain.

### Off-chain checks

- The ERC-8183 `getJob` returns no deliverable, so `deliverableHash` is checked against the escrow's `JobSubmitted` event for the same job.
- `detailHash` is keccak256 over the RFC 8785 canonical JSON of the full verdict document: the fields above, the criteria, the checks run and their results. A rejected provider can then point to the exact check it failed.

## Rationale

- **The signature carries the authority, not the caller.** Any relayer can submit a verdict, so an evaluator can sign offline with an air-gapped key.
- **The digest is the 8183 `reason`.** Existing escrows need no change, and every completion or rejection points at a retrievable, signed document.
- **"Could not check" is a separate outcome.** It records that the evaluator looked and could not decide, without paying or refunding. Under refund-on-expiry the job still expires to the client. Under settle-on-silence the evaluator has to turn provider-side failures into an explicit `REJECT` (#431).
- **Measurement is optional and on chain only as a snapshot.** Deterministic jobs (re-execution, fault proofs) do not need it.

## Security Considerations

- **Replay.** The EIP-712 domain binds chain and evaluator contract; the struct binds escrow and job; the digest can be used once. The conformance suite replays a valid verdict to another job, another escrow and another evaluator deployment on the same escrow, and requires each to revert.
- **Key rotation and disputes.** Disputes over old jobs can outlive a key. Retirement keeps them checkable. Revocation is for compromise only.
- **Measurement can mislead.** A many-facet model places raters on one scale only if their ratings are connected, meaning they shared jobs or anchor items. With fixed, disconnected committees the reported standard error keeps shrinking while the real error stalls. In a synthetic simulation with 21 raters, committees of 3 and 1,008 jobs, the reported SE was 0.20 logits against an actual error of 0.41; with rotating committees it was 0.20 against 0.21 (`measurement/README.md`). Committees SHOULD rotate members or rate shared calibration jobs. A published calibration run SHOULD report its number of disconnected rater groups.
- **Collusion and rater drift** are not handled by this document.
- **Deployed evaluator set.** On today's deployments third-party evaluation is rare: 37 of 81,252 jobs on Virtuals' Base contract, per the census in the thread (#430). Measurement data will have to be created on purpose (rotation, anchors) rather than found.

## Reference implementation and conformance

- `src/SignedVerdictEvaluator8183.sol`: reference evaluator, pre-audit.
- `test/VerdictConformance.sol`: abstract conformance suite. An implementation passes by supplying a small adapter: how to deploy it, how to register a key, and how to retire or revoke one.
- Off-chain signing: any wallet that supports EIP-712 `signTypedData` can sign a verdict, using the domain from `eip712Domain()`. A small SDK is planned.
- `measurement/`: many-facet Rasch estimator and the committee design simulation.

## Copyright

Copyright and related rights waived via CC0.
