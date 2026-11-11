# erc8183-verdicts

Build, sign and verify **ERC-8183 Evaluator Verdicts** ([draft spec](../spec/ERC8183_EVALUATOR_VERDICTS.md), requirements V1–V15) from JavaScript.

- Works with any wallet. `typedData()` returns the standard EIP-712 object. viem, ethers, MetaMask (`eth_signTypedData_v4`) and hardware wallets sign it unchanged.
- Small dependency tree: the audited `@noble/curves` and `@noble/hashes`, nothing else.
- Agrees with four other implementations. The SDK's digests and signatures were checked byte for byte against viem, ethers, Foundry `cast` and the reference evaluator contract.

Status: 0.1.0, pre-audit. It has not been published to npm. Install it from this repository.

## Use

```js
import * as V from './src/index.mjs';

// 1. Read the signing domain from the evaluator itself (EIP-5267, spec V2). Do not hard-code it.
const domain = await V.readDomain(window.ethereum, evaluator);

// 2. Describe the verdict. The detail document is hashed with RFC 8785 canonical JSON.
const verdict = {
  escrow, jobId,
  deliverableHash,                        // the hash from the escrow's JobSubmitted event
  criteriaHash: V.keccakUtf8(criteriaText),
  decision: V.COMPLETE,                   // or V.REJECT, V.COULD_NOT_CHECK
  detailHash: V.detailHash({ jobId: String(jobId), checks: [{ id: 'word_count', pass: true, value: 201 }] }),
  signedAt: now, expiresAt: now + 3600,
  keyId: V.idOf('rater-1/2026-11'),
  modelId: '0x' + '00'.repeat(32),        // 0 = no measurement (V14)
  severityE4: 0, severitySeE4: 0, calibrationRun: '0x' + '00'.repeat(32),
};

// 3a. Sign in a browser wallet ...
const sig = await window.ethereum.request({
  method: 'eth_signTypedData_v4',
  params: [rater, JSON.stringify(V.typedDataJSON(domain, verdict))],
});
// 3b. ... or with viem / ethers
//     await account.signTypedData(V.typedData(domain, verdict))
// 3c. ... or with a raw key on a server or air-gapped machine (deterministic, low-s)
//     const sig = V.signVerdict(domain, verdict, privateKey)

// 4. Check it the way the contract will, before paying gas.
const key = await V.readKey(window.ethereum, evaluator, verdict.keyId);
const res = V.verifyVerdict({ domain, verdict, signature: sig, key, now, escrow });
// res.ok, res.failures = [{ rule: 'V5', reason: 'expired at ...' }, ...]

// 5. Anyone may relay it. The signature carries the authority, not the sender.
const tx = V.submitVerdictTx(evaluator, verdict, sig); // { to, data }
```

## API

| Function | What it does |
|---|---|
| `typedData(domain, verdict)` / `typedDataJSON(...)` | The EIP-712 object. The JSON form writes integers as strings, for `eth_signTypedData_v4` |
| `hashVerdict`, `domainSeparator`, `structHash` | The digest. It is also the ERC-8183 `reason` |
| `signVerdict(domain, verdict, privateKey)` | Raw-key signing. RFC 6979, low-s |
| `recoverVerdictSigner`, `verifyVerdict` | Off-chain check of V3, V4, V5 and V10, with the rule number of each failure |
| `encodeSubmitVerdict`, `submitVerdictTx` | Calldata for `submitVerdict` |
| `readDomain`, `readKey`, `readEscrow`, `readDigest` | Chain reads through any EIP-1193 provider. `readDigest` asks the contract for its own digest |
| `canonicalize`, `detailHash` | RFC 8785 JSON canonicalization, and keccak256 of the result |
| `idOf(label)` | Convention: keccak256 of a readable label, for `keyId` and `modelId` |

`verifyVerdict` cannot check V6–V9, because they depend on escrow and job state. The contract enforces them.

## Calibration ratings (D4)

`src/ratings.mjs` (`import { buildRatings, readVerdictLogs } from 'erc8183-verdicts/ratings'`) turns verdicts into the ratings file that `../measurement/calibrate.py` estimates rater severity from.
- Signed records are verified before they count. A forged signature, an unknown key, a revoked key or a conflicting duplicate is excluded, and each exclusion is listed with its reason.
- Chain logs (`VerdictRecorded`) are taken as already verified by the contract that emitted them.

CLI: `npm run collect -- --records verdicts.jsonl --keys keys.json --out ratings.json`, or `--rpc URL --evaluator 0x...`.

`npm run e2e:calibration` (with `PYTHON` set to a Python that has numpy) runs the whole loop: 21 simulated raters sign 900 verdicts, the file is collected and calibrated, the `runId` is checked to be reproducible, a fixed-committee design is flagged as disconnected, and a new verdict carrying the run's severity and `runId` verifies.

## Escrow forms

- `SignedVerdictEvaluator8183` calls the three-argument `complete/reject(jobId, reason, optParams)`. This is the ERC's reference text and erc-8183/base-contracts.
- `SignedVerdictEvaluator8183TwoArg` calls `(jobId, reason)`.
- Neither reads `getJob`. A mismatched pairing reverts, so nothing is recorded.

## Test vectors

[`vectors/verdict_vectors.json`](vectors/verdict_vectors.json) holds 8 verdicts. Each comes with its domain separator, struct hash, digest, signature and calldata, and the file adds 3 signatures that must be refused (V4). An implementation in another language can check itself field by field. The signing keys are public test keys (`0xA11CE`, `0xB0B`) and must never hold funds. `npm run vectors` regenerates the file, and it refuses to write any vector on which the SDK, viem, ethers and `cast` disagree.

## Tests

```bash
npm install
npm test          # 34 tests: 300 random verdicts vs viem and ethers, signatures, calldata, EIP-5267 decoding, RFC 8785, vectors, ratings collection
npm run e2e       # needs anvil and `forge build` in ../ : 25 checks against the deployed reference evaluator, incl. reading its logs as ratings
```

The end-to-end run deploys the reference evaluator and a mock ERC-8183 escrow on a local anvil chain, then checks:
- A relayer's COMPLETE goes through, and the escrow records the digest as its `reason`.
- The same verdict sent again is refused (V7).
- COULD_NOT_CHECK leaves the job open, and a later REJECT then decides it (V9).
- These verdicts are refused: one replayed to another job, a high-s twin signature, one from an unregistered signer, an expired one, decision 4, and one replayed to a second deployment of the evaluator.
- A verdict recorded before a key is retired stays recorded. After the retirement the key settles nothing new, including a verdict dated inside its old window. After a key is revoked, its verdicts are refused (V13).

### Key windows are judged by the chain's clock (V5, V13)

`signedAt` is written by the signer, so it cannot prove when a verdict was signed. A retired key could otherwise date a new verdict inside its old window. `verifyVerdict` therefore judges the key window at `now`:
- for a verdict you are about to submit, pass the expected submission time;
- for a verdict already on chain, pass the timestamp of the block that recorded its hash (`VerdictRecorded`, or the escrow's `reason`).

`buildRatings` does the same for off-chain records: give a record `anchoredAt` (the block time of a hash on chain that contains it), or it is judged at `asOf` (default: now), and an unanchored record of a retired key is excluded. Thanks to Douglas Borthwick for the report.

## License

MIT. The spec is CC0.

## Commitment terms of the XD escrow (`erc8183-verdicts/terms`)

For the escrow extension in `../src/escrow-xd/` (pre-audit). Domain `ERC8183CommitmentTerms`, version `2`.

```js
import * as T from './src/terms.mjs';

// The 22 CommitmentTermsV2 fields, as the escrow's commitmentTermsOf(jobId) returns them.
const h = T.termsHash(chainId, escrow, terms);          // the provider passes it to confirmTerms, the client to fundWithTermsHash
const d = T.amendmentDigest(chainId, escrow, amendment); // what each party signs for amendHook
const td = T.amendmentTypedData(chainId, escrow, amendment); // for wallets (viem / ethers signTypedData)
T.shares(budget, evaluatorFeeBP, platformFeeBP);        // M1: what each payout right of a completed job is worth
```

`vectors/terms_vectors.json` holds 40 digests that this module, viem, ethers and the Solidity library agree on
(`npm test`, and `forge test --match-path test/escrow-xd/TermsVectors.t.sol` from `omega_adapters/`).
Regenerate with `node scripts/make_terms_vectors.mjs`.

### Check what you sign: `omega-terms`

Before a provider calls `confirmTerms`, or a client calls `fundWithTermsHash`, read the job from the escrow and
recompute the hash yourself:

```
node bin/omega-terms.mjs read --rpc <url> --escrow <escrow address> --job <id>
```

It prints the 22 decoded fields, the escrow's hash, the locally recomputed hash and `match`. The exit code is 1 when
they differ. `hash` and `amendment-digest` work offline on JSON files. In code: `T.readCommitmentTerms(provider,
escrow, jobId)` with any EIP-1193 provider.

`npm run e2e:xd` (anvil on PATH, `forge build` in the parent first) deploys the XD escrow with its four libraries on a
local chain and checks the SDK and this CLI against it: the confirmed and funded hash, an `amendHook` signed with SDK
signatures, and a DEFERRED claim (14 checks).
