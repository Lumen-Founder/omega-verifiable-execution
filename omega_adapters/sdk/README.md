# erc8183-verdicts

Build, sign and verify **ERC-8183 Evaluator Verdicts** ([draft spec](../spec/ERC8183_EVALUATOR_VERDICTS.md), requirements V1–V14) from JavaScript.

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

## Test vectors

[`vectors/verdict_vectors.json`](vectors/verdict_vectors.json) holds 8 verdicts. Each comes with its domain separator, struct hash, digest, signature and calldata, and the file adds 3 signatures that must be refused (V4). An implementation in another language can check itself field by field. The signing keys are public test keys (`0xA11CE`, `0xB0B`) and must never hold funds. `npm run vectors` regenerates the file, and it refuses to write any vector on which the SDK, viem, ethers and `cast` disagree.

## Tests

```bash
npm install
npm test          # 21 tests: 300 random verdicts vs viem and ethers, signatures, calldata, EIP-5267 decoding, RFC 8785, vectors
npm run e2e       # needs anvil and `forge build` in ../ : 22 checks against the deployed reference evaluator
```

The end-to-end run deploys the reference evaluator and a mock ERC-8183 escrow on a local anvil chain, then checks:
- A relayer's COMPLETE goes through, and the escrow records the digest as its `reason`.
- The same verdict sent again is refused (V7).
- COULD_NOT_CHECK leaves the job open, and a later REJECT then decides it (V9).
- These verdicts are refused: one replayed to another job, a high-s twin signature, one from an unregistered signer, an expired one, decision 4, and one replayed to a second deployment of the evaluator.
- After a key is retired, verdicts signed before the retirement are still accepted. After a key is revoked, its verdicts are refused (V13).

## License

MIT. The spec is CC0.
