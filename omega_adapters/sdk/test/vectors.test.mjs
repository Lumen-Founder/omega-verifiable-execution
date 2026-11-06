// The SDK reproduces every value in vectors/verdict_vectors.json and refuses every must-reject case.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as S from '../src/index.mjs';

const doc = JSON.parse(readFileSync(new URL('../vectors/verdict_vectors.json', import.meta.url), 'utf8'));

test('vector file header', () => {
  assert.equal(doc.verdictType, S.VERDICT_TYPE);
  assert.equal(doc.verdictTypehash, S.VERDICT_TYPEHASH);
});

for (const c of doc.vectors) {
  test(`vector ${c.name}`, () => {
    assert.equal(S.domainSeparator(c.domain), c.domainSeparator);
    assert.equal(S.structHash(c.verdict), c.structHash);
    assert.equal(S.hashVerdict(c.domain, c.verdict), c.digest);
    const sig = S.signVerdict(c.domain, c.verdict, c.signingKey);
    assert.equal(sig.signature, c.signature.rsv);
    assert.equal(S.addressOfPrivateKey(c.signingKey), c.signer);
    assert.equal(S.recoverVerdictSigner(c.domain, c.verdict, c.signature), c.signer);
    assert.equal(S.encodeSubmitVerdict(c.verdict, c.signature), c.submitVerdictCalldata);
    const key = { signer: c.signer, validFrom: 0, validUntil: (1n << 64n) - 1n, compromised: false };
    assert.equal(S.verifyVerdict({ domain: c.domain, verdict: c.verdict, signature: c.signature, key }).ok, true);
  });
}

for (const n of doc.mustReject) {
  test(`must reject ${n.name}`, () => {
    const c = doc.vectors.find((x) => x.name === n.of);
    const key = { signer: c.signer, validFrom: 0, validUntil: (1n << 64n) - 1n, compromised: false };
    const res = S.verifyVerdict({ domain: c.domain, verdict: { ...c.verdict, ...(n.verdictOverride ?? {}) }, signature: n.signature, key });
    assert.equal(res.ok, false);
    assert.ok(res.failures.some((f) => f.rule === n.rule), JSON.stringify(res.failures));
  });
}
