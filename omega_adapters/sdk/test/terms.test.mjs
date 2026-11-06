// XD commitment terms and hook amendments: SDK vs viem vs ethers on random inputs, the stored vectors, signatures
// and the M1 share arithmetic. The Solidity side runs in ../test/escrow-xd/TermsVectors.t.sol.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hashTypedData, recoverTypedDataAddress, toFunctionSelector } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { TypedDataEncoder } from 'ethers';
import * as T from '../src/terms.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/terms_vectors.json', import.meta.url), 'utf8'));

test('type strings equal the ones CommitmentTermsLib hashes', () => {
  const sol = readFileSync(new URL('../../src/escrow-xd/CommitmentTermsLib.sol', import.meta.url), 'utf8');
  const literal = (name) => {
    const m = new RegExp(`${name} = keccak256\\(([\\s\\S]*?)\\);`).exec(sol);
    return [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]).join('');
  };
  assert.equal(literal('TERMS_TYPEHASH'), T.TERMS_TYPE);
  assert.equal(literal('AMENDMENT_TYPEHASH'), T.AMENDMENT_TYPE);
  assert.equal(vectors.termsType, T.TERMS_TYPE);
});

test('stored vectors reproduce', () => {
  for (const v of vectors.terms) assert.equal(T.termsHash(v.chainId, v.escrow, v.terms), v.digest, v.name);
  for (const v of vectors.amendments) assert.equal(T.amendmentDigest(v.chainId, v.escrow, v.amendment), v.digest, v.name);
});

test('viem and ethers agree with the SDK on the stored vectors', () => {
  const check = (td, want, name) => {
    const types = { [td.primaryType]: td.types[td.primaryType] };
    assert.equal(hashTypedData({ domain: td.domain, types, primaryType: td.primaryType, message: td.message }), want, name);
    assert.equal(TypedDataEncoder.hash(td.domain, types, td.message), want, name);
  };
  for (const v of vectors.terms) check(T.termsTypedData(v.chainId, v.escrow, v.terms), v.digest, v.name);
  for (const v of vectors.amendments) check(T.amendmentTypedData(v.chainId, v.escrow, v.amendment), v.digest, v.name);
});

test('every field changes the terms hash', () => {
  const base = vectors.terms[0];
  const h0 = T.termsHash(base.chainId, base.escrow, base.terms);
  for (const [n, ty] of T.TERMS_FIELDS) {
    const t = { ...base.terms };
    if (ty === 'address') t[n] = '0x' + 'ab'.repeat(20);
    else if (ty === 'bytes32') t[n] = '0x' + 'cd'.repeat(32);
    else t[n] = (BigInt(t[n]) + 1n).toString();
    assert.notEqual(T.termsHash(base.chainId, base.escrow, t), h0, n);
  }
  assert.notEqual(T.termsHash(base.chainId + 1, base.escrow, base.terms), h0, 'chainId');
  assert.notEqual(T.termsHash(base.chainId, '0x' + '11'.repeat(20), base.terms), h0, 'escrow');
});

test('input checks', () => {
  const t = { ...vectors.terms[0].terms };
  assert.throws(() => T.termsHash(1, vectors.terms[0].escrow, { ...t, evaluatorFeeBP: 65536 }), RangeError);
  assert.throws(() => T.termsHash(1, vectors.terms[0].escrow, { ...t, extra: 1 }), /unknown fields/);
  const { budget, ...missing } = t;
  assert.throws(() => T.termsHash(1, vectors.terms[0].escrow, missing), /budget is missing/);
  assert.throws(() => T.termsHash(1, vectors.terms[0].escrow, { ...t, client: '0x1234' }), /not an address/);
});

test('raw-key amendment signatures match viem and recover to the signer', async () => {
  const pk = '0x' + '0c'.repeat(32);
  const account = privateKeyToAccount(pk);
  for (const v of vectors.amendments.slice(0, 4)) {
    const s = T.signAmendment(v.chainId, v.escrow, v.amendment, pk);
    const td = T.amendmentTypedData(v.chainId, v.escrow, v.amendment);
    const types = { HookAmendment: td.types.HookAmendment };
    const viemSig = await account.signTypedData({ domain: td.domain, types, primaryType: 'HookAmendment', message: td.message });
    assert.equal(s.signature, viemSig, v.name);
    const who = await recoverTypedDataAddress({ domain: td.domain, types, primaryType: 'HookAmendment', message: td.message, signature: s.signature });
    assert.equal(who, account.address);
  }
});

test('M1 shares: the M-1 vector and exact sums', () => {
  assert.deepEqual(T.shares(1000007, 333, 77), { provider: 959007n, evaluator: 33300n, platform: 7700n });
  for (const [b, e, p] of [[0, 1, 1], [1, 9999, 1], [10n ** 30n + 7n, 123, 4567], [9999, 5000, 5000]]) {
    const s = T.shares(b, e, p);
    assert.equal(s.provider + s.evaluator + s.platform, BigInt(b));
  }
});

test('decodeCommitmentTerms round-trips the 23-word return data', () => {
  const v = vectors.terms[0];
  const t = T.normalizeTerms(v.terms);
  const word = (ty, x) =>
    ty === 'address' ? x.slice(2).toLowerCase().padStart(64, '0') : ty === 'bytes32' ? x.slice(2) : BigInt(x).toString(16).padStart(64, '0');
  const hex = '0x' + T.TERMS_FIELDS.map(([n, ty]) => word(ty, t[n])).join('') + v.digest.slice(2);
  const d = T.decodeCommitmentTerms(hex);
  assert.equal(d.escrowHash, v.digest);
  assert.equal(T.termsHash(v.chainId, v.escrow, d.terms), v.digest);
  assert.throws(() => T.decodeCommitmentTerms(hex.slice(0, -64)), /23 words/);
  assert.equal(T.COMMITMENT_TERMS_OF, toFunctionSelector('commitmentTermsOf(uint256)'));
});

test('omega-terms hash prints the vector digest', async () => {
  const { execFileSync } = await import('node:child_process');
  const { writeFileSync, mkdtempSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const v = vectors.terms[0];
  const dir = mkdtempSync(join(tmpdir(), 'omega-terms-'));
  const f = join(dir, 'terms.json');
  writeFileSync(f, JSON.stringify(v.terms));
  const bin = new URL('../bin/omega-terms.mjs', import.meta.url);
  const out = JSON.parse(execFileSync(process.execPath, [bin.pathname.replace(/^\/([A-Za-z]:)/, '$1'), 'hash', '--chain-id', String(v.chainId), '--escrow', v.escrow, f], { encoding: 'utf8' }));
  assert.equal(out.termsHash, v.digest);
});
