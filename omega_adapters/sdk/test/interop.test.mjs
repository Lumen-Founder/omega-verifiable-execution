// Cross-checks the SDK against two independent EIP-712 implementations (viem, ethers) on random verdicts,
// plus the rejection paths the contract applies (V3, V4, V5, V10).
import test from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../src/index.mjs';
import { hashTypedData, encodeFunctionData, encodeAbiParameters, parseAbi } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { TypedDataEncoder, Wallet } from 'ethers';

// deterministic PRNG (xorshift64*) so a failure is reproducible
function rng(seed) {
  let x = BigInt(seed) | 1n;
  const M = (1n << 64n) - 1n;
  return () => {
    x ^= x >> 12n; x ^= (x << 25n) & M; x ^= x >> 27n;
    return (x * 0x2545f4914f6cdd1dn) & M;
  };
}
function randHex(r, bytes) {
  let s = '';
  while (s.length < bytes * 2) s += r().toString(16).padStart(16, '0');
  return '0x' + s.slice(0, bytes * 2);
}
function randVerdict(r) {
  const pick = (vals) => vals[Number(r() % BigInt(vals.length))];
  return {
    escrow: randHex(r, 20),
    jobId: pick([0n, 1n, (1n << 256n) - 1n, r() * r() * r()]),
    deliverableHash: randHex(r, 32),
    criteriaHash: randHex(r, 32),
    decision: pick([1, 2, 3]),
    detailHash: randHex(r, 32),
    signedAt: pick([0n, r() >> 1n, (1n << 64n) - 1n]),
    expiresAt: pick([0n, r(), (1n << 64n) - 1n]),
    keyId: randHex(r, 32),
    modelId: pick(['0x' + '00'.repeat(32), randHex(r, 32)]),
    severityE4: pick([-(2 ** 31), 2 ** 31 - 1, 0, -3512, Number(r() % 100000n) - 50000]),
    severitySeE4: pick([0, 2 ** 32 - 1, 1960]),
    calibrationRun: randHex(r, 32),
  };
}
function randDomain(r) {
  const d = { chainId: Number(r() % 100000n) + 1, verifyingContract: randHex(r, 20) };
  if (r() % 2n) d.name = 'Evaluator ' + randHex(r, 3);
  if (r() % 2n) d.version = String(Number(r() % 9n) + 1);
  if (r() % 4n === 0n) d.salt = randHex(r, 32);
  return d;
}
const PK = '0x' + (0xa11cen).toString(16).padStart(64, '0');

test('typehash is keccak of the V1 type string', () => {
  assert.equal(S.VERDICT_TYPEHASH, S.keccakUtf8(S.VERDICT_TYPE));
  assert.equal(S.VERDICT_TYPE, `Verdict(${S.VERDICT_FIELDS.map(([n, t]) => `${t} ${n}`).join(',')})`);
});

test('digest equals viem and ethers on 300 random verdicts and domains', () => {
  const r = rng(8183);
  for (let i = 0; i < 300; i++) {
    const d = randDomain(r), v = randVerdict(r);
    const td = S.typedData(d, v);
    const ours = S.hashVerdict(d, v);
    assert.equal(ours, hashTypedData(td), `viem case ${i}`);
    const { EIP712Domain, ...types } = td.types;
    assert.equal(ours, TypedDataEncoder.hash(td.domain, types, td.message), `ethers case ${i}`);
  }
});

test('signatures are byte-identical to viem and ethers (RFC 6979, low-s) and recover', async () => {
  const r = rng(42);
  const acct = privateKeyToAccount(PK);
  const wallet = new Wallet(PK);
  for (let i = 0; i < 40; i++) {
    const d = randDomain(r), v = randVerdict(r);
    const td = S.typedData(d, v);
    const ours = S.signVerdict(d, v, PK);
    assert.equal(ours.signature, await acct.signTypedData(td), `viem case ${i}`);
    const { EIP712Domain, ...types } = td.types;
    assert.equal(ours.signature, await wallet.signTypedData(td.domain, types, td.message), `ethers case ${i}`);
    assert.equal(S.recoverVerdictSigner(d, v, ours.signature), acct.address);
    assert.ok(BigInt(ours.s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n);
  }
});

test('typedDataJSON round-trips through JSON (eth_signTypedData_v4) to the same digest', () => {
  const r = rng(7);
  const d = randDomain(r), v = { ...randVerdict(r), jobId: (1n << 255n) + 5n };
  const j = JSON.parse(JSON.stringify(S.typedDataJSON(d, v)));
  assert.equal(typeof j.message.jobId, 'string');
  assert.equal(S.hashVerdict(j.domain, j.message), S.hashVerdict(d, v));
});

test('submitVerdict calldata equals viem encodeFunctionData', () => {
  const abi = parseAbi([
    'function submitVerdict((address escrow,uint256 jobId,bytes32 deliverableHash,bytes32 criteriaHash,uint8 decision,bytes32 detailHash,uint64 signedAt,uint64 expiresAt,bytes32 keyId,bytes32 modelId,int32 severityE4,uint32 severitySeE4,bytes32 calibrationRun) v, uint8 sigV, bytes32 r, bytes32 s) returns (bytes32)',
  ]);
  const r = rng(99);
  for (let i = 0; i < 50; i++) {
    const d = randDomain(r), v = randVerdict(r);
    const sig = S.signVerdict(d, v, PK);
    const viemData = encodeFunctionData({ abi, functionName: 'submitVerdict', args: [S.normalizeVerdict(v), sig.v, sig.r, sig.s] });
    assert.equal(S.encodeSubmitVerdict(v, sig.signature), viemData);
  }
});

test('decodeEip712Domain reads an EIP-5267 return value', () => {
  const data = encodeAbiParameters(
    [{ type: 'bytes1' }, { type: 'string' }, { type: 'string' }, { type: 'uint256' }, { type: 'address' }, { type: 'bytes32' }, { type: 'uint256[]' }],
    ['0x0f', 'SignedVerdictEvaluator8183', '1', 11155111n, '0x5FbDB2315678afecb367f032d93F642f64180aa3', '0x' + '00'.repeat(32), []],
  );
  assert.deepEqual(S.decodeEip712Domain(data), {
    name: 'SignedVerdictEvaluator8183', version: '1', chainId: 11155111n, verifyingContract: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
  });
  const onlyChain = encodeAbiParameters(
    [{ type: 'bytes1' }, { type: 'string' }, { type: 'string' }, { type: 'uint256' }, { type: 'address' }, { type: 'bytes32' }, { type: 'uint256[]' }],
    ['0x0c', '', '', 1n, '0x5FbDB2315678afecb367f032d93F642f64180aa3', '0x' + '00'.repeat(32), []],
  );
  assert.deepEqual(Object.keys(S.decodeEip712Domain(onlyChain)), ['chainId', 'verifyingContract']);
});

const D = { name: 'SignedVerdictEvaluator8183', version: '1', chainId: 31337, verifyingContract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' };
const V = {
  escrow: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512', jobId: 1n, deliverableHash: S.keccakUtf8('deliverable bytes'),
  criteriaHash: S.keccakUtf8('schema v1'), decision: 1, detailHash: S.keccakUtf8('rfc8785 verdict json'), signedAt: 4000n,
  expiresAt: 9000n, keyId: S.idOf('rater-1/2026-11'), modelId: S.idOf('mfrm-dichotomous-v0'), severityE4: -3512, severitySeE4: 1960,
  calibrationRun: S.idOf('calibration-run-0'),
};
const KEY = { signer: S.addressOfPrivateKey(PK), validFrom: 1000n, validUntil: 10_000_000_000n, compromised: false };
const rules = (res) => res.failures.map((f) => f.rule).sort();

test('verifyVerdict accepts a good verdict and names each broken rule', () => {
  const sig = S.signVerdict(D, V, PK);
  assert.equal(S.verifyVerdict({ domain: D, verdict: V, signature: sig, key: KEY, now: 5000, escrow: V.escrow }).ok, true);
  // V3 wrong escrow
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: V, signature: sig, escrow: '0x' + '11'.repeat(20) })), ['V3']);
  // V4 high-s twin of a valid signature
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const hi = { r: sig.r, s: '0x' + (N - BigInt(sig.s)).toString(16).padStart(64, '0'), v: sig.v === 27 ? 28 : 27 };
  assert.equal(S.recoverVerdictSigner(D, V, hi), KEY.signer, 'the twin recovers the same signer, which is why it must be refused');
  assert.ok(rules(S.verifyVerdict({ domain: D, verdict: V, signature: hi, key: KEY })).includes('V4'));
  // V4 another signer
  const other = S.signVerdict(D, V, '0x' + (0xb0bn).toString(16).padStart(64, '0'));
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: V, signature: other, key: KEY })), ['V4']);
  // V4 replay to another job: the signature no longer recovers the key's signer
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: { ...V, jobId: 2n }, signature: sig, key: KEY })), ['V4']);
  // V4 replay to another evaluator deployment (domain)
  assert.deepEqual(rules(S.verifyVerdict({ domain: { ...D, verifyingContract: '0x' + '22'.repeat(20) }, verdict: V, signature: sig, key: KEY })), ['V4']);
  // V5 expired, not yet signed, outside key window, revoked
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: V, signature: sig, now: 9001 })), ['V5']);
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: V, signature: sig, now: 3999 })), ['V5']);
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: V, signature: sig, key: { ...KEY, validUntil: 4000n } })), ['V5']);
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: V, signature: sig, key: { ...KEY, compromised: true } })), ['V5']);
  // V13 a retired key cannot backdate: retired at 4500, signedAt 4000 claims the old window, judged at now 5000
  const retired = { ...KEY, validUntil: 4500n };
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: V, signature: sig, key: retired, now: 5000 })), ['V13']);
  assert.equal(S.verifyVerdict({ domain: D, verdict: V, signature: sig, key: retired, now: 4499 }).ok, true);
  assert.ok(S.verifyVerdict({ domain: D, verdict: V, signature: sig, key: retired }).notes.some((n) => n.includes('retirement not checked')));
  // V10 bad decision
  const bad = { ...V, decision: 4 };
  assert.deepEqual(rules(S.verifyVerdict({ domain: D, verdict: bad, signature: S.signVerdict(D, bad, PK), key: KEY })), ['V10']);
});

test('input validation refuses out-of-range and malformed fields', () => {
  assert.throws(() => S.hashVerdict(D, { ...V, severityE4: 2 ** 31 }), RangeError);
  assert.throws(() => S.hashVerdict(D, { ...V, severitySeE4: -1 }), RangeError);
  assert.throws(() => S.hashVerdict(D, { ...V, signedAt: 1n << 64n }), RangeError);
  assert.throws(() => S.hashVerdict(D, { ...V, decision: 256 }), RangeError);
  assert.throws(() => S.hashVerdict(D, { ...V, jobId: 2 ** 60 }), RangeError, 'unsafe JS number');
  assert.throws(() => S.hashVerdict(D, { ...V, keyId: '0x1234' }), TypeError);
  assert.throws(() => S.hashVerdict(D, { ...V, escrow: '0x1234' }), TypeError);
  assert.throws(() => S.hashVerdict(D, { ...V, extra: 1 }), TypeError);
  const { calibrationRun, ...missing } = V;
  assert.throws(() => S.hashVerdict(D, missing), TypeError);
  assert.throws(() => S.hashVerdict({ name: 'x', chainId: 1 }, V), TypeError, 'V2 needs verifyingContract');
});

test('RFC 8785 canonicalization', () => {
  assert.equal(S.canonicalize({ b: 2, a: 1, c: { z: [3, { y: null, x: true }], é: 'é' } }), '{"a":1,"b":2,"c":{"z":[3,{"x":true,"y":null}],"é":"é"}}');
  // numbers in ECMAScript form (RFC 8785 sec. 3.2.2.3)
  assert.equal(S.canonicalize([1e21, 1e-7, 0.000001, -0, 333333333.33333329, 4.5, 2e-3]), '[1e+21,1e-7,0.000001,0,333333333.3333333,4.5,0.002]');
  // sort by UTF-16 code units: "€" (euro) sorts before "😀" (emoji), and "\r" before "1"
  assert.equal(S.canonicalize({ '\u{1F600}': 1, '€': 2, '1': 3, '\r': 4 }), '{"\\r":4,"1":3,"€":2,"😀":1}');
  assert.equal(S.canonicalize(' \u0007"\\'), '" \\u0007\\"\\\\"');
  assert.throws(() => S.canonicalize({ x: 1n }), TypeError);
  assert.throws(() => S.canonicalize(NaN), RangeError);
  assert.equal(S.detailHash({ b: 1, a: 2 }), S.keccakUtf8('{"a":2,"b":1}'));
});
