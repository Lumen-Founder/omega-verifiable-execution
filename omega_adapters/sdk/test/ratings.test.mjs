import test from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../src/index.mjs';
import { buildRatings, VERDICT_RECORDED_TOPIC } from '../src/ratings.mjs';

const D = { name: 'SignedVerdictEvaluator8183', version: '1', chainId: 31337, verifyingContract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' };
const ESCROW = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512';
const pk = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');
const keyId = (i) => S.idOf(`rater-${i}`);
const keys = Object.fromEntries([1, 2, 3].map((i) => [keyId(i), { signer: S.addressOfPrivateKey(pk(0x1000 + i)), validFrom: 0, validUntil: 10_000_000_000, compromised: false }]));
const verdict = (i, job, decision, over = {}) => ({
  escrow: ESCROW, jobId: job, deliverableHash: S.keccakUtf8(`deliverable-${job}`), criteriaHash: S.keccakUtf8('rubric v1'), decision,
  detailHash: S.keccakUtf8(`detail-${i}-${job}`), signedAt: 4000, expiresAt: 9000, keyId: keyId(i), modelId: '0x' + '00'.repeat(32),
  severityE4: 0, severitySeE4: 0, calibrationRun: '0x' + '00'.repeat(32), ...over,
});
const rec = (i, job, decision, over) => {
  const v = verdict(i, job, decision, over);
  return { domain: D, verdict: v, signature: S.signVerdict(D, v, pk(0x1000 + i)).signature };
};

test('event topic is the interface event', () => {
  assert.equal(VERDICT_RECORDED_TOPIC, S.keccakUtf8('VerdictRecorded(uint256,bytes32,bytes32,uint8,bytes32,bytes32)'));
});

test('verified records become ratings; every exclusion is reported with its reason', () => {
  const good = [rec(1, 1, 1), rec(2, 1, 2), rec(3, 1, 1), rec(1, 2, 2)];
  const tampered = rec(2, 2, 1);
  tampered.verdict = { ...tampered.verdict, decision: 2 }; // signature no longer matches
  const unknown = { domain: D, verdict: verdict(9, 3, 1), signature: S.signVerdict(D, verdict(9, 3, 1), pk(0x1009)).signature };
  const revokedKeys = { ...keys, [keyId(3)]: { ...keys[keyId(3)], compromised: true } };
  const cnc = rec(1, 4, 3);
  const conflictA = rec(2, 5, 1);
  const conflictB = rec(2, 5, 2, { detailHash: S.keccakUtf8('second look') });
  const out = buildRatings({ records: [...good, tampered, unknown, cnc, conflictA, conflictB], keys });
  assert.equal(out.format, 'erc8183-ratings/0.1');
  assert.equal(out.ratings.length, 4);
  assert.equal(out.counts.couldNotCheck, 1);
  const reasons = out.excluded.map((e) => e.reason);
  assert.ok(reasons.some((r) => r.startsWith('V4')), 'tampered refused by signature');
  assert.ok(reasons.includes('unknown keyId'));
  assert.equal(reasons.filter((r) => r.startsWith('conflict')).length, 2);
  const r = out.ratings.find((x) => x.rater === keyId(2).toLowerCase());
  assert.equal(r.x, 0, 'REJECT is 0');
  // revoked key: all of its records excluded with V5
  const out2 = buildRatings({ records: good, keys: revokedKeys });
  assert.equal(out2.ratings.length, 3);
  assert.ok(out2.excluded.every((e) => e.reason.includes('V5')));
});

test('a retired key cannot backdate records: the key window is judged at the anchor time, else at asOf', () => {
  const retiredKeys = { ...keys, [keyId(1)]: { ...keys[keyId(1)], validUntil: 4500 } }; // retired at 4500
  const r = rec(1, 8, 1); // claims signedAt 4000, inside the old window
  const unanchored = buildRatings({ records: [r], keys: retiredKeys, asOf: 5000 });
  assert.equal(unanchored.ratings.length, 0);
  assert.equal(unanchored.asOf, '5000');
  assert.ok(unanchored.excluded[0].reason.startsWith('V13 key not valid (not anchored'));
  const lateAnchor = buildRatings({ records: [{ ...r, anchoredAt: 4600 }], keys: retiredKeys, asOf: 5000 });
  assert.equal(lateAnchor.ratings.length, 0, 'hash first on chain after retirement');
  const earlyAnchor = buildRatings({ records: [{ ...r, anchoredAt: 4400 }], keys: retiredKeys, asOf: 5000 });
  assert.equal(earlyAnchor.ratings.length, 1, 'hash on chain before retirement: stays valid');
});

test('the same verdict from a record and from a chain log counts once; agreeing duplicates merge', () => {
  const a = rec(1, 7, 1);
  const digest = S.hashVerdict(D, a.verdict);
  const log = { jobId: 7n, digest, keyId: keyId(1), decision: 1, deliverableHash: a.verdict.deliverableHash, escrow: ESCROW, source: 'log:1:0' };
  const again = rec(1, 7, 1, { detailHash: S.keccakUtf8('re-signed') });
  const out = buildRatings({ records: [a, again], keys, logs: [log] });
  assert.equal(out.ratings.length, 1);
  assert.equal(out.ratings[0].digests.length, 2);
});
