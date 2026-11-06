// SPDX-License-Identifier: MIT
// Turns ERC-8183 Evaluator Verdicts into a ratings file for many-facet Rasch calibration (../measurement/calibrate.py).
// Two sources:
//  - signed verdict records {domain, verdict, signature} (committee or calibration ratings that never touch the chain);
//    each is verified here: signature, key window, revocation, decision (spec V4, V5, V10);
//  - VerdictRecorded logs of an evaluator contract: already verified on chain by the contract that emitted them.
// One rating = (rater keyId, item, x) with item = escrow:jobId:deliverableHash and x = 1 COMPLETE / 0 REJECT.
// COULD_NOT_CHECK carries no rating; it is counted. A rater who rates the same item twice with different decisions
// is a conflict: both are dropped and reported. Nothing is silently discarded.
import {
  COMPLETE, REJECT, COULD_NOT_CHECK, verifyVerdict, normalizeVerdict, keccakUtf8, checksumAddress, hexToBytes, bytesToHex,
  readEscrow,
} from './index.mjs';

export const RATINGS_FORMAT = 'erc8183-ratings/0.1';
export const VERDICT_RECORDED_TOPIC = keccakUtf8('VerdictRecorded(uint256,bytes32,bytes32,uint8,bytes32,bytes32)');

const itemOf = (escrow, jobId, deliverableHash) => `${checksumAddress(escrow)}:${BigInt(jobId)}:${deliverableHash.toLowerCase()}`;

function lowerKeys(keys) {
  const out = {};
  for (const [k, v] of Object.entries(keys ?? {})) out[k.toLowerCase()] = v;
  return out;
}

/**
 * @param {object} args
 * @param {Array<{domain, verdict, signature}>} [args.records] signed verdicts
 * @param {Record<string, {signer, validFrom, validUntil, compromised}>} [args.keys] keyId -> key record (for records)
 * @param {Array<{jobId, digest, keyId, decision, deliverableHash, escrow, source}>} [args.logs] decoded chain logs
 * @returns {{format, ratings, excluded, counts}}
 */
export function buildRatings({ records = [], keys = {}, logs = [] } = {}) {
  const K = lowerKeys(keys);
  const accepted = [];
  const excluded = [];
  let couldNotCheck = 0;
  records.forEach((rec, i) => {
    let v;
    try {
      v = normalizeVerdict(rec.verdict);
    } catch (e) {
      excluded.push({ source: `record:${i}`, reason: `malformed verdict: ${e.message}` });
      return;
    }
    const key = K[v.keyId];
    if (!key) {
      excluded.push({ source: `record:${i}`, keyId: v.keyId, reason: 'unknown keyId' });
      return;
    }
    const res = verifyVerdict({ domain: rec.domain, verdict: v, signature: rec.signature, key });
    if (!res.ok) {
      excluded.push({ source: `record:${i}`, keyId: v.keyId, digest: res.digest, reason: res.failures.map((f) => `${f.rule} ${f.reason}`).join('; ') });
      return;
    }
    if (v.decision === COULD_NOT_CHECK) {
      couldNotCheck++;
      return;
    }
    accepted.push({ rater: v.keyId, item: itemOf(v.escrow, v.jobId, v.deliverableHash), x: v.decision === COMPLETE ? 1 : 0, digest: res.digest, source: `record:${i}` });
  });
  for (const l of logs) {
    if (Number(l.decision) === COULD_NOT_CHECK) {
      couldNotCheck++;
      continue;
    }
    if (![COMPLETE, REJECT].includes(Number(l.decision))) {
      excluded.push({ source: l.source, reason: `decision ${l.decision}` });
      continue;
    }
    accepted.push({ rater: l.keyId.toLowerCase(), item: itemOf(l.escrow, l.jobId, l.deliverableHash), x: Number(l.decision) === COMPLETE ? 1 : 0, digest: l.digest.toLowerCase(), source: l.source });
  }
  // the same digest from two sources (a record that was also submitted on chain) counts once
  const byDigest = new Map();
  for (const r of accepted) if (!byDigest.has(r.digest)) byDigest.set(r.digest, r);
  // one rating per (rater, item); disagreeing duplicates are conflicts
  const groups = new Map();
  for (const r of byDigest.values()) {
    const k = `${r.rater}|${r.item}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }
  const ratings = [];
  for (const g of groups.values()) {
    const xs = new Set(g.map((r) => r.x));
    if (xs.size > 1) {
      for (const r of g) excluded.push({ source: r.source, keyId: r.rater, digest: r.digest, reason: 'conflict: same rater, same item, different decisions' });
      continue;
    }
    ratings.push({ rater: g[0].rater, item: g[0].item, x: g[0].x, digests: g.map((r) => r.digest).sort() });
  }
  ratings.sort((a, b) => (a.item + a.rater < b.item + b.rater ? -1 : 1));
  return {
    format: RATINGS_FORMAT,
    ratings,
    excluded,
    counts: { records: records.length, logs: logs.length, ratings: ratings.length, excluded: excluded.length, couldNotCheck },
  };
}

function word(data, i) {
  return data.slice(2 + 64 * i, 2 + 64 * (i + 1));
}

/** Reads VerdictRecorded logs from an evaluator through an EIP-1193 provider. */
export async function readVerdictLogs(provider, evaluator, { fromBlock = '0x0', toBlock = 'latest' } = {}) {
  const escrow = await readEscrow(provider, evaluator);
  const logs = await provider.request({
    method: 'eth_getLogs',
    params: [{ address: checksumAddress(evaluator), topics: [VERDICT_RECORDED_TOPIC], fromBlock, toBlock }],
  });
  return logs.map((l) => ({
    jobId: BigInt(l.topics[1]),
    digest: l.topics[2],
    keyId: l.topics[3],
    decision: Number(BigInt('0x' + word(l.data, 0))),
    deliverableHash: '0x' + word(l.data, 1),
    criteriaHash: '0x' + word(l.data, 2),
    escrow,
    source: `log:${l.blockNumber}:${l.logIndex}`,
  }));
}

export { hexToBytes, bytesToHex };
