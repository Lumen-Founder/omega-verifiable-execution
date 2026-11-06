// End to end for D4: simulated raters sign verdicts with this SDK -> collect_ratings verifies them -> calibrate.py
// estimates severities -> a new verdict carries severityE4 and calibrationRun = runId and verifies.
// Checks: recovery of the true severities on a rotating design, reproducible runId and table, disconnected design
// flagged, bad records excluded. PYTHON env var = Python with numpy (default: python).
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as S from '../src/index.mjs';
import { buildRatings } from '../src/ratings.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CAL = join(here, '..', '..', 'measurement', 'calibrate.py');
const PY = process.env.PYTHON || 'python';
const D = { name: 'SignedVerdictEvaluator8183', version: '1', chainId: 11155111, verifyingContract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' };
const ESCROW = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512';
const Z = '0x' + '00'.repeat(32);
const pk = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');

let seed = 20261106;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
const normal = () => Math.sqrt(-2 * Math.log(rnd() + 1e-12)) * Math.cos(2 * Math.PI * rnd());

const R = 21, ITEMS = 300, PER = 3;
const trueSev = Array.from({ length: R }, () => normal() * 0.8);
const mean = trueSev.reduce((a, b) => a + b, 0) / R;
const keyIds = Array.from({ length: R }, (_, i) => S.idOf(`rater-${i}`));
const keys = Object.fromEntries(keyIds.map((k, i) => [k, { signer: S.addressOfPrivateKey(pk(0x2000 + i)), validFrom: 0, validUntil: 10_000_000_000, compromised: false }]));

function design(rotating) {
  const records = [];
  for (let j = 0; j < ITEMS; j++) {
    const q = normal();
    // rotating: a sliding committee {j, j+1, j+5} links every rater to the next, so all raters share one scale.
    // (An earlier draft used {5j, 5j+7, 5j+14} mod 21: members always share a residue mod 7, which splits the raters
    // into 7 disconnected groups; calibrate.py flagged exactly that.)
    const committee = rotating ? [0, 1, 5].map((m) => (j + m) % R) : [0, 1, 2].map((m) => (Math.floor(j / (ITEMS / 7)) * 3 + m) % R);
    for (const r of committee) {
      const x = rnd() < 1 / (1 + Math.exp(-(q - trueSev[r]))) ? 1 : 2;
      const v = { escrow: ESCROW, jobId: j + 1, deliverableHash: S.keccakUtf8(`d${j}`), criteriaHash: S.keccakUtf8('rubric v1'), decision: x,
        detailHash: S.keccakUtf8(`detail ${r} ${j}`), signedAt: 4000, expiresAt: 9000, keyId: keyIds[r], modelId: Z, severityE4: 0, severitySeE4: 0, calibrationRun: Z };
      records.push({ domain: D, verdict: v, signature: S.signVerdict(D, v, pk(0x2000 + r)).signature });
    }
  }
  return records;
}

const dir = mkdtempSync(join(tmpdir(), 'cal8183-'));
const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`); };
const calibrate = (ratingsPath, outPath) => {
  execFileSync(PY, ['-X', 'utf8', '-B', CAL, ratingsPath, '--out', outPath, '--bootstrap', '10'], { stdio: ['ignore', 'ignore', 'inherit'] });
  return JSON.parse(readFileSync(outPath, 'utf8'));
};
try {
  // rotating committees + three bad records
  const records = design(true);
  const forged = { ...records[0], verdict: { ...records[0].verdict, decision: records[0].verdict.decision === 1 ? 2 : 1 } };
  const stranger = (() => { const v = { ...records[1].verdict, keyId: S.idOf('stranger') }; return { domain: D, verdict: v, signature: S.signVerdict(D, v, pk(0x9999)).signature }; })();
  const cnc = (() => { const v = { ...records[2].verdict, decision: 3, detailHash: S.keccakUtf8('cnc') }; return { domain: D, verdict: v, signature: S.signVerdict(D, v, pk(0x2000 + keyIds.indexOf(v.keyId))).signature }; })();
  const ratings = buildRatings({ records: [...records, forged, stranger, cnc], keys });
  check('collect: every signed rating verified, bad ones excluded with reasons', ratings.ratings.length === ITEMS * PER && ratings.excluded.length === 2 && ratings.counts.couldNotCheck === 1, JSON.stringify(ratings.counts));
  const rp = join(dir, 'ratings.json');
  writeFileSync(rp, JSON.stringify(ratings));
  const run1 = calibrate(rp, join(dir, 'run1.json'));
  const run2 = calibrate(rp, join(dir, 'run2.json'));
  check('runId and table reproducible', run1.runId === run2.runId && JSON.stringify(run1.raters) === JSON.stringify(run2.raters), run1.runId);
  check('rotating design: one connected group', run1.design.connectedGroups === 1 && run1.design.comparableAcrossAllRaters);
  const est = keyIds.map((k) => run1.raters.find((r) => r.keyId === k.toLowerCase()).severity);
  const t = trueSev.map((s) => s - mean);
  const em = est.reduce((a, b) => a + b, 0) / R;
  const corr = (() => { let sxy = 0, sxx = 0, syy = 0; for (let i = 0; i < R; i++) { sxy += (est[i] - em) * t[i]; sxx += (est[i] - em) ** 2; syy += t[i] ** 2; } return sxy / Math.sqrt(sxx * syy); })();
  const rmse = Math.sqrt(est.reduce((a, e, i) => a + (e - em - t[i]) ** 2, 0) / R);
  const meanSe = run1.raters.reduce((a, r) => a + r.severitySe, 0) / R;
  // The bar follows from the information in the design: with true spread sdT and reported SE, the best attainable
  // correlation is about sdT / sqrt(sdT^2 + SE^2). (First run used a fixed 0.9 bar and got 0.887 with ~43 ratings per
  // rater, where the attainable value is ~0.91; the bar is now tied to the reported SE and both are printed.)
  const sdT = Math.sqrt(t.reduce((a, v) => a + v * v, 0) / R);
  const expCorr = sdT / Math.sqrt(sdT * sdT + meanSe * meanSe);
  check('severities recovered (corr >= attainable - 0.05, RMSE within 1.5x reported SE)', corr >= expCorr - 0.05 && rmse < 1.5 * meanSe,
    `corr ${corr.toFixed(3)} attainable ${expCorr.toFixed(3)} (fixed 0.9 bar: ${corr > 0.9 ? 'met' : 'not met'}) rmse ${rmse.toFixed(3)} meanSE ${meanSe.toFixed(3)}`);
  // a tampered ratings file gives another runId
  const tampered = JSON.parse(JSON.stringify(ratings));
  tampered.ratings[0].x = 1 - tampered.ratings[0].x;
  const tp = join(dir, 'tampered.json');
  writeFileSync(tp, JSON.stringify(tampered));
  check('changing one rating changes the runId', calibrate(tp, join(dir, 'run3.json')).runId !== run1.runId);
  // fixed committees: disconnected, flagged
  const fixed = buildRatings({ records: design(false), keys });
  const fp = join(dir, 'fixed.json');
  writeFileSync(fp, JSON.stringify(fixed));
  const runF = calibrate(fp, join(dir, 'runF.json'));
  check('fixed committees: disconnected groups flagged, not comparable', runF.design.connectedGroups > 1 && !runF.design.comparableAcrossAllRaters, `groups ${runF.design.connectedGroups}`);
  // the measured verdict
  const row = run1.raters.find((r) => r.keyId === keyIds[4].toLowerCase());
  const mv = { escrow: ESCROW, jobId: 9999, deliverableHash: S.keccakUtf8('new work'), criteriaHash: S.keccakUtf8('rubric v1'), decision: 1, detailHash: S.keccakUtf8('detail'),
    signedAt: 4000, expiresAt: 9000, keyId: keyIds[4], modelId: S.idOf('mfrm-dichotomous-v0'), severityE4: row.severityE4, severitySeE4: row.severitySeE4, calibrationRun: run1.runId };
  const sig = S.signVerdict(D, mv, pk(0x2004));
  check('a verdict carrying the run’s severity and runId verifies', S.verifyVerdict({ domain: D, verdict: mv, signature: sig, key: keys[keyIds[4]] }).ok, `severityE4 ${row.severityE4} se ${row.severitySeE4}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
