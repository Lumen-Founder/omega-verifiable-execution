// Writes vectors/verdict_vectors.json: fixed inputs and every intermediate value, so an implementation in any
// language can check itself field by field. Each digest and signature is cross-checked against viem, ethers and
// Foundry's cast before it is written; the script refuses to write a vector they disagree on.
// The signing keys are throwaway test keys (0xA11CE, 0xB0B) and must never hold funds.
import { writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as S from '../src/index.mjs';
import { hashTypedData } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { TypedDataEncoder, Wallet } from 'ethers';

const here = dirname(fileURLToPath(import.meta.url));
const pk = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');
const PK1 = pk(0xa11ce);
const PK2 = pk(0xb0b);
const Z = '0x' + '00'.repeat(32);

const ref = { name: 'SignedVerdictEvaluator8183', version: '1', chainId: 11155111, verifyingContract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' };
const base = {
  escrow: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
  jobId: 1,
  deliverableHash: S.keccakUtf8('deliverable bytes'),
  criteriaHash: S.keccakUtf8('schema v1'),
  decision: S.COMPLETE,
  detailHash: S.detailHash({ jobId: '1', decision: 'COMPLETE', checks: [{ id: 'word_count', pass: true, value: 201 }] }),
  signedAt: 1762400000,
  expiresAt: 1762403600,
  keyId: S.idOf('rater-1/2026-11'),
  modelId: S.idOf('mfrm-dichotomous-v0'),
  severityE4: -3512,
  severitySeE4: 1960,
  calibrationRun: S.idOf('calibration-run-0'),
};

const cases = [
  ['complete_with_measurement', ref, base, PK1],
  ['reject', ref, { ...base, decision: S.REJECT, jobId: 2 }, PK1],
  ['could_not_check', ref, { ...base, decision: S.COULD_NOT_CHECK, jobId: 3 }, PK1],
  ['no_measurement', ref, { ...base, modelId: Z, severityE4: 0, severitySeE4: 0, calibrationRun: Z }, PK1],
  ['extremes', ref, { ...base, jobId: ((1n << 256n) - 1n).toString(), signedAt: 0, expiresAt: ((1n << 64n) - 1n).toString(), severityE4: -(2 ** 31), severitySeE4: 2 ** 32 - 1 }, PK2],
  ['positive_severity', ref, { ...base, severityE4: 2 ** 31 - 1 }, PK2],
  ['domain_chain_and_contract_only', { chainId: 8453, verifyingContract: ref.verifyingContract }, base, PK1],
  ['domain_with_salt', { ...ref, chainId: 1, salt: S.idOf('salt') }, base, PK1],
];

function cast(td) {
  const dir = mkdtempSync(join(tmpdir(), 'v8183-'));
  try {
    const f = join(dir, 'td.json');
    writeFileSync(f, JSON.stringify(S.typedDataJSON(td.domain, td.message)));
    return execFileSync('cast', ['wallet', 'sign', '--private-key', td.pk, '--data', '--from-file', f], { encoding: 'utf8' }).trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const out = [];
for (const [name, domain, verdict, key] of cases) {
  const td = S.typedData(domain, verdict);
  const digest = S.hashVerdict(domain, verdict);
  const sig = S.signVerdict(domain, verdict, key);
  const { EIP712Domain, ...types } = td.types;
  const checks = {
    viemDigest: hashTypedData(td) === digest,
    ethersDigest: TypedDataEncoder.hash(td.domain, types, td.message) === digest,
    viemSig: (await privateKeyToAccount(key).signTypedData(td)) === sig.signature,
    ethersSig: (await new Wallet(key).signTypedData(td.domain, types, td.message)) === sig.signature,
    castSig: cast({ domain, message: verdict, pk: key }) === sig.signature,
  };
  const bad = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  if (bad.length) throw new Error(`${name}: implementations disagree on ${bad.join(', ')}`);
  out.push({
    name,
    domain: S.typedDataJSON(domain, verdict).domain,
    verdict: S.typedDataJSON(domain, verdict).message,
    signingKey: key,
    signer: S.addressOfPrivateKey(key),
    domainSeparator: S.domainSeparator(domain),
    structHash: S.structHash(verdict),
    digest,
    signature: { v: sig.v, r: sig.r, s: sig.s, rsv: sig.signature },
    submitVerdictCalldata: S.encodeSubmitVerdict(verdict, sig),
  });
}

// Signatures a conforming evaluator must refuse (V4): the high-s twin of case 0 recovers the same signer.
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const c0 = out[0].signature;
const negative = [
  { name: 'high_s_twin_of_complete_with_measurement', rule: 'V4', of: out[0].name, signature: { v: c0.v === 27 ? 28 : 27, r: c0.r, s: '0x' + (N - BigInt(c0.s)).toString(16).padStart(64, '0') } },
  { name: 'v_not_27_or_28', rule: 'V4', of: out[0].name, signature: { v: 29, r: c0.r, s: c0.s } },
  { name: 'replay_to_job_2', rule: 'V4', of: out[0].name, verdictOverride: { jobId: '2' }, signature: c0 },
];

const doc = {
  spec: 'ERC-8183 Evaluator Verdicts (draft), requirements V1-V15',
  verdictType: S.VERDICT_TYPE,
  verdictTypehash: S.VERDICT_TYPEHASH,
  submitVerdictSelector: S.selector('submitVerdict((address,uint256,bytes32,bytes32,uint8,bytes32,uint64,uint64,bytes32,bytes32,int32,uint32,bytes32),uint8,bytes32,bytes32)'),
  note: 'Signing keys are public test keys. Signatures are RFC 6979 deterministic and low-s; checked equal across this SDK, viem, ethers and Foundry cast.',
  vectors: out,
  mustReject: negative,
};
mkdirSync(join(here, '..', 'vectors'), { recursive: true });
writeFileSync(join(here, '..', 'vectors', 'verdict_vectors.json'), JSON.stringify(doc, null, 2) + '\n');
console.log(`wrote ${out.length} vectors and ${negative.length} must-reject cases; viem, ethers and cast agree on all`);
