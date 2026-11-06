// End to end on a local anvil chain: deploy the reference evaluator and a mock ERC-8183 escrow, then check that
// verdicts the SDK builds and signs are accepted or refused by the contract exactly as the spec says.
// Run from sdk/: `forge build` in the parent first, anvil on PATH. Uses anvil's unlocked dev accounts only.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicClient, createWalletClient, http, decodeFunctionResult, encodeFunctionData } from 'viem';
import { foundry } from 'viem/chains';
import * as S from '../src/index.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const art = (p) => JSON.parse(readFileSync(join(root, 'out', p), 'utf8'));
const EV = art('SignedVerdictEvaluator8183.sol/SignedVerdictEvaluator8183.json');
const MOCK = art('OmegaEvaluator8183.t.sol/MockAgenticCommerce.json');
const PORT = 8547;
const RPC = `http://127.0.0.1:${PORT}`;
const RATER = '0x' + (0xa11cen).toString(16).padStart(64, '0'); // public test key
const OTHER = '0x' + (0xb0bn).toString(16).padStart(64, '0');
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
}

const anvil = spawn('anvil', ['--port', String(PORT), '--silent'], { stdio: 'ignore' });
try {
  const pub = createPublicClient({ chain: foundry, transport: http(RPC) });
  for (let i = 0; ; i++) {
    try { await pub.getChainId(); break; } catch { if (i > 50) throw new Error('anvil did not start'); await new Promise((r) => setTimeout(r, 200)); }
  }
  const provider = { request: ({ method, params }) => pub.request({ method, params }) }; // EIP-1193 for the SDK
  const [ADMIN, CLIENT, PROV, RELAYER] = await pub.request({ method: 'eth_accounts' });
  const wallet = createWalletClient({ chain: foundry, transport: http(RPC) });

  async function deploy(a, args = [], from = ADMIN) {
    const hash = await wallet.deployContract({ abi: a.abi, bytecode: a.bytecode.object, args, account: from });
    return (await pub.waitForTransactionReceipt({ hash })).contractAddress;
  }
  async function send(to, abi, functionName, args, from) {
    const hash = await wallet.writeContract({ address: to, abi, functionName, args, account: from });
    const r = await pub.waitForTransactionReceipt({ hash });
    if (r.status !== 'success') throw new Error('reverted');
    return r;
  }
  async function sendRaw(tx, from) {
    // the SDK's calldata as is, from any relayer; returns 'ok' or 'revert'
    try {
      await pub.request({ method: 'eth_estimateGas', params: [{ from, to: tx.to, data: tx.data }] });
    } catch { return 'revert'; }
    const hash = await pub.request({ method: 'eth_sendTransaction', params: [{ from, to: tx.to, data: tx.data }] });
    const r = await pub.waitForTransactionReceipt({ hash });
    return r.status === 'success' ? 'ok' : 'revert';
  }
  const read = (to, abi, functionName, args = []) => pub.readContract({ address: to, abi, functionName, args });

  const escrow = await deploy(MOCK);
  const evaluator = await deploy(EV, [escrow, ADMIN]);
  const keyId = S.idOf('rater-1/2026-11');
  await send(evaluator, EV.abi, 'setKey', [keyId, S.addressOfPrivateKey(RATER), 0n, (1n << 64n) - 1n], ADMIN);
  const now = BigInt((await pub.getBlock()).timestamp);

  async function newJob() {
    const desc = 'write a 200-word product summary';
    const { request, result } = await pub.simulateContract({ address: escrow, abi: MOCK.abi, functionName: 'createJob', args: [PROV, evaluator, now + 86400n, desc], account: CLIENT });
    await send(escrow, MOCK.abi, 'createJob', request.args, CLIENT);
    await send(escrow, MOCK.abi, 'fund', [result, 1000n], CLIENT);
    await send(escrow, MOCK.abi, 'submit', [result], PROV);
    return result;
  }
  const status = async (id) => (await read(escrow, MOCK.abi, 'getJob', [id])).status;
  const verdict = (jobId, decision, over = {}) => ({
    escrow, jobId, deliverableHash: S.keccakUtf8('deliverable bytes'), criteriaHash: S.keccakUtf8('schema v1'), decision,
    detailHash: S.detailHash({ jobId: String(jobId), decision }), signedAt: now - 10n, expiresAt: now + 3600n, keyId,
    modelId: S.idOf('mfrm-dichotomous-v0'), severityE4: -3512, severitySeE4: 1960, calibrationRun: S.idOf('calibration-run-0'), ...over,
  });

  // V2: domain read from chain
  const domain = await S.readDomain(provider, evaluator);
  check('V2 readDomain (EIP-5267) gives chainId 31337 and this evaluator', domain.chainId === 31337n && domain.verifyingContract === S.checksumAddress(evaluator), JSON.stringify(domain, (_, x) => (typeof x === 'bigint' ? String(x) : x)));
  check('readEscrow', (await S.readEscrow(provider, evaluator)) === S.checksumAddress(escrow));
  const k = await S.readKey(provider, evaluator, keyId);
  check('readKey', k.signer === S.addressOfPrivateKey(RATER) && !k.compromised);

  // COMPLETE: digest agrees with the contract, a relayer submits, escrow completes with digest as reason
  const j1 = await newJob();
  const v1 = verdict(j1, S.COMPLETE);
  const s1 = S.signVerdict(domain, v1, RATER);
  check('digest equals contract digestOf', (await S.readDigest(provider, evaluator, v1)) === s1.digest);
  check('verifyVerdict ok against chain key and time', S.verifyVerdict({ domain, verdict: v1, signature: s1, key: k, now, escrow }).ok);
  check('V8 COMPLETE accepted from a third-party relayer', (await sendRaw(S.submitVerdictTx(evaluator, v1, s1), RELAYER)) === 'ok');
  check('V8 escrow completed with reason = digest', (await status(j1)) === 3 && (await read(escrow, MOCK.abi, 'reasonOf', [j1])) === s1.digest);
  check('V7 same verdict again refused', (await sendRaw(S.submitVerdictTx(evaluator, v1, s1), RELAYER)) === 'revert');

  // COULD_NOT_CHECK leaves the job, a later REJECT decides it
  const j2 = await newJob();
  const v2a = verdict(j2, S.COULD_NOT_CHECK);
  check('V9 COULD_NOT_CHECK accepted', (await sendRaw(S.submitVerdictTx(evaluator, v2a, S.signVerdict(domain, v2a, RATER)), RELAYER)) === 'ok');
  check('V9 job still Submitted', (await status(j2)) === 2);
  const v2b = verdict(j2, S.REJECT);
  const s2b = S.signVerdict(domain, v2b, RATER);
  check('V8 REJECT after COULD_NOT_CHECK accepted', (await sendRaw(S.submitVerdictTx(evaluator, v2b, s2b), RELAYER)) === 'ok');
  check('V8 escrow rejected with reason = digest', (await status(j2)) === 4 && (await read(escrow, MOCK.abi, 'reasonOf', [j2])) === s2b.digest);

  // refusals
  const j3 = await newJob();
  const j4 = await newJob();
  const v3 = verdict(j3, S.COMPLETE);
  const s3 = S.signVerdict(domain, v3, RATER);
  check('V4 verdict for job 3 replayed to job 4 refused', (await sendRaw(S.submitVerdictTx(evaluator, { ...v3, jobId: j4 }, s3), RELAYER)) === 'revert');
  const hi = { r: s3.r, s: '0x' + (N - BigInt(s3.s)).toString(16).padStart(64, '0'), v: s3.v === 27 ? 28 : 27 };
  check('V4 high-s twin refused (SDK verify also refuses)', (await sendRaw(S.submitVerdictTx(evaluator, v3, hi), RELAYER)) === 'revert' && !S.verifyVerdict({ domain, verdict: v3, signature: hi, key: k }).ok);
  const vOther = verdict(j3, S.COMPLETE);
  check('V4 unregistered signer refused', (await sendRaw(S.submitVerdictTx(evaluator, vOther, S.signVerdict(domain, vOther, OTHER)), RELAYER)) === 'revert');
  const vExp = verdict(j3, S.COMPLETE, { signedAt: now - 100n, expiresAt: now - 50n });
  check('V5 expired refused', (await sendRaw(S.submitVerdictTx(evaluator, vExp, S.signVerdict(domain, vExp, RATER)), RELAYER)) === 'revert');
  const vBad = verdict(j3, 4);
  check('V10 decision 4 refused', (await sendRaw(S.submitVerdictTx(evaluator, vBad, S.signVerdict(domain, vBad, RATER)), RELAYER)) === 'revert');
  const otherEval = await deploy(EV, [escrow, ADMIN]);
  await send(otherEval, EV.abi, 'setKey', [keyId, S.addressOfPrivateKey(RATER), 0n, (1n << 64n) - 1n], ADMIN);
  check('V4 verdict signed for this evaluator refused by a second deployment', (await sendRaw(S.submitVerdictTx(otherEval, v3, s3), RELAYER)) === 'revert');
  check('job 3 still Submitted after all refusals', (await status(j3)) === 2);
  check('valid verdict for job 3 then accepted', (await sendRaw(S.submitVerdictTx(evaluator, v3, s3), RELAYER)) === 'ok' && (await status(j3)) === 3);

  // V13 retire keeps old verdicts acceptable, revoke kills them
  const j5 = await newJob();
  const v5 = verdict(j5, S.COMPLETE);
  const s5 = S.signVerdict(domain, v5, RATER);
  await send(evaluator, EV.abi, 'retireKey', [keyId, now], ADMIN);
  const kRet = await S.readKey(provider, evaluator, keyId);
  check('V13 after retire, verdict signed before validUntil still accepted', kRet.validUntil === now && S.verifyVerdict({ domain, verdict: v5, signature: s5, key: kRet, now }).ok && (await sendRaw(S.submitVerdictTx(evaluator, v5, s5), RELAYER)) === 'ok');
  const v4b = verdict(j4, S.COMPLETE);
  const s4b = S.signVerdict(domain, v4b, RATER);
  await send(evaluator, EV.abi, 'revokeKey', [keyId], ADMIN);
  const kRev = await S.readKey(provider, evaluator, keyId);
  check('V13 after revoke, readKey shows compromised and verdict refused', kRev.compromised && !S.verifyVerdict({ domain, verdict: v4b, signature: s4b, key: kRev }).ok && (await sendRaw(S.submitVerdictTx(evaluator, v4b, s4b), RELAYER)) === 'revert');
} finally {
  anvil.kill();
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
