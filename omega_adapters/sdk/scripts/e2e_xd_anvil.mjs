// End to end on a local anvil chain for the XD escrow extension (pre-audit): deploy the four libraries, the escrow
// behind an ERC-1967 proxy and a test token, then check that the SDK and the `omega-terms` CLI agree with the escrow:
// the terms hash a provider confirms, the hash a client funds with, and an amendHook signed with SDK signatures.
// Run from sdk/: `forge build` in the parent first, anvil on PATH. Keys are public test keys (0xC1, 0xB2, 0xE3, 0xAD).
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicClient, createWalletClient, http, encodeFunctionData, keccak256 as vKeccak } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import * as T from '../src/terms.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const art = (p) => JSON.parse(readFileSync(join(root, 'out', p), 'utf8'));
const A = {
  XDLogic: art('XDLogic.sol/XDLogic.json'),
  XDPayout: art('XDPayout.sol/XDPayout.json'),
  XDHooks: art('XDHooks.sol/XDHooks.json'),
  XDFlow: art('XDFlow.sol/XDFlow.json'),
  OmegaEscrowXD: art('OmegaEscrowXD.sol/OmegaEscrowXD.json'),
  ERC1967Proxy: art('ERC1967Proxy.sol/ERC1967Proxy.json'),
  TestERC20: art('TestERC20.sol/TestERC20.json'),
  PhaseHook: art('XDStage3Hooks.sol/PhaseHook.json'),
};
const PORT = 8549;
const RPC = `http://127.0.0.1:${PORT}`;
const key = (n) => '0x' + n.toString(16).padStart(64, '0');
const K = { admin: key(0xadn), client: key(0xc1n), prov: key(0xb2n), eval: key(0xe3n) };
const acct = Object.fromEntries(Object.entries(K).map(([k, v]) => [k, privateKeyToAccount(v)]));
const TREASURY = '0x0000000000000000000000000000000000007EA5';

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
}

/** Replaces each library placeholder with the deployed address (forge linkReferences). */
function link(a, deployed) {
  let code = a.bytecode.object.slice(2);
  for (const libs of Object.values(a.bytecode.linkReferences || {})) {
    for (const [name, refs] of Object.entries(libs)) {
      const addr = deployed[name];
      if (!addr) return null;
      for (const { start, length } of refs) {
        code = code.slice(0, start * 2) + addr.slice(2).toLowerCase() + code.slice((start + length) * 2);
      }
    }
  }
  return '0x' + code;
}

const anvil = spawn('anvil', ['--port', String(PORT), '--silent'], { stdio: 'ignore' });
try {
  const pub = createPublicClient({ chain: foundry, transport: http(RPC) });
  for (let i = 0; ; i++) {
    try { await pub.getChainId(); break; } catch { if (i > 50) throw new Error('anvil did not start'); await new Promise((r) => setTimeout(r, 200)); }
  }
  for (const a of Object.values(acct)) {
    await pub.request({ method: 'anvil_setBalance', params: [a.address, '0x56BC75E2D63100000'] }); // 100 ETH
  }
  const wallet = (who) => createWalletClient({ chain: foundry, transport: http(RPC), account: acct[who] });
  async function deployCode(bytecode, abi, args = [], who = 'admin') {
    const hash = await wallet(who).deployContract({ abi, bytecode, args });
    const r = await pub.waitForTransactionReceipt({ hash });
    if (r.status !== 'success') throw new Error('deploy reverted');
    return r.contractAddress;
  }
  async function send(to, abi, functionName, args, who) {
    const hash = await wallet(who).writeContract({ address: to, abi, functionName, args });
    const r = await pub.waitForTransactionReceipt({ hash });
    if (r.status !== 'success') throw new Error(`${functionName} reverted`);
    return r;
  }
  async function reverts(to, abi, functionName, args, who) {
    try {
      await pub.simulateContract({ address: to, abi, functionName, args, account: acct[who] });
      return false;
    } catch { return true; }
  }
  const read = (to, abi, functionName, args = []) => pub.readContract({ address: to, abi, functionName, args });
  const provider = { request: ({ method, params }) => pub.request({ method, params }) };

  // 1. libraries in dependency order, then the escrow
  const deployed = {};
  for (let pass = 0; pass < 4 && Object.keys(deployed).length < 4; pass++) {
    for (const name of ['XDLogic', 'XDPayout', 'XDHooks', 'XDFlow']) {
      if (deployed[name]) continue;
      const code = link(A[name], deployed);
      if (code) deployed[name] = await deployCode(code, A[name].abi);
    }
  }
  check('four libraries deployed and linked without a cycle', Object.keys(deployed).length === 4);
  const impl = await deployCode(link(A.OmegaEscrowXD, deployed), A.OmegaEscrowXD.abi);
  const XA = A.OmegaEscrowXD.abi;
  const init = encodeFunctionData({ abi: XA, functionName: 'initialize', args: [TREASURY, acct.admin.address] });
  const xd = await deployCode(A.ERC1967Proxy.bytecode.object, A.ERC1967Proxy.abi, [impl, init]);
  const runtime = await pub.getCode({ address: impl });
  check('escrow runtime under EIP-170', (runtime.length - 2) / 2 <= 24576, `${(runtime.length - 2) / 2} bytes`);

  const token = await deployCode(A.TestERC20.bytecode.object, A.TestERC20.abi, ['usdc']);
  const hook = await deployCode(A.PhaseHook.bytecode.object, A.PhaseHook.abi);
  const hook2 = await deployCode(A.PhaseHook.bytecode.object, A.PhaseHook.abi);
  await send(xd, XA, 'setPaymentTokenAllowed', [token, true], 'admin');
  await send(xd, XA, 'setHookWhitelist', [hook, true], 'admin');
  await send(xd, XA, 'setHookWhitelist', [hook2, true], 'admin');

  // 2. a DEFERRED job with a REQUIRED hook
  const ct = await read(xd, XA, 'defaultCreateTerms', [hook]);
  const terms = { ...ct, settlementMode: 1 };
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 30 * 86400);
  await send(xd, XA, 'createJobWithTerms', [acct.prov.address, acct.eval.address, expiry, 'e2e', hook, 0n, terms], 'client');
  const jobId = 1n;
  await send(xd, XA, 'setBudget', [jobId, token, 1_000_000n, '0x'], 'prov');

  // 3. SDK read = escrow hash
  const r1 = await T.readCommitmentTerms(provider, xd, jobId);
  check('SDK recomputes the escrow terms hash before funding', r1.match, r1.localHash);
  check('decoded terms carry the locked settlement mode and hook', r1.terms.settlementMode === 1n && r1.terms.hook.toLowerCase() === hook.toLowerCase());
  const tampered = T.termsHash(r1.chainId, xd, { ...r1.terms, budget: r1.terms.budget + 1n });
  check('a different budget gives a different hash', tampered !== r1.escrowHash);
  check('escrow refuses to confirm a hash for other terms', await reverts(xd, XA, 'confirmTerms', [jobId, tampered], 'prov'));

  // 4. CLI read against the node
  const cli = execFileSync(process.execPath, [join(here, '..', 'bin', 'omega-terms.mjs'), 'read', '--rpc', RPC, '--escrow', xd, '--job', '1'], { encoding: 'utf8' });
  const cj = JSON.parse(cli);
  check('omega-terms read: match, same hash as the SDK', cj.match === true && cj.escrowHash === r1.escrowHash);

  // 5. confirm and fund with the SDK hash
  await send(xd, XA, 'confirmTerms', [jobId, r1.localHash], 'prov');
  await send(token, A.TestERC20.abi, 'mint', [acct.client.address, 1_000_000n], 'client');
  await send(token, A.TestERC20.abi, 'approve', [xd, 1_000_000n], 'client');
  await send(xd, XA, 'fundWithTermsHash', [jobId, r1.localHash, '0x'], 'client');
  const st = (await read(xd, XA, 'getJob', [jobId])).status;
  check('funded with the hash the SDK computed', st === 1);
  const r2 = await T.readCommitmentTerms(provider, xd, jobId);
  check('committed terms still hash the same', r2.match && r2.escrowHash === r1.escrowHash);

  // 6. amendHook with SDK signatures
  const x = await read(xd, XA, 'xTermsOf', [jobId]);
  const newCode = vKeccak(await pub.getCode({ address: hook2 }));
  const nt = { ...r2.terms, hook: hook2, hookCodeHash: newCode, hookConfigHash: '0x' + '00'.repeat(32), hookClass: 1n };
  const amendment = {
    jobId,
    oldTermsHash: r2.escrowHash,
    newTermsHash: T.termsHash(r2.chainId, xd, nt),
    newHook: hook2,
    newHookCodeHash: newCode,
    newHookConfigHash: '0x' + '00'.repeat(32),
    newHookClass: 1,
    nonce: x.amendmentNonce,
    deadline: expiry - 1n,
  };
  const sig = (k) => T.signAmendment(r2.chainId, xd, amendment, K[k]).signature;
  const sigs = { client: sig('client'), provider: sig('prov'), evaluator: sig('eval'), platform: '0x' };
  const missing = { ...sigs, evaluator: '0x' };
  check('amendHook without the evaluator signature reverts', await reverts(xd, XA, 'amendHook', [amendment, missing], 'admin'));
  await send(xd, XA, 'amendHook', [amendment, sigs], 'admin'); // anyone may submit; authority is the signatures
  const r3 = await T.readCommitmentTerms(provider, xd, jobId);
  check('amendHook accepted SDK signatures; new hash = SDK newTermsHash', r3.match && r3.escrowHash === amendment.newTermsHash);
  check('replaying the same signatures reverts', await reverts(xd, XA, 'amendHook', [amendment, sigs], 'admin'));

  // 7. settle and claim (DEFERRED)
  await send(xd, XA, 'submit', [jobId, '0x' + '11'.repeat(32), '0x'], 'prov');
  await send(xd, XA, 'complete', [jobId, '0x' + '22'.repeat(32), '0x'], 'eval');
  const [, , amount, status] = await read(xd, XA, 'payoutOf', [jobId, 0]);
  const shares = T.shares(1_000_000n, r3.terms.evaluatorFeeBP, r3.terms.platformFeeBP);
  check('provider right equals SDK M1 share', status === 1 && amount === shares.provider);
  await send(xd, XA, 'claimPayout', [jobId, 0, '0x'], 'admin');
  const bal = await read(token, A.TestERC20.abi, 'balanceOf', [acct.prov.address]);
  check('anyone claims; tokens reach the provider', bal === shares.provider);
} catch (e) {
  check('unexpected error', false, e.shortMessage || e.message);
} finally {
  anvil.kill();
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
