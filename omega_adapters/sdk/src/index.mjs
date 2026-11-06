// SPDX-License-Identifier: MIT
// erc8183-verdicts — build, sign and verify ERC-8183 Evaluator Verdicts (spec: ../spec/ERC8183_EVALUATOR_VERDICTS.md).
// Only dependency: the audited @noble/curves and @noble/hashes. Wallet-agnostic: typedData() returns the standard
// EIP-712 object that viem, ethers, MetaMask (eth_signTypedData_v4) and hardware wallets sign as is.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

export const COMPLETE = 1;
export const REJECT = 2;
export const COULD_NOT_CHECK = 3;

/** V1: the EIP-712 type string, exactly. */
export const VERDICT_TYPE =
  'Verdict(address escrow,uint256 jobId,bytes32 deliverableHash,bytes32 criteriaHash,uint8 decision,' +
  'bytes32 detailHash,uint64 signedAt,uint64 expiresAt,bytes32 keyId,bytes32 modelId,int32 severityE4,' +
  'uint32 severitySeE4,bytes32 calibrationRun)';

export const VERDICT_FIELDS = [
  ['escrow', 'address'],
  ['jobId', 'uint256'],
  ['deliverableHash', 'bytes32'],
  ['criteriaHash', 'bytes32'],
  ['decision', 'uint8'],
  ['detailHash', 'bytes32'],
  ['signedAt', 'uint64'],
  ['expiresAt', 'uint64'],
  ['keyId', 'bytes32'],
  ['modelId', 'bytes32'],
  ['severityE4', 'int32'],
  ['severitySeE4', 'uint32'],
  ['calibrationRun', 'bytes32'],
];

const DOMAIN_FIELDS = [
  ['name', 'string', 0x01],
  ['version', 'string', 0x02],
  ['chainId', 'uint256', 0x04],
  ['verifyingContract', 'address', 0x08],
  ['salt', 'bytes32', 0x10],
];

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N >> 1n;
const ZERO32 = '0x' + '00'.repeat(32);

// ---------------------------------------------------------------- bytes and hashing

const enc = new TextEncoder();

export function bytesToHex(b) {
  let s = '0x';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(h) {
  if (typeof h !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(h)) throw new TypeError(`not a 0x hex byte string: ${h}`);
  const out = new Uint8Array((h.length - 2) / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** keccak256 of bytes, a 0x hex string, or (with utf8) a text string. */
export function keccak256(data) {
  const b = data instanceof Uint8Array ? data : hexToBytes(data);
  return bytesToHex(keccak_256(b));
}

export function keccakUtf8(text) {
  return bytesToHex(keccak_256(enc.encode(text)));
}

/** Convention, not part of the spec: a keyId or modelId derived from a readable label. */
export const idOf = keccakUtf8;

export const VERDICT_TYPEHASH = keccakUtf8(VERDICT_TYPE);

/** EIP-55 checksummed address. */
export function checksumAddress(a) {
  if (typeof a !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(a)) throw new TypeError(`not an address: ${a}`);
  const lower = a.slice(2).toLowerCase();
  const h = bytesToHex(keccak_256(enc.encode(lower))).slice(2);
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  return out;
}

// ---------------------------------------------------------------- ABI words

function toBig(x, field) {
  if (typeof x === 'bigint') return x;
  if (typeof x === 'number') {
    if (!Number.isSafeInteger(x)) throw new RangeError(`${field}: ${x} is not a safe integer; pass a bigint or a decimal string`);
    return BigInt(x);
  }
  if (typeof x === 'string' && /^(-?[0-9]+|0x[0-9a-fA-F]+)$/.test(x)) return BigInt(x);
  throw new TypeError(`${field}: expected an integer, got ${typeof x} ${x}`);
}

function word(n) {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function uintWord(x, bits, field) {
  const n = toBig(x, field);
  if (n < 0n || n >= 1n << BigInt(bits)) throw new RangeError(`${field}: ${n} out of uint${bits} range`);
  return word(n);
}

function intWord(x, bits, field) {
  const n = toBig(x, field);
  const lim = 1n << BigInt(bits - 1);
  if (n < -lim || n >= lim) throw new RangeError(`${field}: ${n} out of int${bits} range`);
  return word(n < 0n ? (1n << 256n) + n : n);
}

function addressWord(a, field) {
  if (typeof a !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(a)) throw new TypeError(`${field}: not an address: ${a}`);
  return concat(new Uint8Array(12), hexToBytes(a));
}

function bytes32Word(h, field) {
  if (typeof h !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(h)) throw new TypeError(`${field}: not a bytes32 hex: ${h}`);
  return hexToBytes(h);
}

function encodeField(type, value, field) {
  switch (type) {
    case 'address':
      return addressWord(value, field);
    case 'bytes32':
      return bytes32Word(value, field);
    case 'string':
      if (typeof value !== 'string') throw new TypeError(`${field}: expected a string`);
      return keccak_256(enc.encode(value));
    default: {
      const m = /^(u?)int(\d+)$/.exec(type);
      if (!m) throw new TypeError(`unsupported type ${type}`);
      return m[1] ? uintWord(value, +m[2], field) : intWord(value, +m[2], field);
    }
  }
}

// ---------------------------------------------------------------- verdict and domain

/**
 * Checks every field's type and range and returns a normalised copy: addresses checksummed, bytes32 lower case,
 * jobId/signedAt/expiresAt as bigint, decision/severityE4/severitySeE4 as numbers.
 */
export function normalizeVerdict(v) {
  if (!v || typeof v !== 'object') throw new TypeError('verdict must be an object');
  const out = {};
  for (const [name, type] of VERDICT_FIELDS) {
    if (!(name in v)) throw new TypeError(`verdict.${name} is missing`);
    encodeField(type, v[name], `verdict.${name}`); // range and format check
    if (type === 'address') out[name] = checksumAddress(v[name]);
    else if (type === 'bytes32') out[name] = v[name].toLowerCase();
    else if (type === 'uint256' || type === 'uint64') out[name] = toBig(v[name], name);
    else out[name] = Number(toBig(v[name], name));
  }
  const extra = Object.keys(v).filter((k) => !VERDICT_FIELDS.some(([n]) => n === k));
  if (extra.length) throw new TypeError(`verdict has unknown fields: ${extra.join(', ')}`);
  return out;
}

/** V2: the domain must carry chainId and verifyingContract. name, version and salt are optional. */
export function normalizeDomain(d) {
  if (!d || typeof d !== 'object') throw new TypeError('domain must be an object');
  if (d.chainId === undefined || d.verifyingContract === undefined)
    throw new TypeError('domain needs chainId and verifyingContract (spec V2)');
  const out = {};
  for (const [name, type] of DOMAIN_FIELDS) {
    if (d[name] === undefined) continue;
    encodeField(type, d[name], `domain.${name}`);
    if (type === 'address') out[name] = checksumAddress(d[name]);
    else if (type === 'uint256') out[name] = toBig(d[name], name);
    else if (type === 'bytes32') out[name] = d[name].toLowerCase();
    else out[name] = d[name];
  }
  const extra = Object.keys(d).filter((k) => !DOMAIN_FIELDS.some(([n]) => n === k));
  if (extra.length) throw new TypeError(`domain has unknown fields: ${extra.join(', ')}`);
  return out;
}

function domainTypeFields(d) {
  return DOMAIN_FIELDS.filter(([n]) => d[n] !== undefined);
}

export function domainSeparator(domain) {
  const d = normalizeDomain(domain);
  const fields = domainTypeFields(d);
  const typeStr = `EIP712Domain(${fields.map(([n, t]) => `${t} ${n}`).join(',')})`;
  return keccak256(concat(keccak_256(enc.encode(typeStr)), ...fields.map(([n, t]) => encodeField(t, d[n], n))));
}

export function structHash(verdict) {
  const v = normalizeVerdict(verdict);
  return keccak256(
    concat(hexToBytes(VERDICT_TYPEHASH), ...VERDICT_FIELDS.map(([n, t]) => encodeField(t, v[n], n))),
  );
}

/** The EIP-712 digest. It is also the ERC-8183 `reason` the evaluator passes to complete/reject. */
export function hashVerdict(domain, verdict) {
  return keccak256(concat(new Uint8Array([0x19, 0x01]), hexToBytes(domainSeparator(domain)), hexToBytes(structHash(verdict))));
}

/**
 * The standard EIP-712 object. Numbers that may exceed 2^53 are bigint, as viem and ethers expect.
 * For eth_signTypedData_v4 over JSON-RPC use typedDataJSON().
 */
export function typedData(domain, verdict) {
  const d = normalizeDomain(domain);
  return {
    domain: d,
    types: {
      EIP712Domain: domainTypeFields(d).map(([name, type]) => ({ name, type })),
      Verdict: VERDICT_FIELDS.map(([name, type]) => ({ name, type })),
    },
    primaryType: 'Verdict',
    message: normalizeVerdict(verdict),
  };
}

/** typedData() with every bigint as a decimal string, ready for JSON.stringify and eth_signTypedData_v4. */
export function typedDataJSON(domain, verdict) {
  return JSON.parse(JSON.stringify(typedData(domain, verdict), (_, x) => (typeof x === 'bigint' ? x.toString() : x)));
}

// ---------------------------------------------------------------- signatures

/** Accepts a 65-byte r||s||v hex (v 27/28 or 0/1) or {v, r, s}. Returns {v: 27|28, r, s, signature}. */
export function splitSignature(sig) {
  let v, r, s;
  if (typeof sig === 'string') {
    const b = hexToBytes(sig);
    if (b.length !== 65) throw new TypeError(`signature must be 65 bytes, got ${b.length}`);
    r = bytesToHex(b.slice(0, 32));
    s = bytesToHex(b.slice(32, 64));
    v = b[64];
  } else if (sig && typeof sig === 'object') {
    ({ r, s } = sig);
    v = Number(sig.v ?? (sig.yParity !== undefined ? 27 + Number(sig.yParity) : undefined));
    bytes32Word(r, 'signature.r');
    bytes32Word(s, 'signature.s');
  } else throw new TypeError('signature must be a hex string or {v, r, s}');
  if (v === 0 || v === 1) v += 27;
  r = r.toLowerCase();
  s = s.toLowerCase();
  return { v, r, s, signature: r + s.slice(2) + v.toString(16).padStart(2, '0') };
}

function pkBytes(privateKey) {
  const b = privateKey instanceof Uint8Array ? privateKey : hexToBytes(privateKey);
  if (b.length !== 32) throw new TypeError('private key must be 32 bytes');
  return b;
}

export function addressOfPrivateKey(privateKey) {
  const pub = secp256k1.getPublicKey(pkBytes(privateKey), false);
  return checksumAddress('0x' + bytesToHex(keccak_256(pub.slice(1))).slice(-40));
}

/**
 * Signs with a raw key (servers, air-gapped signers, tests). Deterministic (RFC 6979) and low-s, so it gives the same
 * bytes as viem, ethers and Foundry for the same key and digest. Browser wallets sign typedData() themselves instead.
 */
export function signVerdict(domain, verdict, privateKey) {
  const digest = hashVerdict(domain, verdict);
  const rec = secp256k1.sign(hexToBytes(digest), pkBytes(privateKey), { prehash: false, lowS: true, format: 'recovered' });
  // noble 'recovered' layout: recovery byte first, then r || s
  const sig = splitSignature({ r: bytesToHex(rec.slice(1, 33)), s: bytesToHex(rec.slice(33, 65)), v: 27 + rec[0] });
  return { digest, ...sig };
}

/** Recovers the signer address from a digest, or null when the signature does not recover. No low-s check here. */
export function recoverAddress(digest, sig) {
  const { v, r, s } = splitSignature(sig);
  if (v !== 27 && v !== 28) return null;
  try {
    const rec = concat(new Uint8Array([v - 27]), hexToBytes(r), hexToBytes(s));
    const pub = secp256k1.recoverPublicKey(rec, hexToBytes(digest), { prehash: false });
    const full = secp256k1.Point.fromBytes(pub).toBytes(false);
    return checksumAddress('0x' + bytesToHex(keccak_256(full.slice(1))).slice(-40));
  } catch {
    return null;
  }
}

export function recoverVerdictSigner(domain, verdict, sig) {
  return recoverAddress(hashVerdict(domain, verdict), sig);
}

/**
 * Off-chain check of the rules a conforming evaluator applies on chain. Pass what you know:
 *  - key: {signer, validFrom, validUntil, compromised} as read from keys(keyId)  -> V4, V5 key window
 *  - now: unix seconds                                                          -> V5 time window
 *  - escrow: the evaluator's escrow                                             -> V3
 * Returns {ok, digest, signer, failures: [{rule, reason}], notes: [...]}. It cannot check V6-V9 (escrow and job state).
 */
export function verifyVerdict({ domain, verdict, signature, key, now, escrow } = {}) {
  const failures = [];
  const notes = [];
  const v = normalizeVerdict(verdict);
  const digest = hashVerdict(domain, v);
  const sig = splitSignature(signature);
  if (![COMPLETE, REJECT, COULD_NOT_CHECK].includes(v.decision)) failures.push({ rule: 'V10', reason: `decision ${v.decision} is not 1, 2 or 3` });
  if (escrow !== undefined && checksumAddress(escrow) !== v.escrow) failures.push({ rule: 'V3', reason: `escrow ${v.escrow} is not the evaluator's escrow ${checksumAddress(escrow)}` });
  if (BigInt(sig.s) > HALF_N) failures.push({ rule: 'V4', reason: 'high-s signature (s > secp256k1n/2)' });
  if (sig.v !== 27 && sig.v !== 28) failures.push({ rule: 'V4', reason: `v ${sig.v} is not 27 or 28` });
  const signer = recoverAddress(digest, sig);
  if (!signer) failures.push({ rule: 'V4', reason: 'signature does not recover' });
  if (key) {
    if (!signer || checksumAddress(key.signer) !== signer) failures.push({ rule: 'V4', reason: `recovered ${signer} is not the key's signer ${key.signer}` });
    const from = toBig(key.validFrom, 'key.validFrom');
    const until = toBig(key.validUntil, 'key.validUntil');
    if (!(from <= v.signedAt && v.signedAt < until)) failures.push({ rule: 'V5', reason: `signedAt ${v.signedAt} outside key window [${from}, ${until})` });
    if (key.compromised) failures.push({ rule: 'V5', reason: 'key is revoked (compromised)' });
  } else notes.push('no key given: signer not compared with keys(keyId)');
  if (now !== undefined) {
    const t = toBig(now, 'now');
    if (v.signedAt > t) failures.push({ rule: 'V5', reason: `signedAt ${v.signedAt} is in the future (now ${t})` });
    if (t > v.expiresAt) failures.push({ rule: 'V5', reason: `expired at ${v.expiresAt} (now ${t})` });
  } else notes.push('no time given: signedAt/expiresAt not checked');
  if (v.modelId === ZERO32) notes.push('modelId is 0: measurement fields carry no meaning (V14)');
  return { ok: failures.length === 0, digest, signer, failures, notes };
}

// ---------------------------------------------------------------- calldata and chain reads

const SUBMIT_SIG =
  'submitVerdict((address,uint256,bytes32,bytes32,uint8,bytes32,uint64,uint64,bytes32,bytes32,int32,uint32,bytes32),uint8,bytes32,bytes32)';

export function selector(signature) {
  return keccakUtf8(signature).slice(0, 10);
}

/** Calldata for submitVerdict. Any relayer may send it; the signature carries the authority. */
export function encodeSubmitVerdict(verdict, signature) {
  const v = normalizeVerdict(verdict);
  const sig = splitSignature(signature);
  return bytesToHex(
    concat(
      hexToBytes(selector(SUBMIT_SIG)),
      ...VERDICT_FIELDS.map(([n, t]) => encodeField(t, v[n], n)),
      word(BigInt(sig.v)),
      hexToBytes(sig.r),
      hexToBytes(sig.s),
    ),
  );
}

/** A transaction request {to, data} for any wallet or relayer. */
export function submitVerdictTx(evaluator, verdict, signature) {
  return { to: checksumAddress(evaluator), data: encodeSubmitVerdict(verdict, signature) };
}

async function ethCall(provider, to, data, block = 'latest') {
  if (!provider || typeof provider.request !== 'function') throw new TypeError('provider must be EIP-1193 ({request})');
  const out = await provider.request({ method: 'eth_call', params: [{ to, data }, block] });
  return hexToBytes(out);
}

function readWord(b, i) {
  const w = b.slice(32 * i, 32 * i + 32);
  if (w.length !== 32) throw new RangeError('return data too short');
  return w;
}

function wordBig(w) {
  let n = 0n;
  for (const x of w) n = (n << 8n) | BigInt(x);
  return n;
}

function readString(b, offset) {
  const len = Number(wordBig(b.slice(offset, offset + 32)));
  return new TextDecoder().decode(b.slice(offset + 32, offset + 32 + len));
}

/** Decodes EIP-5267 eip712Domain() return data into a domain object (only the fields its bitmap marks). */
export function decodeEip712Domain(data) {
  const b = data instanceof Uint8Array ? data : hexToBytes(data);
  const fields = readWord(b, 0)[0];
  const all = {
    name: readString(b, Number(wordBig(readWord(b, 1)))),
    version: readString(b, Number(wordBig(readWord(b, 2)))),
    chainId: wordBig(readWord(b, 3)),
    verifyingContract: checksumAddress(bytesToHex(readWord(b, 4).slice(12))),
    salt: bytesToHex(readWord(b, 5)),
  };
  const extLen = Number(wordBig(b.slice(Number(wordBig(readWord(b, 6))), Number(wordBig(readWord(b, 6))) + 32)));
  if (extLen !== 0) throw new Error('eip712Domain extensions are not supported');
  const d = {};
  for (const [name, , bit] of DOMAIN_FIELDS) if (fields & bit) d[name] = all[name];
  if (fields & ~0x1f) throw new Error(`unknown eip712Domain field bits 0x${fields.toString(16)}`);
  return d;
}

/** Reads the signing domain from chain (V2, EIP-5267). Sign only against a domain read this way. */
export async function readDomain(provider, evaluator) {
  return decodeEip712Domain(await ethCall(provider, checksumAddress(evaluator), selector('eip712Domain()')));
}

/** Reads keys(keyId) -> {signer, validFrom, validUntil, compromised}. */
export async function readKey(provider, evaluator, keyId) {
  const b = await ethCall(provider, checksumAddress(evaluator), bytesToHex(concat(hexToBytes(selector('keys(bytes32)')), bytes32Word(keyId, 'keyId'))));
  return {
    signer: checksumAddress(bytesToHex(readWord(b, 0).slice(12))),
    validFrom: wordBig(readWord(b, 1)),
    validUntil: wordBig(readWord(b, 2)),
    compromised: wordBig(readWord(b, 3)) !== 0n,
  };
}

/** Reads the evaluator's escrow(). */
export async function readEscrow(provider, evaluator) {
  const b = await ethCall(provider, checksumAddress(evaluator), selector('escrow()'));
  return checksumAddress(bytesToHex(readWord(b, 0).slice(12)));
}

/** digestOf(v) computed by the evaluator itself: a direct check that SDK and contract agree. */
export async function readDigest(provider, evaluator, verdict) {
  const v = normalizeVerdict(verdict);
  const data = concat(hexToBytes(selector(SUBMIT_SIG.replace('submitVerdict', 'digestOf').replace(',uint8,bytes32,bytes32)', ')'))), ...VERDICT_FIELDS.map(([n, t]) => encodeField(t, v[n], n)));
  return bytesToHex(readWord(await ethCall(provider, checksumAddress(evaluator), bytesToHex(data)), 0));
}

// ---------------------------------------------------------------- detail document (RFC 8785)

/**
 * RFC 8785 JSON Canonicalization Scheme. Object keys sorted by UTF-16 code units; numbers in ECMAScript form;
 * strings with JSON escaping. Integers beyond 2^53 must be passed as strings (bigint is rejected, as JSON has none).
 */
export function canonicalize(x) {
  if (x === null || typeof x === 'boolean') return JSON.stringify(x);
  if (typeof x === 'number') {
    if (!Number.isFinite(x)) throw new RangeError('RFC 8785: non-finite number');
    return JSON.stringify(x);
  }
  if (typeof x === 'string') return JSON.stringify(x);
  if (typeof x === 'bigint') throw new TypeError('RFC 8785: bigint has no JSON form; pass a decimal string');
  if (Array.isArray(x)) return `[${x.map(canonicalize).join(',')}]`;
  if (typeof x === 'object') {
    const keys = Object.keys(x).filter((k) => x[k] !== undefined).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(x[k])}`).join(',')}}`;
  }
  throw new TypeError(`RFC 8785: unsupported value of type ${typeof x}`);
}

/** detailHash = keccak256(utf8(RFC 8785 canonical JSON of the full verdict document)). */
export function detailHash(doc) {
  return keccakUtf8(canonicalize(doc));
}
