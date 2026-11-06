// SPDX-License-Identifier: MIT
// Commitment terms and hook amendments of the XD escrow extension (src/escrow-xd), EIP-712.
// Pre-audit. Domain: name "ERC8183CommitmentTerms", version "2", chainId, verifyingContract = the escrow.
// The provider signs off on termsHash with confirmTerms(jobId, termsHash); the client funds with
// fundWithTermsHash(jobId, termsHash, optParams). A committed hook changes only through amendHook, signed by the
// client, the provider, the evaluator and (if the job's platform fee is > 0) the platform fee recipient.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, keccakUtf8, checksumAddress, domainSeparator, splitSignature } from './index.mjs';

export const TERMS_DOMAIN_NAME = 'ERC8183CommitmentTerms';
export const TERMS_DOMAIN_VERSION = '2';

export const IMMEDIATE = 0;
export const DEFERRED = 1;
export const HOOK_NONE = 0;
export const HOOK_REQUIRED = 1;
export const HOOK_AUXILIARY = 2;
export const EXPIRE_ONLY = 0;
export const REFUND_ON_FAULT = 1;
export const EVALUATOR_ON_FAULT = 2;
export const PAYEE = { PROVIDER: 0, EVALUATOR: 1, PLATFORM: 2, CLIENT_REFUND: 3 };

/** Field order = type string order. Must match CommitmentTermsLib.TermsV2. */
export const TERMS_FIELDS = [
  ['jobId', 'uint256'],
  ['client', 'address'],
  ['provider', 'address'],
  ['providerAgentId', 'uint256'],
  ['evaluator', 'address'],
  ['providerRecipient', 'address'],
  ['paymentToken', 'address'],
  ['budget', 'uint256'],
  ['expiredAt', 'uint48'],
  ['hook', 'address'],
  ['evaluatorFeeBP', 'uint16'],
  ['platformFeeBP', 'uint16'],
  ['evaluatorFeeRecipient', 'address'],
  ['platformFeeRecipient', 'address'],
  ['settlementMode', 'uint8'],
  ['hookCodeHash', 'bytes32'],
  ['hookConfigHash', 'bytes32'],
  ['hookClass', 'uint8'],
  ['hookFaultPolicy', 'uint8'],
  ['auxHookGas', 'uint32'],
  ['faultWindow', 'uint32'],
  ['termsVersion', 'uint8'],
];

export const AMENDMENT_FIELDS = [
  ['jobId', 'uint256'],
  ['oldTermsHash', 'bytes32'],
  ['newTermsHash', 'bytes32'],
  ['newHook', 'address'],
  ['newHookCodeHash', 'bytes32'],
  ['newHookConfigHash', 'bytes32'],
  ['newHookClass', 'uint8'],
  ['nonce', 'uint64'],
  ['deadline', 'uint48'],
];

const typeString = (name, fields) => `${name}(${fields.map(([n, t]) => `${t} ${n}`).join(',')})`;
export const TERMS_TYPE = typeString('CommitmentTermsV2', TERMS_FIELDS);
export const AMENDMENT_TYPE = typeString('HookAmendment', AMENDMENT_FIELDS);
export const TERMS_TYPEHASH = keccakUtf8(TERMS_TYPE);
export const AMENDMENT_TYPEHASH = keccakUtf8(AMENDMENT_TYPE);

function toBig(x, field) {
  if (typeof x === 'bigint') return x;
  if (typeof x === 'number' && Number.isSafeInteger(x)) return BigInt(x);
  if (typeof x === 'string' && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(x)) return BigInt(x);
  throw new TypeError(`${field}: expected an unsigned integer, got ${typeof x} ${x}`);
}

function encode(type, value, field) {
  if (type === 'address') {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new TypeError(`${field}: not an address`);
    return '00'.repeat(12) + value.slice(2).toLowerCase();
  }
  if (type === 'bytes32') {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new TypeError(`${field}: not a bytes32`);
    return value.slice(2).toLowerCase();
  }
  const bits = Number(/^uint(\d+)$/.exec(type)[1]);
  const n = toBig(value, field);
  if (n < 0n || n >= 1n << BigInt(bits)) throw new RangeError(`${field}: ${n} out of uint${bits} range`);
  return n.toString(16).padStart(64, '0');
}

function normalize(fields, obj, what) {
  if (!obj || typeof obj !== 'object') throw new TypeError(`${what} must be an object`);
  const out = {};
  for (const [n, t] of fields) {
    if (!(n in obj)) throw new TypeError(`${what}.${n} is missing`);
    encode(t, obj[n], `${what}.${n}`);
    if (t === 'address') out[n] = checksumAddress(obj[n]);
    else if (t === 'bytes32') out[n] = obj[n].toLowerCase();
    else if (t === 'uint256' || t === 'uint64' || t === 'uint48') out[n] = toBig(obj[n], n);
    else out[n] = Number(toBig(obj[n], n));
  }
  const extra = Object.keys(obj).filter((k) => !fields.some(([n]) => n === k));
  if (extra.length) throw new TypeError(`${what} has unknown fields: ${extra.join(', ')}`);
  return out;
}

export const normalizeTerms = (t) => normalize(TERMS_FIELDS, t, 'terms');
export const normalizeAmendment = (a) => normalize(AMENDMENT_FIELDS, a, 'amendment');

/** The signing domain of an XD escrow. */
export function termsDomain(chainId, escrow) {
  return { name: TERMS_DOMAIN_NAME, version: TERMS_DOMAIN_VERSION, chainId, verifyingContract: escrow };
}

function structHash(typehash, fields, obj) {
  return bytesToHex(keccak_256(hexToBytes('0x' + typehash.slice(2) + fields.map(([n, t]) => encode(t, obj[n], n)).join(''))));
}

function digest(domain, sh) {
  return bytesToHex(keccak_256(hexToBytes('0x1901' + domainSeparator(domain).slice(2) + sh.slice(2))));
}

/** termsHash as the escrow computes it (`commitmentTermsOf`, `confirmTerms`, `fundWithTermsHash`). */
export function termsHash(chainId, escrow, terms) {
  const t = normalizeTerms(terms);
  return digest(termsDomain(chainId, escrow), structHash(TERMS_TYPEHASH, TERMS_FIELDS, t));
}

/** The digest every required party signs for `amendHook`. */
export function amendmentDigest(chainId, escrow, amendment) {
  const a = normalizeAmendment(amendment);
  return digest(termsDomain(chainId, escrow), structHash(AMENDMENT_TYPEHASH, AMENDMENT_FIELDS, a));
}

/** Standard EIP-712 objects for wallets (viem, ethers, eth_signTypedData_v4 after JSON conversion). */
export function termsTypedData(chainId, escrow, terms) {
  return typed(chainId, escrow, 'CommitmentTermsV2', TERMS_FIELDS, normalizeTerms(terms));
}

export function amendmentTypedData(chainId, escrow, amendment) {
  return typed(chainId, escrow, 'HookAmendment', AMENDMENT_FIELDS, normalizeAmendment(amendment));
}

function typed(chainId, escrow, primaryType, fields, message) {
  const domain = termsDomain(BigInt(chainId), checksumAddress(escrow));
  return {
    domain,
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      [primaryType]: fields.map(([name, type]) => ({ name, type })),
    },
    primaryType,
    message,
  };
}

/** Raw-key signature of an amendment (deterministic, low-s). Wallets sign amendmentTypedData() instead. */
export function signAmendment(chainId, escrow, amendment, privateKey) {
  const d = amendmentDigest(chainId, escrow, amendment);
  const pk = privateKey instanceof Uint8Array ? privateKey : hexToBytes(privateKey);
  const rec = secp256k1.sign(hexToBytes(d), pk, { prehash: false, lowS: true, format: 'recovered' });
  return { digest: d, ...splitSignature({ r: bytesToHex(rec.slice(1, 33)), s: bytesToHex(rec.slice(33, 65)), v: 27 + rec[0] }) };
}

/**
 * M1 shares of a completed job: fees round down, the provider gets the rest. Same arithmetic as XDPayout._share,
 * for budget, settledAmount = 0 and the locked rates.
 */
export function shares(budget, evaluatorFeeBP, platformFeeBP) {
  const a = toBig(budget, 'budget');
  const pf = (a * toBig(platformFeeBP, 'platformFeeBP')) / 10000n;
  const ef = (a * toBig(evaluatorFeeBP, 'evaluatorFeeBP')) / 10000n;
  return { provider: a - pf - ef, evaluator: ef, platform: pf };
}

// ---------------------------------------------------------------- reading the escrow

export const COMMITMENT_TERMS_OF = '0x' + keccakUtf8('commitmentTermsOf(uint256)').slice(2, 10);

/** Decodes the return data of `commitmentTermsOf(jobId)`: 22 static words of terms, then the escrow's hash. */
export function decodeCommitmentTerms(hex) {
  const b = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (b.length !== 23 * 64) throw new TypeError(`commitmentTermsOf: expected 23 words, got ${b.length / 64}`);
  const w = (i) => b.slice(i * 64, (i + 1) * 64);
  const terms = {};
  TERMS_FIELDS.forEach(([n, t], i) => {
    if (t === 'address') terms[n] = checksumAddress('0x' + w(i).slice(24));
    else if (t === 'bytes32') terms[n] = '0x' + w(i);
    else terms[n] = BigInt('0x' + w(i));
  });
  return { terms, escrowHash: '0x' + w(22) };
}

/**
 * Reads a job's terms from the escrow over any EIP-1193 provider ({ request }), recomputes the hash locally and
 * says whether the two agree. This is what a provider checks before `confirmTerms` and a client before funding.
 */
export async function readCommitmentTerms(provider, escrow, jobId) {
  const chainId = BigInt(await provider.request({ method: 'eth_chainId', params: [] }));
  const data = COMMITMENT_TERMS_OF + BigInt(jobId).toString(16).padStart(64, '0');
  const ret = await provider.request({ method: 'eth_call', params: [{ to: escrow, data }, 'latest'] });
  const { terms, escrowHash } = decodeCommitmentTerms(ret);
  const localHash = termsHash(chainId, escrow, terms);
  return { chainId, escrow: checksumAddress(escrow), jobId: BigInt(jobId), terms, escrowHash, localHash, match: localHash === escrowHash };
}
