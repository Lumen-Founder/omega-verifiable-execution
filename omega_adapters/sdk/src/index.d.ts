// SPDX-License-Identifier: MIT
export type Hex = `0x${string}`;
export type Address = Hex;
export type IntLike = bigint | number | string;

export declare const COMPLETE: 1;
export declare const REJECT: 2;
export declare const COULD_NOT_CHECK: 3;
export declare const VERDICT_TYPE: string;
export declare const VERDICT_TYPEHASH: Hex;
export declare const VERDICT_FIELDS: ReadonlyArray<readonly [string, string]>;

export interface Verdict {
  escrow: Address;
  jobId: IntLike;
  deliverableHash: Hex;
  criteriaHash: Hex;
  decision: number;
  detailHash: Hex;
  signedAt: IntLike;
  expiresAt: IntLike;
  keyId: Hex;
  modelId: Hex;
  severityE4: IntLike;
  severitySeE4: IntLike;
  calibrationRun: Hex;
}

export interface NormalizedVerdict extends Verdict {
  jobId: bigint;
  signedAt: bigint;
  expiresAt: bigint;
  decision: number;
  severityE4: number;
  severitySeE4: number;
}

export interface Domain {
  name?: string;
  version?: string;
  chainId: IntLike;
  verifyingContract: Address;
  salt?: Hex;
}

export interface Signature {
  v: 27 | 28 | number;
  r: Hex;
  s: Hex;
  signature: Hex;
}

export interface KeyRecord {
  signer: Address;
  validFrom: IntLike;
  validUntil: IntLike;
  compromised: boolean;
}

export interface VerifyResult {
  ok: boolean;
  digest: Hex;
  signer: Address | null;
  failures: { rule: string; reason: string }[];
  notes: string[];
}

export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<any>;
}

export declare function normalizeVerdict(v: Verdict): NormalizedVerdict;
export declare function normalizeDomain(d: Domain): Domain;
export declare function domainSeparator(d: Domain): Hex;
export declare function structHash(v: Verdict): Hex;
export declare function hashVerdict(d: Domain, v: Verdict): Hex;
export declare function typedData(d: Domain, v: Verdict): {
  domain: Domain;
  types: { EIP712Domain: { name: string; type: string }[]; Verdict: { name: string; type: string }[] };
  primaryType: 'Verdict';
  message: NormalizedVerdict;
};
export declare function typedDataJSON(d: Domain, v: Verdict): Record<string, unknown>;

export declare function splitSignature(sig: Hex | { v?: number; yParity?: number; r: Hex; s: Hex }): Signature;
export declare function signVerdict(d: Domain, v: Verdict, privateKey: Hex | Uint8Array): Signature & { digest: Hex };
export declare function addressOfPrivateKey(privateKey: Hex | Uint8Array): Address;
export declare function recoverAddress(digest: Hex, sig: Hex | Signature): Address | null;
export declare function recoverVerdictSigner(d: Domain, v: Verdict, sig: Hex | Signature): Address | null;
export declare function verifyVerdict(args: {
  domain: Domain;
  verdict: Verdict;
  signature: Hex | Signature;
  key?: KeyRecord;
  now?: IntLike;
  escrow?: Address;
}): VerifyResult;

export declare function selector(signature: string): Hex;
export declare function encodeSubmitVerdict(v: Verdict, sig: Hex | Signature): Hex;
export declare function submitVerdictTx(evaluator: Address, v: Verdict, sig: Hex | Signature): { to: Address; data: Hex };

export declare function decodeEip712Domain(data: Hex | Uint8Array): Domain;
export declare function readDomain(p: Eip1193Provider, evaluator: Address): Promise<Domain>;
export declare function readKey(p: Eip1193Provider, evaluator: Address, keyId: Hex): Promise<KeyRecord & { validFrom: bigint; validUntil: bigint }>;
export declare function readEscrow(p: Eip1193Provider, evaluator: Address): Promise<Address>;
export declare function readDigest(p: Eip1193Provider, evaluator: Address, v: Verdict): Promise<Hex>;

export declare function canonicalize(x: unknown): string;
export declare function detailHash(doc: unknown): Hex;

export declare function keccak256(data: Hex | Uint8Array): Hex;
export declare function keccakUtf8(text: string): Hex;
export declare function idOf(label: string): Hex;
export declare function checksumAddress(a: string): Address;
export declare function bytesToHex(b: Uint8Array): Hex;
export declare function hexToBytes(h: string): Uint8Array;
