#!/usr/bin/env node
// omega-terms — commitment terms of the XD escrow extension (pre-audit).
//   omega-terms read --rpc <url> --escrow <0x..> --job <id>     read a job's terms, recompute the hash, compare
//   omega-terms hash --chain-id <n> --escrow <0x..> <terms.json> hash a terms file (22 fields)
//   omega-terms amendment-digest --chain-id <n> --escrow <0x..> <amendment.json>
// Prints JSON. Exit code 1 when `read` finds that the escrow's hash and the local hash differ.
import { readFileSync } from 'node:fs';
import * as T from '../src/terms.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const opt = {};
const pos = [];
for (let i = 0; i < rest.length; i++) {
  if (rest[i].startsWith('--')) opt[rest[i].slice(2)] = rest[++i];
  else pos.push(rest[i]);
}
const need = (k) => {
  if (opt[k] === undefined) throw new Error(`missing --${k}`);
  return opt[k];
};
const out = (x) => console.log(JSON.stringify(x, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));

try {
  if (cmd === 'read') {
    const rpc = need('rpc');
    let id = 0;
    const provider = {
      async request({ method, params }) {
        const r = await fetch(rpc, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
        });
        const j = await r.json();
        if (j.error) throw new Error(`${method}: ${j.error.message}`);
        return j.result;
      },
    };
    const res = await T.readCommitmentTerms(provider, need('escrow'), need('job'));
    out(res);
    process.exit(res.match ? 0 : 1);
  } else if (cmd === 'hash') {
    const terms = JSON.parse(readFileSync(pos[0], 'utf8'));
    out({ termsHash: T.termsHash(need('chain-id'), need('escrow'), terms) });
  } else if (cmd === 'amendment-digest') {
    const a = JSON.parse(readFileSync(pos[0], 'utf8'));
    out({ amendmentDigest: T.amendmentDigest(need('chain-id'), need('escrow'), a) });
  } else {
    console.error('usage: omega-terms read|hash|amendment-digest ... (see the header of this file)');
    process.exit(2);
  }
} catch (e) {
  console.error(e.message);
  process.exit(2);
}
