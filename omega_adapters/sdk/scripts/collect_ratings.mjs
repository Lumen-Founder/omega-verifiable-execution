// CLI: build a ratings file for ../measurement/calibrate.py.
//   node scripts/collect_ratings.mjs --records verdicts.jsonl --keys keys.json --out ratings.json
//   node scripts/collect_ratings.mjs --rpc https://sepolia.base.org --evaluator 0x... [--from-block 0x...] --out ratings.json
// verdicts.jsonl: one {"domain":..., "verdict":..., "signature":"0x..."} per line.
// keys.json: {"<keyId>": {"signer":"0x...","validFrom":"0","validUntil":"...","compromised":false}, ...}
import { readFileSync, writeFileSync } from 'node:fs';
import { buildRatings, readVerdictLogs } from '../src/ratings.mjs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const records = args.records
  ? readFileSync(args.records, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
  : [];
const keys = args.keys ? JSON.parse(readFileSync(args.keys, 'utf8')) : {};
let logs = [];
if (args.rpc && args.evaluator) {
  let id = 0;
  const provider = {
    async request({ method, params }) {
      const r = await fetch(args.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
      const j = await r.json();
      if (j.error) throw new Error(`${method}: ${j.error.message}`);
      return j.result;
    },
  };
  logs = await readVerdictLogs(provider, args.evaluator, { fromBlock: args['from-block'] ?? '0x0' });
}
const out = buildRatings({ records, keys, logs });
const text = JSON.stringify(out, (_, x) => (typeof x === 'bigint' ? x.toString() : x), 2) + '\n';
if (args.out) writeFileSync(args.out, text);
else process.stdout.write(text);
console.error(JSON.stringify(out.counts));
