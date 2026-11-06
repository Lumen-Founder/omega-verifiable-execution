// Checks that ERC8183Virtual.sol is erc-8183/base-contracts@142e669c ERC8183.sol with only `virtual` added
// (and the contract renamed), and that the two interface files are unmodified copies.
// Usage (from omega_adapters/): node src/escrow-xd/check_dev_copy.mjs
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const upstream = join(here, '..', '..', 'third_party', 'erc8183-base-contracts-142e669c', 'contracts');
// sha256 of the upstream files as fetched (LF), from third_party/SOURCE.md
const PINNED = {
  'ERC8183.sol': 'c5db4bcdc89dce6cc53629a19fcbcb73e973bc07f83b07a730aa4712bdedb1e4',
  'IERC8183Hook.sol': '2d7797c0b59e793092cf67db93ac9d715500372b144de3d12dbadca70b63d744',
  'IDisburser.sol': '51e8dae2f2f0e34fa31a777edb67b45bd5d50a8bc341c605e4eaa5f4f3724209',
};
const sha = (b) => createHash('sha256').update(b).digest('hex');
const lf = (s) => s.replace(/\r\n/g, '\n');
let failed = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` (${detail})` : ''}`);
  if (!ok) failed++;
};

for (const f of ['IERC8183Hook.sol', 'IDisburser.sol']) {
  check(`${f} is the pinned upstream file`, sha(lf(readFileSync(join(here, f), 'utf8'))) === PINNED[f]);
}

const copy = lf(readFileSync(join(here, 'ERC8183Virtual.sol'), 'utf8'));
const base = lf(readFileSync(join(upstream, 'ERC8183.sol'), 'utf8'));
check('upstream ERC8183.sol matches the pinned hash', sha(base) === PINNED['ERC8183.sol']);

// Undo exactly the allowed edits (rename + `virtual`); anything else stays and makes the comparison fail.
const undone = copy
  .replace(/^contract ERC8183Virtual is /m, 'contract ERC8183 is ')
  .replace(/^(    \) internal) virtual( returns \(uint256\))? \{$/gm, (_, a, b) => `${a}${b ?? ''} {`)
  .replace(/(function batchDetachHook\(uint256\[\] calldata jobIds\) external onlyRole\(ADMIN_ROLE\)) virtual \{/, '$1 {')
  .replace(/(function emergencyWithdraw\(address token, address to, uint256 amount\) external onlyRole\(ADMIN_ROLE\) whenPaused) virtual \{/, '$1 {')
  .replace(/(function claimRefund\(uint256 jobId\) external whenNotPaused nonReentrant) virtual \{/, '$1 {');
check('ERC8183Virtual.sol minus the `virtual` edits equals upstream', sha(undone) === PINNED['ERC8183.sol']);

const edits = copy.split('\n').filter((l, i) => l !== base.split('\n')[i]).length;
check('line count unchanged', copy.split('\n').length === base.split('\n').length, `${edits} lines carry an edit`);
process.exit(failed ? 1 : 0);
