Pre-audit. Do not use with real funds. Mainnet deployment is not authorized.

# OMEGA verifiable execution

Open Ethereum contracts and runtime that turn off-chain execution into verifiable results and accountable state changes.

A job names its program, its inputs, the jobs it depends on and the referee that judges it. A false result is disputed and
rejected on chain, every job built on it is voided before it pays, and honest downstream executors are compensated from the
faulty executor's stake. Referees judge deterministic computation only: a bisection game (`OVM0Dispute`), Optimism's fault
dispute games for output roots, and a cloned Cannon game for MIPS64 programs.

- One page: [`docs/world_computer/BRIEF_EN.md`](docs/world_computer/BRIEF_EN.md)
- Run it yourself, locally with no funds or against our Sepolia run from your own RPC:
  [`docs/world_computer/REPRODUCE.md`](docs/world_computer/REPRODUCE.md)
- Our Sepolia run, its closing balances and the two transcript checks: [`runs/sepolia/README.md`](runs/sepolia/README.md)
- Layers and what each one trusts: [`docs/world_computer/LAYERS_AND_TRUST.md`](docs/world_computer/LAYERS_AND_TRUST.md)
- Threat model: [`docs/world_computer/THREAT_MODEL.md`](docs/world_computer/THREAT_MODEL.md)
- Contracts: [`omega_evm/src`](omega_evm/src). Python runtime: `omega_world`, `omega_compute`, `omega_kernel`.

`KIT_MANIFEST.json` lists the sha256 of every file as it was exported from the development repository; this repository starts
from that export and does not carry the development history.

## Status

- No external security audit has been done.
- Testnet only (Sepolia). No customers, no revenue. The contracts have no fee, treasury or admin key.

## License

MIT, see [`LICENSE`](LICENSE).
