# Sepolia run r2 (2026-11-03)

Test keys and test ETH only. Chain id 11155111; contract addresses and deployment steps are in `RUN.json`.

| File | What it is | sha256 as written by the run (CRLF) | sha256 of the file here (LF) |
| --- | --- | --- | --- |
| `RUN.json` | addresses, configuration, deployment manifest, plans and roles: the input of `repro_kit.py check` | `134c9e1bdf86a0257aeff59aacf7112eaf71f4b978be111d114089d217e4afed` | `7439516e881b005aed82b6f349b628a9bbf4b042b714ef7d93296232705d9b27` |
| `TRANSCRIPT.json` | what the chain says happened, rebuilt from its logs; `economics_sha256` 2f05829c… | `efd02d920958689fce11524ca37faa6cfcf6bbb739676f2138ff3f06ae24050c` | `e963b70fbc2ecb7b3c5b5e4023016961d2b9844d8d05cb1922ea99cd0cd93dd1` |
| `RESULT.json` | the run's own checks, measurements and the closing balances | `ec18f86508247115aecb6c807f6eab6f43d0ebf1aa0ffa7c39110e6cff8cf1be` | `bc7d2d9c0c843f5e0ff981c33b46fd44289db87047cab65065bc4f40b3c201de` |

The run wrote these files on Windows with CRLF line endings; git stores them with LF. For `RUN.json` and `TRANSCRIPT.json`
that is the only difference: replace CRLF by LF in the run's file and you get the file here. In `RESULT.json` one field was also
changed before publishing: `rehearsal.scope.state_dir` held the absolute local folder of the run and now reads `state`. Nothing
else differs; the run now records the folder name only. The digests inside the files (`economics_sha256`, `build_sha256`) are
computed over the parsed content and do not depend on line endings.

Checks made on 2026-11-03 with the sources of this repository:

- `repro_kit.py local` (loopback anvil, throwaway keys) then `compare` against `TRANSCRIPT.json`: `"same": true`, no differences.
- `repro_kit.py check RUN.json https://sepolia.gateway.tenderly.co,https://ethereum-sepolia-rpc.publicnode.com`, with no key:
  `code_matches_build: true`, and `compare` against `TRANSCRIPT.json`: `"same": true`.

Measured in this run (from `RESULT.json`): 89 transactions, inclusion mean 12.6 s (p50 12.2 s, p90 23.1 s, max 42.1 s); one false
claim disputed and rejected in 14 moves, 504 s of chain time from claim to rejection; a restart in the middle recovered in 106 s.
At the close the escrow holds no token, and nothing is locked, bonded or covered.

What this run does not show: the Optimism and Cannon referees were deployed and verified but not played; only the `OVM0Dispute`
path was exercised. No external audit has been done.
