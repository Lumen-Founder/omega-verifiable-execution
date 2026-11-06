# Third-party sources used only by tests

Nothing here is part of the evaluator Core or of any optional package. These sources are compiled only by
`test/integration/` and by the package's imports of OpenZeppelin.

## erc8183-base-contracts-142e669c/

Unmodified copies from https://github.com/erc-8183/base-contracts at commit
`142e669c1fd318486a4628395b629f033654dd06` (main on 2026-11-06), MIT license (`LICENSE`, copied from the same commit).

| file | sha256 |
|---|---|
| contracts/ERC8183.sol | c5db4bcdc89dce6cc53629a19fcbcb73e973bc07f83b07a730aa4712bdedb1e4 |
| contracts/IERC8183Hook.sol | 2d7797c0b59e793092cf67db93ac9d715500372b144de3d12dbadca70b63d744 |
| contracts/IDisburser.sol | 51e8dae2f2f0e34fa31a777edb67b45bd5d50a8bc341c605e4eaa5f4f3724209 |
| LICENSE | 40953fdb2ef029617b15a370dcbee145499b771b591b23caeffbc784a6d0af1c |

The hashes are of the files as fetched (LF line endings). A checkout that converts line endings to CRLF changes them.
To check, run `git show HEAD:<path> | sha256sum`.

Compiler settings match the upstream foundry.toml: solc 0.8.28, evm cancun, optimizer on, 200 runs.

## oz/

`npm ci --ignore-scripts` installs `@openzeppelin/contracts@5.6.1` and `@openzeppelin/contracts-upgradeable@5.6.1`
(lockfile integrity hashes in `package-lock.json`, sha256 of the lockfile
7dbb0432748682e6c23449da5383252fbd7bf91e0555a1e7e7c1ac588aaaad1b). base-contracts pins the same release as git
submodules: contracts `5fd1781b1454fd1ef8e722282f86f9293cacf256`, upgradeable
`7bf4727aacdbfaa0f36cbd664654d0c9e1dc52bf` (v5.6.1). On 2026-11-06 the following npm files were compared with those git
revisions and are byte-identical: SafeERC20, IERC20, ReentrancyGuard, ReentrancyGuardTransient, ERC1967Proxy,
ERC1967Utils, ERC165Checker, UUPSUpgradeable, Initializable, AccessControlUpgradeable, PausableUpgradeable,
EIP712Upgradeable. The rest of the tarball was not compared file by file.
