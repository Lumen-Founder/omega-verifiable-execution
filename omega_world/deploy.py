"""Deployment artifacts and verification (docs/adr/ADR-0012, runbook docs/world_computer/RUNBOOK_DEPLOY.md).

- load_config(path, plan_only=False): a chain configuration (deploy/chains/*.json), validated; 'REQUIRED' placeholders
  are refused, and so is a mainnet configuration whose "authorized" is not true, except for plan_only (the unsigned
  plan for review). Only the user sets "authorized" (RUNBOOK_DEPLOY section 1).
- plan(config, deployer, nonce): the unsigned deployment (init code, its keccak, the unsigned transaction, the address
  each CREATE will give, the expected runtime code hash with immutables masked), for an external signer. No key is used.
- manifest_from_receipts(chain, plan, tx_hashes): after an external signer sent the plan, the manifest (from_block
  included) from the creation transactions and their receipts, each checked against the plan. Reads only.
- deploy(chain, signer, config): deploys and returns the manifest, on a test chain or an armed one (require_writable);
  everything else is refused before any transaction. Arming a production chain is the user's (runbook).
- verify(chain, manifest, config): the code at each address equals the local build with immutables masked, every
  immutable getter returns the configured value, each contract's metadata source hashes equal the source files, and
  its creation transaction carried the init code the plan gives. Takes a ReadOnlyChain.
- provenance(): compiler and tool versions, artifact hashes, source hashes (build reproducibility evidence).
- op_contracts_ok / cannon_contracts_ok: the external Optimism contracts are the pinned ones (`codehashes` in the
  referee section: each address as read now from the chain, and keccak of its code; for the two proxies also the
  EIP-1967 implementation) and fit the referee window. A production configuration must carry the pins
  (MISSING_CODEHASH_PINS). referee_guards(config, manifest) gives the orchestrator the same checks before each post.
  pins_now / pins_diff re-read the pins and compare them with a configuration, without a key.
The contracts have no owner, no admin, no pause and no upgrade path: there is no upgrade authority to manage."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from omega_kernel.settlement.evm import TEST_CHAIN_IDS, ReadOnlyChain, Rpc, RpcError, until_mined
from omega_kernel.settlement.evm_crypto import create_address, domain_separator, keccak, word

EVM = Path(__file__).resolve().parent.parent / 'omega_evm'
STACK = ('OVM0Step', 'OVM0Inbox', 'OVM0Dispute', 'OmegaGraphEscrow')
OP_REFEREE = 'OmegaSuperRootReferee'  # deployed too when the configuration has an 'op_referee' section (ADR-0013)
# deployed too when the configuration has a 'cannon_referee' section: OVM0 jobs judged by Optimism's FaultDisputeGame
# over Cannon (SECURITY_REVIEW section 10-1)
CANNON = ('OmegaBondVault', 'OmegaCannonGames', 'OmegaCannonReferee')
CANNON_STATE_VERSION = 8  # tools/world/cannon_check.STATE_TYPE (multithreaded64-5)
# TEST_CHAIN_IDS: chains where a deployment needs no "authorized": local dev and public testnets; every other chain id
# is treated as a production chain (independent review D23: the gate used to look at chain id 1 only)
EIP1967_IMPL = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
OP_PINS = ('factory', 'registry', 'factory_impl', 'registry_impl', 'game_impl', 'game_vm', 'game_oracle')
CANNON_PINS = ('impl', 'vm', 'oracle')


class ConfigError(ValueError):
    pass


def artifact(name):
    return json.loads((EVM / 'out' / f'{name}.sol' / f'{name}.json').read_text())


def _hex(b):
    return bytes.fromhex(b[2:] if b.startswith('0x') else b)


def load_config(path, plan_only=False):
    c = json.loads(Path(path).read_text(encoding='utf-8'))
    bad = [k for k, v in _flat(c) if v == 'REQUIRED']
    if bad:
        raise ConfigError('REQUIRED:' + ','.join(bad))
    d = c['dispute']
    if not isinstance(c['chain_id'], int) or c['bond_bps'] < 10_000 or c['grace'] <= 0:
        raise ConfigError('BAD_ESCROW_PARAMS')
    if not (d['window'] > 0 and d['clock'] > 0 and d['step_cap'] > 0):
        raise ConfigError('BAD_DISPUTE_PARAMS')
    if not 0 < d['reward_wei'] < d['bond_wei']:
        raise ConfigError('BAD_BOND_REWARD')
    tok = _hex(c['token'])
    if len(tok) != 20 or tok == bytes(20):
        raise ConfigError('BAD_TOKEN')
    o = c.get('op_referee')
    if o is not None:
        if any(len(_hex(o[k])) != 20 or _hex(o[k]) == bytes(20) for k in ('factory', 'registry')):
            raise ConfigError('BAD_OP_CONTRACTS')
        if not (o['window'] > 0 and o['register_grace'] > 0 and o['l2_chain_id'] > 0 and o['game_type'] >= 0):
            raise ConfigError('BAD_OP_PARAMS')
    k = c.get('cannon_referee')
    if k is not None:
        if any(len(_hex(k[x])) != 20 or _hex(k[x]) == bytes(20) for x in ('impl', 'vm')):
            raise ConfigError('BAD_CANNON_CONTRACTS')
        if not all(k[x] > 0 for x in ('init_bond_wei', 'finality', 'bond_delay', 'step_cap', 'window',
                                      'register_grace')) or not 0 <= k['game_type'] < 2 ** 32:
            raise ConfigError('BAD_CANNON_PARAMS')
    if c['chain_id'] not in TEST_CHAIN_IDS:  # a production chain trusts the pinned Optimism code only
        for sec, names in ((o, OP_PINS), (k, CANNON_PINS)):
            if sec is not None and sorted(sec.get('codehashes', {})) != sorted(names):
                raise ConfigError('MISSING_CODEHASH_PINS')
    if c['chain_id'] not in TEST_CHAIN_IDS and c.get('authorized') is not True and not plan_only:
        raise ConfigError('NOT_AUTHORIZED')
    return c


def stack(config):
    return STACK + ((OP_REFEREE,) if config.get('op_referee') else ()) + (CANNON if config.get('cannon_referee') else ())


def _flat(d, pre=''):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _flat(v, pre + k + '.')
        else:
            yield pre + k, v


def ctor_args(name, config, addr):
    d = config['dispute']
    if name == 'OVM0Dispute':
        return [addr['OVM0Step'], addr['OVM0Inbox'], d['window'], d['bond_wei'], d['reward_wei'], d['step_cap'],
                d['clock'], d['da_max_age']]
    if name == 'OmegaGraphEscrow':
        return [_hex(config['token']), config['grace'], config['bond_bps']]
    if name == OP_REFEREE:
        o = config['op_referee']
        return [_hex(o['factory']), _hex(o['registry']), o['game_type'], o['l2_chain_id'], o['window'],
                o['register_grace']]
    k = config.get('cannon_referee')
    if name == 'OmegaBondVault':
        return [k['bond_delay']]
    if name == 'OmegaCannonGames':
        return [_hex(k['impl']), _hex(k['vm']), addr['OmegaBondVault'], k['game_type'], k['init_bond_wei'],
                k['finality']]
    if name == 'OmegaCannonReferee':
        return [addr['OmegaCannonGames'], k['step_cap'], k['window'], k['register_grace']]
    return []


def masked_runtime(name, code=None):
    a = artifact(name)
    code = bytearray(_hex(a['deployedBytecode']['object']) if code is None else code)
    for refs in a['deployedBytecode'].get('immutableReferences', {}).values():
        for r in refs:
            code[r['start']:r['start'] + r['length']] = bytes(r['length'])
    return bytes(code)


def plan(config, deployer, nonce):
    """the unsigned deployment for `deployer` (20 bytes) starting at `nonce`"""
    addr, steps = {}, []
    for i, name in enumerate(stack(config)):
        addr[name] = create_address(deployer, nonce + i)
        init = _hex(artifact(name)['bytecode']['object']) + b''.join(word(x) for x in ctor_args(name, config, addr))
        steps.append({'contract': name, 'nonce': nonce + i, 'address': '0x' + addr[name].hex(),
                      'init_code_keccak': '0x' + keccak(init).hex(), 'init_code_len': len(init),
                      'init_code': '0x' + init.hex(),
                      # the rest of the transaction (gas, fees) is the signer's, at signing time, one step at a time
                      'tx': {'chain_id': config['chain_id'], 'from': '0x' + deployer.hex(), 'nonce': nonce + i,
                             'to': None, 'value': 0, 'data': '0x' + init.hex()},
                      'runtime_masked_keccak': '0x' + keccak(masked_runtime(name)).hex(),
                      'constructor_args': [('0x' + x.hex()) if isinstance(x, bytes) else x
                                           for x in ctor_args(name, config, addr)]})
    return {'chain_id': config['chain_id'], 'name': config['name'], 'authorized': config.get('authorized') is True,
            'deployer': '0x' + deployer.hex(), 'steps': steps}


def require_writable(chain, config):
    """the only chains a deployment or a rehearsal may write to: the configuration's own, and that either a test chain
    or a chain armed for exactly this configuration (omega_kernel.settlement.evm.armed_config; A52: load_config alone
    left an unlisted production chain open)"""
    if config['chain_id'] != chain.chain_id:
        raise ConfigError(f"CHAIN_ID_MISMATCH:{config['chain_id']}!={chain.chain_id}")
    if chain.read_only:
        raise ConfigError('READ_ONLY_CHAIN')
    if chain.chain_id not in TEST_CHAIN_IDS and chain.armed != config:
        raise ConfigError(f'NOT_ARMED:{chain.chain_id}')


def _manifest_step(step, tx_hash, block):
    keep = {k: v for k, v in step.items() if k not in ('init_code', 'tx')}
    return keep | {'tx_hash': tx_hash, 'block': block}


def deploy(chain, signer, config):
    require_writable(chain, config)
    chain.flush(signer)  # an earlier attempt's transaction is not this plan's first step
    p = plan(config, signer.address, chain.nonce(signer))
    p['from_block'] = int(chain.rpc('eth_blockNumber'), 16) + 1  # log scans start here (D15)
    addr, steps = {}, []
    for s in p['steps']:
        name = s['contract']
        args = ctor_args(name, config, addr)
        got, rc = until_mined(lambda: chain.deploy_tx(signer, _hex(artifact(name)['bytecode']['object']), *args))
        if '0x' + got.hex() != s['address']:
            raise ConfigError(f'ADDRESS_MISMATCH:{name}')
        addr[name] = got
        steps.append(_manifest_step(s, rc['transactionHash'], int(rc['blockNumber'], 16)))
    p['steps'] = steps
    return p


def manifest_from_receipts(chain, the_plan, tx_hashes):
    """the manifest of a deployment an external signer sent, in plan order (RUNBOOK_DEPLOY 1-4): every creation mined
    and succeeded, carried the plan's init code from the plan's deployer and nonce, and made the plan's address.
    from_block is the first creation's block. Reads only."""
    if len(tx_hashes) != len(the_plan['steps']):
        raise ConfigError(f"TX_COUNT:{len(tx_hashes)}!={len(the_plan['steps'])}")
    steps = []
    for s, h in zip(the_plan['steps'], tx_hashes):
        name = s['contract']
        tx, rc = chain.rpc('eth_getTransactionByHash', h), chain.rpc('eth_getTransactionReceipt', h)
        if tx is None or rc is None:
            raise ConfigError(f'TX_NOT_MINED:{name}')
        if int(rc['status'], 16) != 1:
            raise ConfigError(f'TX_FAILED:{name}')
        if not _creation_ok(tx, rc, s['init_code_keccak'], s['nonce'], the_plan['deployer']):
            raise ConfigError(f'INIT_CODE_MISMATCH:{name}')
        if rc['contractAddress'].lower() != s['address']:
            raise ConfigError(f'ADDRESS_MISMATCH:{name}')
        steps.append(_manifest_step(s, h, int(rc['blockNumber'], 16)))
    return {k: v for k, v in the_plan.items() if k != 'steps'} | {'steps': steps, 'from_block': steps[0]['block']}


def _creation_ok(tx, rc, init_keccak, nonce, deployer):
    return (tx.get('to') is None and int(tx['nonce'], 16) == nonce and tx['from'].lower() == deployer.lower()
            and '0x' + keccak(_hex(tx['input'])).hex() == init_keccak and int(rc['status'], 16) == 1)


def _created_by_plan(chain, step, want, deployer):
    """A102: the transaction named in the manifest created this address with the init code the plan gives for this
    configuration. Runtime code and getters cannot show a constructor that did something else. No hash: not shown."""
    h = step.get('tx_hash')
    tx, rc = (chain.rpc('eth_getTransactionByHash', h), chain.rpc('eth_getTransactionReceipt', h)) if h else (None, None)
    return (tx is not None and rc is not None and _creation_ok(tx, rc, want['init_code_keccak'], want['nonce'], deployer)
            and (rc['contractAddress'] or '').lower() == want['address'] == step['address'])


def verify(chain, manifest, config):
    """-> {contract: {code, getters, init_code, sources}} each True/False, and overall ok"""
    addr = {s['contract']: _hex(s['address']) for s in manifest['steps']}
    want = plan(config, _hex(manifest['deployer']), manifest['steps'][0]['nonce'])['steps']
    want, given = {s['contract']: s for s in want}, {s['contract']: s for s in manifest['steps']}
    out = {}
    for name in stack(config):
        code = _hex(chain.rpc('eth_getCode', '0x' + addr[name].hex(), 'latest'))
        res = {'code': masked_runtime(name, code) == masked_runtime(name) and len(code) > 0}
        res['getters'] = _getters_ok(chain, name, addr, config)
        res['init_code'] = _created_by_plan(chain, given[name], want[name], manifest['deployer'])
        if name == OP_REFEREE:
            res['optimism'] = op_contracts_ok(chain, config['op_referee'])
        if name == 'OmegaCannonGames':
            res['optimism'] = cannon_contracts_ok(chain, config['cannon_referee'])
        res['sources'] = _sources_ok(name)
        out[name] = res
    out['ok'] = all(all(v.values()) for k, v in out.items())
    return out


RESOLVE_SLACK = 302_400  # 3.5 days for the resolve, settle and reject calls after finality (D22)


def game_window_need(chain, impl, vm, finality):
    """the latest a FaultDisputeGame can be finalized after its creation (independent review D27): both chess
    clocks, plus the clock extension each move can grant on the way down (FaultDisputeGame.move: 2 x at the split
    depth, + the PreimageOracle challenge period at the maximum depth), plus the finality delay and RESOLVE_SLACK.
    The earlier bound 2 x clock + finality ignored the extensions: a side that always moves late adds about 3 hours
    a move, about 9 days over 73 levels."""
    from omega_kernel.settlement.evm_crypto import call_data
    u = lambda to, sig: int.from_bytes(chain.call(to, call_data(sig))[:32], 'big')
    ext = u(impl, 'clockExtension()')
    challenge = u(chain.call(vm, call_data('oracle()'))[12:32], 'challengePeriod()')
    return (2 * u(impl, 'maxClockDuration()') + u(impl, 'maxGameDepth()') * ext + ext + challenge + finality
            + RESOLVE_SLACK)


def _game_vm(chain, factory, game_type, scan=50):
    """the VM of the newest game of this type on the factory (an implementation's vm() is a clone argument)"""
    from omega_kernel.settlement.evm_crypto import call_data
    n = int.from_bytes(chain.call(factory, call_data('gameCount()')), 'big')
    for i in range(n - 1, max(n - 1 - scan, -1), -1):
        rec = chain.call(factory, call_data('gameAtIndex(uint256)', i))
        if int.from_bytes(rec[:32], 'big') == game_type:
            return chain.call(rec[64 + 12:96], call_data('vm()'))[12:32]
    raise LookupError('no recent game of the type')


def codehash(chain, a):
    return keccak(_hex(chain.rpc('eth_getCode', '0x' + a.hex(), 'latest')))


def pins_ok(chain, pins, live):
    """pins: name -> {address, codehash} (the configuration); live: name -> the address the chain gives now. Every
    pinned name must be at its pinned address and carry its pinned code. A section without pins (a test chain) has
    nothing to compare."""
    return all(live.get(n) == _hex(p['address']) and codehash(chain, live[n]) == _hex(p['codehash'])
               for n, p in pins.items())


def _eip1967(chain, a):
    return _hex(chain.rpc('eth_getStorageAt', '0x' + a.hex(), EIP1967_IMPL, 'latest'))[-20:]


def _op_live(chain, o):
    """pin name -> the address the chain gives now, for an op_referee section"""
    from omega_kernel.settlement.evm_crypto import call_data
    f, r = _hex(o['factory']), _hex(o['registry'])
    impl = chain.call(f, call_data('gameImpls(uint32)', o['game_type']))[12:32]
    vm = _game_vm(chain, f, o['game_type'])
    return {'factory': f, 'registry': r, 'factory_impl': _eip1967(chain, f), 'registry_impl': _eip1967(chain, r),
            'game_impl': impl, 'game_vm': vm, 'game_oracle': chain.call(vm, call_data('oracle()'))[12:32]}


def _cannon_live(chain, k):
    """pin name -> the address the chain gives now, for a cannon_referee section"""
    from omega_kernel.settlement.evm_crypto import call_data
    vm = _hex(k['vm'])
    return {'impl': _hex(k['impl']), 'vm': vm, 'oracle': chain.call(vm, call_data('oracle()'))[12:32]}


def _token_live(chain, t):
    """pin name -> the address the chain gives now, for a token_pins section: the settlement token and, when it is a proxy
    its issuer can upgrade, the implementation in impl_slot. A changed token is reported (PINS_CHANGED), it does not stop the
    stack by itself: what the runbook does about it is the operator's call (audit A44)"""
    a = _hex(t['token'])
    return {'proxy': a, 'impl': _hex(chain.rpc('eth_getStorageAt', '0x' + a.hex(), t['impl_slot'], 'latest'))[-20:]}


def pins_now(chain, config):
    """section -> pin name -> {address, codehash} as the chain gives them now (RUNBOOK_DEPLOY section 0). Reads only."""
    out = {}
    for sec, live in (('op_referee', _op_live), ('cannon_referee', _cannon_live), ('token_pins', _token_live)):
        if config.get(sec):
            out[sec] = {n: {'address': '0x' + a.hex(), 'codehash': '0x' + codehash(chain, a).hex()}
                        for n, a in live(chain, config[sec]).items()}
    return out


def pins_diff(chain, config):
    """-> [(section, pin name, pinned, now)] for every pin of the configuration the chain no longer matches"""
    out = []
    for sec, names in pins_now(chain, config).items():
        pinned = config[sec].get('codehashes', {})
        for n, now in names.items():
            was = pinned.get(n)
            if was is None or (_hex(was['address']), _hex(was['codehash'])) != (_hex(now['address']), _hex(now['codehash'])):
                out.append((sec, n, was, now))
    return out


_NOT_THE_CONTRACT = (RpcError, LookupError, ValueError, ArithmeticError)  # what a read can say about the code behind it


def _changed(e):
    """False: the contract answered and is not the one expected (a revert, an answer of another shape, no such game). A
    refusal of the read itself (a rate limit, a node behind) says nothing about the code: it goes on as RpcError and the
    caller refuses for that reason, not as REFEREE_CONTRACTS_CHANGED (READINESS_AUDIT A55). So does a lost connection."""
    if isinstance(e, RpcError) and e.revert is None and 'revert' not in str(e).lower():
        raise e
    return False


def op_contracts_ok(chain, o):
    """the configured Optimism contracts fit together and fit the window (D23): the registry belongs to the factory,
    the configured game type is the respected one and has an implementation, and window >= both game clocks +
    the registry's finality delay (game_window_need, with the clock extensions). The factory and the registry are
    proxies Optimism can upgrade and the factory owner can replace the game implementation: with pins, every one of
    them must still be the pinned code (a changed contract is refused, the referee is not trusted on new code)."""
    from omega_kernel.settlement.evm_crypto import call_data
    try:
        u = lambda to, data: int.from_bytes(chain.call(to, data)[:32], 'big')
        f, r = _hex(o['factory']), _hex(o['registry'])
        if chain.call(r, call_data('disputeGameFactory()'))[12:32] != f:
            return False
        if u(r, call_data('respectedGameType()')) != o['game_type']:
            return False
        live = _op_live(chain, o)
        impl, vm = live['game_impl'], live['game_vm']
        if impl == bytes(20):
            return False
        if not pins_ok(chain, o.get('codehashes', {}), live):
            return False
        return o['window'] >= game_window_need(chain, impl, vm, u(r, call_data('disputeGameFinalityDelaySeconds()')))
    except _NOT_THE_CONTRACT as e:
        return _changed(e)


def cannon_contracts_ok(chain, k):
    """the configured Optimism FaultDisputeGame implementation and MIPS64 are the ones the OVM0 guest and agent were
    checked against (depth 73, split 30, Cannon state version 8, an oracle behind the VM), and the referee's window
    covers the longest game and the finality delay (game_window_need)"""
    from omega_kernel.settlement.evm_crypto import call_data
    try:
        u = lambda to, sig: int.from_bytes(chain.call(to, call_data(sig))[:32], 'big')
        impl, vm = _hex(k['impl']), _hex(k['vm'])
        if (u(impl, 'maxGameDepth()'), u(impl, 'splitDepth()')) != (73, 30):
            return False
        oracle = chain.call(vm, call_data('oracle()'))[12:32]
        if u(vm, 'stateVersion()') != CANNON_STATE_VERSION or oracle == bytes(20):
            return False
        if not pins_ok(chain, k.get('codehashes', {}), {'impl': impl, 'vm': vm, 'oracle': oracle}):
            return False
        return k['window'] >= game_window_need(chain, impl, vm, k['finality'])
    except _NOT_THE_CONTRACT as e:
        return _changed(e)


def referee_guards(config, manifest):
    """referee address -> check(chain) for the orchestrator (Orchestrator(guards=...)): before a task is posted on
    the Optimism or the Cannon referee, the external contracts it trusts are re-checked against the pins; a False
    refuses the post (the task waits; it is never moved to another referee)"""
    addr = {s['contract']: _hex(s['address']) for s in manifest['steps']}
    out = {}
    if config.get('op_referee') and OP_REFEREE in addr:
        out[addr[OP_REFEREE]] = lambda chain: op_contracts_ok(chain, config['op_referee'])
    if config.get('cannon_referee') and 'OmegaCannonReferee' in addr:
        out[addr['OmegaCannonReferee']] = lambda chain: cannon_contracts_ok(chain, config['cannon_referee'])
    return out


def _call_word(chain, to, sig):
    from omega_kernel.settlement.evm_crypto import selector
    return chain.call(to, selector(sig))[:32]


def _getters_ok(chain, name, addr, config):
    d = config['dispute']
    a = addr[name]
    if name == 'OVM0Dispute':
        want = {'referee()': word(addr['OVM0Step']), 'inbox()': word(addr['OVM0Inbox']), 'window()': word(d['window']),
                'bond()': word(d['bond_wei']), 'reward()': word(d['reward_wei']), 'stepCap()': word(d['step_cap']),
                'clock()': word(d['clock']), 'daMaxAge()': word(d['da_max_age'])}
    elif name == 'OmegaGraphEscrow':
        want = {'token()': word(_hex(config['token'])), 'grace()': word(config['grace']),
                'bondBps()': word(config['bond_bps']),
                'DOMAIN_SEPARATOR()': domain_separator('OmegaGraphEscrow', '1', config['chain_id'], a)}
    elif name == OP_REFEREE:
        o = config['op_referee']
        want = {'factory()': word(_hex(o['factory'])), 'registry()': word(_hex(o['registry'])),
                'gameType()': word(o['game_type']), 'l2ChainId()': word(o['l2_chain_id']),
                'window()': word(o['window']), 'registerGrace()': word(o['register_grace'])}
    elif name in CANNON:
        k = config['cannon_referee']
        want = {'OmegaBondVault': {'delay()': word(k['bond_delay'])},
                'OmegaCannonGames': {'impl()': word(_hex(k['impl'])), 'vm()': word(_hex(k['vm'])),
                                     'weth()': word(addr['OmegaBondVault']), 'gameTypeId()': word(k['game_type']),
                                     'initBond()': word(k['init_bond_wei']), 'finality()': word(k['finality'])},
                'OmegaCannonReferee': {'games()': word(addr['OmegaCannonGames']), 'stepCap()': word(k['step_cap']),
                                       'window()': word(k['window']),
                                       'registerGrace()': word(k['register_grace'])}}[name]
    else:
        return True
    return all(_call_word(chain, a, sig) == v for sig, v in want.items())


def _sources_ok(name):
    meta = artifact(name)['metadata']
    for path, s in meta['sources'].items():  # the compiler sees LF line ends (the repository's form; a Windows
        # checkout with autocrlf has CRLF on disk), so the comparison normalizes them the same way
        if keccak((EVM / path).read_bytes().replace(b'\r\n', b'\n')).hex() != s['keccak256'][2:]:
            return False
    return True


def provenance(build_twice=True):
    """tool versions, compiler settings, and the hashes of every deployed artifact; with build_twice, a forced rebuild
    must give byte-identical bytecode"""
    import os
    forge = str(Path.home() / '.foundry' / 'bin' / ('forge.exe' if os.name == 'nt' else 'forge'))
    ver = subprocess.run([forge, '--version'], capture_output=True, text=True).stdout.splitlines()[:2]

    def hashes():
        return {n: {'init': hashlib.sha256(_hex(artifact(n)['bytecode']['object'])).hexdigest(),
                    'runtime': hashlib.sha256(_hex(artifact(n)['deployedBytecode']['object'])).hexdigest()}
                for n in STACK + (OP_REFEREE,) + CANNON}
    first = hashes()
    same = None
    if build_twice:
        subprocess.run([forge, 'build', '--force'], cwd=EVM, check=True, capture_output=True, timeout=600)
        same = hashes() == first
    meta = artifact('OmegaGraphEscrow')['metadata']
    return {'forge': ver, 'solc': meta['compiler']['version'], 'settings': {k: meta['settings'].get(k) for k in
                                                                            ('optimizer', 'evmVersion', 'metadata')},
            'artifacts_sha256': first, 'rebuild_identical': same,
            'sources_keccak': {n: {p: s['keccak256'] for p, s in artifact(n)['metadata']['sources'].items()}
                               for n in STACK + (OP_REFEREE,) + CANNON}}


def main(argv):
    """the operator's tools around an external signer: they hold no key and send nothing.
    plan <config.json> <deployer> <nonce> <out.json> | manifest <plan.json> <rpc-url> <out.json> <tx hash>...
    | verify <config.json> <manifest.json> <rpc-url> | pins <config.json> <rpc-url>"""
    cmd = argv[0] if argv else ''
    if cmd == 'plan' and len(argv) == 5:
        p = plan(load_config(argv[1], plan_only=True), _hex(argv[2]), int(argv[3]))
        Path(argv[4]).write_text(json.dumps(p, indent=1), encoding='utf-8')
        return 0
    if cmd == 'manifest' and len(argv) >= 5:
        p = json.loads(Path(argv[1]).read_text(encoding='utf-8'))
        m = manifest_from_receipts(ReadOnlyChain(Rpc(argv[2], allow_remote=True, timeout=60), p['chain_id']), p, argv[4:])
        Path(argv[3]).write_text(json.dumps(m, indent=1), encoding='utf-8')
        return 0
    if cmd == 'verify' and len(argv) == 4:
        c, m = load_config(argv[1], plan_only=True), json.loads(Path(argv[2]).read_text(encoding='utf-8'))
        out = verify(ReadOnlyChain(Rpc(argv[3], allow_remote=True, timeout=60), c['chain_id']), m, c)
        print(json.dumps(out, indent=1))
        return 0 if out['ok'] else 1
    if cmd == 'pins' and len(argv) == 3:
        c = load_config(argv[1], plan_only=True)
        ro = ReadOnlyChain(Rpc(argv[2], allow_remote=True, timeout=60), c['chain_id'])
        diff = pins_diff(ro, c)
        print(json.dumps({'now': pins_now(ro, c), 'differs': diff}, indent=1))
        return 1 if diff else 0
    raise SystemExit(main.__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
