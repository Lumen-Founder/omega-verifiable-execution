"""EVM settlement adapter for the OmegaSettlement contract (omega_evm/src/OmegaSettlement.sol).

Safety rules enforced here, not by convention:
  * chain id is checked at start-up against the configured one; Chain writes only on the test chains in TEST_CHAIN_IDS.
    Every other id is a production chain, known or not: refused unless armed (armed_config: a deploy/chains file with
    "authorized": true whose sha256 is in OMEGA_ARM_CONFIG_SHA256, re-read before each write; only the user arms,
    RUNBOOK_DEPLOY section 1). The same arming is asked before a transaction in flight is sent again or replaced.
    ReadOnlyChain reads any chain and has no way to write;
  * the RPC must be loopback unless allow_remote=True (testnets);
  * the signed raw transaction is written to a local store BEFORE broadcast, so a crash or lost ack is
    recovered by re-reading / re-broadcasting the same bytes; UNKNOWN therefore means "never sent";
  * the contract settles a key at most once and rejects a reused key with other contents, so a rebuilt
    transaction (new nonce after a nonce conflict, or after a reorg) can never double-settle;
  * CONFIRMED is reported only at `confirmations` depth; a reorged-out settlement falls back to PENDING
    and is re-broadcast;
  * gas is paid by the operator in ETH (sponsored), so the kernel-visible asset fee is 0 and a gas-price
    cap bounds operator spend: the fee a transaction signs for never exceeds it (max_fee_cap_wei of the chain's file; on a
    production chain the armed file's value is a ceiling no process can raise).

Chain's write path (REAUDIT_20261103 B5, B10, B11): one transaction per signer is in flight. With a state folder it is on disk
before its broadcast (the signed bytes and the call, what the node gets anyway; no key, nothing before signing), without one in
memory. Overdue, it is replaced at a higher fee on the same nonce by the same call or by any other: one stuck transaction does
not hold a signer back, and a restart picks it up. A transaction this object has no record of is replaced at the node's latest
nonce once it is overdue (one nonce: only one of the two can ever mine). A nonce used up without a receipt in sight is
TX_OUTCOME_UNKNOWN: the call is never sent again on that evidence, a read node may just be behind.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from omega_kernel.settlement.base import SettlementAdapter, transfer_digest
from omega_kernel.settlement.evm_crypto import (call_data, create_address, domain_separator, keccak, recover, selector,
                                                 settle_digest, sign_1559, sign_typed, word, words)

TEST_CHAIN_IDS = frozenset({31337, 1337, 11155111, 17000, 560048, 84532, 11155420})  # local dev chains, public testnets
ARM_ENV = 'OMEGA_ARM_CONFIG_SHA256'
RECEIPT_TIMEOUT = 180.0  # seconds a send waits for its receipt: 15 blocks of 12 s; a retry waits again, it does not resend
DEFAULT_FEE_CAP = 200 * 10 ** 9  # wei per gas a transaction may sign for, where the chain's file does not say (B6)
# EIP-7825: a node refuses a transaction with a larger gas limit (re-audit B21). A chain's rule, not a constant of Ethereum: on
# Sepolia's Glamsterdam rules state gas is outside it, and the escrow's deployment was mined there with a limit of 41,001,443 and
# 33,889,405 gas used (rehearsal r1, 2026-11-03). Such a chain's config says tx_gas_cap: null.
TX_GAS_CAP = 2 ** 24
FEE_ALARM_S = 900  # seconds a fee alarm stays up after the last send that met it: a role that stopped asking is not a price
UNKNOWN_HOLD_S = 120  # at least this long a used-up nonce without a receipt holds the signer: long enough for a read node
POLL_MIN, POLL_MAX = 0.02, 2.0  # seconds between receipt polls: quick on a dev chain, gentle on a provider
DEFAULT_CONFIRMATIONS = 12  # depth an archive waits for on a production chain (RUNBOOK_INCIDENT)
READ_METHODS = frozenset({'eth_chainId', 'eth_blockNumber', 'eth_call', 'eth_getLogs', 'eth_getCode', 'eth_getStorageAt',
                          'eth_getBalance', 'eth_getBlockByNumber', 'eth_getBlockByHash',
                          'eth_getBlockTransactionCountByNumber', 'eth_getTransactionByHash',
                          'eth_getTransactionReceipt', 'eth_getTransactionCount', 'eth_maxPriorityFeePerGas',
                          'eth_gasPrice', 'eth_feeHistory', 'eth_estimateGas'})
ERRORS = ['NotOperator', 'NotOwner', 'AccountTaken', 'KeyReuse', 'DeadlinePassed', 'MandateRevoked', 'MandateExpired',
          'TargetDenied', 'OverPerSettle', 'OverWindow', 'InsufficientBalance', 'ZeroAmount', 'TokenTransferFailed',
          'BadSignature', 'BadCosign', 'CosignRequired', 'SameKey',  # OmegaSettlementV2
          'NoSuccessor', 'BadProgramCommitment', 'BadInputsCommitment', 'BadInstructionProof', 'BadInputProof',  # OVM0Step
          'BadFinalState', 'ZeroSteps', 'WrongStatus', 'WrongTurn', 'NotParty', 'TooLate', 'TooEarly', 'NotSingleStep',
          'BadPreState', 'WrongBond', 'StillOpen', 'NothingToWithdraw', 'PayoutFailed', 'TooManySteps', 'NotPublished', 'StalePublication', 'BadReward',  # OVM0Dispute
          'BadStackWitness', 'BadMemoryProof',  # OVM0StepM
          'BadProgram', 'BadInputs',  # OVM0Inbox
          'BadCondition', 'ProgramDenied', 'ExecutorDenied', 'OverPerJob', 'JobNotOpen', 'ClaimNotAccepted',
          'ClaimMismatch', 'StaleClaim', 'LateClaim', 'ClaimUsed', 'BadJob', 'BadBondRatio', 'NotExecutor',
          'AlreadyBonded', 'NotBonded', 'InsufficientBond', 'ClaimNotRejected',  # OmegaJobEscrow
          'AccountNotOpen', 'BadRefereeDelay']  # OmegaGraphEscrow
ERROR_BY_SELECTOR = {selector(e + '()'): e for e in ERRORS}
SETTLE = 'settle(bytes32,bytes32,bytes32,uint256,uint64,bytes32)'


class RpcError(Exception):
    def __init__(self, message, data=None):
        super().__init__(message)
        self.data = data

    @property
    def revert(self):
        d = self.data
        if isinstance(d, dict):
            d = d.get('data')
        if isinstance(d, str) and d.startswith('0x') and len(d) >= 10:
            return ERROR_BY_SELECTOR.get(bytes.fromhex(d[2:10]), 'REVERT_' + d[2:10])
        return None


class TxOutcome(RpcError):
    """a broadcast transaction that did not succeed; the caller's next pass re-reads the chain and decides again"""

    def __init__(self, message, tx_hash, nonce, data=None):
        super().__init__(message, data)
        self.tx_hash, self.nonce = tx_hash, nonce


class TxNotMined(TxOutcome):
    """no receipt yet: the transaction may still mine (tx_hash None: one this object did not send). Not a failure."""


class TxFailed(TxOutcome):
    """mined with status 0 (for example it lost a same-block race); data is the receipt"""

    def __init__(self, message, rc, nonce):
        super().__init__(message, rc['transactionHash'], nonce, rc)


class ReadOnlyChainError(RuntimeError):
    """a write through a ReadOnlyChain: a wiring error, deliberately not an RpcError (no caller skips it as refused)"""


class Rpc:
    def __init__(self, url, allow_remote=False, timeout=10):
        got = urlparse(url)
        if got.scheme not in ('http', 'https') or not got.hostname:  # no message of this holds the URL: it may hold a provider's key
            raise ValueError('RPC_BAD_URL')
        host = got.hostname
        if not allow_remote and host not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('RPC_NOT_LOOPBACK')
        self.url, self.timeout, self.n = url, timeout, 0

    def __call__(self, method, *params):
        self.n += 1
        body = json.dumps({'jsonrpc': '2.0', 'id': self.n, 'method': method, 'params': list(params)}).encode()
        req = urllib.request.Request(self.url, body, {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            out = json.loads(r.read())
        if 'error' in out:
            raise RpcError(out['error'].get('message', 'rpc error'), out['error'].get('data'))
        return out['result']


def hx(i):
    return hex(i)


def account_id(account):
    return keccak(b'OMEGA-ACCOUNT-v1\x00' + account.encode())


def key_id(key):
    return keccak(b'OMEGA-KEY-v1\x00' + key.encode())


LOG_SPAN = 10_000  # blocks per eth_getLogs window; providers commonly allow 1k to 10k, the query halves if refused
RANGE_REFUSALS = ('block range', 'range is too', 'too many results', 'too many logs', 'max results', 'response size',
                  'query returned more than', 'exceeds max block range', 'range too large', 'result limit')
NOT_RANGE = ('rate limit', 'rate-limit', 'too many requests', 'capacity', 'quota')  # back off, do not shrink (D18)
REPLACE_REFUSED = ('underpriced', 'nonce too low', 'already known', 'already imported')  # a replacement of what we cannot see


def armed_config(path, chain_id):
    """the configuration the write path on a production chain is armed for, or ValueError NOT_ARMED:<why>. Armed means
    both: the file says "authorized": true for this chain id, and OMEGA_ARM_CONFIG_SHA256 holds this file's sha256.
    Only the user sets them (RUNBOOK_DEPLOY section 1)."""
    raw = Path(path).read_bytes()
    c = json.loads(raw)
    if c.get('authorized') is not True:
        raise ValueError('NOT_ARMED:NOT_AUTHORIZED')
    if c.get('chain_id') != chain_id:
        raise ValueError('NOT_ARMED:CHAIN_ID')
    if os.environ.get(ARM_ENV, '').strip().lower() != hashlib.sha256(raw).hexdigest():
        raise ValueError('NOT_ARMED:SHA256')
    return c


def until_mined(send, tries=5):
    """send() again while its transaction is broadcast and not mined: each retry waits for the same transaction (and
    raises its fee once overdue), so a long-running script survives a slow network without sending anything twice"""
    for i in range(tries):
        try:
            return send()
        except TxNotMined:
            if i == tries - 1:
                raise


class Chain:
    """Signed-transaction helper shared by the adapter and by test/deploy scripts. One transaction per signer is in
    flight through send/deploy: while it has no receipt the same call waits for it and any other call is told so; overdue, either
    of them raises its fee (module docstring)."""
    read_only = False

    def __init__(self, rpc, chain_id, max_fee_cap=None, receipt_timeout=RECEIPT_TIMEOUT, arm_config=None, state_dir=None,
                 urgent_fee_cap=None, urgent_signers=(), tx_gas_cap=TX_GAS_CAP):
        """tx_gas_cap: the largest gas limit this chain's nodes take, None if it has none (default EIP-7825's).
        arm_config: a production chain's deploy/chains file, see armed_config; without it only test chains.
        max_fee_cap: wei per gas (default DEFAULT_FEE_CAP); urgent_fee_cap, urgent_signers: the higher cap of the signers whose
        moves have a deadline (default the same cap); on a production chain the armed file's values are ceilings.
        state_dir: where the transaction in flight is kept across a restart (default: memory only)"""
        got = int(rpc('eth_chainId'), 16)
        self.arm_config, self.armed = None, None
        if chain_id not in TEST_CHAIN_IDS or got not in TEST_CHAIN_IDS:
            if arm_config is None:
                raise ValueError('MAINNET_REFUSED')
            self.arm_config, self.armed = arm_config, armed_config(arm_config, chain_id)
        if got != chain_id:
            raise ValueError(f'CHAIN_ID_MISMATCH:{got}')
        if self.armed is None:
            self.max_fee_cap = DEFAULT_FEE_CAP if max_fee_cap is None else max_fee_cap
            self.urgent_fee_cap = self.max_fee_cap if urgent_fee_cap is None else urgent_fee_cap
        else:
            normal = self.armed.get('max_fee_cap_wei', DEFAULT_FEE_CAP)
            self.max_fee_cap = normal if max_fee_cap is None else min(max_fee_cap, normal)
            urgent = self.armed.get('urgent_fee_cap_wei', normal)
            self.urgent_fee_cap = urgent if urgent_fee_cap is None else min(urgent_fee_cap, urgent)
        self.rpc, self.chain_id, self.receipt_timeout = rpc, chain_id, receipt_timeout
        self.tx_gas_cap = self.armed.get('tx_gas_cap', TX_GAS_CAP) if self.armed is not None else tx_gas_cap
        self.log_span = LOG_SPAN
        self.state_dir = Path(state_dir) if state_dir is not None else None
        self.urgent_signers = {bytes(a) for a in urgent_signers}
        self.unknown_hold = max(receipt_timeout, UNKNOWN_HOLD_S)
        self.inflight = {}  # signer address -> the transaction broadcast (or maybe broadcast) and without a receipt
        self.unknown_since = {}  # signer address -> (nonce, when first seen, bid step) of a pending transaction with no record here
        self.fee_alarms = {}  # signer address -> (code, detail, when)

    def logs(self, address, topics=None, from_block=0, to_block=None):
        """eth_getLogs from `from_block` to the head, in windows of at most `log_span` blocks: real providers cap the
        block range or the result size of one query (ADR-0012 D17). A window the provider refuses as too large is
        halved and asked again; any other error is raised (a rate limit too: shrinking would only multiply the load).
        `to_block` fixes the end; a caller that scans several addresses passes one head to all (D18)."""
        head = int(self.rpc('eth_blockNumber'), 16) if to_block is None else to_block
        out, lo, span = [], from_block, max(1, self.log_span)
        while lo <= head:
            hi = min(head, lo + span - 1)
            q = {'address': '0x' + address.hex(), 'fromBlock': hex(lo), 'toBlock': hex(hi)}
            if topics:
                q['topics'] = topics
            try:
                out += self.rpc('eth_getLogs', q)
            except RpcError as e:
                msg = str(e).lower()
                if span > 1 and any(w in msg for w in RANGE_REFUSALS) and not any(w in msg for w in NOT_RANGE):
                    span //= 2
                    continue
                raise
            lo = hi + 1
        return out

    def _prices(self):
        return (int(self.rpc('eth_getBlockByNumber', 'latest', False)['baseFeePerGas'], 16),
                int(self.rpc('eth_maxPriorityFeePerGas'), 16))

    def fees(self):
        base, tip = self._prices()
        return tip, 2 * base + tip

    def check_armed(self):
        """before anything is signed or sent: ValueError NOT_ARMED:<why> once the user took the arming away"""
        if self.arm_config is not None:
            armed_config(self.arm_config, self.chain_id)

    def _cap(self, me):
        return max(self.max_fee_cap, self.urgent_fee_cap) if me in self.urgent_signers else self.max_fee_cap

    def _alarm(self, me, code, detail):
        self.fee_alarms[me] = (code, detail, time.time())

    def _price_alarm(self, me, base, tip):
        """what this price means for this signer: over its cap, over the normal cap (it pays the deadline's price), or nothing"""
        need, cap = base + tip, self._cap(me)
        if need > cap:
            self._alarm(me, 'GAS_PRICE_OVER_CAP', f'base {base} tip {tip} cap {cap}')
        elif need > self.max_fee_cap:
            self._alarm(me, 'GAS_PRICE_URGENT', f'base {base} tip {tip} normal cap {self.max_fee_cap}')
        else:
            self.fee_alarms.pop(me, None)

    def fee_alerts(self, now=None):
        """[(code, signer, detail)]: GAS_PRICE_OVER_CAP (a send was refused, or a stuck transaction cannot be raised),
        GAS_PRICE_URGENT (a deadline's signer is paying over the normal cap). monitor.SEVERITY has them"""
        now = time.time() if now is None else now
        for me in [m for m, a in self.fee_alarms.items() if now - a[2] > FEE_ALARM_S]:
            del self.fee_alarms[me]
        return [(code, '0x' + me.hex(), detail) for me, (code, detail, _) in self.fee_alarms.items()]

    def _fields(self, signer, to, data, value, gas=None):
        """(tip, max fee, gas) for a transaction to sign; every write passes here, so the arming is re-read each time. The cap
        bounds what is signed: it refuses only what could not be included at it"""
        self.check_armed()
        base, tip = self._prices()
        self._price_alarm(signer.address, base, tip)
        cap = self._cap(signer.address)
        if base + tip > cap:
            raise RpcError('GAS_PRICE_OVER_CAP')
        max_fee = min(2 * base + tip, cap)
        call = {'from': '0x' + signer.address.hex(), 'data': '0x' + data.hex(), 'value': hx(value)}
        if to:
            call['to'] = '0x' + to.hex()
        if gas is None:
            needed = int(self.rpc('eth_estimateGas', call), 16)
            gas = needed * 6 // 5 + 10_000
            if self.tx_gas_cap is not None:
                if needed > self.tx_gas_cap:  # the margin stops at the cap; below the need it would only burn the fee
                    raise RpcError('TX_GAS_OVER_CAP')
                gas = min(gas, self.tx_gas_cap)
        return tip, max_fee, gas

    def build(self, signer, to, data, nonce, gas=None, value=0):
        tip, max_fee, gas = self._fields(signer, to, data, value, gas)
        return sign_1559(signer, self.chain_id, nonce, tip, max_fee, gas, to or b'', value, data)

    def nonce(self, signer):
        return int(self.rpc('eth_getTransactionCount', '0x' + signer.address.hex(), 'pending'), 16)

    def send(self, signer, to, data, value=0):
        """Build, sign, broadcast and wait for the receipt, polling up to receipt_timeout. TxNotMined: not mined yet
        (the same call again waits for that transaction); TxFailed: mined, status 0."""
        return self._submit(signer, to, data, value, 'TX')[0]

    def wait(self, tx_hash, timeout=None):
        """Receipt of tx_hash (or of whichever of several hashes of one nonce mined), polling up to timeout seconds
        (default receipt_timeout), or None"""
        hashes = [tx_hash] if isinstance(tx_hash, str) else tx_hash

        def read():
            for h in hashes:
                rc = self.rpc('eth_getTransactionReceipt', h)
                if rc is not None:
                    return rc
            return None
        return self._poll(read, self.receipt_timeout if timeout is None else timeout)

    def _poll(self, read, timeout):
        end, pause = time.monotonic() + timeout, POLL_MIN
        while True:
            got = read()
            left = end - time.monotonic()
            if got is not None or left <= 0:
                return got
            time.sleep(min(pause, left))
            pause = min(pause * 1.5, POLL_MAX)

    def _submit(self, signer, to, data, value, tag):
        """-> (receipt, nonce). A retry after TxNotMined, a lost connection or a restart finds its transaction here, so one
        call is one transaction: the node's mempool and the contract never see it twice from this signer's record. A pending
        transaction there is no record of: the caller decided on a state it may change, so the caller is told to read again
        (TX_IN_FLIGHT), and once it is overdue this call takes its nonce at a higher fee."""
        call, me = (to or None, bytes(data), value), signer.address
        p = self._open(me)
        if p is not None:
            same = p['call'] == call
            rc = self._settle(signer, p, tag, retry=same)
            if same and rc is not None:
                return self._outcome(rc, p['nonce'], tag), p['nonce']
        n, bid = self._nonce_to_use(me)
        tip, max_fee, gas = self._fields(signer, to, data, value)
        if bid:
            cap = self._cap(me)
            max_fee = min(max_fee * 5 ** bid // 4 ** bid + 1, cap)
            tip = min(tip * 5 ** bid // 4 ** bid + 1, max_fee)
        raw, h = sign_1559(signer, self.chain_id, n, tip, max_fee, gas, to or b'', value, data)
        self.inflight[me] = {'call': call, 'nonce': n, 'hashes': [h], 'raw': raw.hex(), 'tip': tip, 'max_fee': max_fee,
                             'gas': gas, 'at': time.time()}  # before the broadcast: an ack can be lost, a process can die
        try:
            self._journal(me)
        except OSError:  # no record, no broadcast: a restart must find what was sent
            del self.inflight[me]
            raise
        try:
            self.rpc('eth_sendRawTransaction', '0x' + raw.hex())
        except RpcError as e:  # the node refused it: nothing is in flight; a lost connection stays above and is retried
            self._forget(me)
            if bid and any(w in str(e).lower() for w in REPLACE_REFUSED):  # bid more next time, or the node was only behind
                self.unknown_since[me] = (*self.unknown_since[me][:2], bid + 1)
                raise TxNotMined('TX_IN_FLIGHT', None, n) from None
            raise
        rc = self.wait(h)
        if rc is None:
            raise TxNotMined(tag + '_NOT_MINED', h, n)
        self._forget(me)
        return self._outcome(rc, n, tag), n

    def _nonce_to_use(self, me):
        """-> (nonce, bid step): the node's next nonce and 0, or with something pending that this object knows nothing about,
        TX_IN_FLIGHT until it is overdue, then the latest nonce and the step of the bid over it"""
        who = '0x' + me.hex()
        latest = int(self.rpc('eth_getTransactionCount', who, 'latest'), 16)
        n = max(latest, int(self.rpc('eth_getTransactionCount', who, 'pending'), 16))
        if n == latest:
            self.unknown_since.pop(me, None)
            return n, 0
        seen = self.unknown_since.get(me)
        if seen is None or seen[0] != latest:  # a new one, or the chain moved: the wait starts now
            seen = self.unknown_since[me] = (latest, time.time(), 1)
        elif time.time() - seen[1] >= self.receipt_timeout:
            return latest, seen[2]
        self._poll(lambda: True if int(self.rpc('eth_getTransactionCount', who, 'latest'), 16) >= n else None, self.receipt_timeout)
        raise TxNotMined('TX_IN_FLIGHT', None, n - 1)

    def _outcome(self, rc, nonce, tag):
        if int(rc['status'], 16) != 1:
            raise TxFailed(tag + '_FAILED', rc, nonce)
        return rc

    def _overdue(self, p):
        return time.time() - p['at'] >= self.receipt_timeout

    def _known(self, p):
        """does the node know any hash of this nonce: a refused replacement leaves the one before it in the pool"""
        return any(self.rpc('eth_getTransactionByHash', h) is not None for h in reversed(p['hashes']))

    def _settle(self, signer, p, tag, retry):
        """the signer's in-flight transaction ended: its receipt, or None if the node lost it and the nonce is free. Still open:
        TxNotMined. Its nonce used up with no receipt in sight: TxNotMined TX_OUTCOME_UNKNOWN, also after the hold, when it is
        forgotten: the caller reads the chain before it asks again. `retry`: the same call was asked again, so it is pushed and
        waited for; any other call pushes only what is overdue and does not wait, it must not hang behind a stuck transaction."""
        me = signer.address
        rc = self.wait(p['hashes'], 0)
        if rc is None and 'spent_at' not in p:
            known = self._known(p)
            if retry or (known and self._overdue(p)):
                self._push(signer, p, known)
            elif not known and int(self.rpc('eth_getTransactionCount', '0x' + me.hex(), 'latest'), 16) <= p['nonce']:
                self._forget(me)  # the caller moved on, and nothing took its nonce: the next transaction may
                return None
            elif not known:
                p['spent_at'] = time.time()
            rc = self.wait(p['hashes'], self.receipt_timeout if retry and 'spent_at' not in p else 0)
        if rc is not None:
            self._forget(me)
            return rc
        if 'spent_at' not in p:
            raise TxNotMined(tag + '_NOT_MINED', p['hashes'][-1], p['nonce'])
        if time.time() - p['spent_at'] >= self.unknown_hold:
            self._forget(me)
        raise TxNotMined('TX_OUTCOME_UNKNOWN', p['hashes'][-1], p['nonce'])

    def _push(self, signer, p, known):
        """replace an overdue transaction at a higher fee, within the signer's cap (same nonce: only one of its hashes can ever
        mine), or put back one the node has lost. Nothing goes out unarmed. "nonce too low": someone's transaction used it,
        maybe this one on a node the reads do not see: nothing is sent again (B11)."""
        self.check_armed()
        try:
            if self._overdue(p) and self._replace(signer, p):
                return
            if not known:
                self.rpc('eth_sendRawTransaction', '0x' + p['raw'])
        except RpcError as e:
            m = str(e).lower()
            if 'nonce too low' in m:
                p['spent_at'] = time.time()
            elif not any(w in m for w in ('already known', 'already imported', 'underpriced')):
                raise

    def _replace(self, signer, p):
        """-> False if the cap leaves no bid a node would take (it asks for 10 % more on both fees)"""
        me, (to, data, value) = signer.address, p['call']
        base, fresh = self._prices()
        cap = self._cap(me)
        max_fee = min(max(2 * base + fresh, p['max_fee'] * 5 // 4 + 1), cap)
        tip = min(max(fresh, p['tip'] * 5 // 4 + 1), max_fee)
        self._price_alarm(me, base, fresh)
        if max_fee < p['max_fee'] * 11 // 10 + 1 or tip < p['tip'] * 11 // 10 + 1:
            self._alarm(me, 'GAS_PRICE_OVER_CAP', f"nonce {p['nonce']} stuck at {p['max_fee']}, cap {cap}")
            return False
        raw, h = sign_1559(signer, self.chain_id, p['nonce'], tip, max_fee, p['gas'], to or b'', value, data)
        before = {k: p[k] for k in ('raw', 'tip', 'max_fee', 'hashes')}
        p.update(raw=raw.hex(), tip=tip, max_fee=max_fee, at=time.time(), hashes=[*p['hashes'], h])
        self._journal(me)  # on disk first, as the first broadcast
        try:
            self.rpc('eth_sendRawTransaction', '0x' + raw.hex())
        except RpcError as e:
            if not any(w in str(e).lower() for w in ('already known', 'already imported')):  # what the node has is the one before
                p.update(before)
                self._journal(me)
                raise
        return True

    # ---- the record of what is in flight ----------------------------------------------------------------------------------
    def _journal_path(self, me):
        return self.state_dir / f'inflight-{self.chain_id}-{me.hex()}.json'

    def _journal(self, me):
        """the transaction in flight, in the configured folder only: its signed bytes and call, nothing a node does not get"""
        if self.state_dir is None:
            return
        p = self.inflight[me]
        to, data, value = p['call']
        text = json.dumps({'chain_id': self.chain_id, 'address': me.hex(), 'nonce': p['nonce'], 'hashes': p['hashes'],
                           'raw': p['raw'], 'tip': p['tip'], 'max_fee': p['max_fee'], 'gas': p['gas'], 'at': p['at'],
                           'to': to.hex() if to else None, 'data': data.hex(), 'value': value}, sort_keys=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        path = self._journal_path(me)
        tmp = Path(str(path) + '.tmp')
        with tmp.open('w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)

    def _open(self, me):
        """the signer's transaction in flight: in memory, or left on disk by an earlier process. A file that does not say
        what its signed bytes say is put aside (<file>.bad) and the node's pending count decides."""
        p = self.inflight.get(me)
        if p is not None or self.state_dir is None:
            return p
        path = self._journal_path(me)
        try:
            r = json.loads(path.read_text(encoding='utf-8'))
            raw = bytes.fromhex(r['raw'])
            if (r['chain_id'], r['address'], r['nonce']) != (self.chain_id, me.hex(), _nonce_of(raw)) \
                    or r['hashes'][-1] != '0x' + keccak(raw).hex():
                raise ValueError('JOURNAL_MISMATCH')
            p = {'call': (bytes.fromhex(r['to']) if r['to'] else None, bytes.fromhex(r['data']), r['value']), 'nonce': r['nonce'],
                 'hashes': list(r['hashes']), 'raw': r['raw'], 'tip': r['tip'], 'max_fee': r['max_fee'], 'gas': r['gas'],
                 'at': r['at']}
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
            path.replace(str(path) + '.bad')
            return None
        self.inflight[me] = p
        return p

    def _forget(self, me):
        self.inflight.pop(me, None)
        if self.state_dir is not None:
            try:
                self._journal_path(me).unlink(missing_ok=True)
            except OSError:  # the next open finds it, its receipt or the node's answer ends it again
                pass

    def open_transactions(self):
        """-> how many in-flight transactions can still mine; those that mined or that the node lost are forgotten (a
        sender that has moved on never asks about them again, and its next pass reads the chain anyway). A nonce used up
        with no receipt in sight stays for its hold."""
        for who, p in list(self.inflight.items()):
            ended = self.wait(p['hashes'], 0) is not None
            if not ended:
                ended = not self._known(p) if 'spent_at' not in p else time.time() - p['spent_at'] >= self.unknown_hold
            if ended:
                self._forget(who)
        return len(self.inflight)

    def flush(self, signer):
        """wait out the signer's in-flight transaction, so that what comes next is a new call, not a retry of it"""
        p = self._open(signer.address)
        if p is not None:
            self._settle(signer, p, 'TX', retry=True)

    def deploy_tx(self, signer, bytecode, *args):
        """-> (address, receipt)"""
        rc, n = self._submit(signer, None, bytecode + b''.join(map(word, args)), 0, 'DEPLOY')
        addr = bytes.fromhex(rc['contractAddress'][2:])
        assert addr == create_address(signer.address, n)
        return addr, rc

    def deploy(self, signer, bytecode, *args):
        return self.deploy_tx(signer, bytecode, *args)[0]

    def call(self, to, data, block='latest', sender=None):
        c = {'to': '0x' + to.hex(), 'data': '0x' + data.hex()}
        if sender:
            c['from'] = '0x' + sender.hex()
        return bytes.fromhex(self.rpc('eth_call', c, block)[2:])


class ReadOnlyChain(Chain):
    """Any chain id, reads only: verify, referee_guards, Board, GraphEscrow, Indexer, monitor, WorldClient's read side.
    It holds no signer path and its rpc passes only READ_METHODS, so nothing can be sent through it."""
    read_only = True

    def __init__(self, rpc, chain_id):
        got = int(rpc('eth_chainId'), 16)
        if got != chain_id:
            raise ValueError(f'CHAIN_ID_MISMATCH:{got}')

        def reads(method, *params):
            if method not in READ_METHODS:
                raise ReadOnlyChainError(f'READ_ONLY_CHAIN:{method}')
            return rpc(method, *params)
        self.rpc, self.chain_id, self.log_span, self.armed, self.arm_config = reads, chain_id, LOG_SPAN, None, None
        self.inflight, self.fee_alarms, self.state_dir = {}, {}, None

    def _refuse(self, *a, **k):
        raise ReadOnlyChainError('READ_ONLY_CHAIN')

    _fields = build = send = deploy = deploy_tx = flush = _submit = _settle = _push = _replace = _journal = _refuse


class EvmAdapter(SettlementAdapter):
    deadline_enforced = True  # block.timestamp >= deadline reverts in the contract

    def __init__(self, chain, signer, contract, store_path, asset='USDC', confirmations=2):
        self.c, self.signer, self.contract, self.asset = chain, signer, contract, asset
        self.chain_id, self.confirmations, self.lock = f'eip155:{chain.chain_id}', confirmations, threading.RLock()
        self._check_signer()
        self.db = sqlite3.connect(str(store_path), timeout=30, isolation_level=None, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS sent(key TEXT PRIMARY KEY, digest TEXT NOT NULL, tx_hash TEXT NOT NULL,'
                        ' raw TEXT NOT NULL, nonce INTEGER NOT NULL, rebuilt INTEGER NOT NULL DEFAULT 0, at INTEGER)')
        self.faults = {'crash_before_broadcast': 0, 'lose_ack': 0}
        self.calls = {'submit': 0, 'status': 0, 'broadcast': 0, 'rebroadcast': 0, 'rebuild': 0}

    def _check_signer(self):
        if self.c.call(self.contract, selector('operator()'))[-20:] != self.signer.address:
            raise ValueError('SIGNER_IS_NOT_CONTRACT_OPERATOR')

    def close(self):
        self.db.close()

    # read side -------------------------------------------------------------------
    def balance(self, account, asset):
        if asset != self.asset:
            return 0
        return int.from_bytes(self.c.call(self.contract, call_data('balanceOf(bytes32)', account_id(account))), 'big')

    def estimate_fee(self, transfer):
        return 0  # gas is sponsored by the operator in ETH; nothing is charged in the settled asset

    def _settle_data(self, key, t):
        return call_data(SETTLE, key_id(key), account_id(t['source']), account_id(t['target']), t['amount'],
                         t['deadline'], bytes.fromhex(transfer_digest(t)))

    def simulate(self, transfer):
        probe = 'sim:' + secrets.token_hex(16)
        try:
            self.c.call(self.contract, self._settle_data(probe, transfer), sender=self.signer.address)
            return {'ok': True, 'code': None}
        except RpcError as e:
            return {'ok': False, 'code': e.revert or 'SIMULATION_ERROR'}

    def _record(self, key, block):
        w = words(self.c.call(self.contract, call_data('records(bytes32)', key_id(key)), block=block))
        return (w[0].hex(), w[1]) if w[1] != bytes(32) else None

    def _row(self, key):
        r = self.db.execute('SELECT digest, tx_hash, raw, nonce FROM sent WHERE key=?', (key,)).fetchone()
        return dict(zip(('digest', 'tx_hash', 'raw', 'nonce'), r)) if r else None

    def status(self, key):
        with self.lock:
            self.calls['status'] += 1
            head = int(self.c.rpc('eth_blockNumber'), 16)
            safe = max(0, head - self.confirmations + 1)
            row = self._row(key)
            ref = row['tx_hash'] if row else None
            rec = self._record(key, hx(safe))
            if rec:
                return {'status': 'CONFIRMED', 'ref': ref, 'code': None, 'transfer_digest': rec[0]}
            rec = self._record(key, 'latest')
            if rec:
                return {'status': 'PENDING', 'ref': ref, 'code': 'CONFIRMING', 'transfer_digest': rec[0]}
            if row is None:
                return {'status': 'UNKNOWN', 'ref': None, 'code': None, 'transfer_digest': None}
            rc = self.c.rpc('eth_getTransactionReceipt', row['tx_hash'])
            if rc is not None:
                if int(rc['status'], 16) == 0 and int(rc['blockNumber'], 16) <= safe:
                    return {'status': 'FAILED', 'ref': ref, 'code': self._revert_code(rc),
                            'transfer_digest': row['digest']}
                return {'status': 'PENDING', 'ref': ref, 'code': 'MINED_UNSAFE', 'transfer_digest': row['digest']}
            if self.c.rpc('eth_getTransactionByHash', row['tx_hash']) is None:
                ended = self._rebroadcast(key, row)  # dropped, reorged out, or never sent before a crash
                if ended is not None:
                    return ended
            return {'status': 'PENDING', 'ref': self._row(key)['tx_hash'], 'code': 'IN_MEMPOOL',
                    'transfer_digest': row['digest']}

    def _revert_code(self, rc):
        """Diagnostic only (the receipt status is authoritative): replay on the parent state with the mined
        block's time/number, so time-dependent reverts (DeadlinePassed, window roll) are named correctly.
        Earlier transactions in the same block are not replayed."""
        tx = self.c.rpc('eth_getTransactionByHash', rc['transactionHash'])
        blk = self.c.rpc('eth_getBlockByNumber', rc['blockNumber'], False)
        call = {'from': tx['from'], 'to': tx['to'], 'data': tx['input']}
        parent = hx(int(rc['blockNumber'], 16) - 1)
        for extra in (({}, {'time': blk['timestamp'], 'number': rc['blockNumber']}), ()):
            try:
                self.c.rpc('eth_call', call, parent, *extra)
            except RpcError as e:
                if e.revert:
                    return e.revert
                if extra and 'revert' not in str(e).lower():
                    continue  # node does not support block overrides: plain replay
                return 'REVERTED'
        return 'REVERTED'

    # write side ------------------------------------------------------------------
    def _broadcast(self, raw):
        self.calls['broadcast'] += 1
        try:
            self.c.rpc('eth_sendRawTransaction', '0x' + raw)
        except RpcError as e:
            m = str(e).lower()
            if 'already known' in m or 'already imported' in m:
                return 'OK'
            if 'nonce too low' in m:
                return 'NONCE_TAKEN'
            raise
        return 'OK'

    def _rebroadcast(self, key, row):
        """-> None if it is on its way again, or the status when it is not: unarmed nothing goes out (it stays pending), and a
        transaction whose nonce is taken and whose call now reverts can never be: FAILED (B19). Too high a price is a wait."""
        status = lambda st, code: {'status': st, 'ref': row['tx_hash'], 'code': code, 'transfer_digest': row['digest']}
        try:
            self.c.check_armed()
        except ValueError:
            return status('PENDING', 'NOT_ARMED')
        self.calls['rebroadcast'] += 1
        if self._broadcast(row['raw']) != 'NONCE_TAKEN':
            return None
        # our tx can never mine; the on-chain key check makes a rebuild with a fresh nonce safe
        self.calls['rebuild'] += 1
        nonce = self.c.nonce(self.signer)
        try:
            raw, h = self.c.build(self.signer, self.contract, bytes.fromhex(self._data_for(row)), nonce)
        except RpcError as e:
            if e.revert or 'revert' in str(e).lower():
                return status('FAILED', e.revert or 'REVERTED')
            return status('PENDING', str(e)[:80])
        self.db.execute('UPDATE sent SET tx_hash=?, raw=?, nonce=?, rebuilt=rebuilt+1 WHERE key=?',
                        (h, raw.hex(), nonce, key))
        self._broadcast(raw.hex())
        return None

    def _data_for(self, row):
        tx = self.c.rpc('eth_getTransactionByHash', row['tx_hash'])
        if tx is not None:
            return tx['input'][2:]
        return _decode_data(bytes.fromhex(row['raw']))

    def _next_nonce(self):
        r = self.db.execute('SELECT max(nonce) FROM sent').fetchone()[0]
        return max(self.c.nonce(self.signer), -1 if r is None else r + 1)

    def submit(self, key, transfer, now):
        d = transfer_digest(transfer)
        with self.lock:
            self.calls['submit'] += 1
            prior = self.status(key)
            if prior['status'] != 'UNKNOWN':
                if prior['transfer_digest'] != d:
                    return {'status': 'FAILED', 'ref': None, 'code': 'KEY_REUSE', 'transfer_digest': d}
                return prior
            if now >= transfer['deadline']:
                return {'status': 'FAILED', 'ref': None, 'code': 'DEADLINE_PASSED', 'transfer_digest': d}
            data = self._settle_data(key, transfer)
            try:
                raw, h = self.c.build(self.signer, self.contract, data, self._next_nonce())
            except RpcError as e:  # estimateGas reverted or gas price over cap: nothing was sent
                return {'status': 'FAILED', 'ref': None, 'code': e.revert or str(e), 'transfer_digest': d}
            self.db.execute('INSERT INTO sent(key, digest, tx_hash, raw, nonce, at) VALUES(?,?,?,?,?,?)',
                            (key, d, h, raw.hex(), _nonce_of(raw), now))  # write-ahead (autocommit, synchronous=FULL)
            if self.faults['crash_before_broadcast'] > 0:
                self.faults['crash_before_broadcast'] -= 1
                raise ConnectionError('simulated crash after write-ahead, before broadcast')
            self._broadcast(raw.hex())
            if self.faults['lose_ack'] > 0:
                self.faults['lose_ack'] -= 1
                raise TimeoutError('simulated lost ack after broadcast')
            return self.status(key)


def _rlp_items(b):
    """Minimal RLP list decoder for our own signed transactions."""
    def item(i):
        p = b[i]
        if p < 0x80:
            return b[i:i + 1], i + 1
        if p < 0xb8:
            return b[i + 1:i + 1 + p - 0x80], i + 1 + p - 0x80
        if p < 0xc0:
            n = int.from_bytes(b[i + 1:i + 1 + p - 0xb7], 'big')
            s = i + 1 + p - 0xb7
            return b[s:s + n], s + n
        if p < 0xf8:
            n, s = p - 0xc0, i + 1
        else:
            n, s = int.from_bytes(b[i + 1:i + 1 + p - 0xf7], 'big'), i + 1 + p - 0xf7
        out, j = [], s
        while j < s + n:
            v, j = item(j)
            out.append(v)
        return out, s + n
    return item(0)[0]


def _nonce_of(raw):
    return int.from_bytes(_rlp_items(raw[1:])[1], 'big')


def _decode_data(raw):
    return _rlp_items(raw[1:])[7].hex()


SETTLE2 = 'settle(bytes32,bytes32,bytes32,uint256,uint64,bytes32,uint8,bytes32,bytes32)'
SETTLE2_COSIGNED = 'settleCosigned(bytes32,bytes32,bytes32,uint256,uint64,bytes32,(uint8,bytes32,bytes32),(uint8,bytes32,bytes32))'


class EvmAgentSignedAdapter(EvmAdapter):
    """OmegaSettlementV2: the agent's EIP-712 signature is the authority; this adapter only relays and pays gas.
    Without a stored agent signature nothing is simulated as OK and nothing is sent (default deny).
    With `cosigner` (the kernel's policy key) every settlement also carries its signature, for accounts whose owner
    registered it on chain: then neither the agent key nor this process alone can move funds (2-of-2)."""

    def __init__(self, chain, relayer, contract, store_path, asset='USDC', confirmations=2, cosigner=None):
        self.cosigner = cosigner
        super().__init__(chain, relayer, contract, store_path, asset, confirmations)
        self.db.execute('CREATE TABLE IF NOT EXISTS auths(key TEXT PRIMARY KEY, digest TEXT NOT NULL, struct TEXT NOT NULL,'
                        ' v INTEGER NOT NULL, r TEXT NOT NULL, s TEXT NOT NULL)')
        self.domain = domain_separator('OmegaSettlement', '2', chain.chain_id, contract)
        if self.c.call(contract, selector('DOMAIN_SEPARATOR()')) != self.domain:
            raise ValueError('DOMAIN_SEPARATOR_MISMATCH')

    def _check_signer(self):
        pass  # any relayer may submit; authority is the agent signature checked on chain

    def typed(self, key, t):
        """-> (struct_hash, digest) the agent must sign for this intent key and transfer."""
        return settle_digest(self.domain, key_id(key), account_id(t['source']), account_id(t['target']), t['amount'],
                             t['deadline'], bytes.fromhex(transfer_digest(t)))

    def agent_of(self, account):
        return words(self.c.call(self.contract, call_data('mandates(bytes32)', account_id(account))))[1][-20:]

    def authorize(self, key, transfer, v, r, s):
        """Store the agent's signature for (key, transfer) after checking it off chain against the on-chain agent."""
        struct, digest = self.typed(key, transfer)
        try:
            ok = v in (27, 28) and recover(digest, v - 27, r, s) == self.agent_of(transfer['source'])
        except ValueError:
            ok = False
        if not ok:
            return {'ok': False, 'code': 'BadSignature'}
        d = transfer_digest(transfer)
        with self.lock:
            prior = self.db.execute('SELECT digest FROM auths WHERE key=?', (key,)).fetchone()
            if prior and prior[0] != d:
                return {'ok': False, 'code': 'KEY_REUSE'}
            self.db.execute('INSERT OR IGNORE INTO auths VALUES(?,?,?,?,?,?)', (key, d, struct.hex(), v, hex(r), hex(s)))
        return {'ok': True, 'code': None}

    def _auth(self, key):
        r = self.db.execute('SELECT digest, struct, v, r, s FROM auths WHERE key=?', (key,)).fetchone()
        return dict(zip(('digest', 'struct', 'v', 'r', 's'), r)) if r else None

    def _settle_data(self, key, t):
        a = self._auth(key)
        head = (key_id(key), account_id(t['source']), account_id(t['target']), t['amount'], t['deadline'],
                bytes.fromhex(transfer_digest(t)), a['v'], int(a['r'], 16).to_bytes(32, 'big'),
                int(a['s'], 16).to_bytes(32, 'big'))
        if self.cosigner is None:
            return call_data(SETTLE2, *head)
        v, r, s = sign_typed(self.cosigner, self.typed(key, t)[1])  # only reached after kernel policy and preflight
        return call_data(SETTLE2_COSIGNED, *head, v, r.to_bytes(32, 'big'), s.to_bytes(32, 'big'))

    def simulate(self, transfer):
        row = self.db.execute('SELECT key FROM auths WHERE digest=? ORDER BY rowid DESC LIMIT 1',
                              (transfer_digest(transfer),)).fetchone()
        if row is None:
            return {'ok': False, 'code': 'NO_AGENT_SIGNATURE'}
        try:
            self.c.call(self.contract, self._settle_data(row[0], transfer), sender=self.signer.address)
            return {'ok': True, 'code': None}
        except RpcError as e:
            return {'ok': False, 'code': e.revert or 'SIMULATION_ERROR'}

    def _record(self, key, block):
        sh = self.c.call(self.contract, call_data('records(bytes32)', key_id(key)), block=block)[:32]
        if sh == bytes(32):
            return None
        a = self._auth(key)
        return (a['digest'] if a and a['struct'] == sh.hex() else 'onchain-struct:' + sh.hex(), sh)

    def submit(self, key, transfer, now):
        a = self._auth(key)
        if a is None or a['digest'] != transfer_digest(transfer):
            prior = self.status(key)
            if prior['status'] != 'UNKNOWN':
                return prior
            return {'status': 'FAILED', 'ref': None, 'code': 'NO_AGENT_SIGNATURE', 'transfer_digest': transfer_digest(transfer)}
        return super().submit(key, transfer, now)
