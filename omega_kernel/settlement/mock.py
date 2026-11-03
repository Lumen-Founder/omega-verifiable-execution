"""Mock settlement backend: a separate SQLite ledger standing in for an external chain.

Fault injection reproduces the cases the kernel must survive:
  fail_before_commit  transport error, nothing recorded
  lose_ack            transfer committed, caller gets a timeout (ambiguous outcome)
  pending             accepted into a mempool-like queue; settles or fails at mine()
Amounts are stored as decimal text so values up to 10**30 stay exact.
"""
import sqlite3
import threading
from omega_kernel.settlement.base import SettlementAdapter, transfer_digest

FEE_SINK = 'acct:fee-sink'


class MockLedger(SettlementAdapter):
    chain_id = 'mock-1'
    deadline_enforced = True

    def __init__(self, path, fee=1000):
        self.fee, self.lock = fee, threading.RLock()
        self.db = sqlite3.connect(str(path), timeout=30, isolation_level=None, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS balances(account TEXT, asset TEXT, amount TEXT NOT NULL, PRIMARY KEY(account, asset));
          CREATE TABLE IF NOT EXISTS txs(key TEXT PRIMARY KEY, digest TEXT NOT NULL, source TEXT, target TEXT, asset TEXT,
            amount TEXT, fee TEXT, status TEXT NOT NULL, code TEXT, ref TEXT, at INTEGER);
        ''')
        self.faults = {'fail_before_commit': 0, 'lose_ack': 0, 'pending': False}
        self.calls = {'submit': 0, 'status': 0}

    def close(self):
        self.db.close()

    # read side ---------------------------------------------------------------
    def _bal(self, account, asset):
        r = self.db.execute('SELECT amount FROM balances WHERE account=? AND asset=?', (account, asset)).fetchone()
        return int(r[0]) if r else 0

    def balance(self, account, asset):
        with self.lock:
            return self._bal(account, asset)

    def estimate_fee(self, transfer):
        return self.fee

    def _check(self, t):
        if t['fee_limit'] < self.fee:
            return 'FEE_LIMIT'
        if self._bal(t['source'], t['asset']) < t['amount'] + self.fee:
            return 'INSUFFICIENT_FUNDS'
        return None

    def simulate(self, transfer):
        with self.lock:
            code = self._check(transfer)
        return {'ok': code is None, 'code': code}

    def status(self, key):
        with self.lock:
            self.calls['status'] += 1
            r = self.db.execute('SELECT status, ref, code, digest FROM txs WHERE key=?', (key,)).fetchone()
        if r is None:
            return {'status': 'UNKNOWN', 'ref': None, 'code': None, 'transfer_digest': None}
        return {'status': r[0], 'ref': r[1], 'code': r[2], 'transfer_digest': r[3]}

    def total(self, asset):
        with self.lock:
            return sum(int(r[0]) for r in self.db.execute('SELECT amount FROM balances WHERE asset=?', (asset,)))

    def settled_count(self, key=None):
        q = "SELECT count(*) FROM txs WHERE status='CONFIRMED'" + (' AND key=?' if key else '')
        with self.lock:
            return self.db.execute(q, (key,) if key else ()).fetchone()[0]

    # write side --------------------------------------------------------------
    def mint(self, account, asset, amount):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            self._add(account, asset, amount)
            self.db.execute('COMMIT')

    def _add(self, account, asset, delta):
        new = self._bal(account, asset) + delta
        if new < 0:
            raise ValueError('NEGATIVE_BALANCE')
        self.db.execute('INSERT INTO balances VALUES(?,?,?) ON CONFLICT(account, asset) DO UPDATE SET amount=excluded.amount',
                        (account, asset, str(new)))

    def _apply(self, key):
        """Settle a recorded tx atomically (caller holds the write transaction)."""
        k, d, src, dst, asset, amount, fee = self.db.execute(
            'SELECT key,digest,source,target,asset,amount,fee FROM txs WHERE key=?', (key,)).fetchone()
        amount, fee = int(amount), int(fee)
        if self._bal(src, asset) < amount + fee:
            self.db.execute("UPDATE txs SET status='FAILED', code='INSUFFICIENT_FUNDS' WHERE key=?", (key,))
            return 'FAILED'
        self._add(src, asset, -(amount + fee))
        self._add(dst, asset, amount)
        self._add(FEE_SINK, asset, fee)
        self.db.execute("UPDATE txs SET status='CONFIRMED', ref=? WHERE key=?", ('mock:' + d[:16], key))
        return 'CONFIRMED'

    def submit(self, key, transfer, now):
        d = transfer_digest(transfer)
        with self.lock:
            self.calls['submit'] += 1
            prior = self.status(key)
            if prior['status'] != 'UNKNOWN':
                if prior['transfer_digest'] != d:
                    return {'status': 'FAILED', 'ref': None, 'code': 'KEY_REUSE', 'transfer_digest': d}
                return prior
            if self.faults['fail_before_commit'] > 0:
                self.faults['fail_before_commit'] -= 1
                raise ConnectionError('mock transport failure before commit')
            code = 'DEADLINE_PASSED' if now >= transfer['deadline'] else self._check(transfer)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO txs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                                (key, d, transfer['source'], transfer['target'], transfer['asset'], str(transfer['amount']),
                                 str(self.fee), 'FAILED' if code else 'PENDING', code, None, now))
                if code is None and not self.faults['pending']:
                    self._apply(key)
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            if self.faults['lose_ack'] > 0:
                self.faults['lose_ack'] -= 1
                raise TimeoutError('mock ack lost after commit')
            return self.status(key)

    def move(self, key, source, target, asset, amount, now):
        """Fee-free, key-idempotent internal transfer: models a contract moving funds it holds (escrow
        payout) inside a transaction whose gas the caller pays, so the escrow itself is not charged."""
        d = transfer_digest({'kind': 'move', 'source': source, 'target': target, 'asset': asset, 'amount': amount})
        with self.lock:
            prior = self.status(key)
            if prior['status'] != 'UNKNOWN':
                return prior if prior['transfer_digest'] == d else {'status': 'FAILED', 'ref': None, 'code': 'KEY_REUSE',
                                                                    'transfer_digest': d}
            if self.faults['fail_before_commit'] > 0:
                self.faults['fail_before_commit'] -= 1
                raise ConnectionError('mock transport failure before commit')
            ok = type(amount) is int and amount > 0 and self._bal(source, asset) >= amount
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO txs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                                (key, d, source, target, asset, str(amount), '0', 'CONFIRMED' if ok else 'FAILED',
                                 None if ok else 'INSUFFICIENT_FUNDS', 'mock:' + d[:16] if ok else None, now))
                if ok:
                    self._add(source, asset, -amount)
                    self._add(target, asset, amount)
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            if self.faults['lose_ack'] > 0:
                self.faults['lose_ack'] -= 1
                raise TimeoutError('mock ack lost after commit')
            return self.status(key)

    def mine(self):
        """Settle every PENDING tx (in key order). Returns {key: status}."""
        out = {}
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            for (key,) in self.db.execute("SELECT key FROM txs WHERE status='PENDING' ORDER BY at, key").fetchall():
                out[key] = self._apply(key)
            self.db.execute('COMMIT')
        return out
