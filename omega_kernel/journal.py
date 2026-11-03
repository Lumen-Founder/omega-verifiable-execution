"""Execution journal: one SQLite file binds intent state, policies and a hash-chained event log.

Same storage discipline as arena/store.py: WAL + synchronous=FULL, canonical JSON,
`previous` hash chain. Every state change is a compare-and-set against the explicit
transition table; an illegal move raises instead of silently overwriting.
"""
import hashlib
import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from omega_kernel.canonical import canonical
from omega_kernel.policy import Policy

TRANSITIONS = {
    None: {'REJECTED', 'ACCEPTED'},
    'ACCEPTED': {'SUBMITTING', 'EXPIRED', 'REJECTED'},
    'SUBMITTING': {'SUBMITTING', 'SUBMITTED', 'CONFIRMED', 'FAILED'},
    'SUBMITTED': {'SUBMITTED', 'CONFIRMED', 'FAILED'},
}
TERMINAL = {'REJECTED', 'CONFIRMED', 'FAILED', 'EXPIRED'}
RELEASED = {'REJECTED', 'FAILED', 'EXPIRED'}       # reservation no longer held
IN_FLIGHT = {'ACCEPTED', 'SUBMITTING', 'SUBMITTED'}
ZERO = '0' * 64
REDACT_KEY = re.compile(r'secret|private|passw|token|mnemonic|seed|api.?key|credential|^key$|^tag$', re.I)

SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policies(agent_id TEXT NOT NULL, version INTEGER NOT NULL, body TEXT NOT NULL,
  PRIMARY KEY(agent_id, version));
CREATE TABLE IF NOT EXISTS intents(intent_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, nonce INTEGER NOT NULL,
  digest TEXT NOT NULL, envelope TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, source TEXT,
  amount TEXT NOT NULL DEFAULT '0', reserved TEXT NOT NULL DEFAULT '0', asset TEXT, received_at INTEGER NOT NULL, accepted_at INTEGER,
  expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, ref TEXT,
  lease_until INTEGER NOT NULL DEFAULT 0, preflight TEXT, UNIQUE(agent_id, nonce));
CREATE INDEX IF NOT EXISTS intents_state ON intents(state);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, intent_id TEXT, kind TEXT NOT NULL,
  body TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);
'''


class StateConflict(RuntimeError):
    pass


def redact(value):
    """Defense in depth: envelopes already refuse secret-like fields; never let one reach disk."""
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if REDACT_KEY.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str) and len(value) > 512:
        return value[:512] + '...[truncated]'
    return value


def _event_hash(seq, at, intent_id, kind, body, previous):
    return hashlib.sha256(canonical({'seq': seq, 'at': at, 'intent_id': intent_id, 'kind': kind,
                                     'body': body, 'previous': previous})).hexdigest()


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(SCHEMA)  # executescript commits implicitly: run outside tx()

    def close(self):
        self.db.close()

    @contextmanager
    def tx(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield self.db
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            self.db.execute('COMMIT')

    # events -----------------------------------------------------------------
    def event(self, c, intent_id, kind, body, at):
        body = json.loads(canonical(redact(body)))
        tail = c.execute('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        seq, previous = (tail[0] + 1, tail[1]) if tail else (1, ZERO)
        h = _event_hash(seq, at, intent_id, kind, body, previous)
        c.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                  (seq, at, intent_id, kind, canonical(body).decode(), previous, h))
        return h

    def events(self, intent_id=None):
        q = 'SELECT * FROM events' + (' WHERE intent_id=?' if intent_id else '') + ' ORDER BY seq'
        return [dict(r) | {'body': json.loads(r['body'])} for r in self.db.execute(q, (intent_id,) if intent_id else ())]

    def verify_chain(self):
        previous = ZERO
        for r in self.db.execute('SELECT * FROM events ORDER BY seq'):
            body = json.loads(r['body'])
            if r['previous'] != previous or _event_hash(r['seq'], r['at'], r['intent_id'], r['kind'], body, previous) != r['hash']:
                return {'ok': False, 'first_bad_seq': r['seq']}
            previous = r['hash']
        return {'ok': True, 'head': previous}

    # policies ---------------------------------------------------------------
    def put_policy(self, c, policy, at):
        cur = self.policy(c, policy.agent_id)
        if cur is not None and policy.version <= cur.version:
            raise StateConflict('POLICY_VERSION_NOT_INCREASING')
        c.execute('INSERT INTO policies VALUES(?,?,?)', (policy.agent_id, policy.version, policy.to_json()))
        self.event(c, None, 'policy', json.loads(policy.to_json()), at)

    def policy(self, c, agent_id):
        r = c.execute('SELECT body FROM policies WHERE agent_id=? ORDER BY version DESC LIMIT 1', (agent_id,)).fetchone()
        return Policy.from_json(r[0]) if r else None

    # intents ----------------------------------------------------------------
    def get(self, c, intent_id):
        r = c.execute('SELECT * FROM intents WHERE intent_id=?', (intent_id,)).fetchone()
        return dict(r) if r else None

    def nonce_used(self, c, agent_id, nonce):
        return c.execute('SELECT 1 FROM intents WHERE agent_id=? AND nonce=?', (agent_id, nonce)).fetchone() is not None

    def insert(self, c, env, digest, state, reason, at, source=None, amount='0', reserved='0', preflight=None):
        if state not in TRANSITIONS[None]:
            raise StateConflict(f'ILLEGAL_INITIAL:{state}')
        c.execute('INSERT INTO intents(intent_id,agent_id,nonce,digest,envelope,state,reason,source,amount,reserved,asset,'
                  'received_at,accepted_at,expires_at,updated_at,preflight) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (env['intent_id'], env['agent_id'], env['nonce'], digest, canonical(env).decode(), state, reason,
                   source, amount if state == 'ACCEPTED' else '0', reserved if state == 'ACCEPTED' else '0',
                   env['params']['asset'], at, at if state == 'ACCEPTED' else None, env['expires_at'], at,
                   canonical(preflight).decode() if preflight is not None else None))
        self.event(c, env['intent_id'], 'state', {'from': None, 'to': state, 'reason': reason}, at)

    def move(self, c, intent_id, to, at, reason=None, **fields):
        row = self.get(c, intent_id)
        if row is None:
            raise StateConflict('NOT_FOUND')
        frm = row['state']
        if to not in TRANSITIONS.get(frm, set()):
            raise StateConflict(f'ILLEGAL_TRANSITION:{frm}->{to}')
        sets = {'state': to, 'updated_at': at} | ({'reason': reason} if reason is not None else {}) | fields
        if to in RELEASED:
            sets |= {'reserved': '0', 'lease_until': 0}
        cols = ','.join(f'{k}=?' for k in sets)
        cur = c.execute(f'UPDATE intents SET {cols} WHERE intent_id=? AND state=? AND attempts=?',
                        (*sets.values(), intent_id, frm, row['attempts']))
        if cur.rowcount != 1:
            raise StateConflict('CONCURRENT_UPDATE')
        self.event(c, intent_id, 'state', {'from': frm, 'to': to, 'reason': reason,
                                           **{k: v for k, v in fields.items() if k in ('attempts', 'ref')}}, at)
        return frm

    def usage(self, c, agent_id, since):
        """spend: amounts of accepted intents still holding or having used funds; calls: every
        authenticated intent recorded in the window, rejected ones included (a keyed agent must not
        be able to flood the journal with requests it knows will be denied)."""
        rows = c.execute('SELECT amount FROM intents WHERE agent_id=? AND accepted_at>=? AND state NOT IN '
                         "('REJECTED','FAILED','EXPIRED')", (agent_id, since)).fetchall()
        calls = c.execute('SELECT count(*) FROM intents WHERE agent_id=? AND received_at>=?', (agent_id, since)).fetchone()[0]
        return {'spend': sum(int(r[0]) for r in rows), 'calls': calls}

    def in_flight(self, c, source, asset):
        q = 'SELECT reserved FROM intents WHERE source=? AND asset=? AND state IN (?,?,?)'
        return sum(int(r[0]) for r in c.execute(q, (source, asset, *sorted(IN_FLIGHT))))

    def open_intents(self):
        q = 'SELECT intent_id FROM intents WHERE state IN (?,?,?) ORDER BY accepted_at, intent_id'
        return [r[0] for r in self.db.execute(q, tuple(sorted(IN_FLIGHT)))]
