"""OMEGA Agent Execution & Settlement Kernel (ADR-0001).

submit   validate -> authenticate -> (one transaction) dedupe/replay -> policy -> preflight -> ACCEPTED|REJECTED
execute  ACCEPTED -> SUBMITTING committed BEFORE the adapter is called (write-ahead), then the outcome
reconcile/recover  ask the adapter by idempotency key; resubmit the same key, or settle the record

Preflight values are predictions (`kind: predicted`); only the adapter's status settles an intent.
"""
import hashlib
import json
import time
import uuid
from omega_kernel import envelope as E
from omega_kernel import policy as P
from omega_kernel.journal import Journal, TERMINAL
from omega_kernel.settlement.base import transfer_digest


class Kernel:
    def __init__(self, journal, adapter, keyring, clock=time.time, lease_seconds=30, max_attempts=8, clock_skew=30):
        self.j = journal if isinstance(journal, Journal) else Journal(journal)
        self.a, self.keys, self.clock = adapter, keyring, clock
        self.lease_seconds, self.max_attempts, self.skew = lease_seconds, max_attempts, clock_skew
        self.owner = uuid.uuid4().hex[:12]

    def now(self):
        return int(self.clock())

    # admin --------------------------------------------------------------------
    def put_policy(self, policy):
        with self.j.tx() as c:
            self.j.put_policy(c, policy, self.now())

    # developer API: submit ----------------------------------------------------
    def submit(self, raw, auth_tag):
        now = self.now()
        try:
            env = E.parse(raw)
        except E.EnvelopeError as e:
            rawb = raw if isinstance(raw, (bytes, bytearray)) else (raw if isinstance(raw, str) else json.dumps(raw, default=str)).encode('utf-8', 'replace')
            with self.j.tx() as c:
                self.j.event(c, None, 'input_rejected', {'code': e.code, 'raw_sha256': hashlib.sha256(rawb[:65536]).hexdigest()}, now)
            return {'ok': False, 'state': None, 'code': e.code}
        d = E.digest(env)
        key = self.keys.get(env['agent_id'])
        if key is None or not E.verify_tag(key, env, auth_tag):
            # no intent row: an unauthenticated caller must not consume the victim's nonce or intent_id
            with self.j.tx() as c:
                self.j.event(c, None, 'auth_failed', {'agent_id': env['agent_id'], 'digest': d}, now)
            return {'ok': False, 'state': None, 'code': 'AUTH_FAILED'}
        with self.j.tx() as c:
            row = self.j.get(c, env['intent_id'])
            if row is not None:
                if row['digest'] == d:
                    return self._receipt(row, duplicate=True)
                self.j.event(c, None, 'intent_id_conflict', {'intent_id': env['intent_id'], 'digest': d}, now)
                return {'ok': False, 'state': None, 'code': 'INTENT_ID_CONFLICT'}
            if self.j.nonce_used(c, env['agent_id'], env['nonce']):
                self.j.event(c, None, 'replay_rejected', {'agent_id': env['agent_id'], 'nonce': env['nonce'], 'digest': d}, now)
                return {'ok': False, 'state': None, 'code': 'REPLAY_NONCE'}
            pol = self.j.policy(c, env['agent_id'])
            code = None
            if now + self.skew < env['created_at']:
                code = 'INTENT_NOT_YET_VALID'
            elif now >= env['expires_at']:
                code = 'EXPIRED_ON_ARRIVAL'
            if code is None:
                usage = self.j.usage(c, env['agent_id'], now - pol.window_seconds) if pol else None
                code = P.evaluate(pol, env, usage, now)
            self.j.event(c, env['intent_id'], 'policy_decision',
                         {'decision': code or 'ALLOW', 'policy_version': pol.version if pol else None, 'digest': d}, now)
            pre = None
            if code is None:
                pre, code = self._preflight(c, pol, env, now)
                self.j.event(c, env['intent_id'], 'preflight', pre | {'decision': code or 'PASS'}, now)
            if code:
                self.j.insert(c, env, d, 'REJECTED', code, now, source=pol.source_account if pol else None, preflight=pre)
            else:
                self.j.insert(c, env, d, 'ACCEPTED', None, now, source=pol.source_account, amount=env['params']['amount'],
                              reserved=str(pre['reserve']), preflight=pre)
            return self._receipt(self.j.get(c, env['intent_id']))

    def _transfer(self, source, env):
        return {'source': source, 'target': env['target'], 'asset': env['params']['asset'],
                'amount': int(env['params']['amount']), 'fee_limit': int(env['constraints'].get('max_fee', 10 ** 30)),
                'deadline': env['expires_at']}

    def _preflight(self, c, pol, env, now):
        t = self._transfer(pol.source_account, env)
        fee = self.a.estimate_fee(t)
        pre = {'kind': 'predicted', 'at': now, 'fee_estimate': fee, 'reserve': t['amount'] + fee}
        if fee > pol.max_fee_per_intent:
            return pre, 'FEE_OVER_POLICY'
        if fee > t['fee_limit']:
            return pre, 'FEE_OVER_MAX'
        bal, held = self.a.balance(t['source'], t['asset']), self.j.in_flight(c, t['source'], t['asset'])
        pre |= {'balance_seen': bal, 'in_flight_reserved': held}
        if bal - held < t['amount'] + fee:
            return pre, 'INSUFFICIENT_BALANCE'
        sim = self.a.simulate(t)
        pre['simulation'] = sim
        if not sim['ok']:
            return pre, 'SIMULATION_FAILED'
        return pre, None

    # developer API: execution ---------------------------------------------------
    def execute(self, intent_id):
        now = self.now()
        with self.j.tx() as c:
            row = self.j.get(c, intent_id)
            if row is None:
                return {'ok': False, 'code': 'NOT_FOUND'}
            if row['state'] in ('SUBMITTING', 'SUBMITTED'):
                claimed = None  # already in flight: reconcile below
            elif row['state'] != 'ACCEPTED':
                return self._receipt(row)
            elif now >= row['expires_at']:
                self.j.move(c, intent_id, 'EXPIRED', now, reason='EXPIRED_BEFORE_SUBMIT')
                return self._receipt(self.j.get(c, intent_id))
            else:
                code = P.still_allows(self.j.policy(c, row['agent_id']), json.loads(row['envelope']), now)
                if code:
                    self.j.move(c, intent_id, 'REJECTED', now, reason='POLICY_CHANGED:' + code)
                    return self._receipt(self.j.get(c, intent_id))
                self.j.move(c, intent_id, 'SUBMITTING', now, attempts=row['attempts'] + 1, lease_until=now + self.lease_seconds)
                claimed = self.j.get(c, intent_id)
        # the SUBMITTING row is committed (write-ahead) before the adapter is contacted
        return self._call_adapter(claimed) if claimed else self.reconcile(intent_id)

    def _call_adapter(self, row):
        now = self.now()
        env = json.loads(row['envelope'])
        t = self._transfer(row['source'], env)
        try:
            r = self.a.submit(row['intent_id'], t, now)
        except Exception as e:  # outcome unknown: keep SUBMITTING, release lease for reconcile
            with self.j.tx() as c:
                self.j.event(c, row['intent_id'], 'attempt', {'n': row['attempts'], 'outcome': 'TRANSPORT_ERROR',
                                                              'error_class': type(e).__name__}, now)
                c.execute('UPDATE intents SET lease_until=0 WHERE intent_id=? AND state=?', (row['intent_id'], 'SUBMITTING'))
                return self._receipt(self.j.get(c, row['intent_id']))
        with self.j.tx() as c:
            self.j.event(c, row['intent_id'], 'attempt', {'n': row['attempts'], 'outcome': r['status'], 'code': r.get('code')}, now)
            return self._settle(c, row['intent_id'], r, now)

    def _settle(self, c, intent_id, r, now):
        row = self.j.get(c, intent_id)
        if r['status'] == 'CONFIRMED':
            self.j.move(c, intent_id, 'CONFIRMED', now, ref=r['ref'], lease_until=0)
        elif r['status'] == 'FAILED':
            self.j.move(c, intent_id, 'FAILED', now, reason='SETTLEMENT_FAILED:' + str(r.get('code')))
        elif r['status'] == 'PENDING':
            if row['state'] == 'SUBMITTING':
                self.j.move(c, intent_id, 'SUBMITTED', now, ref=r.get('ref'), lease_until=0)
        return self._receipt(self.j.get(c, intent_id))

    def reconcile(self, intent_id):
        now = self.now()
        with self.j.tx() as c:
            row = self.j.get(c, intent_id)
            if row is None:
                return {'ok': False, 'code': 'NOT_FOUND'}
            if row['state'] not in ('SUBMITTING', 'SUBMITTED') or row['lease_until'] > now:
                return self._receipt(row)
        try:
            s = self.a.status(intent_id)
        except Exception as e:
            with self.j.tx() as c:
                self.j.event(c, intent_id, 'status_error', {'error_class': type(e).__name__}, now)
                return self._receipt(self.j.get(c, intent_id))
        with self.j.tx() as c:
            row = self.j.get(c, intent_id)
            if row['state'] not in ('SUBMITTING', 'SUBMITTED'):
                return self._receipt(row)
            ours = transfer_digest(self._transfer(row['source'], json.loads(row['envelope'])))
            self.j.event(c, intent_id, 'settlement_status', {'status': s['status'], 'code': s.get('code')}, now)
            if s['status'] != 'UNKNOWN' and s.get('transfer_digest') != ours:
                self.j.event(c, intent_id, 'integrity_mismatch', {'adapter_digest': s.get('transfer_digest'), 'ours': ours}, now)
                return self._receipt(row) | {'needs_attention': 'INTEGRITY_MISMATCH'}
            if s['status'] in ('CONFIRMED', 'FAILED', 'PENDING'):
                return self._settle(c, intent_id, s, now)
            # UNKNOWN: the adapter never recorded this key
            if row['state'] == 'SUBMITTED':
                self.j.event(c, intent_id, 'needs_attention', {'why': 'SUBMITTED_BUT_ADAPTER_UNKNOWN'}, now)
                return self._receipt(row) | {'needs_attention': 'SUBMITTED_BUT_ADAPTER_UNKNOWN'}
            if now >= row['expires_at']:
                if self.a.deadline_enforced:
                    self.j.move(c, intent_id, 'FAILED', now, reason='DEADLINE_PASSED_UNSETTLED')
                    return self._receipt(self.j.get(c, intent_id))
                return self._receipt(row) | {'needs_attention': 'DEADLINE_PASSED_BACKEND_NOT_ENFORCING'}
            if row['attempts'] >= self.max_attempts:
                return self._receipt(row) | {'needs_attention': 'MAX_ATTEMPTS'}
            self.j.move(c, intent_id, 'SUBMITTING', now, attempts=row['attempts'] + 1, lease_until=now + self.lease_seconds)
            row = self.j.get(c, intent_id)
        return self._call_adapter(row)

    def recover(self):
        """Drive every non-terminal intent forward once. Safe to run at every start-up."""
        return {i: self.execute(i).get('state') for i in self.j.open_intents()}

    # developer API: queries ---------------------------------------------------------
    def status(self, intent_id):
        with self.j.tx() as c:
            row = self.j.get(c, intent_id)
        return self._receipt(row) if row else {'ok': False, 'code': 'NOT_FOUND'}

    def verify(self, intent_id):
        """Journal chain integrity + cross-check of the journal state against the settlement backend."""
        st = self.status(intent_id)
        if st.get('state') is None:  # not found; REJECTED/FAILED records (ok=False) are still verified
            return st
        chain = self.j.verify_chain()
        s = self.a.status(intent_id)
        state, issues = st['state'], []
        if state == 'CONFIRMED' and s['status'] != 'CONFIRMED':
            issues.append('JOURNAL_CONFIRMED_BACKEND_NOT')
        if state in ('REJECTED', 'FAILED', 'EXPIRED') and s['status'] == 'CONFIRMED':
            issues.append('BACKEND_SETTLED_JOURNAL_NOT')
        if state == 'ACCEPTED' and s['status'] != 'UNKNOWN':
            issues.append('BACKEND_SAW_UNSUBMITTED_INTENT')
        if not chain['ok']:
            issues.append('JOURNAL_CHAIN_BROKEN')
        return {'ok': True, 'intent_id': intent_id, 'journal_state': state, 'backend': s, 'journal_chain': chain,
                'consistent': not issues, 'issues': issues,
                'events': [e['kind'] for e in self.j.events(intent_id)]}

    def recovery_report(self):
        out = []
        for i in self.j.open_intents():
            st = self.status(i)
            out.append({k: st[k] for k in ('intent_id', 'state', 'attempts', 'reason')} |
                       {'needs_attention': st['attempts'] >= self.max_attempts})
        return {'open': out, 'journal_chain': self.j.verify_chain()}

    def _receipt(self, row, duplicate=False):
        return {'ok': row['state'] not in ('REJECTED', 'FAILED', 'EXPIRED'), 'intent_id': row['intent_id'],
                'state': row['state'], 'reason': row['reason'], 'attempts': row['attempts'], 'ref': row['ref'],
                'terminal': row['state'] in TERMINAL, 'duplicate': duplicate,
                'preflight': json.loads(row['preflight']) if row['preflight'] else None}

