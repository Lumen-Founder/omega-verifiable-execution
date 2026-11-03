"""Compute job market over a SettlementAdapter: escrowed reward, executor/challenger bonds, slashing.

Flow: the requester funds acct:escrow:<job> (normally through the kernel, so the payment obeys its policy);
an executor posts a claim plus a bond; within the challenge window anyone may challenge with a bond, and the
dispute is resolved by the Referee (bisection + one-step proof). Every payment is key-idempotent, so a crash
or lost acknowledgement during finalize() is repaired by calling finalize() again.

Payouts (escrow always drains to zero):
  executor wins / no dispute   executor <- reward + own bond + every losing challenger bond
  executor proven wrong        requester <- reward;  winning challenger <- own bond + executor bond
                               + every earlier losing challenger bond
"""
from omega_compute import vm
from omega_compute.dispute import Referee


class MarketError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ComputeMarket:
    def __init__(self, adapter, clock, window=600, bond=10_000, asset='USDC', claim_timeout=3600):
        self.a, self.clock, self.window, self.bond, self.asset = adapter, clock, window, bond, asset
        self.claim_timeout, self.jobs = claim_timeout, {}

    @staticmethod
    def escrow(job_id):
        return f'acct:escrow:{job_id}'

    def open_job(self, job_id, requester, program, inputs, max_steps, reward):
        if job_id in self.jobs:
            raise MarketError('JOB_EXISTS')
        vm.initial(vm.check_program(program), inputs)
        self.jobs[job_id] = {'requester': requester, 'program': program, 'inputs': inputs, 'max_steps': max_steps,
                             'reward': reward, 'opened': self.clock(), 'state': 'OPEN', 'claim': None, 'executor': None,
                             'deadline': None, 'challenges': [], 'outcome': None, 'payouts': None}
        return self.jobs[job_id]

    def _job(self, job_id, *states):
        j = self.jobs.get(job_id)
        if j is None:
            raise MarketError('NO_JOB')
        if states and j['state'] not in states:
            raise MarketError('BAD_STATE:' + j['state'])
        return j

    def funded(self, job_id, kernel=None, intent_id=None):
        """Ground truth is the escrow balance; if a kernel intent is named it must also be CONFIRMED and consistent."""
        j = self._job(job_id)
        if kernel is not None:
            v = kernel.verify(intent_id)
            if v.get('journal_state') != 'CONFIRMED' or not v.get('consistent'):
                return False
        return self.a.balance(self.escrow(job_id), self.asset) >= j['reward']

    def _bond_in(self, job_id, key, account):
        r = self.a.move(f'{job_id}:{key}', account, self.escrow(job_id), self.asset, self.bond, self.clock())
        if r['status'] != 'CONFIRMED':
            raise MarketError('BOND_NOT_POSTED:' + str(r.get('code')))

    def post_claim(self, job_id, executor_account, submission):
        j = self._job(job_id, 'OPEN')
        if not self.funded(job_id):
            raise MarketError('NOT_FUNDED')
        ref = Referee(j['program'], j['inputs'], j['max_steps'])
        refusal = ref.validate_claim(*submission)
        if refusal:
            raise MarketError('CLAIM_REFUSED:' + refusal)
        self._bond_in(job_id, 'bond:executor', executor_account)
        j.update(state='CLAIMED', claim=submission[0], executor=executor_account, deadline=self.clock() + self.window)
        return j

    def challenge(self, job_id, challenger_account, challenger, executor):
        """Synchronous interactive dispute (prototype: both parties answer in-process)."""
        j = self._job(job_id, 'CLAIMED')
        if self.clock() >= j['deadline']:
            raise MarketError('WINDOW_CLOSED')
        i = len(j['challenges'])
        self._bond_in(job_id, f'bond:challenger:{i}', challenger_account)
        res = Referee(j['program'], j['inputs'], j['max_steps']).resolve(j['claim'], executor, challenger)
        j['challenges'].append({'account': challenger_account, 'winner': res['winner'], 'reason': res['reason'],
                                'cost': res['cost']})
        if res['winner'] == 'challenger':
            j.update(state='FRAUD', outcome={'winner': 'challenger', 'by': challenger_account, 'reason': res['reason']})
        return res

    def _plan(self, j):
        losing = [c for c in j['challenges'] if c['winner'] == 'executor']
        if j['state'] == 'FRAUD':
            return [('refund', j['requester'], j['reward']),
                    ('challenger', j['outcome']['by'], self.bond * (2 + len(losing)))]
        if j['state'] == 'CLAIMED':
            return [('executor', j['executor'], j['reward'] + self.bond * (1 + len(losing)))]
        return [('refund', j['requester'], j['reward'])]  # EXPIRED: nobody claimed in time

    def finalize(self, job_id):
        j = self._job(job_id, 'CLAIMED', 'FRAUD', 'EXPIRING', 'SETTLING', 'SETTLED')
        now = self.clock()
        if j['state'] == 'CLAIMED' and now < j['deadline']:
            raise MarketError('WINDOW_OPEN')
        if j['state'] in ('CLAIMED', 'FRAUD', 'EXPIRING'):
            j['payouts'] = self._plan(j)
            j['state'] = 'SETTLING'
        out = []
        for name, account, amount in j['payouts']:
            r = self.a.move(f'{job_id}:payout:{name}', self.escrow(job_id), account, self.asset, amount, now)
            if r['status'] != 'CONFIRMED':
                raise MarketError('PAYOUT_FAILED:' + str(r.get('code')))
            out.append((name, account, amount))
        j['state'] = 'SETTLED'
        return {'job_id': job_id, 'payouts': out, 'escrow_left': self.a.balance(self.escrow(job_id), self.asset)}

    def expire(self, job_id):
        j = self._job(job_id, 'OPEN')
        if self.clock() < j['opened'] + self.claim_timeout:
            raise MarketError('NOT_EXPIRED')
        j['state'] = 'EXPIRING'
        return self.finalize(job_id)
