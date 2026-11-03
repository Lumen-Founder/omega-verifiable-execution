"""The outside team's kit (tools/world/repro_kit.py, omega_world.e2e) on a local anvil: the whole job ends with nothing left in the
escrow, the accounting is the one written down here, two runs from nothing give the same digests, and a run that differs does not."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from omega_world import e2e as E2E

ROOT = Path(__file__).resolve().parent.parent
KIT = ROOT / 'tools' / 'world' / 'repro_kit.py'
ANVIL = Path.home() / '.foundry' / 'bin' / ('anvil.exe' if os.name == 'nt' else 'anvil')


@unittest.skipUnless(ANVIL.exists(), 'foundry not installed')
class Kit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.a, cls.b = Path(cls.tmp.name) / 'a', Path(cls.tmp.name) / 'b'
        cls.codes = [subprocess.run([sys.executable, '-X', 'utf8', '-B', str(KIT), 'local', str(w)], cwd=ROOT, capture_output=True,
                                    text=True, timeout=600).returncode for w in (cls.a, cls.b)]
        cls.result = json.loads((cls.a / 'RESULT.json').read_text(encoding='utf-8'))
        cls.got = cls.result['transcript']

    def test_the_run_passes_and_the_escrow_ends_empty(self):
        self.assertEqual(self.codes, [0, 0])
        self.assertTrue(self.result['ok'])
        close = self.result['close']
        self.assertEqual(close['escrow_tokens_left'], 0)
        self.assertEqual(close['totals'], {'locked': 0, 'bondsHeld': 0, 'coversHeld': 0})
        self.assertEqual(close['dispute_contract_wei_left'], close['dispute_burned_wei'])
        self.assertEqual(close['refund']['before'], close['refund']['after_expiry'])  # the price came back

    def test_the_accounting(self):
        """three prices of 1,000 paid, 100 of comps from the liar's cover, the liar's 1,250 bond to the account"""
        e = self.got['economics']
        net = {k: v['out'] - v['in'] for k, v in e['token_flows'].items()}
        self.assertEqual(net, {'owner': -3_000 + 1_250, 'executor': 3_000 + 100, 'liar': -1_250 - 100})
        self.assertEqual(sum(net.values()), 0)  # nobody else took anything: no fee, no treasury
        self.assertNotIn('other', e['token_flows'])
        self.assertEqual(e['nodes']['R#0']['events'], [['Posted'], ['Expired']])
        self.assertEqual(e['nodes']['A#0']['claim']['status'], 'rejected')
        self.assertEqual(e['nodes']['A#0']['claim']['games'][0]['challenger'], 'watcher')
        self.assertEqual({k: e['outputs'][k]['output'] for k in ('A#1', 'B#1', 'C#1')}, {'A#1': 55, 'B#1': 56, 'C#1': 112})

    def test_two_runs_from_nothing_give_the_same_digests(self):
        other = json.loads((self.b / 'TRANSCRIPT.json').read_text(encoding='utf-8'))
        self.assertEqual(E2E.compare(self.got, other), [])
        self.assertEqual(self.got['economics_sha256'], other['economics_sha256'])
        self.assertNotEqual(self.got['contracts'], other['contracts'])  # the digests do not depend on addresses

    def test_compare_finds_a_changed_amount(self):
        forged = copy.deepcopy(self.got)
        forged['economics']['token_flows']['executor']['out'] += 1
        forged['economics_sha256'] = E2E._digest(forged['economics'])
        self.assertEqual(E2E.compare(self.got, forged), [{'economics': 'token_flows'}])
        forged = copy.deepcopy(self.got)
        forged['economics']['nodes']['R#0']['events'] = [['Posted']]
        forged['economics_sha256'] = E2E._digest(forged['economics'])
        self.assertEqual([d.get('job') or d.get('economics') for d in E2E.compare(self.got, forged)], ['nodes', 'R#0'])

    def test_compare_finds_another_build(self):
        forged = copy.deepcopy(self.got)
        forged['build']['OVM0Step'] = '00'
        forged['build_sha256'] = E2E._digest(forged['build'])
        self.assertEqual(E2E.compare(self.got, forged), [{'build': ['OVM0Step']}])

    def test_nothing_secret_in_what_is_published(self):
        run = (self.a / 'RUN.json').read_text(encoding='utf-8')
        self.assertFalse(any('key' in k.lower() for k in json.loads(run)['roles']))
        self.assertFalse(list(self.a.glob('**/*.key')))  # the local keys are gone with the run

    def test_the_closing_step_refuses_an_unfinished_rehearsal(self):
        from omega_kernel.settlement.evm import Chain
        with self.assertRaisesRegex(RuntimeError, 'REHEARSAL_NOT_FINISHED'):
            with tempfile.TemporaryDirectory(dir=self.tmp.name) as empty:
                chain = Chain.__new__(Chain)
                chain.chain_id, chain.armed, chain.read_only = 11_155_111, None, False
                chain.rpc = lambda m, *a: hex(11_155_111)
                E2E.close(chain, {}, {'chain_id': 11_155_111, 'authorized': False}, empty)


class Bundle(unittest.TestCase):
    """the kit's zip alone runs: a module it needs outside the zip (directional0 was one, found on Linux 2026-11-03) fails
    here, and the audit package holds every file the kit's code needs"""

    def test_the_zip_alone_imports_everything(self):
        import zipfile
        with tempfile.TemporaryDirectory() as tmp:
            got = subprocess.run([sys.executable, '-X', 'utf8', '-B', str(KIT), 'bundle', tmp], cwd=ROOT, capture_output=True,
                                 text=True, timeout=300)
            self.assertEqual(got.returncode, 0, got.stderr)
            zpath = next(Path(tmp).glob('OMEGA_REPRO_KIT_*.zip'))
            names = zipfile.ZipFile(zpath).namelist()
            zipfile.ZipFile(zpath).extractall(Path(tmp) / 'kit')
            probe = ('import sys, runpy; sys.argv = ["repro_kit.py"]; sys.path.insert(0, ".")\n'
                     'import omega_world.e2e, omega_world.rehearsal, omega_world.daemon, omega_world.sdk, omega_world.cannon_agent\n'
                     'runpy.run_path("tools/world/repro_kit.py", run_name="__main__")')
            run = subprocess.run([sys.executable, '-I', '-X', 'utf8', '-B', '-c', probe], cwd=Path(tmp) / 'kit', capture_output=True,
                                 text=True, timeout=120)
            self.assertNotIn('ModuleNotFoundError', run.stderr, run.stderr[-2000:])
            self.assertIn('repro_kit.py local', run.stdout)  # the usage text: it got as far as main()
        sys.path.insert(0, str(ROOT / 'tools' / 'world'))
        import audit_package as AP
        specs = [s for v in AP.SCOPE.values() for s in v]
        code = [n for n in names if n.endswith('.py') and n.split('/')[0] in ('omega_world', 'omega_compute', 'omega_kernel')]
        self.assertEqual([n for n in code if not any(n == s or n.startswith(s.rstrip('/') + '/') for s in specs)], [])


if __name__ == '__main__':
    unittest.main()
