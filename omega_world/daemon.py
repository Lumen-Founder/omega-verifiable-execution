"""The long-running driver of the world stack (READINESS_AUDIT A08, A16; docs/world_computer/RUNBOOK_DEPLOY.md section 1-7): it
ticks the plans it finds, steps the executors and watchers, runs the monitor, delivers alerts and says it is alive.

    python -X utf8 -B -m omega_world.daemon run <config.json>                                 # exit 2: refused, see stderr
    python -X utf8 -B -m omega_world.daemon check-heartbeat <heartbeat.json> <max age s>      # exit 1: stale, unreadable, not ok
    python -X utf8 -B -m omega_world.daemon verify-archive <archive.jsonl>                    # exit 1: damaged or not there
    python -X utf8 -B -m omega_world.daemon backup <archive.jsonl> <dest dir>                 # exit 1: damaged or not there, not copied
    python -X utf8 -B -m omega_world.daemon reset-archive <config.json>                       # aside, and again from the chain

What a crash can leave behind is nothing it needs: plans are files, executors and watchers re-read the chain (they keep no
state), the archive repairs its own tail and follows a reorganization, and state.json only holds what was already told to whom
and what is not delivered yet. So a kill at any moment, a restart, a lost RPC answer change nothing on chain (the same calls are safe twice, D2, D10).
One process owns a state folder (a kernel lock, gone with the process).

A role's failure is that role's: every step is isolated, a failing one alerts after `fail_alert_after` passes in a row while
the others go on, the pass slows down only when everything failed. What a role swallows and goes on without it says in failing()
(a {kind: detail}, empty when healthy), read after each step: ROLE_FAILING, told once. The monitor failing is an alert too; the
process dying is what a heartbeat is for: check-heartbeat from another machine's timer, or another daemon's `watch_heartbeats`.

Keys: on a test chain from OMEGA_DAEMON_KEYS/<name>.key, read only into LocalTestSigner objects. On any other chain this entry
point has no key path at all (KEY_FILES_ON_PRODUCTION_CHAIN): a process that only reads (monitor, archive) needs none and uses
ReadOnlyChain; writing roles there need the user's arming (`arm_config`, RUNBOOK_DEPLOY) and signer objects from a real signer
through build_stack(cfg, signers=...), which does not exist in this repository yet.

Configuration (JSON). Only what is present runs; addresses are 0x hex:
    chain_id, rpc_urls [in order of preference], escrow, state_dir: required
    allow_remote (default false), rpc_timeout_s (30), receipt_timeout_s (30)
    deploy_config, manifest: the deploy/chains file and the deployment's manifest. They give every role that stakes or posts the
    pins (deploy.referee_guards) and the monitor its pin check. On a production chain a process without them does not start
    (NO_PINS_ON_PRODUCTION_CHAIN); on a test chain it runs without. monitor.deploy_config and monitor.manifest count too.
    max_fee_cap_wei, urgent_fee_cap_wei (default the deploy_config's, else 200 gwei): evm.Chain; the urgent one is for the keys of
    executors and watchers. On a production chain the armed file's values are ceilings.
    token, from_block (0), confirmations (default by chain), archive
    interval_s (12), monitor_every (1), fail_alert_after (3), max_backoff_s (300), stall_s (default 300, off on 31337 and 1337),
    renotify_s (3600), heartbeat (default <state_dir>/heartbeat.json), name (default 'omega')
    boards [OVM0Dispute addresses], inbox (default the boards')
    orchestrator {agent, relayer, plans_dir}: key names; a plan is a file <plans_dir>/*.json of Plan.to_json
    executors [{key, board, accounts, referees, min_price, max_cover, max_lock_s?, min_eth_wei?, keep_stake?, payout?}]
    watchers [{key, board, gas_reserve_wei?}]: the ether a challenge must leave; default: the worst game on today's mainnet rules
    cannon {referee, inbox, toolchain, work, known_programs?, executor {key, withstand_wei, accounts, referees, min_price, max_cover, keep_stake?,
            payout?, gas_price_wei?}?, watcher {key}?}
    op {referee, factory, game_type, inbox, l2_rpc, executor {key, accounts, referees, min_price, max_cover}?, challenger {key}?}
    monitor {accounts?, false_claim_grace_s (600), watch_heartbeats {name: {path, max_age_s}}?,
             capital {referee: {withstand_wei, watcher, gas_price_wei?}}?, archive_tail (64), full_check_every (100), codec?}
    alerts {file, command [argv], webhook, command_min_severity ('medium'), webhook_min_severity ('medium')}
    arm_config (a production chain's deploy/chains file; the user's)

Alert events are JSON objects: {t, event: raised|repeat|cleared, code, severity, key, detail, source}. The command gets one on
stdin per run (no shell), the webhook one per POST. No URL, no key and no path of a key is ever in an event or a heartbeat."""
import http.client
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from omega_compute import evm_step as E
from omega_compute import evm_step_m as EM
from omega_compute.dispute_agent import Board, Watchtower
from omega_kernel.settlement.evm import TX_GAS_CAP, NOT_RANGE, RANGE_REFUSALS, TEST_CHAIN_IDS, Chain, ReadOnlyChain, Rpc, RpcError
from omega_kernel.settlement.evm_crypto import LocalTestSigner, keccak
from omega_world import cannon as CN
from omega_world import cannon_agent as CA
from omega_world import deploy as DP
from omega_world import indexer as IX
from omega_world import monitor as MON
from omega_world import op_attest as OA
from omega_world import referee_policy as RP
from omega_world.executor import AcceptPolicy, WorldExecutor
from omega_world.plan import Plan, PlanError
from omega_world.sdk import WorldClient

NO_ANSWER = (OSError, http.client.HTTPException, ValueError, TypeError, KeyError, AttributeError)  # the endpoint, not the request
# what a request itself caused: another endpoint would say the same, and it must reach the caller as it is. Everything else in a
# JSON-RPC error is the provider's (auth, internal, upstream, a block it has not got): the next endpoint is asked (B7)
REQUEST_ERRORS = ('revert', 'nonce too', 'already known', 'already imported', 'underpriced', 'insufficient funds', 'intrinsic gas',
                  'gas required exceeds', 'gas limit', 'out of gas', 'invalid opcode', 'max fee per gas', 'max priority fee',
                  'fee cap', 'tip higher', 'transaction type', 'oversized', 'invalid sender', 'exceeds the configured cap')
EVERYONE_REFUSES = ('not found', 'unknown block', 'does not exist', 'not supported', 'unsupported')  # still their answer if all say it
URL = re.compile(r'[a-z][a-z0-9+.-]*://\S+', re.I)
RETRY_PRIMARY_S = 60
RECEIPT_WAIT_S = 30  # a role's send gives way to the next role: its next pass waits for the same transaction
MAX_PENDING = 1000  # undelivered events kept per sink; the oldest go first, and the count of those lost is told
REDELIVER = ('CONSERVATION', 'SURPLUS', 'UNCHALLENGED_FALSE_CLAIM')  # for these a changed detail is news


class DaemonError(RuntimeError):
    pass


def _hex(a):
    return bytes.fromhex(a[2:] if a.startswith('0x') else a)


def _told(text):
    """what goes into an alert, a heartbeat, state.json: short, and no URL in it, they often hold a provider's key"""
    return URL.sub('<url>', str(text))[:200]


def _brief(e):
    return _told(f'{type(e).__name__}:{e}')


def _atomic(path, text):
    """the whole file or the old one, for a process killed at any moment and a reader at any moment"""
    tmp = Path(str(path) + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


class FailoverRpc:
    """Several endpoints behind one Rpc call. An endpoint is used only after it has said it serves chain_id. An endpoint that
    does not answer (a lost connection, an HTTP error, a page that is not JSON), says it is rate limited or answers with its own
    fault gives way to the next one for this call and on; a JSON-RPC error the request itself caused (REQUEST_ERRORS, revert data,
    a log range too large) is raised. Every retry_primary_s the first choice is asked for its head and used again if it has not
    fallen behind: one that answers and stands still is no first choice. All failing: ConnectionError, with the type of the last
    failure only, or their common answer (EVERYONE_REFUSES). No URL leaves this object: they often hold a provider's key."""

    def __init__(self, endpoints, chain_id, allow_remote=False, timeout=30, retry_primary_s=RETRY_PRIMARY_S, clock=time.monotonic):
        """endpoints: URLs, or callables like Rpc (tests)"""
        if not endpoints:
            raise DaemonError('NO_RPC_ENDPOINT')
        self.eps = []
        for i, e in enumerate(endpoints):
            try:
                self.eps.append(e if callable(e) else Rpc(e, allow_remote=allow_remote, timeout=timeout))
            except ValueError as why:  # the configuration refuses to run; which one, by position
                raise DaemonError(f'{why}:endpoint {i}') from None
        self.chain_id, self.retry_primary_s, self.clock = chain_id, retry_primary_s, clock
        self.active, self.since = 0, clock()
        self.known = {}  # endpoint index -> serves chain_id
        self.failures = [0] * len(self.eps)

    @property
    def wrong_chain(self):
        return sorted(i for i, ok in self.known.items() if not ok)

    def _serves(self, i):
        if i not in self.known:
            self.known[i] = int(self.eps[i]('eth_chainId'), 16) == self.chain_id
        return self.known[i]

    def _caught_up(self):
        """is the first choice answering and not behind the one in use? (B12) An answer that is no number: the call will tell"""
        try:
            if not self._serves(0):
                return False
            return int(self.eps[0]('eth_blockNumber'), 16) >= int(self.eps[self.active]('eth_blockNumber'), 16)
        except ValueError:
            return True
        except (*NO_ANSWER, RpcError):
            return False

    def _order(self):
        if self.active != 0 and self.clock() - self.since >= self.retry_primary_s:
            self.since = self.clock()
            if self._caught_up():
                return list(range(len(self.eps)))
        return [self.active] + [i for i in range(len(self.eps)) if i != self.active]

    def probe(self):
        """ask every endpoint which chain it serves, now, not on the day it is needed; one that does not answer is asked later"""
        for i in range(len(self.eps)):
            try:
                self._serves(i)
            except (*NO_ANSWER, RpcError):
                pass

    def rotate(self):
        """the active endpoint is answering but stale (Daemon: the head does not move): try another from now on"""
        usable = [i for i in range(len(self.eps)) if self.known.get(i, True) and i != self.active]
        if usable:
            self.active, self.since = usable[0], self.clock()

    def __call__(self, method, *params):
        last, retried = None, False
        for i in self._order():
            if self.known.get(i) is False:
                continue
            try:
                if not self._serves(i):
                    continue
                out = self.eps[i](method, *params)
            except NO_ANSWER as e:
                self.failures[i] += 1
                last, retried = e, True
                continue
            except RpcError as e:
                msg = str(e).lower()
                if method == 'eth_sendRawTransaction' and retried and any(
                        w in msg for w in ('already known', 'already imported', 'nonce too low')):
                    return '0x' + keccak(bytes.fromhex(params[0][2:])).hex()  # the lost attempt did reach the network
                if any(w in msg for w in NOT_RANGE):
                    self.failures[i] += 1
                    last, retried = e, False
                    continue
                if e.revert or any(w in msg for w in (*REQUEST_ERRORS, *RANGE_REFUSALS)):
                    raise
                self.failures[i] += 1
                last, retried = e, True  # its own fault: a raw transaction may have got through before it
                continue
            if i != self.active:
                self.active, self.since = i, self.clock()
            return out
        if not any(self.known.get(i, True) for i in range(len(self.eps))):
            raise ConnectionError('RPC_NO_ENDPOINT_ON_THIS_CHAIN')
        if isinstance(last, RpcError) and any(w in str(last).lower() for w in EVERYONE_REFUSES):
            raise last
        raise ConnectionError(f'RPC_ALL_ENDPOINTS_FAILED:{len(self.eps)}:{type(last).__name__}')


# ---- sinks: send(event) raises if the event did not get there ---------------------------------------------------------
class FileSink:
    name, min_severity = 'file', 'info'

    def __init__(self, path):
        self.path = Path(path)

    def send(self, event):
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(event, sort_keys=True) + '\n')
            f.flush()
            os.fsync(f.fileno())


class CommandSink:
    name = 'command'

    def __init__(self, argv, min_severity='medium', timeout=30):
        self.argv, self.min_severity, self.timeout = list(argv), min_severity, timeout

    def send(self, event):
        r = subprocess.run(self.argv, input=json.dumps(event, sort_keys=True).encode(), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=self.timeout, check=False)
        if r.returncode != 0:
            raise OSError(f'exit {r.returncode}')


class WebhookSink:
    name = 'webhook'

    def __init__(self, url, min_severity='medium', timeout=15):
        if not url.startswith(('http://', 'https://')):
            raise DaemonError('BAD_WEBHOOK')
        self.url, self.min_severity, self.timeout = url, min_severity, timeout

    def send(self, event):
        req = urllib.request.Request(self.url, json.dumps(event, sort_keys=True).encode(),
                                     {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            r.read()


@dataclass
class Stack:
    """what a daemon runs: components() -> [(name, step)], monitor() -> alerts, head() -> block number, alerts(): what the
    last components() found wrong with its inputs and what the chain said about fees; rpc: FailoverRpc if there is one. A step
    that is a bound method of an object with failing() is read after each pass (module docstring)"""
    components: callable
    monitor: callable = None
    head: callable = None
    alerts: callable = list
    rpc: object = None


class Daemon:
    def __init__(self, state_dir, build, sinks=(), heartbeat=None, name='omega', interval=12, monitor_every=1, fail_alert_after=3,
                 max_backoff=300, stall_s=None, renotify_s=3600, wall=time.time, sleep=time.sleep):
        """build() -> Stack, tried again at each pass until it works (the chain may be down when this starts)"""
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path, self.heartbeat = self.dir / 'state.json', Path(heartbeat) if heartbeat else self.dir / 'heartbeat.json'
        self.build, self.sinks, self.name, self.interval = build, list(sinks), name, interval
        self.monitor_every, self.fail_alert_after, self.max_backoff = monitor_every, fail_alert_after, max_backoff
        self.stall_s, self.renotify_s, self.wall, self.sleep = stall_s, renotify_s, wall, sleep
        self.stack, self.stopping, self.lock = None, False, None
        self.fails, self.mon_fails, self.mon_error, self.last_alerts = {}, 0, '', []
        self.head_seen, self.head_at = None, None
        self.cycle_no, self.active, self.pending, self.lost = 0, {}, {s.name: [] for s in self.sinks}, 0
        self.delivery_errors, self.last_health = {}, 'ok'
        self.role_failing = {}  # role name -> what its failing() said
        self._load()

    # ---- state -------------------------------------------------------------------------------------------------------
    def _load(self):
        try:
            st = json.loads(self.state_path.read_text(encoding='utf-8'))
            self.cycle_no, self.active, self.lost = st['cycle'], st['active'], st.get('lost', 0)
            for name, evs in st.get('pending', {}).items():
                if name in self.pending:
                    self.pending[name] = evs
        except FileNotFoundError:
            pass
        except (ValueError, KeyError, TypeError):  # not readable: everything is told again, nothing depends on it
            self.state_path.replace(str(self.state_path) + '.bad')

    def _save(self):
        _atomic(self.state_path, json.dumps({'cycle': self.cycle_no, 'active': self.active, 'pending': self.pending,
                                             'lost': self.lost}, sort_keys=True))

    def acquire(self):
        """one process per state folder. Fails with ALREADY_RUNNING while another holds it; the kernel drops the lock with
        the process, whichever way it ends."""
        f = (self.dir / 'daemon.lock').open('a+')
        try:
            if os.name == 'nt':
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            f.close()
            raise DaemonError('ALREADY_RUNNING') from e
        self.lock = f

    def release(self):
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    # ---- one pass -----------------------------------------------------------------------------------------------------
    def cycle(self):
        """-> True if something worked: the loop slows down only when nothing did"""
        self.cycle_no += 1
        extra, worked = [], False
        if self.stack is None:
            try:
                self.stack = self.build()
                self.mon_fails, self.mon_error = 0, ''
            except DaemonError:  # the configuration refuses to run: no pass will change that
                raise
            except Exception as e:
                self.mon_fails += 1
                self.mon_error = _told(f'BUILD:{type(e).__name__}:{e}')
        if self.stack is not None:
            worked = self._steps()
            worked = self._monitor() or worked
            extra += self._rpc_alerts()
            extra += self.stack.alerts()
        if self.mon_fails >= self.fail_alert_after or (self.stack is None and self.mon_fails):
            extra.append(MON.Alert('MONITOR_FAILED', detail=self.mon_error))
        for name, (n, why) in self.fails.items():
            if n >= self.fail_alert_after:
                extra.append(MON.Alert('COMPONENT_FAILED', name, why))
        for name, said in self.role_failing.items():
            extra += [MON.Alert('ROLE_FAILING', f'{name}:{kind}', _told(detail)) for kind, detail in said.items()]
        extra += [MON.Alert('ALERT_DELIVERY_FAILED', name, why) for name, why in self.delivery_errors.items()]
        alerts = self.last_alerts + extra
        self.last_health = MON.health(alerts)
        self._keep(lambda: self._deliver(alerts), self._beat, self._save)
        return worked

    def _keep(self, *acts):
        """its own bookkeeping (a full disk, a file held by another program): the roles must not stop for that"""
        why = None
        for act in acts:
            try:
                act()
            except OSError as e:
                why = _brief(e)
        if why:
            self.fails['daemon'] = (self.fails.get('daemon', (0,))[0] + 1, why)
        else:
            self.fails.pop('daemon', None)

    def _steps(self):
        steps, worked = [], False
        try:
            steps = self.stack.components()
        except Exception as e:
            self.fails['components'] = (self.fails.get('components', (0,))[0] + 1, _brief(e))
        else:
            for gone in set(self.fails) - {n for n, _ in steps} - {'daemon'}:  # a plan file taken away, a list that reads again
                del self.fails[gone]
            for gone in set(self.role_failing) - {n for n, _ in steps}:
                del self.role_failing[gone]
        for name, step in steps:
            try:
                step()
            except Exception as e:  # a role's failure is that role's; KeyboardInterrupt and SystemExit end the process
                self.fails[name] = (self.fails.get(name, (0,))[0] + 1, _brief(e))
            else:
                self.fails.pop(name, None)
                worked = True
            self._read_failing(name, step)
        return worked

    def _read_failing(self, name, step):
        """what the role swallowed and went on without. One it cannot say is said too: silence is not health"""
        read = getattr(getattr(step, '__self__', None), 'failing', None)
        try:
            said = dict(read()) if callable(read) else {}
        except Exception as e:
            said = {'failing': _brief(e)}
        if said:
            self.role_failing[name] = said
        else:
            self.role_failing.pop(name, None)

    def _monitor(self):
        if self.stack.monitor is None:
            return False
        if self.cycle_no % self.monitor_every:
            return True
        try:
            self.last_alerts = list(self.stack.monitor())
        except Exception as e:  # the alerts of the last good pass stay up: nothing is known to have ended
            self.mon_fails += 1
            self.mon_error = _brief(e)
            return False
        self.mon_fails, self.mon_error = 0, ''
        return True

    def _rpc_alerts(self):
        out, rpc = [], self.stack.rpc
        if rpc is not None:
            out += [MON.Alert('RPC_WRONG_CHAIN', f'endpoint {i}') for i in rpc.wrong_chain]
            if rpc.active != 0:
                out.append(MON.Alert('RPC_FAILOVER', detail=f'endpoint {rpc.active}'))
        if self.stall_s and self.stack.head is not None:
            try:
                head, now = self.stack.head(), self.wall()
            except Exception:  # the same failure the monitor reports
                return out
            if self.head_seen is None or head > self.head_seen:
                self.head_seen, self.head_at = head, now
            elif now - self.head_at > self.stall_s:
                out.append(MON.Alert('CHAIN_STALLED', detail=f'{int(now - self.head_at)} s at {head}'))
                if rpc is not None:
                    rpc.rotate()
        return out

    # ---- alerts -------------------------------------------------------------------------------------------------------
    def _event(self, kind, a, now):
        return {'t': now, 'event': kind, 'code': a['code'], 'severity': MON.SEVERITY[a['code']], 'key': a['key'],
                'detail': a['detail'], 'source': self.name}

    def _queue(self, ev):
        for s in self.sinks:
            if MON.ORDER.index(ev['severity']) >= MON.ORDER.index(s.min_severity):
                q = self.pending[s.name]
                q.append(ev)
                if len(q) > MAX_PENDING:
                    del q[0]
                    self.lost += 1

    def _deliver(self, alerts):
        now = self.wall()
        seen = {}
        for a in alerts:
            seen[f'{a.code}|{a.key}'] = {'code': a.code, 'key': a.key, 'detail': a.detail}
        for k, a in seen.items():
            was = self.active.get(k)
            if was is None:
                self.active[k] = a | {'since': now, 'told': now}
                self._queue(self._event('raised', a, now))
            elif a['code'] in REDELIVER and a['detail'] != was['detail']:
                was.update(detail=a['detail'], told=now)
                self._queue(self._event('raised', a, now))
            elif MON.SEVERITY[a['code']] == 'critical' and now - was['told'] >= self.renotify_s:
                was['told'] = now
                self._queue(self._event('repeat', a, now))
        for k in [k for k in self.active if k not in seen]:
            self._queue(self._event('cleared', self.active.pop(k), now))
        self._flush()

    def _flush(self):
        failing = {}
        for s in self.sinks:
            q = self.pending[s.name]
            while q:
                try:
                    s.send(q[0])
                except Exception as e:  # in order, from here, next pass; the next pass also tells the other sinks
                    failing[s.name] = type(e).__name__
                    break
                q.pop(0)
        self.delivery_errors = failing

    def _beat(self):
        _atomic(self.heartbeat, json.dumps({'t': self.wall(), 'name': self.name, 'cycle': self.cycle_no, 'health': self.last_health,
                                            'failing': sorted({*self.fails, *self.role_failing}), 'pid': os.getpid()},
                                           sort_keys=True))

    # ---- the loop -----------------------------------------------------------------------------------------------------
    def run(self, max_cycles=None):
        self.acquire()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, lambda *_: setattr(self, 'stopping', True))
            except ValueError:  # not the main thread: a test driving it from a thread stops it by the flag
                pass
        streak, n = 0, 0
        try:
            while not self.stopping and (max_cycles is None or n < max_cycles):
                n += 1
                worked = self.cycle()
                streak = 0 if worked else streak + 1
                end = self.wall() + min(self.interval * 2 ** min(streak, 16), self.max_backoff)
                while not self.stopping and self.wall() < end:
                    self.sleep(min(1.0, max(0.0, end - self.wall())))
        finally:
            self.release()


# ---- the stack from a configuration ------------------------------------------------------------------------------------
def load_signers(names, chain_id):
    """name -> LocalTestSigner from OMEGA_DAEMON_KEYS/<name>.key; on a test chain only"""
    if not names:
        return {}
    if chain_id not in TEST_CHAIN_IDS:
        raise DaemonError('KEY_FILES_ON_PRODUCTION_CHAIN')
    folder = os.environ.get('OMEGA_DAEMON_KEYS')
    if not folder:
        raise DaemonError('NO_KEY_FOLDER')
    out = {}
    for n in names:
        try:
            text = (Path(folder) / f'{n}.key').read_text().strip()
            out[n] = LocalTestSigner(bytes.fromhex(text[2:] if text.startswith('0x') else text))
            del text
        except (OSError, ValueError):  # no message of these goes on: it would hold the path, or part of the file
            raise DaemonError(f'KEY_FILE_UNUSABLE:{n}') from None
    return out


def _key_names(cfg):
    names = []
    o = cfg.get('orchestrator')
    if o:
        names += [o['agent'], o['relayer']]
    names += [x['key'] for x in [*cfg.get('executors', ()), *cfg.get('watchers', ())]]
    for sec, roles in (('cannon', ('executor', 'watcher')), ('op', ('executor', 'challenger'))):
        names += [cfg[sec][r]['key'] for r in roles if cfg.get(sec, {}).get(r)]
    return list(dict.fromkeys(names))


def _deadline_keys(cfg):
    """the keys whose moves have a deadline: a clock or a window loses money if they wait out a price"""
    names = [x['key'] for x in [*cfg.get('executors', ()), *cfg.get('watchers', ())]]
    for sec, roles in (('cannon', ('executor', 'watcher')), ('op', ('executor', 'challenger'))):
        names += [cfg[sec][r]['key'] for r in roles if cfg.get(sec, {}).get(r)]
    return names


def _policy(x, guards=None):
    return AcceptPolicy(frozenset(_hex(a) for a in x.get('accounts', ())), frozenset(_hex(r) for r in x['referees']),
                        min_price=x['min_price'], max_cover=x['max_cover'], max_lock_s=x.get('max_lock_s', 45 * 86_400),
                        min_eth_wei=x.get('min_eth_wei', 0), guards=guards or {})


def _stake_settings(x):
    return {'keep_stake': x.get('keep_stake'), 'payout': _hex(x['payout']) if x.get('payout') else None}


def _pins(cfg):
    """(deploy config, manifest), from the top level or the monitor's section. A production chain needs both, of that chain: a
    role without the pins stakes on external contracts nobody compares (B13). Read before the network and the key files."""
    mon = cfg.get('monitor') or {}
    d, m = (cfg.get(k) or mon.get(k) for k in ('deploy_config', 'manifest'))
    production = cfg['chain_id'] not in TEST_CHAIN_IDS
    if production and not (d and m):
        raise DaemonError('NO_PINS_ON_PRODUCTION_CHAIN')
    try:
        deploy_cfg = DP.load_config(d, plan_only=True) if d else None
        manifest = json.loads(Path(m).read_text(encoding='utf-8')) if m else None
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise DaemonError(f'PINS_UNREADABLE:{type(e).__name__}') from None
    if production and {deploy_cfg.get('chain_id'), manifest.get('chain_id', cfg['chain_id'])} != {cfg['chain_id']}:
        raise DaemonError('PINS_OF_ANOTHER_CHAIN')
    return deploy_cfg, manifest


class _Plans:
    """the plans in a folder, a step per plan that is not finished. A file that does not parse is reported and waited for
    (a plan is put there by writing another name and renaming it, so a half-written one is only an operator's mistake). A plan
    done on the head stays in the passes for `depth` blocks (head() -> block number): a reorganization can undo it, and a plan
    in the file of finished ones is never ticked again (B26)."""

    def __init__(self, client, folder, state_dir, depth=0, head=None):
        self.client, self.folder, self.done_path = client, Path(folder), Path(state_dir) / 'finished_plans.json'
        self.depth, self.head, self.done_at = depth, head, {}
        try:
            self.done = set(json.loads(self.done_path.read_text(encoding='utf-8')))
        except (OSError, ValueError):
            self.done = set()
        self.problems, self.stuck = [], {}

    def steps(self):
        self.problems, out = [], []
        for f in sorted(self.folder.glob('*.json')):
            try:
                plan = Plan.from_json(f.read_text(encoding='utf-8'))
            except (OSError, ValueError, KeyError, TypeError, PlanError) as e:
                self.problems.append(MON.Alert('PLAN_UNREADABLE', f.name, type(e).__name__))
                continue
            pid = plan.plan_id().hex()
            if pid not in self.done:
                out.append((f'plan:{pid[:12]}', lambda p=plan, i=pid: self._step(p, i)))
        return out

    def _step(self, plan, pid):
        self.client.tick(plan)
        orch = self.client.orchestrator(plan)
        if orch.done():
            self.stuck.pop(pid, None)
            now = self.head() if self.depth else 0
            if now - self.done_at.setdefault(pid, now) >= self.depth:
                self.done.add(pid)
                self.done_at.pop(pid)
                _atomic(self.done_path, json.dumps(sorted(self.done)))
        else:
            self.done_at.pop(pid, None)
            stuck = orch.stuck()
            if stuck:
                self.stuck[pid] = stuck
            else:
                self.stuck.pop(pid, None)

    def alerts(self):
        return self.problems + [MON.Alert('PLAN_STUCK', pid[:12], ','.join(s)) for pid, s in self.stuck.items()]


def build_stack(cfg, signers=None):
    """-> Stack from a configuration (module docstring). `signers`: name -> signer object, instead of key files"""
    chain_id = cfg['chain_id']
    deploy_cfg, manifest = _pins(cfg)
    urls = cfg['rpc_urls']
    rpc = FailoverRpc(urls, chain_id, allow_remote=cfg.get('allow_remote', False), timeout=cfg.get('rpc_timeout_s', 30))
    rpc.probe()
    names = _key_names(cfg)
    if signers is None:
        signers = load_signers(names, chain_id)
    if names:
        cap = lambda k: cfg.get(k, (deploy_cfg or {}).get(k))
        chain = Chain(rpc, chain_id, max_fee_cap=cap('max_fee_cap_wei'), receipt_timeout=cfg.get('receipt_timeout_s', RECEIPT_WAIT_S),
                      arm_config=cfg.get('arm_config'), state_dir=cfg.get('state_dir'), urgent_fee_cap=cap('urgent_fee_cap_wei'),
                      urgent_signers=[signers[k].address for k in _deadline_keys(cfg) if k in signers],
                      tx_gas_cap=(deploy_cfg or {}).get('tx_gas_cap', TX_GAS_CAP))
    else:
        chain = ReadOnlyChain(rpc, chain_id)
    escrow = _hex(cfg['escrow'])
    from_block = cfg.get('from_block', 0)
    boards = {_hex(a): Board(chain, _hex(a), from_block) for a in cfg.get('boards', ())}
    o = cfg.get('orchestrator') or {}
    cannon, op = cfg.get('cannon') or {}, cfg.get('op') or {}
    mon = cfg.get('monitor')
    guards = DP.referee_guards(deploy_cfg, manifest) if deploy_cfg and manifest else None
    gas = RP.gas_table(deploy_cfg or {})  # the chain's own prices of a Cannon dispute (a chain with other gas rules says so)
    capital = {_hex(r): RP.CannonCapital(c['withstand_wei'], _hex(c['watcher']), c.get('gas_price_wei', RP.GAS_PRICE_WEI), gas)
               for r, c in ((mon or {}).get('capital') or {}).items()}
    toolchain = CN.Prestates(CN.Toolchain(cannon['toolchain']), Path(cannon['work'])) if cannon else None
    inbox = _hex(cfg['inbox']) if cfg.get('inbox') else None
    referees = [_hex(s['referee']) for s in (cannon, op) if s]
    client = WorldClient(chain, escrow, signers.get(o.get('agent')), signers.get(o.get('relayer')),
                         token=_hex(cfg['token']) if cfg.get('token') else None, boards=boards, archive=cfg.get('archive'),
                         from_block=from_block, capital=capital, guards=guards, confirmations=cfg.get('confirmations'),
                         inbox=inbox, prestates=toolchain, referees=referees)
    players = []
    for x in cfg.get('executors', ()):
        b = boards[_hex(x['board'])]
        players.append((f"executor:{x['key']}", WorldExecutor(
            b, client.esc, signers[x['key']], int.from_bytes(b.view('bond()')[:32], 'big'), policy=_policy(x, guards),
            **_stake_settings(x)).step))
    for x in cfg.get('watchers', ()):
        b = boards[_hex(x['board'])]
        players.append((f"watcher:{x['key']}", Watchtower(b, signers[x['key']], int.from_bytes(b.view('bond()')[:32], 'big'), E,
                                                          gas_reserve_wei=x.get('gas_reserve_wei')).step))
    judges = {}
    if cannon:
        view, ib = CA.CannonReferee(chain, _hex(cannon['referee']), from_block), _hex(cannon['inbox'])
        known = tuple(_hex(k) for k in cannon.get('known_programs', ()))
        if cannon.get('executor'):
            x = cannon['executor']
            players.append((f"cannon-executor:{x['key']}", CA.CannonExecutor(
                view, client.esc, ib, signers[x['key']], toolchain, policy=_policy(x, guards), withstand_wei=x['withstand_wei'],
                gas_price_wei=x.get('gas_price_wei', RP.GAS_PRICE_WEI), known_programs=known, gas=gas, **_stake_settings(x)).step))
        if cannon.get('watcher'):
            x = cannon['watcher']
            players.append((f"cannon-watcher:{x['key']}", CA.CannonWatcher(view, client.esc, ib, signers[x['key']], toolchain,
                                                                           known_programs=known).step))
        judges[_hex(cannon['referee'])] = CA.false_claim_judge(view, ib, toolchain, known_programs=known)
    if op:
        ref, games = OA.SuperRootReferee(chain, _hex(op['referee'])), OA.OpGames(chain, _hex(op['factory']), op['game_type'])
        source = lambda t: OA.output_root(op['l2_rpc'], t)
        if op.get('executor'):
            x = op['executor']
            players.append((f"op-executor:{x['key']}", OA.AttestExecutor(
                client.esc, ref, games, signers[x['key']], source, policy=_policy(x, guards), inbox=_hex(op['inbox']),
                from_block=from_block).step))
        if op.get('challenger'):
            x = op['challenger']
            players.append((f"op-challenger:{x['key']}", OA.OpChallenger(ref, games, signers[x['key']], source).step))
        judges[_hex(op['referee'])] = OA.false_claim_judge(ref, games, source)
    head = lambda: int(chain.rpc('eth_blockNumber'), 16)
    plans = _Plans(client, o['plans_dir'], cfg['state_dir'], client.ix.confirmations, head) if o else None

    def components():
        return (plans.steps() if plans else []) + players

    monitor = None
    if mon is not None:
        # a process that runs no watcher must know of one: none known is said, it is the one security assumption
        heartbeats = mon.get('watch_heartbeats', None if cfg.get('watchers') else {})
        pin_check = (lambda c: DP.pins_diff(c, deploy_cfg)) if deploy_cfg else None
        codec = {'evm_step_m': EM, None: E}[mon.get('codec')]
        scope = {'accounts': {_hex(a) for a in mon['accounts']} if mon.get('accounts') else None, 'codec': codec,
                 'judges': judges, 'false_claim_grace': mon.get('false_claim_grace_s', 600), 'pin_check': pin_check,
                 'watchers': heartbeats, 'capital': capital or None}
        tail, every, count = mon.get('archive_tail', 64), mon.get('full_check_every', 100), [0]

        def monitor():
            count[0] += 1
            found = client.alerts(tail=None if count[0] % every == 1 else tail, **scope)
            if any(a.code == 'ARCHIVE_REORG' for a in found):  # said once and repaired: the chain is the record (A66)
                client.ix.recover()
            return found

    def alerts():
        return (plans.alerts() if plans else []) + [MON.Alert(code, who, detail) for code, who, detail in chain.fee_alerts()]
    return Stack(components, monitor, head, alerts, rpc)


def sinks_from(alerts):
    out = []
    if alerts.get('file'):
        out.append(FileSink(alerts['file']))
    if alerts.get('command'):
        out.append(CommandSink(alerts['command'], alerts.get('command_min_severity', 'medium')))
    if alerts.get('webhook'):
        out.append(WebhookSink(alerts['webhook'], alerts.get('webhook_min_severity', 'medium')))
    return out


def daemon_from(cfg, signers=None, **kw):
    if not cfg.get('rpc_urls'):
        raise DaemonError('NO_RPC_ENDPOINT')
    missing = [k for k in ('chain_id', 'escrow', 'state_dir') if not cfg.get(k)]
    if missing:
        raise DaemonError('CONFIG_MISSING:' + ','.join(missing))
    stall = cfg['stall_s'] if 'stall_s' in cfg else (None if cfg['chain_id'] in (31337, 1337) else 300)
    return Daemon(cfg['state_dir'], lambda: build_stack(cfg, signers), sinks_from(cfg.get('alerts') or {}),
                  heartbeat=cfg.get('heartbeat'), name=cfg.get('name', 'omega'), interval=cfg.get('interval_s', 12),
                  monitor_every=cfg.get('monitor_every', 1), fail_alert_after=cfg.get('fail_alert_after', 3),
                  max_backoff=cfg.get('max_backoff_s', 300), stall_s=stall, renotify_s=cfg.get('renotify_s', 3600), **kw)


def check_heartbeat(path, max_age, now=None):
    """-> (ok, what to say). Run it from elsewhere: a process cannot report its own death"""
    now = time.time() if now is None else now
    try:
        hb = json.loads(Path(path).read_text(encoding='utf-8'))
        age = now - float(hb['t'])
    except (OSError, ValueError, KeyError, TypeError) as e:
        return False, f'NO_SIGNAL:{type(e).__name__}'
    if age > max_age:
        return False, f"STALE:{int(age)} s:{hb.get('name')}"
    ok = hb.get('health') == 'ok' and not hb.get('failing')
    return ok, f"{'' if ok else 'NOT_OK:'}cycle {hb.get('cycle')} {int(age)} s ago, {hb.get('health')}, failing {hb.get('failing')}"


def main(argv):
    cmd = argv[0] if argv else ''
    if cmd == 'run' and len(argv) == 2:
        try:
            cfg = json.loads(Path(argv[1]).read_text(encoding='utf-8'))
        except (OSError, ValueError) as e:
            print(f'CONFIG_UNREADABLE:{type(e).__name__}', file=sys.stderr)
            return 2
        try:
            daemon_from(cfg).run()
        except DaemonError as e:
            print(str(e), file=sys.stderr)
            return 2
        return 0
    if cmd == 'check-heartbeat' and len(argv) == 3:
        ok, said = check_heartbeat(argv[1], float(argv[2]))
        print(said)
        return 0 if ok else 1
    if cmd == 'verify-archive' and len(argv) == 2:
        try:
            recs, head = IX.verify_archive(argv[1], must_exist=True)
        except IX.ArchiveError as e:
            print(str(e))
            return 1
        print(json.dumps({'records': len(recs), 'head': head}))
        return 0
    if cmd == 'backup' and len(argv) == 3:
        try:
            print(json.dumps(IX.backup(argv[1], argv[2])))
        except IX.ArchiveError as e:
            print(str(e))
            return 1
        return 0
    if cmd == 'reset-archive' and len(argv) == 2:
        try:
            cfg = json.loads(Path(argv[1]).read_text(encoding='utf-8'))
            rpc = FailoverRpc(cfg.get('rpc_urls'), cfg['chain_id'], allow_remote=cfg.get('allow_remote', False),
                              timeout=cfg.get('rpc_timeout_s', 30))
        except (OSError, ValueError, KeyError, TypeError, DaemonError) as e:
            print(str(e) if isinstance(e, DaemonError) else f'CONFIG_UNREADABLE:{type(e).__name__}', file=sys.stderr)
            return 2
        chain = ReadOnlyChain(rpc, cfg['chain_id'])
        client = WorldClient(chain, _hex(cfg['escrow']), None, None, token=_hex(cfg['token']) if cfg.get('token') else None,
                             boards={_hex(a): Board(chain, _hex(a), cfg.get('from_block', 0)) for a in cfg.get('boards', ())},
                             archive=cfg['archive'], from_block=cfg.get('from_block', 0), confirmations=cfg.get('confirmations'),
                             inbox=_hex(cfg['inbox']) if cfg.get('inbox') else None,
                             referees=[_hex(s['referee']) for s in (cfg.get('cannon'), cfg.get('op')) if s])
        print(json.dumps({'kept': client.ix.reset(), 'records': len(IX.verify_archive(cfg['archive'])[0])}))
        return 0
    raise SystemExit(__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
