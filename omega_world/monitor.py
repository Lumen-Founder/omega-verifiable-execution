"""Operations monitor (docs/adr/ADR-0012 L8; runbook docs/world_computer/RUNBOOK_INCIDENT.md). check() reads the
chain and the archive and returns alerts. It only reads; every remedy is an ordinary permissionless call (reject,
voidNode, settle, expire) or an owner action (revoke the mandate, deny a referee), listed per alert in the runbook.
A broken file blinds nothing: with the chain at hand the check goes on from the chain's logs. omega_world/daemon.py runs it
periodically and delivers what it says; the codes it adds itself are in the same table.

Alert codes (severity):
- CONSERVATION (critical): the escrow holds fewer tokens than its books (account balances + locked prices + free stakes +
  held bonds + held covers) plus what was donated to it. Must never happen.
- SURPLUS (low): it holds more than its books, or took tokens by a path the file cannot classify. Anyone can do this
  with one unit of the token, and nothing in the contract can take it back: seen, and nothing more.
- DRULE (critical): a CLAIMED node holds less cover than its liability. Must never happen.
- UNCHALLENGED_FALSE_CLAIM (critical): re-execution says a bound claim is false and no game is open against it, detail
  claimed, accepted or paid. The one security assumption (an honest watcher, R2, T37) is failing, or has failed.
- TOKEN_FROZEN (critical): a transfer of the token out of the escrow would revert right now (T28: a freeze moves no balance).
- PINS_CHANGED (critical): an external contract is not the pinned code: jobs in flight may be judged by other code (R13).
- ARCHIVE_TAMPERED / ARCHIVE_MISMATCH (critical): the archive's hash chain is broken, or an archived log is not on
  the chain as archived.
- MONITOR_FAILED (critical, also from WorldClient.health): the check itself could not run. Silence is not health.
- RPC_WRONG_CHAIN (critical, daemon): a configured RPC endpoint serves another chain; it is never used.
- UNPROCESSED_REJECTION (high): a bound claim was rejected and reject() has not been called (the liar's stake is
  still held; children cannot be voided yet).
- PENDING_VOID (high): a node is built on a rejected node and has not been voided (its payees wait).
- REFEREE_DOWN (high): a node's referee cannot be read, or answers less than a claim.
- WATCHER_SILENT (high): a watcher's heartbeat is older than allowed, unreadable, or none is configured.
- WATCHER_FAILING (high): a watcher's heartbeat is fresh and names roles that fail: it is alive and is not doing its work.
- ARCHIVE_REORG (high): the archive's last block is no longer on the chain (Indexer.recover).
- GAME_IMPROPER (high): a registered Optimism or Cannon game was retired or blacklisted: it can no longer be Rejected, the
  node ends by expiry (T30).
- CANNON_CAPITAL_SHORT (high): a live job on a Cannon referee is defended by less than referee_policy requires (T33).
- JOB_UNKNOWN (high): the claim of a node is bound and its judge cannot find the job behind it: no publication rebuilds to
  its prestate (a flood of look-alike publications, re-audit B3, or none at all), or the build failed here. Nobody here
  can tell whether it is true, and no watcher here plays that game.
- COMPONENT_FAILED, ALERT_DELIVERY_FAILED, CHAIN_STALLED (high, daemon): a role keeps failing; an alert did not reach a sink;
  the chain's head does not move on any endpoint.
- ROLE_FAILING (high, daemon): a role goes on but its failing() names what it swallowed: a refused call, an unknown game.
- GAS_PRICE_OVER_CAP, GAS_PRICE_URGENT (high, daemon): a send was refused or a stuck transaction cannot be raised at the cap; a
  signer with a deadline is paying over the normal cap.
- EXPIRY_DUE (medium): a node is past its expiry and not expired.
- REFEREE_STALLED (medium): a bound claim is past its decision deadline (window end + 2 * clock) and still undecided.
- ARCHIVE_LAG (medium): the chain has events, at the archive's depth, the archive does not.
- ARCHIVE_TORN (medium): the file ends in an unfinished line (a crash while appending); sync() repairs it and says so once.
- PINS_UNREADABLE (medium): the pins could not be read (not a code change).
- REFEREE_GAS_HIGH (medium): getClaim nears the gas the escrow gives it (T26); above it the escrow reads "no decision".
- NODE_UNREADABLE (medium): one node could not be examined; the others were.
- RPC_FAILOVER, PLAN_STUCK, PLAN_UNREADABLE (medium, daemon): working from a backup endpoint; a plan can never finish; a plan
  file does not parse.
- SETTLEABLE (info): a node can be settled now.
- CLAIM_NOT_RECOMPUTED (info): nobody here can say whether this bound claim is true (no judge for its referee)."""
import json
import time
from dataclasses import dataclass
from pathlib import Path
from omega_compute import evm_step as E
from omega_compute.graph_escrow import ACCEPTED, CLAIMED, REJECTED
from omega_kernel.settlement.evm import RpcError
from omega_kernel.settlement.evm_crypto import call_data, selector
from omega_world import indexer as IX
from omega_world import referee_policy as RP
from omega_world.orchestrator import claim_view

SEVERITY = {'CONSERVATION': 'critical', 'DRULE': 'critical', 'ARCHIVE_TAMPERED': 'critical',
            'ARCHIVE_MISMATCH': 'critical', 'UNCHALLENGED_FALSE_CLAIM': 'critical', 'TOKEN_FROZEN': 'critical',
            'PINS_CHANGED': 'critical', 'MONITOR_FAILED': 'critical', 'RPC_WRONG_CHAIN': 'critical',
            'UNPROCESSED_REJECTION': 'high', 'PENDING_VOID': 'high', 'REFEREE_DOWN': 'high', 'WATCHER_SILENT': 'high',
            'ARCHIVE_REORG': 'high', 'GAME_IMPROPER': 'high', 'CANNON_CAPITAL_SHORT': 'high', 'JOB_UNKNOWN': 'high',
            'COMPONENT_FAILED': 'high',
            'ALERT_DELIVERY_FAILED': 'high', 'CHAIN_STALLED': 'high', 'ROLE_FAILING': 'high', 'WATCHER_FAILING': 'high',
            'GAS_PRICE_OVER_CAP': 'high', 'GAS_PRICE_URGENT': 'high', 'EXPIRY_DUE': 'medium', 'REFEREE_STALLED': 'medium',
            'ARCHIVE_LAG': 'medium', 'ARCHIVE_TORN': 'medium', 'PINS_UNREADABLE': 'medium', 'REFEREE_GAS_HIGH': 'medium',
            'NODE_UNREADABLE': 'medium', 'RPC_FAILOVER': 'medium', 'PLAN_STUCK': 'medium', 'PLAN_UNREADABLE': 'medium',
            'SURPLUS': 'low', 'SETTLEABLE': 'info', 'CLAIM_NOT_RECOMPUTED': 'info'}
ORDER = ('info', 'low', 'medium', 'high', 'critical')
REFEREE_GAS_WARN = 150_000  # the escrow's _acceptedOrUnknown gives getClaim 200,000 (OmegaGraphEscrow.REFEREE_GAS)
TX_BASE_GAS = 22_000  # what eth_estimateGas counts besides the call: the transaction and its calldata
DEPOSITS = tuple('0x' + selector(s).hex() for s in ('deposit(bytes32,uint256)', 'depositBond(uint256)'))
ENDED = ('final', 'rejected', 'voided')  # states no later block changes: once quiet, a node is not read again


@dataclass(frozen=True)
class Alert:
    code: str
    key: str = ''
    detail: str = ''

    @property
    def severity(self):
        return SEVERITY[self.code]


def _u(chain, to, sig, *a, block='latest'):
    return int.from_bytes(chain.call(to, call_data(sig, *a), block=block)[:32], 'big')


def health(alerts):
    sev = {a.severity for a in alerts}
    return 'critical' if 'critical' in sev else 'degraded' if sev & {'high', 'medium'} else 'ok'


def conservation(tokens, books, donated, unclassified):
    """the rule on four numbers. A donation raises what must be there: the same amount gone would otherwise leave the
    difference at 0 and no alert (READINESS_AUDIT A85, A107). An inflow through someone's contract may be a deposit or a
    donation: it cannot raise the bar without false alarms, so it is only reported."""
    if tokens < books + donated:
        return [Alert('CONSERVATION', detail=f'tokens {tokens} books {books} donated {donated}')]
    if tokens > books or unclassified:
        return [Alert('SURPLUS', detail=f'tokens {tokens} books {books} donated {donated} unclassified {unclassified}')]
    return []


def _inflows(chain, esc, token, records):
    """(donated, unclassified): tokens that reached the escrow by a transaction to the token itself (the books cannot have
    moved) and by a transaction to a third contract"""
    donated, unclassified, me, tok = 0, 0, '0x' + esc.hex(), '0x' + token.hex()
    for r in records:
        if r['event'] != 'Transfer' or r['args']['to'] != me:
            continue
        via = r['via'] if 'via' in r else IX.via_of(chain, r['tx'])
        if via is not None and via['to'] == tok:
            donated += r['args']['value']
        elif via is None or via['to'] != me or via['selector'] not in DEPOSITS:
            unclassified += r['args']['value']
    return donated, unclassified


def _books(chain, escrow, token, records, reorged, out):
    # one block for every read: a withdrawal landing between two of them looks like money gone. `records` reach at least
    # that block (the archive may wait for confirmations, or lag), so the books name whoever appears in it
    a, esc, head = chain, escrow.address, chain.rpc('eth_blockNumber')
    accounts = {r['args']['account'] for r in records if r['event'] == 'Opened'}
    holders = {r['args']['executor'] for r in records if r['event'] == 'Posted'}
    holders |= {r['args']['from'] for r in records if r['event'] == 'Transfer'}
    books = (sum(_u(a, esc, 'balanceOf(bytes32)', bytes.fromhex(x[2:]), block=head) for x in accounts)
             + sum(_u(a, esc, 'bondOf(address)', bytes.fromhex(x[2:]), block=head) for x in holders)
             + _u(a, esc, 'locked()', block=head) + _u(a, esc, 'bondsHeld()', block=head)
             + _u(a, esc, 'coversHeld()', block=head))
    tokens = _u(a, token, 'balanceOf(address)', esc, block=head)
    donated, unclassified = _inflows(chain, esc, token, records)
    # an archived transfer in an orphaned block never happened: the tally waits for recover()
    out += conservation(tokens, books, 0 if reorged else donated, unclassified)
    try:
        moved = chain.call(token, call_data('transfer(address,uint256)', esc, 0), sender=esc)
    except RpcError as e:
        if e.revert is None and 'revert' not in str(e).lower():
            raise
        out.append(Alert('TOKEN_FROZEN', detail=str(e)[:160]))
    else:
        if moved and not any(moved):
            out.append(Alert('TOKEN_FROZEN', detail='transfer returned false'))


def _archive(chain, archive_path, ix, tail, out):
    """-> (archived records and those of later blocks, reorged?), or None if nothing can be read"""
    recs, reorged, broken = [], False, False
    if archive_path is not None:
        try:
            recs, _ = IX.verify_archive(archive_path)
        except IX.ArchiveTorn as e:
            out.append(Alert('ARCHIVE_TORN', detail=str(e)))
            recs = e.records
        except IX.ArchiveError as e:
            out.append(Alert('ARCHIVE_TAMPERED', detail=str(e)))
            if ix is None:
                return None
            recs, broken = [], True
    if ix is None:
        return recs, False
    if archive_path is not None and not broken:
        reorged = ix.reorged(recs)
        if reorged:
            out.append(Alert('ARCHIVE_REORG', detail=f"block {recs[-1]['block']}"))
        else:
            bad = ix.check_on_chain(recs[-tail:] if tail else recs)
            if bad:
                out.append(Alert('ARCHIVE_MISMATCH', detail=str(bad[:5])))
    last = recs[-1]['block'] if recs else 0
    seen = {(r['blockHash'], r['logIndex']) for r in recs}
    deep = int(chain.rpc('eth_blockNumber'), 16) - ix.confirmations
    logs = [lg for lg in ix.fetch(last, confirmations=0) if (lg['blockHash'], int(lg['logIndex'], 16)) not in seen]
    lag = sum(int(lg['blockNumber'], 16) <= deep for lg in logs)
    if lag and archive_path is not None and not broken:
        out.append(Alert('ARCHIVE_LAG', detail=f'{lag} logs'))
    return recs + [IX.record_of(lg) for lg in logs], reorged


def _verdict(n, c, reg, judges, codec, cache):
    """True, False, 'contested' (false, and a game is on), 'unknown' (a judge's: it looked for the job and found none), or
    None if nobody here can tell"""
    judge = (judges or {}).get(n['referee'])
    if judge is not None:
        return judge(n, c)
    known = reg.get((n['prog'], n['inputs']))
    if known is None:
        return None
    k = (n['prog'], n['inputs'], n['maxSteps'])
    if k not in cache['runs']:
        cache['runs'][k] = IX.recompute(known[0], known[1], n['maxSteps'], codec)[:2]
    if cache['runs'][k] == (c['n'], c['hN']):
        return True
    return 'contested' if c['open'] else False


def _false_claim(key, n, c, now, grace, verdict, chain, out):
    if verdict is False and c['status'] == CLAIMED:
        try:  # the watcher's chance comes first; a referee that does not say its window is judged at once
            if now < c['deadline'] - _u(chain, n['referee'], 'window()') + grace:
                return
        except RpcError:
            pass
        out.append(Alert('UNCHALLENGED_FALSE_CLAIM', key, 'claimed'))
    elif verdict in (False, 'contested') and c['status'] == ACCEPTED:  # whatever was played, a false claim stood (B2)
        out.append(Alert('UNCHALLENGED_FALSE_CLAIM', key, 'paid' if n['state'] == 'final' else 'accepted'))


def _game_kind(chain, ref, cache):
    """'op', 'cannon' or None, once per referee: only a revert says "not this function" (referee_policy.cannon_bonds)"""
    if ref not in cache['kinds']:
        try:
            chain.call(ref, selector('registerGrace()'))
            try:
                reg = chain.call(ref, selector('registry()'))
                cache['kinds'][ref] = ('op', reg[12:32])
            except RpcError as e:
                if e.revert is None and 'revert' not in str(e).lower():
                    raise
                cache['kinds'][ref] = ('cannon', chain.call(ref, selector('games()'))[12:32])
        except RpcError as e:
            if e.revert is None and 'revert' not in str(e).lower():
                raise
            cache['kinds'][ref] = None
    return cache['kinds'][ref]


def _improper(chain, ref, cid, cache):
    kind = _game_kind(chain, ref, cache)
    if kind is None:
        return False
    sig = 'rootOf(uint256)' if kind[0] == 'op' else 'gameOf(uint256)'
    game = chain.call(ref, call_data(sig, cid))[12:32]
    return _u(chain, kind[1], 'isGameProper(address)', game) == 0


def _referee_alive(chain, ref, cache):
    """a node without a claim: can its referee be read at all? Once per check"""
    if ref not in cache['alive']:
        try:
            chain.call(ref, selector('window()'))
            cache['alive'][ref] = True
        except RpcError:
            cache['alive'][ref] = False
    return cache['alive'][ref]


def _node(key, n, chain, escrow, states, now, reg, opts, cache, out):
    st, raw = n['state'], bytes.fromhex(key[2:])
    c = {}
    if n['claimId']:
        c = claim_view(chain, n['referee'], n['claimId'])
        if c is None:
            if st in ('claimed', 'verified'):
                out.append(Alert('REFEREE_DOWN', key, '0x' + n['referee'].hex()))
            c = {}
    elif st == 'posted' and not _referee_alive(chain, n['referee'], cache):
        out.append(Alert('REFEREE_DOWN', key, '0x' + n['referee'].hex()))
    if st == 'claimed' and n['coverHeld'] and n['cover'] < n['liab']:
        out.append(Alert('DRULE', key, f"cover {n['cover']} < L {n['liab']}"))
    if st == 'claimed' and c.get('status') == REJECTED:
        out.append(Alert('UNPROCESSED_REJECTION', key))
    anc = escrow.ancestors(raw)
    anc_states = [states.get('0x' + x.hex(), escrow.node(x))['state'] for x in anc]
    if st in ('posted', 'claimed', 'verified', 'expired') and 'rejected' in anc_states:
        out.append(Alert('PENDING_VOID', key))
    if st in ('posted', 'claimed', 'verified') and now > n['expiry']:
        out.append(Alert('EXPIRY_DUE', key))
    if c and st in ('claimed', 'verified', 'final'):
        verdict = _verdict(n | {'key': raw, 'escrow': escrow.address}, c, reg, opts['judges'], opts['codec'], cache)
        _false_claim(key, n, c, now, opts['false_claim_grace'], verdict, chain, out)
        if verdict is None and st != 'final':
            out.append(Alert('CLAIM_NOT_RECOMPUTED', key, '0x' + n['referee'].hex()))
        elif verdict == 'unknown':
            out.append(Alert('JOB_UNKNOWN', key, '0x' + n['referee'].hex()))
    if st == 'claimed' and c.get('status') == CLAIMED:
        ref = n['referee']
        if ref not in cache['clocks']:
            try:
                cache['clocks'][ref] = _u(chain, ref, 'clock()')
            except RpcError:
                cache['clocks'][ref] = None
        if cache['clocks'][ref] is not None and now > c['deadline'] + 2 * cache['clocks'][ref]:
            out.append(Alert('REFEREE_STALLED', key))
        if _improper(chain, ref, n['claimId'], cache):
            out.append(Alert('GAME_IMPROPER', key, '0x' + ref.hex()))
    if st in ('claimed', 'verified') and c:
        gas = int(chain.rpc('eth_estimateGas', {'to': '0x' + n['referee'].hex(), 'data': '0x' + call_data(
            'getClaim(uint256)', n['claimId']).hex()}), 16) - TX_BASE_GAS
        if gas >= REFEREE_GAS_WARN:
            out.append(Alert('REFEREE_GAS_HIGH', key, str(gas)))
    if st in ('claimed', 'verified') and c.get('status') == ACCEPTED and all(s == 'final' for s in anc_states):
        out.append(Alert('SETTLEABLE', key))


def _capital(chain, capital, states, cache, out):
    """T33: what defends the jobs in flight, read now: the policy that admitted them, at their current balances"""
    for ref, policy in (capital or {}).items():
        nodes = [n for n in states.values() if n['referee'] == ref and n['state'] in ('posted', 'claimed')]
        live = {n['executor'] for n in nodes}
        if not live:
            continue
        if ref not in cache['bonds']:
            cache['bonds'][ref] = RP.cannon_bonds(chain, ref)
        staked = [n for n in nodes if n['state'] == 'claimed' or n['bonded']]  # an offer nobody took asks for nothing yet
        for who in sorted(live):
            mine = [n for n in staked if n['executor'] == who]
            try:  # new: the jobs in flight are what is asked about; an executor named by offers alone still answers for one
                RP.admit_on_chain(chain, cache['bonds'][ref], policy, who, ref, mine, staked, new=0 if mine else 1)
            except RP.Refused as e:
                out.append(Alert('CANNON_CAPITAL_SHORT', '0x' + who.hex(), str(e)))


def _watcher_failing(name, hb):
    """B4: the file is fresh and says its roles fail: an alive process that is not doing the work"""
    failing = hb.get('failing') if isinstance(hb, dict) else None
    return [Alert('WATCHER_FAILING', name, ','.join(map(str, failing))[:160])] if failing else []


def watcher_alerts(watchers, wall_now):
    """watchers: name -> {path, max_age_s}, the heartbeat files of the watchers (omega_world.daemon writes them). Another
    host's arrive by whatever carries files; a heartbeat that cannot be read is not a live watcher."""
    if not watchers:
        return [Alert('WATCHER_SILENT', detail='NO_WATCHER_CONFIGURED')]
    out = []
    for name, w in watchers.items():
        try:
            hb = json.loads(Path(w['path']).read_text(encoding='utf-8'))
            age = wall_now - float(hb['t'])
        except (OSError, ValueError, KeyError, TypeError) as e:
            out.append(Alert('WATCHER_SILENT', name, 'NO_SIGNAL:' + type(e).__name__))
            continue
        if age > w['max_age_s']:
            out.append(Alert('WATCHER_SILENT', name, f'{int(age)} s'))
        else:
            out += _watcher_failing(name, hb)
    return out


def check(chain, escrow, token, archive_path, ix=None, accounts=None, codec=E, judges=None, false_claim_grace=0,
          watchers=None, pin_check=None, capital=None, cache=None, tail=None, wall_now=None):
    """escrow: omega_compute.graph_escrow.GraphEscrow; ix: an Indexer over the same contracts (ARCHIVE_LAG, what the archive
    does not hold yet); archive_path None: the chain's logs only;
    accounts: the bytes32 ids whose nodes this operator answers for (default all: anyone's referee can then raise alerts here);
    codec: the referee's state hash (evm_step, or evm_step_m for OVM0StepM);
    judges: referee address -> (node, claim) -> True, False, 'contested' or None, for a referee whose claims are not OVM-0
    runs of this file: cannon_agent.false_claim_judge, op_attest.false_claim_judge;
    false_claim_grace: seconds a watcher has before a false claim alerts;
    watchers: as watcher_alerts; None: not asked (a library call), {}: none exists, and that is said;
    pin_check: chain -> differences (deploy.pins_diff with the configuration);
    capital: Cannon referee address -> referee_policy.CannonCapital;
    cache: a dict kept between checks: runs not repeated, ended nodes not read again;
    tail: only the last records are re-found on the chain (the full walk is one RPC call per block);
    wall_now: seconds since the epoch, for heartbeats"""
    out = []
    cache = cache if cache is not None else {}
    for k in ('runs', 'kinds', 'bonds', 'clocks', 'alive'):
        cache.setdefault(k, {})
    cache['alive'], cache['clocks'] = {}, {}
    quiet = cache.setdefault('quiet', set())
    got = _archive(chain, archive_path, ix, tail, out)
    if got is None:
        return out
    records, reorged = got
    if token is not None:
        _books(chain, escrow, token, records, reorged, out)
    if pin_check is not None:
        try:
            for sec, name, _, _ in pin_check(chain):
                out.append(Alert('PINS_CHANGED', f'{sec}:{name}'))
        except (RpcError, OSError) as e:
            out.append(Alert('PINS_UNREADABLE', detail=str(e)[:160]))
    if watchers is not None:
        out += watcher_alerts(watchers, time.time() if wall_now is None else wall_now)
    now = int(chain.rpc('eth_getBlockByNumber', 'latest', False)['timestamp'], 16)
    reg = IX.da(records)
    opts = {'judges': judges, 'codec': codec, 'false_claim_grace': false_claim_grace}
    states = {}
    for key in [r['args']['key'] for r in records if r['event'] == 'Posted' and r['args']['key'] not in quiet]:
        try:
            n = escrow.node(bytes.fromhex(key[2:]))
        except (RpcError, ValueError, LookupError, ArithmeticError) as e:
            out.append(Alert('NODE_UNREADABLE', key, str(e)[:160]))
            continue
        if accounts is None or n['account'] in accounts:
            states[key] = n
    for key, n in states.items():
        before = len(out)
        try:
            _node(key, n, chain, escrow, states, now, reg, opts, cache, out)
        except (RpcError, ValueError, LookupError, ArithmeticError) as e:  # that node's; a lost connection stops the check
            del out[before:]
            out.append(Alert('NODE_UNREADABLE', key, str(e)[:160]))
            continue
        if n['state'] in ENDED and len(out) == before:
            quiet.add(key)
    _capital(chain, capital, states, cache, out)
    return out
