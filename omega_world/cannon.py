"""OVM0 jobs on Optimism's fault proof contracts: everything an account, an executor and a watcher share at runtime
(docs/adr/ADR-0012 section 11, SECURITY_REVIEW section 10-1; the players are in omega_world/cannon_agent.py).

A job game (omega_evm/src/OmegaCannonGames.sol) is a clone of Optimism's FaultDisputeGame implementation whose absolute
prestate is the OVM0 Cannon guest with one job embedded (tools/world/cannon_guest/ovm0, "oracle" mode), whose VM is
Optimism's MIPS64 and whose anchor is a fixed value. The root claim is the commitment of the claimed output. Above the
split depth every position claims the output at sequence 1 (the only one), so an actor posts its belief about the output
there; below it an actor posts Cannon state hashes of the guest run with the leaf's local data (starting and disputed
claims), computed by tools/world/cannon_guest/driver. The response rule is op-challenger's: agree with a claim -> defend,
disagree -> attack, at the maximum depth -> step, loading the local datum into the PreimageOracle first when the step
reads one. A claim that is what the actor would have posted itself, whoever posted it, gets no answer.

- Toolchain, Prestates: the reproducible build of a job's prestate (D25: never a value someone else gave).
- find_job: from a node's hash back to its job, through OVM0Inbox publications. The prestate is a hash no contract can
  look into, so which publication is the job can only be decided by rebuilding: the poster's publication comes first and
  the number of rebuilds is bounded, because anyone may publish and a rebuild takes seconds.

The position arithmetic, the starting/disputed search and the local context mirror LibPosition and FaultDisputeGame
(_findStartingAndDisputedOutputs, _computeLocalContext); the fork test checks the agent against the deployed contract."""
import hashlib
import json
import os
import shutil
import subprocess
from collections import namedtuple
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from omega_compute import evm_step as E
from omega_compute import vm
from omega_compute.dispute_agent import published_logs
from omega_compute.graph_escrow import GraphJob
from omega_kernel.settlement.evm import RpcError, TxNotMined
from omega_kernel.settlement.evm_crypto import call_data, keccak, selector

GUEST = Path(__file__).resolve().parent.parent / 'tools' / 'world' / 'cannon_guest' / 'ovm0'
STATE_TYPE = 'multithreaded64-5'  # state version 8, the version of the MIPS64 that mainnet games use
MAX_ORACLE_STEPS = 10000  # cannon_guest/ovm0 MaxOracleSteps = OmegaCannonReferee stepCap on mainnet
MAX_REBUILDS = 16  # rebuilds find_job spends on one job's publications (the poster's come first)
MAX_DEPTH, SPLIT = 73, 30
EXEC_DEPTH = MAX_DEPTH - SPLIT
ANCHOR = hashlib.sha256(b'OMEGA-OVM0-ANCHOR-v1').digest()
VALID, INVALID = 0, 1
TRAPS = {'none': 0, 'PC_OUT_OF_RANGE': 1, 'STACK_UNDERFLOW': 2, 'DIV_BY_ZERO': 3, 'INPUT_OUT_OF_RANGE': 4,
         'MEM_OUT_OF_RANGE': 5, 'STACK_OVERFLOW': 6, 'STEP_LIMIT': 7}  # omega_compute.evm_step.TRAPS


class ToolFailed(RuntimeError):
    """the Go build, cannon or the driver failed on this machine: nothing about the job, and no verdict (not a ValueError:
    find_job takes that as a publication the guest cannot take). One job's failure, as any other (B25)."""


def _tool(args, **kw):
    try:
        return subprocess.run(args, capture_output=True, **kw)
    except (OSError, subprocess.SubprocessError) as e:
        raise ToolFailed(f'{Path(args[0]).stem}: {type(e).__name__}') from e


@dataclass(frozen=True)
class CannonJob(GraphJob):
    """prog is the Cannon absolute prestate (it commits to the guest and the job); inputs as any OVM0 job"""
    prestate: bytes = b''

    def commitments(self):
        return self.prestate, E.inputs_commit(list(self.inputs)).commitment


def _lists(program):
    return [list(i) for i in program]


def claim_of(program, inputs, max_steps):
    """the true output of a job in the guest's text form: (stack top | none, trap | none, steps)"""
    out = vm.output(vm.run(_lists(program), list(inputs), max_steps)[0])
    return ('none' if out['stack_top'] is None else str(out['stack_top']), out['trap'] or 'none', out['steps'])


def oracle_job_text(program, inputs, max_steps):
    """the job of a dispute game guest ("oracle" mode). Refuses what the guest would turn into a verdict that does
    not depend on the truth (independent review D25): a malformed program, inputs outside the guest's u64 range or
    over 1,024, and a step limit outside 1..MAX_ORACLE_STEPS (an unfinished trace cannot be proved by either side)."""
    vm.check_program(program)
    if not 1 <= len(program) <= 4096 or len(inputs) > 1024 or not all(0 <= int(x) < 1 << 64 for x in inputs):
        raise ValueError('BAD_JOB_SIZE')
    if not 1 <= int(max_steps) <= MAX_ORACLE_STEPS:
        raise ValueError('BAD_MAX_STEPS')
    lines = ['inputs ' + ' '.join(str(int(x)) for x in inputs), f'max {int(max_steps)}', 'oracle']
    lines += ['P ' + ' '.join(str(x) for x in ins) for ins in program]
    return '\n'.join(lines) + '\n'


class Toolchain:
    def __init__(self, root):
        """root: a folder holding bin/cannon(.exe), bin/omega-driver(.exe) and go124/go (Go 1.24 for the guest)"""
        self.root = Path(root)
        exe = '.exe' if os.name == 'nt' else ''
        self.cannon = self.root / 'bin' / f'cannon{exe}'
        self.driver_exe = self.root / 'bin' / f'omega-driver{exe}'
        self.go = self.root / 'go124' / 'go' / 'bin' / f'go{exe}'
        cache = self.root / 'gocache-guest'
        self.env = os.environ | {'GOROOT': str(self.go.parents[1]), 'GOCACHE': str(cache), 'GOTOOLCHAIN': 'local',
                                 'GOPATH': str(self.root / 'gopath'), 'GOTELEMETRY': 'off', 'GOFLAGS': '-mod=mod',
                                 'GOTMPDIR': str(self.root / 'gotmp')}
        (self.root / 'gotmp').mkdir(exist_ok=True)

    def ok(self):
        return self.cannon.exists() and self.go.exists()

    def build(self, work, job, mips=True):
        """copy the guest into work, embed the job, build -> path of the ELF (mips) or native executable"""
        work = Path(work)
        work.mkdir(parents=True, exist_ok=True)
        for f in ('main.go', 'go.mod'):
            shutil.copyfile(GUEST / f, work / f)
        (work / 'job.txt').write_text(job, encoding='utf-8', newline='\n')
        env = self.env | ({'GOOS': 'linux', 'GOARCH': 'mips64', 'GOMIPS64': 'softfloat'} if mips else {})
        out = work / ('ovm0.elf' if mips else 'ovm0-native' + ('.exe' if os.name == 'nt' else ''))
        p = _tool([str(self.go), 'build', '-trimpath', '-o', str(out), '.'], cwd=work, env=env, timeout=600)
        if p.returncode != 0:
            raise ToolFailed('go build: ' + p.stderr[-2000:].decode('utf-8', 'replace'))
        return out

    def prestate_of(self, work, program, inputs, max_steps):
        """the absolute prestate of a dispute game job, rebuilt from the job itself: what a poster names as the
        job's prog and what an executor recomputes before reserving (it must equal the node's prog)"""
        work = Path(work)
        elf = self.build(work, oracle_job_text(program, inputs, max_steps))
        self._cannon('load-elf', '--type', STATE_TYPE, '--path', str(elf), '--out', 'state.bin.gz',
                     '--meta', 'meta.json', cwd=work)
        return bytes.fromhex(self.witness('state.bin.gz', work)['witnessHash'][2:])

    def driver(self, state):
        return Driver(self.driver_exe, state)

    def _cannon(self, *args, cwd):
        p = _tool([str(self.cannon), *args], cwd=cwd, text=True, timeout=3600)
        if p.returncode != 0:
            raise ToolFailed(f'cannon {args[0]}: {p.stderr[-2000:]}')
        return p

    def witness(self, state, cwd):
        out = self._cannon('witness', '--input', str(state), cwd=cwd).stdout
        try:
            return json.loads(out)
        except ValueError as e:
            raise ToolFailed('cannon witness: not JSON') from e


class Prestates:
    """(program, inputs, max_steps) -> the job's prestate, built here and nowhere else (D25), one folder per job and guest
    under `work`, so that a restart does not build again. Each party holds its own: that is the check."""

    def __init__(self, toolchain, work):
        self.toolchain, self.work = toolchain, Path(work)
        self.guest = hashlib.sha256((GUEST / 'main.go').read_bytes() + (GUEST / 'go.mod').read_bytes()).digest()
        self._drivers = {}  # one per job folder, so that Driver.hash_after's cache lasts from pass to pass (B22)

    def dir(self, program, inputs, max_steps):
        job = oracle_job_text(_lists(program), list(inputs), max_steps)
        return self.work / hashlib.sha256(self.guest + job.encode()).hexdigest()[:32]

    def __call__(self, program, inputs, max_steps):
        d = self.dir(program, inputs, max_steps)
        done = d / 'prestate.hex'
        if done.exists():
            return bytes.fromhex(done.read_text())
        pre = self.toolchain.prestate_of(d, _lists(program), list(inputs), max_steps)
        done.write_text(pre.hex())
        return pre

    def driver(self, program, inputs, max_steps):
        self(program, inputs, max_steps)
        d = self.dir(program, inputs, max_steps)
        if d not in self._drivers:
            self._drivers[d] = self.toolchain.driver(d / 'state.bin.gz')
        return self._drivers[d]


def find_job(chain, inbox, prestates, prestate, inputs_commit, max_steps, from_block=0, prefer=None, max_rebuilds=MAX_REBUILDS,
             known=()):
    """(program, inputs) of the publication whose rebuild gives this prestate, or None. A flood of publications with
    these inputs must not stand between a watcher and the job within one game clock: `known` (program commitments a
    party knows, from its plan) are asked for by their topic, which no flood can bury, then `prefer` (who sent the node's
    post) goes first, and after max_rebuilds distinct programs the job counts as not found. A publication the guest cannot
    take is not the job. A build that fails is about this machine, not the job, and raises."""
    for prog in known:
        for r in published_logs(chain, inbox, from_block, inputs_commit, prog)[:1]:
            try:
                if prestates(r.program, r.values, max_steps) == prestate:
                    return r.program, r.values
            except ValueError:
                pass
    rows = sorted(published_logs(chain, inbox, from_block, inputs_commit), key=lambda r: r.publisher != prefer)
    seen = set()
    for r in rows:
        if r.prog in seen:
            continue
        if len(seen) == max_rebuilds:
            return None
        seen.add(r.prog)
        try:
            if prestates(r.program, r.values, max_steps) == prestate:
                return r.program, r.values
        except ValueError:
            continue
    return None


def commit(inputs, max_steps, top, trap, steps):
    """the claim for an output of the job with these inputs and step limit (guest text form):
    sha256("OVM0-OUT-v2" || sha256(inputs as 32-byte words) || maxSteps u64 || hasTop u8 || top u64 || trap u8 ||
    steps u64), as the guest and OmegaCannonReferee.outputCommit compute it"""
    has = top != 'none'
    ih = hashlib.sha256(b''.join(int(x).to_bytes(32, 'big') for x in inputs)).digest()
    return hashlib.sha256(b'OVM0-OUT-v2' + ih + int(max_steps).to_bytes(8, 'big') + bytes([has])
                          + (int(top) if has else 0).to_bytes(8, 'big') + bytes([TRAPS[trap]])
                          + int(steps).to_bytes(8, 'big')).digest()


def register_data(game, inputs, max_steps, top, trap, steps):
    """calldata of OmegaCannonReferee.register(address,uint256[],uint64,bool,uint64,uint8,uint64) for an output in
    the guest's text form"""
    has = top != 'none'
    head = [game.rjust(32, b'\x00'), (7 * 32).to_bytes(32, 'big'), int(max_steps).to_bytes(32, 'big'),
            int(has).to_bytes(32, 'big'), (int(top) if has else 0).to_bytes(32, 'big'),
            TRAPS[trap].to_bytes(32, 'big'), int(steps).to_bytes(32, 'big')]
    tail = len(inputs).to_bytes(32, 'big') + b''.join(int(x).to_bytes(32, 'big') for x in inputs)
    return selector('register(address,uint256[],uint64,bool,uint64,uint8,uint64)') + b''.join(head) + tail


# ---- LibPosition ----

def depth(p):
    return p.bit_length() - 1


def index_at(p):
    return p - (1 << depth(p))


def trace_index(p, max_depth):
    r = max_depth - depth(p)
    return ((p << r) | ((1 << r) - 1)) - (1 << max_depth)


def move(p, attack):
    return (p | (0 if attack else 1)) << 1


def trace_ancestor(p):
    lsb = ~p & (p + 1)
    a = p >> depth(lsb)
    return a or 1


def relative(p, at=SPLIT):
    """the position relative to its ancestor at depth `at` (op-challenger RelativeToAncestorAtDepth)"""
    d = depth(p) - at
    return (1 << d) | (index_at(p) & ((1 << d) - 1))


def exec_trace_index(p):
    return trace_index(relative(p), EXEC_DEPTH)


# ---- the game's claims ----

Claim = namedtuple('Claim', 'index parent countered claimant bond value pos')


def outputs(claims, parent_index, pos):
    """(starting claim, starting pos, disputed claim, disputed pos) for an execution-game claim at `pos` whose
    parent is claims[parent_index]: FaultDisputeGame._findStartingAndDisputedOutputs (pos may not be posted yet)"""
    chain = [(pos, parent_index)]
    idx = parent_index
    while depth(claims[idx].pos) > SPLIT:
        chain.append((claims[idx].pos, claims[idx].parent))
        idx = claims[idx].parent
    out = claims[idx]  # the claim at the split depth
    exec_root_pos = next(p for p, _ in chain if depth(p) == SPLIT + 1)
    if exec_root_pos >> 1 == out.pos:  # the execution game began with an attack on the output leaf
        if index_at(out.pos) > 0:
            s = find_trace_ancestor(claims, out.pos - 1, idx)
            starting, spos = s.value, s.pos
        else:
            starting, spos = ANCHOR, 0
        return starting, spos, out.value, out.pos
    d = find_trace_ancestor(claims, out.pos + 1, idx)
    return out.value, out.pos, d.value, d.pos


def find_trace_ancestor(claims, pos, start):
    want = trace_ancestor(pos)
    c = claims[start]
    while c.pos != want:
        c = claims[c.parent]
    return c


def local_context(starting, spos, disputed, dpos):
    if spos == 0:
        return keccak(disputed + dpos.to_bytes(32, 'big'))
    return keccak(starting + spos.to_bytes(32, 'big') + disputed + dpos.to_bytes(32, 'big'))


# ---- traces ----

class Driver:
    def __init__(self, exe, state):
        self.exe, self.state = str(exe), str(state)

    def _run(self, starting, disputed, steps, proof=False):
        args = [self.exe, '-state', self.state, '-l1', '0x' + '00' * 32, '-l2', '0x' + starting.hex(),
                '-l3', '0x' + disputed.hex(), '-l4', '0x' + (1).to_bytes(8, 'big').hex(),
                '-at', ','.join(str(s) for s in steps)]
        if proof:
            args.append('-proof')
        p = _tool(args, text=True, timeout=600)
        if p.returncode != 0:
            raise ToolFailed('driver: ' + p.stderr[-1000:])
        try:
            return [json.loads(ln) for ln in p.stdout.splitlines()]
        except ValueError as e:
            raise ToolFailed('driver: not JSON') from e

    @lru_cache(maxsize=4096)
    def hash_after(self, starting, disputed, n):
        """state hash after n steps (the final state if the trace ends earlier)"""
        return bytes.fromhex(self._run(starting, disputed, [n])[0]['hash'][2:])

    def proof(self, starting, disputed, step):
        """the witness of step `step` (from the state after `step` steps)"""
        return self._run(starting, disputed, [step], proof=True)[0]['proof']  # past the end: the no-op step


class Actor:
    """One side of a job game: what it believes about the output, and the trace it runs below the split depth.
    `lie_from` makes a dishonest actor: from that trace index on, its execution claims are fabricated, with VM status
    `lie_status` (a challenger must open an execution game with INVALID, a proposer's side with VALID)."""

    def __init__(self, name, signer, driver, output_claim, lie_from=None, lie_status=VALID):
        self.name, self.signer, self.driver, self.output_claim, self.lie_from, self.lie_status = (
            name, signer, driver, output_claim, lie_from, lie_status)

    def value(self, claims, parent_index, pos):
        if depth(pos) <= SPLIT:
            return self.output_claim
        starting, _, disputed, _ = outputs(claims, parent_index, pos)
        t = exec_trace_index(pos)
        if self.lie_from is not None and t >= self.lie_from:
            return bytes([self.lie_status]) + hashlib.sha256(b'fabricated' + t.to_bytes(8, 'big')).digest()[1:]
        return self.driver.hash_after(starting, disputed, t + 1)


# ---- the game contract ----

def _bytes_arg(b):
    return len(b).to_bytes(32, 'big') + b + b'\x00' * ((-len(b)) % 32)


class Game:
    def __init__(self, chain, address):
        self.chain, self.address = chain, address

    def _word(self, sig, *a):
        return self.chain.call(self.address, call_data(sig, *a))

    def claims(self):
        n = int.from_bytes(self._word('claimDataLen()'), 'big')
        out = []
        for i in range(n):
            w = self._word('claimData(uint256)', i)
            g = [w[k:k + 32] for k in range(0, len(w), 32)]
            out.append(Claim(i, int.from_bytes(g[0], 'big'), g[1][12:], g[2][12:], int.from_bytes(g[3], 'big'),
                             g[4], int.from_bytes(g[5], 'big')))
        return out

    def status(self):
        return int.from_bytes(self._word('status()'), 'big')

    def bond(self, pos):
        return int.from_bytes(self._word('getRequiredBond(uint128)', pos), 'big')

    def move(self, signer, disputed, parent_index, value, attack):
        sig = 'attack(bytes32,uint256,bytes32)' if attack else 'defend(bytes32,uint256,bytes32)'
        return self.chain.send(signer, self.address, call_data(sig, disputed, parent_index, value), value=self._bond)

    def step(self, signer, claim_index, attack, state_data, proof_data):
        sd, pd = _bytes_arg(state_data), _bytes_arg(proof_data)
        data = (selector('step(uint256,bool,bytes,bytes)') + claim_index.to_bytes(32, 'big')
                + int(attack).to_bytes(32, 'big') + (128).to_bytes(32, 'big') + (128 + len(sd)).to_bytes(32, 'big')
                + sd + pd)
        return self.chain.send(signer, self.address, data)

    def add_local_data(self, signer, ident, leaf_index, part_offset):
        return self.chain.send(signer, self.address,
                               call_data('addLocalData(uint256,uint256,uint256)', ident, leaf_index, part_offset))


def _reverted(e, name):
    """FaultDisputeGame's custom errors come as REVERT_<selector> (their selectors are in the deployed 2.2.0's bytecode)"""
    return e.revert == 'REVERT_' + selector(name + '()').hex()


def respond(game, actor, log, skip=()):
    """the actor answers every uncountered claim that needs its answer, oldest first (independent review D26: answering
    only the newest claim leaves an earlier branch to win on the clock). Its own claims need none; nor does a claim it
    would have posted itself, nor one someone already answered as it would: two honest parties must not fight (READINESS_AUDIT A17).
    A claim that cannot be answered now stays that claim's: the others are still answered (re-audit B1, B17). skip: claims
    this actor gave up on. -> 'moved' | 'stepped' | 'idle' | 'retry' (a failure the next pass tries again, in the log) |
    'step_refused' (the contract's ValidStep on a claim: the actor cannot prove that side, whatever it sends)"""
    claims = game.claims()
    answered = {c.parent for c in claims if c.claimant == actor.signer.address}
    done = 'idle'
    refused = retry = False
    for c in claims:
        if c.countered != b'\x00' * 20 or c.index in answered or c.index in skip:
            continue
        try:
            if _honest(actor, claims, c):
                continue
            r = _answer(game, actor, claims, c, log)
        except (RpcError, ValueError, ArithmeticError, LookupError, ToolFailed) as e:
            retry = _failed(actor, c, e, log) or retry
            if isinstance(e, TxNotMined) and e.tx_hash is None:
                break  # a transaction this object does not know holds the nonce: every other send would wait for it too
            continue
        refused = refused or r == 'step_refused'
        if r not in ('idle', 'step_refused'):
            done = r
    return 'step_refused' if refused else 'retry' if retry else done


def _failed(actor, c, e, log):
    """a claim that was not answered: True if the next pass should try it again"""
    revert = getattr(e, 'revert', None)
    entry = {'actor': actor.name, 'claim': c.index, 'revert': revert, 'error': str(e)[:200]}
    if isinstance(e, RpcError) and _reverted(e, 'ClaimAlreadyExists'):
        log.append(entry | {'raced': c.index})  # someone gave this answer between the read and the send
        return False
    if isinstance(e, RpcError) and _reverted(e, 'ClockTimeExceeded'):
        log.append(entry | {'late': c.index})  # its clock has run out: no move can answer it any more
        return False
    log.append(entry | {'retry': c.index})
    return True


def _belief(actor, claims, c):
    return actor.value(claims, c.parent, c.pos) if c.index else actor.output_claim


def _honest(actor, claims, c):
    """c is what this actor would have posted: its own claim, the root it agrees with, or the right answer to a claim
    that needs one, whoever posted it (op-challenger's honest claim set)"""
    if c.claimant == actor.signer.address:
        return True
    if c.index == 0:
        return actor.output_claim == c.value
    p = claims[c.parent]
    if _honest(actor, claims, p):
        return False
    return c.pos == move(p.pos, _belief(actor, claims, p) != p.value) and c.value == actor.value(claims, p.index, c.pos)


def _answer(game, actor, claims, c, log):
    mine = _belief(actor, claims, c)
    agree = mine == c.value
    if depth(c.pos) == MAX_DEPTH:
        starting, spos, disputed, dpos = outputs(claims, c.parent, c.pos)
        t = exec_trace_index(c.pos)
        attack = not agree
        s = t if attack else t + 1  # attack: re-run step t from the agreed state t; defend: step t+1 from c
        pr = actor.driver.proof(starting, disputed, s)
        try:
            if pr['has-oracle']:
                key = bytes.fromhex(pr['oracle-key'][2:])
                if key[0] != 1:
                    raise ValueError('ORACLE_KEY_NOT_LOCAL')  # only local data is served
                game.add_local_data(actor.signer, int.from_bytes(key[24:], 'big'), c.index, pr['oracle-offset'])
            game.step(actor.signer, c.index, attack, bytes.fromhex(pr['state-data'][2:]),
                      bytes.fromhex(pr['proof-data'][2:]))
        except RpcError as e:
            if _reverted(e, 'DuplicateStep'):  # someone countered this leaf first: that is what the step was for
                log.append({'actor': actor.name, 'duplicate_step': s, 'claim': c.index})
                return 'idle'
            if not _reverted(e, 'ValidStep'):
                raise  # a late receipt, a fee cap, a provider's limit, a lost race: nothing the contract said about the step
            log.append({'actor': actor.name, 'step_refused': s, 'attack': attack, 'claim': c.index,
                        'revert': e.revert, 'error': str(e)[:200]})
            return 'step_refused'
        log.append({'actor': actor.name, 'step': s, 'attack': attack, 'claim': c.index, 'oracle': pr['has-oracle'],
                    'context': '0x' + local_context(starting, spos, disputed, dpos).hex()})
        return 'stepped'
    if agree and c.index == 0:
        return 'idle'  # the root cannot be defended; agreeing with it means nothing to do
    pos = move(c.pos, not agree)
    value = actor.value(claims, c.index, pos)
    if any(x.parent == c.index and x.pos == pos and x.value == value for x in claims):
        return 'idle'  # already answered as this actor would: the contract refuses the same claim twice
    game._bond = game.bond(pos)
    game.move(actor.signer, c.value, c.index, value, not agree)
    log.append({'actor': actor.name, 'pos': pos, 'depth': depth(pos), 'attack': not agree, 'parent': c.index})
    return 'moved'
