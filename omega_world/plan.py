"""World computer work model (docs/adr/ADR-0012): a Plan is a DAG of Tasks, each one job that OmegaGraphEscrow can pay
for. A task's kind says what its referee judges:
- 'ovm0' (OVM0Dispute): a program with inputs; its prog is the program's commitment.
- 'cannon' (OmegaCannonReferee): the same job, run by the Cannon guest; its prog is the absolute prestate, which commits to
  the guest, the program, the inputs and the step limit (so a child's prog follows from its parents' outputs).
- 'op' (OmegaSuperRootReferee): a question, "what is the output root of L2 chain c at L2 time t?": no program, no
  values, one step, always a root. Make it with op_task. Its output is the root's first 8 bytes.
The referee reports the same commitments for a claim, and the escrow binds a claim only if they match the node's.
A task's inputs are its parents' verified outputs (in parent order) followed by its own constants. Everything an
orchestrator needs is derived from the plan alone:
- the job key of every attempt (keccak of plan id, task name, attempt), so a restarted orchestrator finds its nodes;
- the claim deadline of every attempt (anchor + ttl * (attempt + 1)), so a re-signed request is byte-identical and its
  re-post is an idempotent no-op;
- the D-rule cover of every task (sum of owed over its planned descendant set, ADR-0010 §3), so every planned link fits.
Retries are new attempts (new nodes, ADR-0011 K2); attempt i is assigned to executors[i % len(executors)]."""
import json
from dataclasses import asdict, dataclass, field
from omega_compute import evm_step as E
from omega_compute import graph_liability as GL
from omega_compute import vm
from omega_kernel.settlement.evm_crypto import keccak
from omega_world.cannon import MAX_ORACLE_STEPS
from omega_world.op_attest import PROG as OP_PROG

MAX_PARENTS, MAX_INPUTS, MAX_ANCESTORS = 8, 64, 32  # the escrow's limits
# OVM0Inbox takes 4096 instructions and 1024 inputs, and such a transaction cannot be mined (re-audit F4: publish(4096, 1024)
# takes 18,159,304 gas over EIP-7825's 2 ** 24; (4096, 0) passes today and not under Glamsterdam's calldata floor). A public
# mempool refuses transactions above about 128 KB. A job whose publication cannot be mined cannot be watched: not posted.
PUBLISH_MAX_BYTES, TX_GAS_CAP = 120_000, 1 << 24
KINDS = ('ovm0', 'cannon', 'op')


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class Task:
    name: str
    program: tuple
    inputs: tuple = ()  # constants after the parents' outputs
    parents: tuple = ()  # task names, earlier in the plan
    executors: tuple = ()  # 0x-hex addresses, one per attempt (round robin)
    referee: str = ''  # 0x-hex address of the referee contract
    price: int = 1_000
    comp: int = 0
    ext: int = 0
    cond: int = 0
    cond_arg: int = 0
    max_steps: int = 10_000
    kind: str = 'ovm0'
    l2_chain_id: int = 0  # kind 'op': the question
    l2_time: int = 0


def op_task(name, l2_chain_id, l2_time, executors, referee, **terms):
    """the task of an Optimism output root question"""
    return Task(name, (), (), (), executors, referee, kind='op', l2_chain_id=l2_chain_id, l2_time=l2_time, max_steps=1,
                **terms)


def meets(task, c):
    """the claimed result halted cleanly and meets the task's condition (as OmegaGraphEscrow pays)"""
    if c['trap'] != 0:
        return False
    out, arg = c['output'], task.cond_arg
    return {0: True, 1: out == arg, 2: out <= arg, 3: out >= arg}[task.cond]


def publish_bytes(t):
    """the size of the task's OVM0Inbox.publish calldata: the selector, three offsets and lengths, then one word per value.
    A parent's output is one word whatever it says"""
    return 4 + 6 * 32 + 32 * (2 * len(t.program) + len(t.parents) + len(t.inputs))


def _check_kind(t):
    """what the task's referee and guest cannot take, before any money is locked for it"""
    if t.kind not in KINDS or (t.kind != 'op' and (t.l2_chain_id or t.l2_time)):
        raise PlanError(f'BAD_KIND:{t.name}')
    if t.kind == 'op':
        if t.program or t.inputs or t.parents or t.max_steps != 1 or t.l2_chain_id <= 0 or t.l2_time <= 0:
            raise PlanError(f'BAD_OP_JOB:{t.name}')
        return
    if t.kind == 'cannon' and (not 1 <= t.max_steps <= MAX_ORACLE_STEPS or not all(0 <= int(x) < 1 << 64 for x in t.inputs)):
        raise PlanError(f'BAD_CANNON_JOB:{t.name}')
    vm.check_program([list(x) for x in t.program])


@dataclass
class Plan:
    account: str  # 0x-hex bytes32
    anchor: int  # unix time the plan was fixed
    ttl: int  # seconds per attempt
    tasks: tuple
    max_attempts: int = 3
    _index: dict = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self):
        self.tasks = tuple(t if isinstance(t, Task) else Task(**{**t, 'program': tuple(tuple(i) for i in t['program']),
                                                                 'inputs': tuple(t.get('inputs', ())),
                                                                 'parents': tuple(t.get('parents', ())),
                                                                 'executors': tuple(t.get('executors', ()))})
                           for t in self.tasks)
        if not self.tasks:
            raise PlanError('EMPTY')
        if self.ttl <= 0 or not 1 <= self.max_attempts <= 16:
            raise PlanError('BAD_TIMING')
        for i, t in enumerate(self.tasks):
            if t.name in self._index:
                raise PlanError(f'DUPLICATE_TASK:{t.name}')
            if len(t.parents) > MAX_PARENTS or len(set(t.parents)) != len(t.parents):
                raise PlanError(f'BAD_PARENTS:{t.name}')
            for p in t.parents:
                if p not in self._index:  # parents must come first: the plan is acyclic by construction
                    raise PlanError(f'UNKNOWN_OR_LATER_PARENT:{t.name}<-{p}')
            _check_kind(t)
            if len(t.parents) + len(t.inputs) > MAX_INPUTS or (t.kind != 'op' and not t.parents and not t.inputs):
                raise PlanError(f'BAD_INPUTS:{t.name}')
            if t.price <= 0 or min(t.comp, t.ext, t.cond_arg) < 0 or not t.executors or not t.referee:
                raise PlanError(f'BAD_TERMS:{t.name}')
            self._index[t.name] = i
        g = self.graph()
        for i, t in enumerate(self.tasks):
            if len(g.ancestors(i)) > MAX_ANCESTORS:
                raise PlanError(f'TOO_DEEP:{t.name}')

    # ---- derived ----------------------------------------------------------------------------------------------------
    def task(self, name):
        return self.tasks[self._index[name]]

    def graph(self):
        g = GL.Graph()
        for t in self.tasks:
            g.add(GL.Node(t.price, t.comp, t.ext, 0, tuple(self._index[p] for p in t.parents)))
        return g

    def covers(self):
        """D-rule cover per task: owed of its planned descendant set (each once)"""
        g = self.graph()
        return {t.name: g.coverage(i, 'desc') for i, t in enumerate(self.tasks)}

    def children(self, name):
        return [t.name for t in self.tasks if name in t.parents]

    def to_json(self):
        def fields(t):  # an OVM-0 task writes what it always wrote: a plan's id and keys must not move
            d = {**asdict(t), 'program': [list(i) for i in t.program], 'inputs': list(t.inputs),
                 'parents': list(t.parents), 'executors': list(t.executors)}
            return d if t.kind != 'ovm0' else {k: v for k, v in d.items() if k not in ('kind', 'l2_chain_id', 'l2_time')}
        body = {'account': self.account, 'anchor': self.anchor, 'ttl': self.ttl, 'max_attempts': self.max_attempts,
                'tasks': [fields(t) for t in self.tasks]}
        return json.dumps(body, sort_keys=True, separators=(',', ':'))

    @classmethod
    def from_json(cls, text):
        d = json.loads(text)
        return cls(d['account'], d['anchor'], d['ttl'], tuple(d['tasks']), d['max_attempts'])

    def plan_id(self):
        return keccak(b'OMEGA-WORLD-PLAN-v1\x00' + self.to_json().encode())

    def key(self, name, attempt):
        """bound to the account (first 12 bytes = keccak(account)'s, ADR-0012 D10)"""
        tail = keccak(b'OMEGA-WORLD-TASK-v1\x00' + self.plan_id() + name.encode() + b'\x00' + attempt.to_bytes(4, 'big'))
        return keccak(bytes.fromhex(self.account[2:]))[:12] + tail[:20]

    def deadline(self, attempt):
        return self.anchor + self.ttl * (attempt + 1)

    def executor(self, name, attempt):
        ex = self.task(name).executors
        return bytes.fromhex(ex[attempt % len(ex)][2:])

    def programs(self, prestates=None, outputs=None):
        """task name -> the prog an owner must allow (setProgram) for the task's honest run. A Cannon prestate commits to
        the inputs, and a child's inputs are its parents' outputs: they follow from the reference VM, so one pass before
        the plan starts covers every honest attempt and an agent never needs the owner (READINESS_AUDIT A21). A task
        missing here depends on something not computed here: `outputs` gives what is known of it (an Optimism answer, a
        task's result read from chain). Nothing is given under a parent that traps or misses its condition (D13)."""
        out, known = {}, dict(outputs or {})
        for t in self.tasks:
            if t.kind == 'op':
                out[t.name] = OP_PROG
                continue
            prog = [list(i) for i in t.program]
            if t.kind == 'ovm0':
                out[t.name] = E.program_commit(prog).commitment
            if any(p not in known for p in t.parents):
                continue
            inputs = [known[p] for p in t.parents] + list(t.inputs)
            if t.kind == 'cannon':
                if prestates is None:
                    raise PlanError('CANNON_NEEDS_PRESTATES')
                out[t.name] = prestates(prog, inputs, t.max_steps)
            r = vm.output(vm.run(prog, inputs, t.max_steps)[0])
            c = {'trap': 1 if r['trap'] else 0, 'output': r['stack_top'] or 0}
            if t.name not in known and meets(t, c):
                known[t.name] = c['output']
        return out
