"""Independent reference model of the W1 graph escrow (docs/adr/ADR-0011 §1), written from the ADR's state table and
D-rule, not from the Solidity. Where the contract keeps incremental books (a stored ancestor list, `liab` raised at
attach and lowered at each resolution, a chosen payer), this model recomputes from the graph every time:
- ancestors and descendants are SETS found by traversal of the parent links;
- L(a) = sum of owed (comp + ext) over the descendants of a that are not yet resolved (VOIDED or REJECTED);
- a rejected node holds exactly L(a); voiding d moves owed(d) out of every rejected ancestor's cover, one share to d's
  payees and the others to the account, so no payer has to be chosen (T5: balances do not depend on it);
- a settled price is a credit to the executor's free balance (ADR-0012, audit A60): tokens leave only by withdrawal.
Operations raise ModelError(<the contract's custom error name>) when the contract must revert. Amounts are ints in the
token's smallest unit; time is abstracted as a `past_expiry` flag the caller passes."""
from dataclasses import dataclass, field

POSTED, CLAIMED, VERIFIED, FINAL, REJECTED, VOIDED, EXPIRED = (
    'posted', 'claimed', 'verified', 'final', 'rejected', 'voided', 'expired')
STATUS_CODE = {POSTED: 1, CLAIMED: 2, VERIFIED: 3, FINAL: 4, REJECTED: 5, VOIDED: 6, EXPIRED: 7}
RESOLVED = (VOIDED, REJECTED)
MAX_ANCESTORS = 32


class ModelError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


@dataclass
class MNode:
    key: str
    executor: str
    price: int
    comp: int
    ext: int
    cover: int
    parents: tuple
    grade: int
    meets: bool = True  # the verified result halts cleanly and meets the job's condition
    status: str = POSTED
    bonded: bool = False
    cover_held: bool = False
    claim: str = 'none'  # the bound claim at the referee: none / claimed / accepted / rejected

    @property
    def owed(self):
        return self.comp + self.ext


@dataclass
class Model:
    bond_bps: int
    account: int  # the account's free balance
    free: dict = field(default_factory=dict)  # executor -> free balance: stake, received comp and received prices
    withdrawn: dict = field(default_factory=dict)  # executor -> free balance taken out of the escrow as tokens
    nodes: dict = field(default_factory=dict)
    locked: int = 0
    bonds: int = 0
    covers: int = 0

    # ---- graph ----------------------------------------------------------------------------------------------------
    def bond(self, price):
        return -(-price * self.bond_bps // 10_000)

    def ancestors(self, key):
        out, todo = set(), list(self.nodes[key].parents)
        while todo:
            p = todo.pop()
            if p not in out:
                out.add(p)
                todo.extend(self.nodes[p].parents)
        return out

    def descendants(self, key):
        return {d for d in self.nodes if key in self.ancestors(d)}

    def L(self, key):
        return sum(self.nodes[d].owed for d in self.descendants(key) if self.nodes[d].status not in RESOLVED)

    def tokens(self):
        """what the escrow must hold: free balance + locked prices + free stakes + held bonds + held covers"""
        return self.account + self.locked + sum(self.free.values()) + self.bonds + self.covers

    def view(self, key):
        """what the contract's getNode must show for this node (cover/liab only while the cover is held)"""
        n = self.nodes[key]
        held = n.cover_held
        cover = (self.L(key) if n.status == REJECTED else n.cover) if held else None
        return {'status': STATUS_CODE[n.status], 'bonded': n.bonded, 'coverHeld': held, 'grade': n.grade,
                'cover': cover, 'liab': self.L(key) if held else None}

    # ---- operations (each either raises before any change or applies all of it) ---------------------------------
    def post(self, key, executor, price, comp=0, ext=0, cover=0, parents=(), grade=1, meets=True):
        if key in self.nodes:
            raise ModelError('KeyReuse')
        if self.account < price:
            raise ModelError('InsufficientBalance')
        seen = []
        anc = set()
        g = grade
        for p in parents:
            if p in seen:
                raise ModelError('DuplicateParent')
            seen.append(p)
            if p not in self.nodes:
                raise ModelError('UnknownParent')
            pn = self.nodes[p]
            if pn.claim == 'none':
                raise ModelError('ParentNotBound')
            if pn.claim == 'rejected':
                raise ModelError('ParentRejected')
            g = min(g, pn.grade)
            anc |= {p} | self.ancestors(p)
            if len(anc) > MAX_ANCESTORS:
                raise ModelError('TooManyAncestors')
        owed = comp + ext
        if any(self.nodes[a].status in (REJECTED, VOIDED) for a in anc):
            raise ModelError('AncestorDead')
        if any(self.nodes[a].status == EXPIRED for a in anc):
            raise ModelError('AncestorExpired')
        if any(self.nodes[a].status == CLAIMED and self.nodes[a].cover - self.L(a) < owed for a in anc):
            raise ModelError('ExposureExceeded')
        self.nodes[key] = MNode(key, executor, price, comp, ext, cover, tuple(parents), g, meets)
        self.account -= price
        self.locked += price

    def reserve(self, key):
        n = self.nodes[key]
        if n.status != POSTED:
            raise ModelError('WrongStatus')
        if n.bonded or n.cover_held:
            raise ModelError('AlreadyBonded')
        need = self.bond(n.price) + n.cover
        if self.free.get(n.executor, 0) < need:
            raise ModelError('InsufficientBond')
        self.free[n.executor] -= need
        self.bonds += self.bond(n.price)
        self.covers += n.cover
        n.bonded = n.cover_held = True

    def bind(self, key, claim='claimed'):
        n = self.nodes[key]
        if n.status != POSTED:
            raise ModelError('WrongStatus')
        if not n.bonded:
            raise ModelError('NotBonded')
        if claim not in ('claimed', 'accepted'):
            raise ModelError('ClaimNotLive')
        n.claim, n.status = claim, CLAIMED

    def decide(self, key, claim):
        """the referee decides the bound claim (no escrow call)"""
        self.nodes[key].claim = claim

    def _release_cover(self, n):
        n.cover_held = False
        self.covers -= n.cover
        self.free[n.executor] = self.free.get(n.executor, 0) + n.cover

    def verify(self, key):
        n = self.nodes[key]
        if n.status != CLAIMED:
            raise ModelError('WrongStatus')
        if n.claim != 'accepted':
            raise ModelError('ClaimNotAccepted')
        n.status = VERIFIED
        self._release_cover(n)

    def settle(self, key):
        n = self.nodes[key]
        if n.status not in (CLAIMED, VERIFIED):
            raise ModelError('WrongStatus')
        if n.claim != 'accepted':
            raise ModelError('ClaimNotAccepted')
        if any(self.nodes[a].status != FINAL for a in self.ancestors(key)):
            raise ModelError('AncestorNotFinal')
        n.status = FINAL
        if n.cover_held:
            self._release_cover(n)
        self.locked -= n.price
        if n.meets:
            self.free[n.executor] = self.free.get(n.executor, 0) + n.price
        else:
            self.account += n.price
        return n.meets

    def _rejected_ancestors(self, key):
        return [a for a in self.ancestors(key) if self.nodes[a].status == REJECTED]

    def reject(self, key):
        n = self.nodes[key]
        if n.status != CLAIMED:
            raise ModelError('WrongStatus')
        if n.claim != 'rejected':
            raise ModelError('ClaimNotRejected')
        held_before = {a: self.L(a) for a in self._rejected_ancestors(key)}
        surplus = n.cover - self.L(key)
        n.status = REJECTED
        to_account = n.price + surplus
        self.locked -= n.price
        if n.bonded:
            n.bonded = False
            self.bonds -= self.bond(n.price)
            to_account += self.bond(n.price)
        # every rejected ancestor's held cover falls by owed(key) (n is now resolved); nobody is paid for a liar
        released = sum(held_before[a] - self.L(a) for a in held_before)
        self.covers -= surplus + released
        self.account += to_account + released

    def void(self, key, bind_open=False):
        """bind_open: time is still within the node's deadline + grace (a staked POSTED node waits for its bind)"""
        n = self.nodes[key]
        s = n.status
        if s == CLAIMED:
            if n.claim == 'rejected':
                raise ModelError('ClaimRejected')
            if n.claim != 'accepted':
                raise ModelError('ClaimPending')
            honest = True
        elif s == VERIFIED:
            honest = True
        elif s == EXPIRED:
            honest = n.claim == 'accepted'
        elif s == POSTED:
            if n.bonded and bind_open:
                raise ModelError('ClaimPending')
            honest = False
        else:
            raise ModelError('WrongStatus')
        rej = self._rejected_ancestors(key)
        if not rej:
            raise ModelError('NoRejectedAncestor')
        held_before = sum(self.L(a) for a in rej)
        n.status = VOIDED
        to_account = 0
        if s != EXPIRED:
            self.locked -= n.price
            to_account += n.price
        if n.cover_held:
            self._release_cover(n)
        released = held_before - sum(self.L(a) for a in rej)  # = len(rej) * owed
        assert released == len(rej) * n.owed
        self.covers -= released
        # one rejected ancestor's share pays d's payees, the others go to the account
        to_account += released - n.owed + n.ext + (0 if honest else n.comp)
        if honest:
            self.free[n.executor] = self.free.get(n.executor, 0) + n.comp
        self.account += to_account
        return honest

    def expire(self, key, past_expiry=True):
        n = self.nodes[key]
        if n.status not in (POSTED, CLAIMED, VERIFIED):
            raise ModelError('WrongStatus')
        if not past_expiry:
            raise ModelError('TooEarly')
        if n.status == CLAIMED and n.claim == 'rejected':
            raise ModelError('ClaimRejected')
        if n.status != POSTED and n.claim == 'accepted' and not any(self.nodes[a].status in (REJECTED, VOIDED, EXPIRED)
                                                                    for a in self.ancestors(key)):
            raise ModelError('Settleable')  # ADR-0012 D11: settle it, or wait for its ancestors
        n.status = EXPIRED
        self.locked -= n.price
        self.account += n.price
        if n.bonded:
            n.bonded = False
            self.bonds -= self.bond(n.price)
            self.free[n.executor] = self.free.get(n.executor, 0) + self.bond(n.price)
        if n.cover_held:
            self._release_cover(n)

    def release(self, key, past_expiry=True):
        n = self.nodes[key]
        if not n.bonded:
            raise ModelError('NotBonded')
        if n.status not in (FINAL, VOIDED):
            raise ModelError('WrongStatus')
        if not past_expiry:
            raise ModelError('TooEarly')
        n.bonded = False
        self.bonds -= self.bond(n.price)
        self.free[n.executor] = self.free.get(n.executor, 0) + self.bond(n.price)

    def slash(self, key, past_expiry=False):
        """another (unbound) claim of the node's executor for its computation was rejected"""
        n = self.nodes[key]
        if not n.bonded:
            raise ModelError('NotBonded')
        if past_expiry:
            raise ModelError('TooLate')
        n.bonded = False
        self.bonds -= self.bond(n.price)
        self.account += self.bond(n.price)

    def withdraw_bond(self, executor, amount):
        if self.free.get(executor, 0) < amount:
            raise ModelError('InsufficientBond')
        self.free[executor] = self.free.get(executor, 0) - amount
        self.withdrawn[executor] = self.withdrawn.get(executor, 0) + amount

    # ---- invariants -----------------------------------------------------------------------------------------------
    def exposure_ok(self):
        """D-rule: every node that holds cover covers its unresolved descendants' owed (CLAIMED: cover >= L;
        REJECTED: holds exactly L)"""
        return all(n.cover >= self.L(k) for k, n in self.nodes.items() if n.cover_held and n.status == CLAIMED)


def final_settlement_latency(depth, exec_s, window, early):
    """ADR-0010 §2 model of an honest chain of `depth` jobs with no disputes: sequential = every job waits for its parent
    to be paid; early = each job starts on its parent's claimed result and payment waits for the ancestors. Finalizing
    needs one second past the window."""
    if early:
        return depth * exec_s + window + 1
    return depth * (exec_s + window + 1)
