"""Reference model for W1 (docs/adr/ADR-0010): the liability of a dependency graph of claims whose results are consumed
before they are final. Pure Python and exhaustive over small graphs; the Solidity OmegaGraphEscrow has to agree with it.

A node is one claim (a job's result). Each node d carries:
  price     paid by the account to d's executor, only once d and every ancestor of d are FINAL (never earlier);
  comp      owed to d's executor if d is VOIDED (some ancestor rejected): the wasted honest work;
  external  declared irreversible exposure created by relying on d before it is final, owed to the account if d is
            voided (only what was declared is covered);
  bond      d's own deterrence stake (bondFor(price)), always to the account when d itself is rejected;
  coverage  d's stake that pays the owed amounts of its voided descendants when d is rejected.
owed(d) = comp(d) + external(d). The rule under test (descendant set): coverage(a) >= sum of owed(d) over the SET of
descendants of a, each descendant counted once however many paths reach it. Edges point from parents to children and a
node can only name existing parents, so the graph is acyclic by construction.
"""
from dataclasses import dataclass
from itertools import combinations, permutations


@dataclass(frozen=True)
class Node:
    price: int
    comp: int
    external: int = 0
    bond: int = 0
    parents: tuple = ()

    @property
    def owed(self):
        return self.comp + self.external


class GraphError(ValueError):
    pass


class Graph:
    def __init__(self):
        self.nodes = []

    def add(self, node):
        if len(set(node.parents)) != len(node.parents):
            raise GraphError('DuplicateParent')
        for p in node.parents:
            if not 0 <= p < len(self.nodes):
                raise GraphError('UnknownParent')  # a node may name only existing nodes: no cycle can form
        self.nodes.append(node)
        return len(self.nodes) - 1

    def children(self, i):
        return [j for j, n in enumerate(self.nodes) if i in n.parents]

    def descendants(self, i):
        seen, todo = set(), list(self.children(i))
        while todo:
            j = todo.pop()
            if j not in seen:
                seen.add(j)
                todo.extend(self.children(j))
        return seen

    def ancestors(self, i):
        seen, todo = set(), list(self.nodes[i].parents)
        while todo:
            j = todo.pop()
            if j not in seen:
                seen.add(j)
                todo.extend(self.nodes[j].parents)
        return seen

    def paths(self, i, j):
        if i == j:
            return 1
        return sum(self.paths(c, j) for c in self.children(i))

    def first_parent_chain(self, d):
        out, cur = [], d
        while self.nodes[cur].parents:
            cur = self.nodes[cur].parents[0]
            out.append(cur)
        return out

    # ---- coverage rules ------------------------------------------------------------------------------------------------
    def coverage(self, i, rule='desc'):
        n = self.nodes
        if rule == 'desc':  # the rule under test
            return sum(n[d].owed for d in self.descendants(i))
        if rule == 'edge':  # direct children only
            return sum(n[c].owed for c in self.children(i))
        if rule == 'single':  # each node charged to its first-parent chain only (to "avoid double counting")
            return sum(n[d].owed for d in range(len(n)) if i in self.first_parent_chain(d))
        if rule == 'path':  # once per path: never short, counts merges twice
            return sum(n[d].owed * self.paths(i, d) for d in self.descendants(i))
        raise ValueError(rule)

    def stakes(self, rule='desc'):
        return [self.coverage(i, rule) for i in range(len(self.nodes))]

    # ---- outcomes ------------------------------------------------------------------------------------------------------
    def outcome(self, rejected, cover, order=None, stalled=()):
        """All false claims are rejected (one honest watcher). Processing the rejections in `order`, each rejected node's
        coverage pays the still-unpaid owed amounts of its voided descendants; its bond goes to the account.
        `stalled`: claims never decided (the verifier stalls): their descendants expire, with nobody slashed.
        -> dict(shortfall, paid_owed, account, voided, final, uncovered_liveness)"""
        rejected = set(rejected)
        voided = set().union(*(self.descendants(a) for a in rejected)) - rejected if rejected else set()
        expired = set().union(*(self.descendants(s) for s in stalled)) - voided - rejected if stalled else set()
        paid = {}
        account = 0
        for a in (order if order is not None else sorted(rejected)):
            left = cover[a]
            for d in sorted(self.descendants(a)):
                if d in voided and d not in paid:
                    take = min(left, self.nodes[d].owed)
                    paid[d] = take
                    left -= take
            account += self.nodes[a].bond + left
        owed = sum(self.nodes[d].owed for d in voided)
        final = [i for i in range(len(self.nodes)) if i not in rejected | voided | expired | set(stalled)]
        return {'shortfall': owed - sum(paid.values()), 'paid_owed': sum(paid.values()), 'account': account,
                'voided': sorted(voided), 'final': final,
                'uncovered_liveness': sum(self.nodes[d].owed for d in expired)}

    def worst(self, rule='desc', max_orders=24):
        """max shortfall over every set of rejected claims and (up to max_orders) processing orders, with the stakes the
        rule asks for; also whether the account got every rejected node's bond. -> (shortfall, witness)"""
        cover = self.stakes(rule)
        idx = range(len(self.nodes))
        worst, witness = 0, None
        for k in range(1, len(self.nodes) + 1):
            for rej in combinations(idx, k):
                for m, order in enumerate(permutations(rej)):
                    if m >= max_orders:
                        break
                    r = self.outcome(rej, cover, order)
                    if r['shortfall'] > worst:
                        worst, witness = r['shortfall'], {'rejected': list(rej), 'order': list(order), **r}
        return worst, witness

    def attach(self, node, cover, final=frozenset(), rejected=frozenset()):
        """Add `node` under its parents if every non-final ancestor has room for its owed amount (reserved once per
        ancestor, however many paths). -> new index; raises ExposureExceeded / ParentRejected without changing anything."""
        for p in node.parents:
            if p in rejected:
                raise GraphError('ParentRejected')
        anc = set()
        for p in node.parents:
            anc |= {p} | self.ancestors(p)
        need = {a: node.owed for a in anc if a not in final}
        for a, x in need.items():
            if cover[a] - self.coverage(a) < x:
                raise GraphError('ExposureExceeded')
        return self.add(node)


def chain(k, price=10, comp=4, bond=13):
    g = Graph()
    prev = None
    for _ in range(k):
        prev = g.add(Node(price, comp, 0, bond, () if prev is None else (prev,)))
    return g
