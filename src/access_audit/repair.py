"""Offline minimal-cost separation-of-duty repair via exact branch-and-bound.

Given one validated RBAC snapshot (``--source``) and a repair plan
(``--plan``) of at most 24 candidate edge deletions -- user-role assignments
and role-role inherits, each with a positive integer cost -- plus protected
concrete requests, select the globally optimal subset of candidate edges to
delete.  Only candidate edges may be deleted; every user, role and grant is
kept.  The repaired policy must satisfy all of:

* no user's effective roles contain both roles of any exclusion pair;
* every protected request still decides ``allow``;
* no user gains an ``allow`` on any legal (action, resource) pair relative to
  the source policy -- in particular deleting a deny-carrying role must never
  turn a deny into an allow (deny revocation grants nothing).

The objective is lexicographic: minimal total cost, then minimal number of
deleted edges, then the lexicographically smallest sorted edit-id sequence.
The search is an exact branch-and-bound over the candidate edges -- never a
greedy heuristic and never a 2^N enumeration of complete policies:

* positive costs bound any completion by the current cost, so a node whose
  cost reaches the incumbent is pruned;
* a deletion set only shrinks effective roles, so a conflict surviving
  deletion of every remaining candidate is unfixable, and a protected request
  already broken stays broken;
* if a deny-covered (action, resource) cell already lost every deny role
  while an allow role survives even under maximal remaining deletion, every
  completion grants a new allow and the subtree is doomed;
* each unresolved exclusion needs at least one remaining edge from the paths
  towards its roles; a maximal family of pairwise disjoint such constraints
  sums their cheapest edges into a lower bound on any completion's extra cost;
* an edge whose deletion alone breaks a protected request, or dooms every
  superset via deny revival, can never be selected and is dropped upfront.

Infeasibility is reported as a plain error: no combination of the candidate
edits satisfies every constraint, the command exits 2 and keeps the old
report.
"""
from .common import require, ident, rows, number, read
from .model import load_policy, parse_requests, pattern
from .diff import _probe_universe
from .bulk import GrantIndex

MAX_EDITS = 24
MAX_PROTECT = 10_000
_KINDS = ('assignment', 'inherits')


def _check_edit(raw):
    require(raw, 'id kind source role cost')
    edit = {'id': ident(raw['id']), 'kind': raw['kind'],
            'source': ident(raw['source']), 'role': ident(raw['role']),
            'cost': number(raw['cost'], 1)}
    if edit['kind'] not in _KINDS:
        raise ValueError('edit kind must be assignment or inherits')
    return edit


def _check_protect(raw, users):
    require(raw, 'id user action resource')
    request = {'id': ident(raw['id']), 'user': raw['user'],
               'action': ident(raw['action']), 'resource': pattern(raw['resource'])}
    if request['user'] not in users or '*' in request['action'] or '*' in request['resource']:
        raise ValueError('invalid concrete protect request')
    return request


def compile_plan(plan, data, users):
    """Validate the plan document against the already validated source document."""
    require(plan, 'edits protect')
    if not isinstance(plan['edits'], list) or len(plan['edits']) > MAX_EDITS:
        raise ValueError('edits must be an array of at most %d candidate edits' % MAX_EDITS)
    role_inherits = {row['id']: row['inherits'] for row in data['roles']}
    user_roles = {row['id']: row['roles'] for row in data['users']}
    edits = []
    ids = set()
    edges = set()
    for raw in plan['edits']:
        edit = _check_edit(raw)
        if edit['id'] in ids:
            raise ValueError('duplicate edit id: ' + edit['id'])
        ids.add(edit['id'])
        edge = (edit['kind'], edit['source'], edit['role'])
        if edge in edges:
            raise ValueError('duplicate candidate edge: %s %s %s' % edge)
        edges.add(edge)
        known = user_roles.get(edit['source'], ()) if edit['kind'] == 'assignment' \
            else role_inherits.get(edit['source'], ())
        if edit['role'] not in known:
            raise ValueError('candidate edge does not exist: %s %s %s' % edge)
        edits.append(edit)
    protect = []
    request_ids = set()
    for raw in rows(plan['protect'], MAX_PROTECT):
        request = _check_protect(raw, users)
        if request['id'] in request_ids:
            raise ValueError('duplicate protect request id: ' + request['id'])
        request_ids.add(request['id'])
        protect.append(request)
    return edits, protect


class Repair:
    """Exact minimal-cost repair search for one source document and one plan."""

    def __init__(self, data, plan):
        closure, users, grants, exclusions = load_policy(data)
        parse_requests(data, users)  # source requests are validated and carried, never compared
        self.data = data
        self.grants = grants
        self.edits, self.protect = compile_plan(plan, data, users)
        self.roles = sorted(closure)
        self.bit = {role: 1 << index for index, role in enumerate(self.roles)}
        self.user_order = sorted(users)
        self.eff0 = {}
        for uid in self.user_order:
            mask = 0
            for role in users[uid]:
                mask |= self.bit[role]
            self.eff0[uid] = mask
        self.cost = [edit['cost'] for edit in self.edits]
        self.ids = [edit['id'] for edit in self.edits]
        edge_index = {}
        for index, edit in enumerate(self.edits):
            edge_index[(edit['kind'], edit['source'], edit['role'])] = index
        self.role_parents = {}
        for row in data['roles']:
            self.role_parents[row['id']] = [
                (parent, edge_index.get(('inherits', row['id'], parent)))
                for parent in row['inherits']]
        self.user_roles = {}
        for row in data['users']:
            self.user_roles[row['id']] = [
                (role, edge_index.get(('assignment', row['id'], role)))
                for role in row['roles']]
        self._eff_cache = {}
        # Deterministic probe universe (the same construction as access-diff):
        # every legal (action, resource) decision change is witnessed by a probe.
        # Grants are bucketed by literal pattern, so each probe only inspects
        # the few buckets its concrete action/resource can hit.
        index = GrantIndex(grants)
        actions, resources = _probe_universe(grants)
        signatures = set()
        for action in actions:
            for resource in resources:
                allow = deny = 0
                for grant in index.candidates(action, resource):
                    if grant['effect'] == 'allow':
                        allow |= self.bit[grant['role']]
                    else:
                        deny |= self.bit[grant['role']]
                signatures.add((allow, deny))
        self.signatures = sorted(signatures)
        # Probe cells where the user is denied in the source policy: only those
        # can become illegal new allows after deletions.
        self.denied = {}
        for uid in self.user_order:
            mask = self.eff0[uid]
            self.denied[uid] = [signature for signature in self.signatures
                                if (mask & signature[1]) or not (mask & signature[0])]
        self.protect_checks = []
        for request in self.protect:
            allow = deny = 0
            for grant in index.candidates(request['action'], request['resource']):
                if grant['effect'] == 'allow':
                    allow |= self.bit[grant['role']]
                else:
                    deny |= self.bit[grant['role']]
            mask = self.eff0[request['user']]
            if (mask & deny) or not (mask & allow):
                raise ValueError("no feasible repair: protected request '%s' is not allow "
                                 "in the source policy" % request['id'])
            self.protect_checks.append((request['user'], allow))
        self.pairs = [((self.bit[pair[0]] | self.bit[pair[1]]), (pair[0], pair[1]))
                      for pair in exclusions]
        # Candidate edges lying on some path from a user towards a conflicting
        # role; a superset of the edges able to remove that role, used only as
        # a sound lower-bound ingredient.
        conflict_roles = {role for _mask, pair in self.pairs for role in pair}
        self.path_edges = {}
        for index, edit in enumerate(self.edits):
            if edit['kind'] == 'assignment':
                for role in closure[edit['role']] & conflict_roles:
                    if self.eff0[edit['source']] & self.bit[role]:
                        self.path_edges.setdefault((edit['source'], role), set()).add(index)
            else:
                targets = closure[edit['role']] & conflict_roles
                if not targets:
                    continue
                for uid in self.user_order:
                    if not (self.eff0[uid] & self.bit[edit['source']]):
                        continue
                    for role in targets:
                        if self.eff0[uid] & self.bit[role]:
                            self.path_edges.setdefault((uid, role), set()).add(index)
        self.nodes = 0

    def effective(self, deleted):
        """Effective role bitmask per user after deleting the given edge indices."""
        cached = self._eff_cache.get(deleted)
        if cached is not None:
            return cached
        closures = {}

        def visit(role):
            mask = closures.get(role)
            if mask is None:
                mask = self.bit[role]
                for parent, edge in self.role_parents[role]:
                    if edge is None or edge not in deleted:
                        mask |= visit(parent)
                closures[role] = mask
            return mask

        for role in self.roles:
            visit(role)
        effective = {}
        for uid in self.user_order:
            mask = 0
            for role, edge in self.user_roles[uid]:
                if edge is None or edge not in deleted:
                    mask |= closures[role]
            effective[uid] = mask
        self._eff_cache[deleted] = effective
        return effective

    def _live(self, effective):
        """Exclusion conflicts present under these effective roles."""
        return [(uid, mask, pair) for uid in self.user_order
                for mask, pair in self.pairs if effective[uid] & mask == mask]

    def _protects_ok(self, effective):
        return all(effective[uid] & allow for uid, allow in self.protect_checks)

    def _no_new_allow_ok(self, effective):
        for uid in self.user_order:
            mask = effective[uid]
            for allow, deny in self.denied[uid]:
                if not (mask & deny) and (mask & allow):
                    return False
        return True

    def _doomed(self, current, maximal):
        """Some deny-covered cell already lost every deny role while an allow
        role survives even under maximal remaining deletion: every completion
        grants a new allow, so the whole subtree is infeasible."""
        for uid in self.user_order:
            now = current[uid]
            most = maximal[uid]
            for allow, deny in self.denied[uid]:
                if not (now & deny) and (most & allow):
                    return True
        return False

    def _conflict_lower_bound(self, live, remaining):
        """Lower bound on the extra cost any completion must spend: each live
        conflict needs at least one remaining edge from the paths towards its
        roles; a maximal family of pairwise disjoint constraints sums minima."""
        constraints = []
        for uid, _mask, (first, second) in live:
            edges = (self.path_edges.get((uid, first), set())
                     | self.path_edges.get((uid, second), set())) & remaining
            if not edges:
                return None
            constraints.append(edges)
        constraints.sort(key=lambda edges: -min(self.cost[index] for index in edges))
        used = set()
        bound = 0
        for edges in constraints:
            if not (edges & used):
                bound += min(self.cost[index] for index in edges)
                used |= edges
        return bound

    def solve(self):
        """Return the optimal set of edge indices, or None when infeasible."""
        usable = list(range(len(self.edits)))
        while True:  # edges that can never belong to a feasible solution
            maximal = self.effective(frozenset(usable))
            kept = [index for index in usable
                    if self._protects_ok(self.effective(frozenset((index,))))
                    and not self._doomed(self.effective(frozenset((index,))), maximal)]
            if len(kept) == len(usable):
                break
            usable = kept
        bad = self._live(self.effective(frozenset(usable)))
        if bad:
            uid, _mask, (first, second) = bad[0]
            raise ValueError("no feasible repair: separation conflict for user '%s' on roles "
                             "['%s', '%s'] cannot be resolved with the candidate edits"
                             % (uid, first, second))
        order = sorted(usable, key=lambda index: (-self.cost[index], self.ids[index]))
        suffix = [frozenset(order[position:]) for position in range(len(order) + 1)]
        best = []

        def visit(selected, cost, position):
            self.nodes += 1
            if best and cost > best[0][0]:
                return
            current = self.effective(selected)
            remaining = suffix[position]
            if self._live(self.effective(selected | remaining)):
                return  # conflicts survive every completion in this subtree
            if not self._protects_ok(current):
                return  # a broken protect can never be restored by deleting more
            if self._doomed(current, self.effective(selected | remaining)):
                return
            live = self._live(current)
            if not live and self._no_new_allow_ok(current):
                key = (cost, len(selected), tuple(sorted(self.ids[index] for index in selected)))
                if not best or key < best[0]:
                    best[:] = [key, selected]
                return  # positive costs: no completion of a feasible set can win
            if best:
                if cost == best[0][0]:
                    return
                bound = self._conflict_lower_bound(live, remaining)
                if bound is None or cost + bound > best[0][0]:
                    return
            if position == len(order):
                return
            edge = order[position]
            visit(selected, cost, position + 1)                             # exclude
            visit(selected | {edge}, cost + self.cost[edge], position + 1)  # include

        visit(frozenset(), 0, 0)
        return best[1] if best else None


def repaired_policy(data, selected):
    """Apply the chosen edits to the source document: delete only the selected
    assignment/inherits edges; keep every user, role and grant."""
    drop_assignment = {}
    drop_inherits = {}
    for edit in selected:
        drops = drop_assignment if edit['kind'] == 'assignment' else drop_inherits
        drops.setdefault(edit['source'], set()).add(edit['role'])
    roles = [{'id': row['id'],
              'inherits': sorted(parent for parent in row['inherits']
                                 if parent not in drop_inherits.get(row['id'], ()))}
             for row in sorted(data['roles'], key=lambda row: row['id'])]
    users = [{'id': row['id'],
              'roles': sorted(role for role in row['roles']
                              if role not in drop_assignment.get(row['id'], ()))}
             for row in sorted(data['users'], key=lambda row: row['id'])]
    return {'roles': roles, 'users': users,
            'grants': sorted(data['grants'], key=lambda row: row['id']),
            'exclusions': data['exclusions'], 'requests': data['requests']}


def run(source, plan_path):
    """Compute the optimal repair and return the auditable report."""
    data, source_sha256 = read(source)
    plan, plan_sha256 = read(plan_path)
    engine = Repair(data, plan)
    selected = engine.solve()
    if selected is None:
        raise ValueError('no feasible repair: no combination of the %d candidate edits '
                         'satisfies all constraints' % len(engine.edits))
    chosen = [engine.edits[index] for index in sorted(selected)]
    return {'schema_version': 1, 'source_sha256': source_sha256, 'plan_sha256': plan_sha256,
            'selected_edits': sorted(edit['id'] for edit in chosen),
            'total_cost': sum(edit['cost'] for edit in chosen),
            'policy': repaired_policy(data, chosen)}
