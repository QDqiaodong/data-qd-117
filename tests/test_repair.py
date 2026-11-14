import hashlib, json, random, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from access_audit import repair
from access_audit.model import analyze
from access_audit.diff import compile_snapshot, diff_snapshots

ROOT = Path(__file__).resolve().parents[1]

def role(rid, inherits=()): return {'id': rid, 'inherits': list(inherits)}
def user(uid, roles=()): return {'id': uid, 'roles': list(roles)}
def grant(gid, r, action, resource, effect):
    return {'id': gid, 'role': r, 'action': action, 'resource': resource, 'effect': effect}
def edit(eid, kind, source, role_id, cost):
    return {'id': eid, 'kind': kind, 'source': source, 'role': role_id, 'cost': cost}
def preq(rid, uid, action, resource):
    return {'id': rid, 'user': uid, 'action': action, 'resource': resource}
def policy(roles, users, grants, exclusions, requests=None):
    return {'roles': roles, 'users': users, 'grants': grants,
            'exclusions': exclusions, 'requests': requests or []}
def plan(edits, protect=()): return {'edits': list(edits), 'protect': list(protect)}

def solve(data, pl):
    engine = repair.Repair(data, pl)
    return engine, engine.solve()

def key_of(engine, selected):
    return (sum(engine.cost[i] for i in selected), len(selected),
            tuple(sorted(engine.ids[i] for i in selected)))

def chosen_edits(engine, selected):
    return [engine.edits[i] for i in sorted(selected)]

def assert_audit_clean(case, source, repaired, protect):
    """The repaired policy is directly auditable: no separation conflict, every
    protected request still allows, and no user gains any allow vs the source."""
    case.assertEqual(analyze(repaired)['separation_conflicts'], [])
    if protect:
        audited = analyze(dict(repaired, requests=list(protect)))
        case.assertEqual([r['decision'] for r in audited['requests']],
                         ['allow'] * len(protect))
    drift = diff_snapshots(compile_snapshot(source), compile_snapshot(repaired), 's', 'r')
    for change in drift['user_changes']:
        case.assertEqual(change['granted'], [])

class ScenarioTests(unittest.TestCase):
    def test_diamond_multipath_requires_cutting_both_paths(self):
        # U reaches C through two inheritance paths; one cut never removes C
        roles = [role('A', ['C']), role('B', ['C']), role('C'), role('D')]
        users = [user('U', ['A', 'B', 'D'])]
        grants = [grant('G1', 'C', 'read', '/c', 'allow'),
                  grant('G2', 'D', 'read', '/d', 'allow')]
        data = policy(roles, users, grants, [['C', 'D']])
        pl = plan([edit('E_UA', 'assignment', 'U', 'A', 5),
                   edit('E_UB', 'assignment', 'U', 'B', 5),
                   edit('E_AC', 'inherits', 'A', 'C', 2),
                   edit('E_BC', 'inherits', 'B', 'C', 2),
                   edit('E_UD', 'assignment', 'U', 'D', 10)])
        engine, selected = solve(data, pl)
        # cheapest single edge can never fix the diamond: C survives via the other parent
        alone = next(i for i, e in enumerate(engine.edits) if e['id'] == 'E_AC')
        self.assertIn('C', [r for r in engine.roles
                            if engine.bit[r] & engine.effective(frozenset({alone}))['U']])
        # the optimum cuts both inheritance paths (2+2 beats 5+5 and 10)
        self.assertEqual(key_of(engine, selected), (4, 2, ('E_AC', 'E_BC')))
        repaired = repair.repaired_policy(data, chosen_edits(engine, selected))
        self.assertEqual(repaired['roles'],
                         [role('A'), role('B'), role('C'), role('D')])
        self.assertEqual(repaired['users'], [user('U', ['A', 'B', 'D'])])
        assert_audit_clean(self, data, repaired, pl['protect'])

    def test_shared_inherits_edge_serves_two_users(self):
        # one shared inherits edge repairs both users' conflicts at once
        roles = [role('A', ['B']), role('B'), role('D')]
        users = [user('U1', ['A', 'D']), user('U2', ['A', 'D'])]
        grants = [grant('G1', 'B', 'read', '/b', 'allow')]
        data = policy(roles, users, grants, [['B', 'D']])
        pl = plan([edit('E_U1A', 'assignment', 'U1', 'A', 5),
                   edit('E_U2A', 'assignment', 'U2', 'A', 5),
                   edit('E_AB', 'inherits', 'A', 'B', 7)])
        engine, selected = solve(data, pl)
        # 7 for the shared edge beats 5+5 for the two per-user assignments
        self.assertEqual(key_of(engine, selected), (7, 1, ('E_AB',)))
        repaired = repair.repaired_policy(data, chosen_edits(engine, selected))
        self.assertEqual(repaired['roles'][0], role('A'))
        assert_audit_clean(self, data, repaired, pl['protect'])

    def test_greedy_cheapest_first_is_suboptimal(self):
        # two conflicts; cheapest-first greedy takes 4+4=8, the optimum is 6
        roles = [role('M'), role('N'), role('X')]
        users = [user('U', ['M', 'N', 'X'])]
        data = policy(roles, users, [], [['M', 'X'], ['N', 'X']])
        pl = plan([edit('E_UM', 'assignment', 'U', 'M', 4),
                   edit('E_UN', 'assignment', 'U', 'N', 4),
                   edit('E_UX', 'assignment', 'U', 'X', 6)])
        engine, selected = solve(data, pl)
        self.assertEqual(key_of(engine, selected), (6, 1, ('E_UX',)))
        repaired = repair.repaired_policy(data, chosen_edits(engine, selected))
        self.assertEqual(repaired['users'], [user('U', ['M', 'N'])])
        assert_audit_clean(self, data, repaired, pl['protect'])

    def test_protect_request_makes_repair_infeasible(self):
        # the only conflict resolution deletes the role behind a protected allow
        roles = [role('P'), role('Q')]
        users = [user('U', ['P', 'Q'])]
        grants = [grant('G1', 'P', 'read', '/x', 'allow')]
        data = policy(roles, users, grants, [['P', 'Q']])
        pl = plan([edit('E_UP', 'assignment', 'U', 'P', 1)],
                  [preq('PR1', 'U', 'read', '/x')])
        with self.assertRaisesRegex(ValueError, 'no feasible repair'):
            solve(data, pl)

    def test_deny_revocation_never_grants(self):
        # deleting the deny role (cost 1) would turn /secret from deny into allow
        roles = [role('A'), role('B'), role('X')]
        users = [user('U', ['A', 'B', 'X'])]
        grants = [grant('G1', 'A', 'read', '/secret', 'allow'),
                  grant('G2', 'B', 'read', '/secret', 'deny')]
        data = policy(roles, users, grants, [['B', 'X']])
        pl = plan([edit('E_UB', 'assignment', 'U', 'B', 1),
                   edit('E_UX', 'assignment', 'U', 'X', 5)])
        engine, selected = solve(data, pl)
        # the cheap but forbidden edge is rejected; the safe cost-5 edge wins
        self.assertEqual(key_of(engine, selected), (5, 1, ('E_UX',)))
        repaired = repair.repaired_policy(data, chosen_edits(engine, selected))
        assert_audit_clean(self, data, repaired, pl['protect'])
        # the deny on /secret is untouched, so /secret stays denied
        audited = analyze(dict(repaired, requests=[preq('Q', 'U', 'read', '/secret')]))
        self.assertEqual(audited['requests'][0]['decision'], 'deny')

    def test_deny_revocation_under_wildcards(self):
        # same risk through wildcard patterns: prefix deny + exact allow
        roles = [role('A'), role('B'), role('X')]
        users = [user('U', ['A', 'B', 'X'])]
        grants = [grant('G1', 'A', 'read', '/docs/x', 'allow'),
                  grant('G2', 'B', '*', '/docs/*', 'deny')]
        data = policy(roles, users, grants, [['B', 'X']])
        pl = plan([edit('E_UB', 'assignment', 'U', 'B', 1),
                   edit('E_UX', 'assignment', 'U', 'X', 5)])
        engine, selected = solve(data, pl)
        self.assertEqual(key_of(engine, selected), (5, 1, ('E_UX',)))
        repaired = repair.repaired_policy(data, chosen_edits(engine, selected))
        assert_audit_clean(self, data, repaired, pl['protect'])

    def test_protect_allow_via_inherited_prefix_grant(self):
        # the protected allow arrives through inheritance and a /* grant
        roles = [role('base'), role('mid', ['base']), role('top', ['mid']), role('Q')]
        users = [user('U', ['top', 'Q'])]
        grants = [grant('G1', 'base', 'read', '/docs/*', 'allow')]
        data = policy(roles, users, grants, [['top', 'Q']])
        pl = plan([edit('E_TM', 'inherits', 'top', 'mid', 2),
                   edit('E_MB', 'inherits', 'mid', 'base', 2),
                   edit('E_UQ', 'assignment', 'U', 'Q', 3)],
                  [preq('PR1', 'U', 'read', '/docs/a')])
        engine, selected = solve(data, pl)
        # cutting top->mid or mid->base would kill the protected allow; drop Q instead
        self.assertEqual(key_of(engine, selected), (3, 1, ('E_UQ',)))
        repaired = repair.repaired_policy(data, chosen_edits(engine, selected))
        assert_audit_clean(self, data, repaired, pl['protect'])

    def test_already_compliant_selects_nothing(self):
        roles = [role('A'), role('B')]
        users = [user('U', ['A'])]
        grants = [grant('G1', 'A', 'read', '/a', 'allow')]
        data = policy(roles, users, grants, [['A', 'B']])
        pl = plan([edit('E_UA', 'assignment', 'U', 'A', 1)],
                  [preq('PR1', 'U', 'read', '/a')])
        engine, selected = solve(data, pl)
        self.assertEqual(selected, frozenset())
        self.assertEqual(key_of(engine, selected), (0, 0, ()))
        repaired = repair.repaired_policy(data, [])
        self.assertEqual(analyze(repaired)['separation_conflicts'], [])

    def test_tiebreak_edge_count_beats_id_sequence(self):
        # {E9} alone (cost 5) vs {E1,E2} (cost 2+3): fewer edges wins over smaller ids
        roles = [role('R', ['P']), role('S', ['P']), role('P'), role('Q')]
        users = [user('U', ['R', 'S', 'Q'])]
        data = policy(roles, users, [], [['P', 'Q']])
        pl = plan([edit('E1', 'inherits', 'R', 'P', 2),
                   edit('E2', 'inherits', 'S', 'P', 3),
                   edit('E9', 'assignment', 'U', 'Q', 5),
                   edit('E8', 'assignment', 'U', 'R', 5),
                   edit('E7', 'assignment', 'U', 'S', 5)])
        engine, selected = solve(data, pl)
        self.assertEqual(key_of(engine, selected), (5, 1, ('E9',)))

    def test_tiebreak_sorted_id_sequence(self):
        # equal cost and count: the lexicographically smaller sorted id wins
        roles = [role('P'), role('Q')]
        users = [user('U', ['P', 'Q'])]
        data = policy(roles, users, [], [['P', 'Q']])
        pl = plan([edit('E2', 'assignment', 'U', 'P', 5),
                   edit('E10', 'assignment', 'U', 'Q', 5)])
        engine, selected = solve(data, pl)
        self.assertEqual(key_of(engine, selected), (5, 1, ('E10',)))

    def test_no_candidate_can_fix_conflict_reports_specifically(self):
        roles = [role('P'), role('Q')]
        users = [user('U', ['P', 'Q'])]
        data = policy(roles, users, [], [['P', 'Q']])
        pl = plan([edit('E1', 'assignment', 'U', 'P', 1),
                   edit('E2', 'assignment', 'U', 'P', 1)])  # placeholder, replaced below
        pl['edits'] = [edit('E1', 'assignment', 'U', 'P', 1)]
        # removing P alone works, so instead drop all candidates: empty plan
        with self.assertRaisesRegex(ValueError, 'cannot be resolved'):
            solve(data, plan([]))

    def test_empty_plan_on_compliant_policy_selects_nothing(self):
        roles = [role('P')]
        users = [user('U', ['P'])]
        data = policy(roles, users, [], [])
        engine, selected = solve(data, plan([]))
        self.assertEqual(selected, frozenset())

class PlanValidationTests(unittest.TestCase):
    def setUp(self):
        self.data = policy([role('A', ['B']), role('B')], [user('U', ['A'])],
                           [grant('G1', 'B', 'read', '/b', 'allow')], [])
    def rejects(self, pl, needle=None):
        if needle is None:
            with self.assertRaises(ValueError):
                repair.Repair(self.data, pl)
        else:
            with self.assertRaisesRegex(ValueError, needle):
                repair.Repair(self.data, pl)

    def test_too_many_edits_rejected(self):
        edits = [edit('E%02d' % i, 'assignment', 'U', 'A', 1) for i in range(25)]
        for i, e in enumerate(edits):  # make edges distinct yet real is impossible; ids distinct
            e['role'] = 'A'
        with self.assertRaisesRegex(ValueError, '24'):
            repair.Repair(self.data, plan(edits))

    def test_duplicate_edit_id_and_duplicate_edge_rejected(self):
        self.rejects(plan([edit('E1', 'assignment', 'U', 'A', 1),
                           edit('E1', 'inherits', 'A', 'B', 1)]), 'duplicate edit id')
        self.rejects(plan([edit('E1', 'assignment', 'U', 'A', 1),
                           edit('E2', 'assignment', 'U', 'A', 1)]), 'duplicate candidate edge')

    def test_candidate_edge_must_exist(self):
        self.rejects(plan([edit('E1', 'assignment', 'U', 'B', 1)]), 'does not exist')
        self.rejects(plan([edit('E1', 'assignment', 'Ghost', 'A', 1)]), 'does not exist')
        self.rejects(plan([edit('E1', 'inherits', 'A', 'A', 1)]), 'does not exist')
        self.rejects(plan([edit('E1', 'inherits', 'B', 'A', 1)]), 'does not exist')

    def test_bad_cost_and_kind_and_shape_rejected(self):
        for bad in (0, -1, 1.5, True, '3', None):
            self.rejects(plan([edit('E1', 'assignment', 'U', 'A', bad)]))
        self.rejects(plan([edit('E1', 'grant', 'U', 'A', 1)]), 'kind')
        self.rejects(plan([{'id': 'E1', 'kind': 'assignment', 'source': 'U', 'role': 'A'}]))
        self.rejects(plan([dict(edit('E1', 'assignment', 'U', 'A', 1), extra=1)]))
        self.rejects({'edits': []})                      # missing protect
        self.rejects({'edits': [], 'protect': [], 'x': 1})  # unknown field
        self.rejects(plan([edit('E1', 'assignment', 'U', 'A', 1)],
                          [preq('P1', 'Ghost', 'read', '/b')]))   # unknown user
        self.rejects(plan([edit('E1', 'assignment', 'U', 'A', 1)],
                          [preq('P1', 'U', 'read', '/b/*')]))     # wildcard request
        self.rejects(plan([edit('E1', 'assignment', 'U', 'A', 1)],
                          [preq('P1', 'U', 'read', '/b'),
                           preq('P1', 'U', 'read', '/b')]))       # duplicate request id

    def test_user_and_role_may_share_an_id(self):
        # assignment (user X -> A) and inherits (role X -> A) are distinct edges
        roles = [role('X', ['A']), role('A'), role('B')]
        users = [user('X', ['A']), user('U', ['X', 'B'])]
        data = policy(roles, users, [], [['A', 'B']])
        pl = plan([edit('E1', 'assignment', 'X', 'A', 1),
                   edit('E2', 'inherits', 'X', 'A', 1)])
        engine, selected = solve(data, pl)
        # U's conflict on {A,B} is fixed by cutting the shared inherits edge E2
        self.assertEqual(key_of(engine, selected), (1, 1, ('E2',)))

    def test_valid_plan_accepted(self):
        engine = repair.Repair(self.data, plan([edit('E1', 'assignment', 'U', 'A', 3),
                                                edit('E2', 'inherits', 'A', 'B', 2)],
                                               [preq('P1', 'U', 'read', '/b')]))
        self.assertEqual(len(engine.edits), 2)

def instance_24():
    """24 candidate edges: 8 independent conflict gadgets (2 edges each) plus 8
    decoys.  G1's cheap edge is protect-blocked, G2's cheap edge would revive an
    allow by deleting a deny; decoys are protect-blocked, deny-blocked or
    irrelevant.  The global optimum is the analytic sum of per-gadget minima."""
    roles, users, grants, exclusions, edits, protect = [], [], [], [], [], []
    for i in range(1, 9):
        roles += [role('P%d' % i), role('Q%d' % i)]
        users.append(user('U%d' % i, ['P%d' % i, 'Q%d' % i]))
        exclusions.append(['P%d' % i, 'Q%d' % i])
    # G1: deleting P1 (cost 2) breaks protected request PR1 -> must take Q1 (9)
    grants.append(grant('G1A', 'P1', 'read', '/keep1', 'allow'))
    protect.append(preq('PR1', 'U1', 'read', '/keep1'))
    # G2: deleting P2 (cost 2) revives Q2's allow on /zone2 -> must take Q2 (9)
    grants.append(grant('G2D', 'P2', 'read', '/zone2', 'deny'))
    grants.append(grant('G2A', 'Q2', 'read', '/zone2', 'allow'))
    costs = {1: (2, 9), 2: (2, 9), 3: (3, 7), 4: (8, 4),
             5: (5, 6), 6: (9, 2), 7: (4, 4), 8: (6, 3)}
    for i in range(1, 9):
        a, b = costs[i]
        edits.append(edit('E%02dA' % i, 'assignment', 'U%d' % i, 'P%d' % i, a))
        edits.append(edit('E%02dB' % i, 'assignment', 'U%d' % i, 'Q%d' % i, b))
    # decoys D01/D02: U9's roles; D01 is protect-blocked, D02 irrelevant
    roles += [role('V1'), role('V2')]
    users.append(user('U9', ['V1', 'V2']))
    grants.append(grant('D1A', 'V1', 'read', '/keep9', 'allow'))
    protect.append(preq('PR9', 'U9', 'read', '/keep9'))
    edits.append(edit('D01', 'assignment', 'U9', 'V1', 30))
    edits.append(edit('D02', 'assignment', 'U9', 'V2', 31))
    # decoy D03: deleting W1->W2 revives Z's allow on /zoneW (deny blocked)
    roles += [role('W1', ['W2']), role('W2', ['W3']), role('W3'), role('Z')]
    users.append(user('U10', ['W1', 'Z']))
    grants.append(grant('D3D', 'W2', 'read', '/zoneW', 'deny'))
    grants.append(grant('D3A', 'Z', 'read', '/zoneW', 'allow'))
    grants.append(grant('D4A', 'W3', 'read', '/extraW', 'allow'))
    edits.append(edit('D03', 'inherits', 'W1', 'W2', 32))
    edits.append(edit('D04', 'inherits', 'W2', 'W3', 33))
    # decoys D05..D08: plain irrelevant assignments of U11
    roles += [role('Y%d' % i) for i in range(1, 5)]
    users.append(user('U11', ['Y1', 'Y2', 'Y3', 'Y4']))
    for i in range(1, 5):
        grants.append(grant('D5A%d' % i, 'Y%d' % i, 'read', '/y%d' % i, 'allow'))
        edits.append(edit('D%02d' % (4 + i), 'assignment', 'U11', 'Y%d' % i, 33 + i))
    assert len(edits) == 24
    data = policy(roles, users, grants, exclusions)
    expected_ids = ('E01B', 'E02B', 'E03A', 'E04B', 'E05A', 'E06B', 'E07A', 'E08B')
    expected_cost = 9 + 9 + 3 + 4 + 5 + 2 + 4 + 3
    return data, plan(edits, protect), expected_ids, expected_cost

class PrunableInstanceTests(unittest.TestCase):
    def test_24_candidates_exact_optimum_deterministic_under_60s(self):
        data, pl, expected_ids, expected_cost = instance_24()
        engine = repair.Repair(data, pl)
        start = time.monotonic()
        selected = engine.solve()
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 60)
        self.assertIsNotNone(selected)
        self.assertEqual(tuple(sorted(engine.ids[i] for i in selected)), expected_ids)
        self.assertEqual(sum(engine.cost[i] for i in selected), expected_cost)
        # branch-and-bound prunes: far below the 2^24 = 16777216 full policies
        self.assertLess(engine.nodes, 1_000_000)
        # determinism: a fresh search selects exactly the same set
        again = repair.Repair(data, pl)
        self.assertEqual(again.solve(), selected)
        # the repaired policy is directly auditable
        repaired = repair.repaired_policy(data, chosen_edits(engine, selected))
        assert_audit_clean(self, data, repaired, pl['protect'])

def oracle_apply(data, chosen):
    repaired = json.loads(json.dumps(data))
    for e in chosen:
        if e['kind'] == 'assignment':
            row = next(u for u in repaired['users'] if u['id'] == e['source'])
            row['roles'].remove(e['role'])
        else:
            row = next(r for r in repaired['roles'] if r['id'] == e['source'])
            row['inherits'].remove(e['role'])
    return repaired

def oracle_feasible(source_snap, repaired, protect):
    if analyze(repaired)['separation_conflicts']:
        return False
    if protect:
        decisions = analyze(dict(repaired, requests=list(protect)))['requests']
        if any(r['decision'] != 'allow' for r in decisions):
            return False
    drift = diff_snapshots(source_snap, compile_snapshot(repaired), 's', 'r')
    return all(c['granted'] == [] for c in drift['user_changes'])

def oracle_optimum(data, pl):
    """Exhaustive 2^N oracle over the plan's edits, independent of repair.py."""
    edits = pl['edits']
    source_snap = compile_snapshot(data)
    best = None
    for mask in range(1 << len(edits)):
        chosen = [edits[i] for i in range(len(edits)) if mask >> i & 1]
        repaired = oracle_apply(data, chosen)
        if not oracle_feasible(source_snap, repaired, pl['protect']):
            continue
        key = (sum(e['cost'] for e in chosen), len(chosen),
               tuple(sorted(e['id'] for e in chosen)))
        if best is None or key < best:
            best = key
    return best

def random_instance(rng):
    role_ids = ['r%d' % i for i in range(8)]
    roles = [role(r, [role_ids[j] for j in range(i + 1, 8) if rng.random() < 0.25])
             for i, r in enumerate(role_ids)]
    users = [user('u%d' % i, [r for r in role_ids if rng.random() < 0.3])
             for i in range(4)]
    grants = [grant('g%d' % i, rng.choice(role_ids), rng.choice(['read', 'write', '*']),
                    rng.choice(['/a', '/a/*', '/b', '*']), rng.choice(['allow', 'deny']))
              for i in range(10)]
    exclusions = [sorted(rng.sample(role_ids, 2)) for _ in range(2)]
    real = [('assignment', u['id'], r) for u in users for r in u['roles']]
    real += [('inherits', ro['id'], p) for ro in roles for p in ro['inherits']]
    rng.shuffle(real)
    edits = [edit('E%02d' % i, k, s, r, rng.randint(1, 9))
             for i, (k, s, r) in enumerate(real[:10])]
    protect = [preq('PR%d' % i, rng.choice([u['id'] for u in users]), 'read', '/a')
               for i in range(2)]
    return policy(roles, users, grants, exclusions), plan(edits, protect)

class BruteForceCrossCheckTests(unittest.TestCase):
    def test_random_small_instances_match_exhaustive_oracle(self):
        rng = random.Random(117)
        for _ in range(5):
            data, pl = random_instance(rng)
            try:
                engine = repair.Repair(data, pl)
                selected = engine.solve()
                got = None if selected is None else key_of(engine, selected)
            except ValueError:
                got = None  # infeasible: protect denied in source or unfixable conflict
            self.assertEqual(got, oracle_optimum(data, pl))

class RepairCLITests(unittest.TestCase):
    def setUp(self):
        self.td_obj = tempfile.TemporaryDirectory()
        self.td = Path(self.td_obj.name)
    def tearDown(self):
        self.td_obj.cleanup()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'access_audit.repair_cli', *args],
                              capture_output=True, text=True)

    def write(self, name, obj):
        path = self.td / name
        path.write_text(json.dumps(obj), encoding='utf-8')
        return path

    def test_fixture_demo_report_stdout_and_byte_stability(self):
        out = self.td / 'repair.json'
        source = ROOT / 'fixtures' / 'input.json'
        pl = ROOT / 'fixtures' / 'repair-plan.json'
        result = self.run_cli('--source', str(source), '--plan', str(pl), '--output', str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(out.read_text())
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['source_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(report['plan_sha256'], hashlib.sha256(pl.read_bytes()).hexdigest())
        self.assertEqual(report['selected_edits'], ['E2'])
        self.assertEqual(report['total_cost'], 3)
        ada = next(u for u in report['policy']['users'] if u['id'] == 'Ada')
        self.assertEqual(ada, {'id': 'Ada', 'roles': ['editor', 'finance']})
        # five-field repaired policy is directly auditable by the existing tools
        self.assertEqual(analyze(report['policy'])['separation_conflicts'], [])
        self.assertEqual(len(report['policy']['requests']), 4)
        drift = diff_snapshots(compile_snapshot(json.loads(source.read_text())),
                               compile_snapshot(report['policy']), 's', 'r')
        self.assertTrue(all(c['granted'] == [] for c in drift['user_changes']))
        # stdout carries the same report; reruns are byte stable
        self.assertEqual(json.loads(result.stdout), report)
        first = out.read_bytes()
        self.assertEqual(self.run_cli('--source', str(source), '--plan', str(pl),
                                      '--output', str(out)).returncode, 0)
        self.assertEqual(first, out.read_bytes())

    def test_prunable_instance_via_cli_is_byte_identical(self):
        data, pl, expected_ids, expected_cost = instance_24()
        src = self.write('policy.json', data)
        pln = self.write('plan.json', pl)
        out1, out2 = self.td / 'r1.json', self.td / 'r2.json'
        r1 = self.run_cli('--source', str(src), '--plan', str(pln), '--output', str(out1))
        self.assertEqual(r1.returncode, 0, r1.stderr)
        r2 = self.run_cli('--source', str(src), '--plan', str(pln), '--output', str(out2))
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(out1.read_bytes(), out2.read_bytes())
        report = json.loads(out1.read_text())
        self.assertEqual(tuple(report['selected_edits']), expected_ids)
        self.assertEqual(report['total_cost'], expected_cost)

    def test_infeasible_exit2_and_old_report_kept(self):
        data = policy([role('P'), role('Q')], [user('U', ['P', 'Q'])],
                      [grant('G1', 'P', 'read', '/x', 'allow')], [['P', 'Q']])
        pl = plan([edit('E_UP', 'assignment', 'U', 'P', 1)], [preq('PR1', 'U', 'read', '/x')])
        src = self.write('policy.json', data)
        pln = self.write('plan.json', pl)
        out = self.td / 'report.json'
        out.write_text('prior')
        result = self.run_cli('--source', str(src), '--plan', str(pln), '--output', str(out))
        self.assertEqual(result.returncode, 2)
        self.assertIn('no feasible repair', result.stderr)
        self.assertEqual(out.read_text(), 'prior')

    def test_invalid_inputs_exit2_and_old_report_kept(self):
        good = self.write('good.json', policy([role('A')], [user('U', ['A'])], [], []))
        bad = self.write('bad.json', {'edits': [], 'protect': []})
        out = self.td / 'report.json'
        out.write_text('prior')
        cases = [(bad, good),                       # invalid source
                 (good, self.write('p1.json', {'edits': []})),  # invalid plan shape
                 (good, self.write('p2.json', plan([edit('E1', 'assignment', 'U', 'A', 0)]))),
                 (good, self.write('p3.json', [1, 2, 3]))]      # plan not an object
        # plan with >24 edits
        many = plan([edit('E%02d' % i, 'assignment', 'U', 'A', 1) for i in range(25)])
        cases.append((good, self.write('p4.json', many)))
        for src, pln in cases:
            result = self.run_cli('--source', str(src), '--plan', str(pln), '--output', str(out))
            self.assertEqual(result.returncode, 2, (src, pln))
            self.assertEqual(out.read_text(), 'prior')

    def test_paths_pairwise_distinct_and_no_symlink_output(self):
        src = self.write('policy.json', policy([role('A')], [user('U', ['A'])], [], []))
        pln = self.write('plan.json', plan([]))
        for args in (('--source', str(src), '--plan', str(pln), '--output', str(src)),
                     ('--source', str(src), '--plan', str(pln), '--output', str(pln)),
                     ('--source', str(src), '--plan', str(src), '--output', str(self.td / 'o.json'))):
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 2, args)
        link = self.td / 'link.json'
        link.symlink_to(pln)
        result = self.run_cli('--source', str(src), '--plan', str(pln), '--output', str(link))
        self.assertEqual(result.returncode, 2)

    def test_missing_inputs_exit2(self):
        src = self.write('policy.json', policy([role('A')], [], [], []))
        pln = self.write('plan.json', plan([]))
        out = self.td / 'report.json'
        out.write_text('prior')
        for args in (('--source', str(self.td / 'none.json'), '--plan', str(pln)),
                     ('--source', str(src), '--plan', str(self.td / 'none.json'))):
            result = self.run_cli(*args, '--output', str(out))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(out.read_text(), 'prior')

if __name__ == '__main__':
    unittest.main()
