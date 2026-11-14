import json, os, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path
from access_audit import ledger
from access_audit.model import analyze

ROOT = Path(__file__).resolve().parents[1]

def ev(eid, kind, oid, at, op, value):
    return {'event_id': eid, 'kind': kind, 'id': oid, 'at': at, 'op': op, 'value': value}

def role(rid, inherits=()): return {'id': rid, 'inherits': list(inherits)}
def user(uid, roles=()): return {'id': uid, 'roles': list(roles)}
def grant(gid, r, action, resource, effect):
    return {'id': gid, 'role': r, 'action': action, 'resource': resource, 'effect': effect}

def write_ndjson(path, events):
    path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')

def base_events():
    """A small valid policy: reader role, Ada, allow grant; all effective at 1/10."""
    return [ev('e1', 'role', 'reader', 1, 'upsert', role('reader')),
            ev('e2', 'user', 'Ada', 1, 'upsert', user('Ada', ['reader'])),
            ev('e3', 'grant', 'G1', 10, 'upsert', grant('G1', 'reader', 'read', '/docs/*', 'allow'))]

class LedgerCLIMixin:
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'access_audit.ledger_cli', *args],
                              capture_output=True, text=True)
    def ingest(self, db, events, name='events.ndjson'):
        src = Path(self.td) / name
        write_ndjson(src, events)
        return self.run_cli('ingest', '--db', str(db), '--input', str(src))
    def snap(self, db, out='snap.json', *extra):
        return self.run_cli('snapshot', '--db', str(db), '--output', str(Path(self.td) / out), *extra)

class LedgerIngestTests(LedgerCLIMixin, unittest.TestCase):
    def setUp(self):
        self.td_obj = tempfile.TemporaryDirectory(); self.td = self.td_obj.name
        self.db = Path(self.td) / 'ledger.db'
    def tearDown(self): self.td_obj.cleanup()

    def committed(self, result, batch, ingested, ignored=0):
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary, {'status': 'committed', 'batch': batch,
                                   'ingested': ingested, 'ignored': ignored})

    def test_empty_ledger_starts_from_empty_policy(self):
        result = self.ingest(self.db, [])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {'status': 'replayed', 'batch': 0, 'ingested': 0, 'ignored': 0})
        result = self.snap(self.db)
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads((Path(self.td) / 'snap.json').read_text())
        self.assertEqual(policy, {'roles': [], 'users': [], 'grants': [],
                                  'exclusions': [], 'requests': []})

    def test_commit_snapshot_and_audit_composition(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        result = self.snap(self.db)
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads((Path(self.td) / 'snap.json').read_text())
        self.assertEqual(policy, {'roles': [role('reader')], 'users': [user('Ada', ['reader'])],
                                  'grants': [grant('G1', 'reader', 'read', '/docs/*', 'allow')],
                                  'exclusions': [], 'requests': []})
        # the projected document is a valid input for the existing audit engine
        report = analyze(policy)
        self.assertEqual(report['effective_roles'], {'Ada': ['reader']})
        self.assertEqual(report['separation_conflicts'], [])

    def test_cross_batch_late_arrival_rewrites_only_new_queries(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        before = self.snap(self.db, 'before.json', '--at', '8')
        self.assertEqual(before.returncode, 0, before.stderr)
        late = [ev('e4', 'grant', 'G1', 5, 'upsert', grant('G1', 'reader', 'read', '/docs/*', 'deny'))]
        self.committed(self.ingest(self.db, late), batch=2, ingested=1)
        # latest view at effective time 8 now sees the late deny
        result = self.snap(self.db, 'after.json', '--at', '8')
        self.assertEqual(result.returncode, 0, result.stderr)
        grants = json.loads((Path(self.td) / 'after.json').read_text())['grants']
        self.assertEqual(grants, [grant('G1', 'reader', 'read', '/docs/*', 'deny')])
        # the old batch cut-off is byte-identical to before the late import
        result = self.snap(self.db, 'old.json', '--batch', '1', '--at', '8')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((Path(self.td) / 'before.json').read_bytes(),
                         (Path(self.td) / 'old.json').read_bytes())
        self.assertEqual(json.loads((Path(self.td) / 'old.json').read_text())['grants'], [])

    def test_historical_batch_reproduction_after_later_imports(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        self.assertEqual(self.snap(self.db, 'b1.json', '--batch', '1').returncode, 0)
        more = [ev('e5', 'role', 'editor', 3, 'upsert', role('editor', ['reader'])),
                ev('e6', 'user', 'Ada', 20, 'upsert', user('Ada', ['editor'])),
                ev('e7', 'grant', 'G1', 30, 'delete', None)]
        self.committed(self.ingest(self.db, more), batch=2, ingested=3)
        self.assertEqual(self.snap(self.db, 'b1again.json', '--batch', '1').returncode, 0)
        self.assertEqual((Path(self.td) / 'b1.json').read_bytes(),
                         (Path(self.td) / 'b1again.json').read_bytes())
        # latest view reflects the batch-2 changes: inheritance, reassignment, deletion
        self.assertEqual(self.snap(self.db, 'latest.json').returncode, 0)
        latest = json.loads((Path(self.td) / 'latest.json').read_text())
        self.assertEqual(latest['roles'], [role('editor', ['reader']), role('reader')])
        self.assertEqual(latest['users'], [user('Ada', ['editor'])])
        self.assertEqual(latest['grants'], [])

    def test_transient_dangling_reference_rejected_despite_final_fix(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        # user references role ghost at 20; ghost only appears at 30: final state is
        # fine but the boundary at 20 dangles, so the whole batch must roll back
        events = [ev('e8', 'user', 'Bo', 20, 'upsert', user('Bo', ['ghost'])),
                  ev('e9', 'role', 'ghost', 30, 'upsert', role('ghost'))]
        result = self.ingest(self.db, events)
        self.assertEqual(result.returncode, 2)
        self.assertIn('unknown', result.stderr)
        self.assertEqual(self.db_event_count(), 3)
        self.assertEqual(self.db_batches(), [1])

    def test_transient_inheritance_cycle_rejected_despite_final_fix(self):
        events = [ev('e1', 'role', 'A', 10, 'upsert', role('A')),
                  ev('e2', 'role', 'B', 10, 'upsert', role('B'))]
        self.committed(self.ingest(self.db, events), batch=1, ingested=2)
        # boundary 30 has A->B->A; boundary 40 repairs it.  Still rejected.
        events = [ev('e3', 'role', 'A', 20, 'upsert', role('A', ['B'])),
                  ev('e4', 'role', 'B', 30, 'upsert', role('B', ['A'])),
                  ev('e5', 'role', 'B', 40, 'upsert', role('B'))]
        result = self.ingest(self.db, events)
        self.assertEqual(result.returncode, 2)
        self.assertIn('cycle', result.stderr)
        self.assertEqual(self.db_event_count(), 2)
        self.assertEqual(self.db_batches(), [1])

    def test_replay_is_idempotent_and_never_adds_a_batch(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        # pure replay: same file again, plus key/array reordering (canonical content)
        reordered = [ev('e3', 'grant', 'G1', 10, 'upsert', grant('G1', 'reader', 'read', '/docs/*', 'allow')),
                     ev('e1', 'role', 'reader', 1, 'upsert', role('reader')),
                     ev('e2', 'user', 'Ada', 1, 'upsert', user('Ada', ['reader']))]
        result = self.ingest(self.db, reordered)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {'status': 'replayed', 'batch': 1, 'ingested': 0, 'ignored': 3})
        self.assertEqual(self.db_batches(), [1])
        # mixed replay: one duplicate plus one new event commits only the new one
        mixed = base_events()[:1] + [ev('e9', 'role', 'editor', 10, 'upsert', role('editor'))]
        self.committed(self.ingest(self.db, mixed), batch=2, ingested=1, ignored=1)
        # same event_id with different content is rejected and changes nothing
        tampered = [ev('e1', 'role', 'reader', 2, 'upsert', role('reader'))]
        result = self.ingest(self.db, tampered)
        self.assertEqual(result.returncode, 2)
        self.assertIn('e1', result.stderr)
        self.assertEqual(self.db_batches(), [1, 2])
        self.assertEqual(self.db_event_count(), 4)

    def test_kind_id_at_conflict_rejected_within_file_and_against_ledger(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        # different event_id reusing an occupied (kind, id, at) instant
        clash = [ev('eX', 'role', 'reader', 1, 'upsert', role('reader'))]
        result = self.ingest(self.db, clash)
        self.assertEqual(result.returncode, 2)
        self.assertIn('conflict', result.stderr)
        # same inside a single input file
        clash = [ev('f1', 'role', 'r9', 7, 'upsert', role('r9')),
                 ev('f2', 'role', 'r9', 7, 'delete', None)]
        result = self.ingest(self.db, clash)
        self.assertEqual(result.returncode, 2)
        self.assertIn('conflict', result.stderr)
        self.assertEqual(self.db_batches(), [1])
        self.assertEqual(self.db_event_count(), 3)

    def test_delete_semantics_and_noop_delete_of_absent_object(self):
        events = base_events() + [ev('e4', 'grant', 'G9', 10, 'delete', None)]  # absent: no-op
        self.committed(self.ingest(self.db, events), batch=1, ingested=4)
        self.committed(self.ingest(self.db, [ev('e5', 'grant', 'G1', 20, 'delete', None)]),
                       batch=2, ingested=1)
        self.assertEqual(self.snap(self.db, 's1.json').returncode, 0)
        policy = json.loads((Path(self.td) / 's1.json').read_text())
        self.assertEqual(policy['grants'], [])
        # delete at 20 then upsert at 30: the later event wins
        self.committed(self.ingest(self.db, [ev('e6', 'grant', 'G1', 30, 'upsert',
                                                grant('G1', 'reader', 'write', '/a', 'deny'))]),
                       batch=3, ingested=1)
        self.assertEqual(self.snap(self.db, 's2.json').returncode, 0)
        policy = json.loads((Path(self.td) / 's2.json').read_text())
        self.assertEqual(policy['grants'], [grant('G1', 'reader', 'write', '/a', 'deny')])
        # but at 25 the delete is still the last effective event
        self.assertEqual(self.snap(self.db, 's3.json', '--at', '25').returncode, 0)
        self.assertEqual(json.loads((Path(self.td) / 's3.json').read_text())['grants'], [])

    def test_invalid_events_rejected_before_any_write(self):
        good = base_events()
        bad_shapes = [
            [dict(ev('e1', 'role', 'r', 1, 'upsert', role('r')), extra=1)],          # extra field
            [{'event_id': 'e1', 'kind': 'role', 'id': 'r', 'at': 1, 'op': 'upsert'}],  # missing value
            [ev('e1', 'policy', 'r', 1, 'upsert', role('r'))],                        # bad kind
            [ev('e1', 'role', 'r', 1, 'create', role('r'))],                           # bad op
            [ev('e1', 'role', 'r', -1, 'upsert', role('r'))],                          # negative at
            [ev('e1', 'role', 'r', 1.5, 'upsert', role('r'))],                         # non-integer at
            [ev('e1', 'role', 'r', True, 'upsert', role('r'))],                        # bool at
            [ev('e1', 'role', 'r', 1, 'upsert', role('OTHER'))],                       # id mismatch
            [ev('e1', 'role', 'r', 1, 'delete', role('r'))],                           # delete with value
            [ev('e1', 'role', 'r', 1, 'upsert', None)],                                # upsert null value
            [ev('e1', 'grant', 'G', 1, 'upsert', grant('G', 'r', 'read', '/a', 'maybe'))],  # bad effect
            [ev('e1', 'grant', 'G', 1, 'upsert', grant('G', 'r', 're*', '/a', 'allow'))],   # bad wildcard
            [ev('e1', 'grant', 'G', 1, 'upsert', grant('G', 'r', 'read', '/a//b', 'allow'))],  # bad path
            [ev(' e1', 'role', 'r', 1, 'upsert', role('r'))],                          # bad event_id
        ]
        for i, events in enumerate(bad_shapes):
            result = self.ingest(self.db, events, 'bad%d.ndjson' % i)
            self.assertEqual(result.returncode, 2, (i, result.stdout))
            self.assertFalse(self.db.exists(), i)
        # malformed JSON lines
        raw = Path(self.td) / 'raw.ndjson'
        for content in ('{"a":1,"a":2}\n', '{"at":NaN}\n', '[1,2]\n', '{"event_id":\n'):
            raw.write_text(content)
            result = self.run_cli('ingest', '--db', str(self.db), '--input', str(raw))
            self.assertEqual(result.returncode, 2, content)
            self.assertFalse(self.db.exists(), content)
        # a valid file still commits afterwards
        self.committed(self.ingest(self.db, good), batch=1, ingested=3)

    def test_failed_ingest_rolls_back_and_next_batch_number_stays_contiguous(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        # batch mixes valid new events with one that breaks a later boundary
        events = [ev('e8', 'role', 'editor', 10, 'upsert', role('editor')),
                  ev('e9', 'user', 'Bo', 20, 'upsert', user('Bo', ['ghost']))]
        result = self.ingest(self.db, events)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.db_batches(), [1])
        self.assertEqual(self.db_event_count(), 3)
        # a fresh process sees no half batch and the next commit reuses batch 2
        result = self.ingest(self.db, [ev('e8', 'role', 'editor', 10, 'upsert', role('editor'))])
        self.committed(result, batch=2, ingested=1)

    def test_process_death_mid_transaction_leaves_no_half_batch(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        self.assertEqual(self.snap(self.db, 'before.json').returncode, 0)
        # a writer that inserts a batch row plus an event and dies before COMMIT
        script = Path(self.td) / 'crash_writer.py'
        script.write_text(
            "import sqlite3, os, sys\n"
            "con = sqlite3.connect(sys.argv[1])\n"
            "con.isolation_level = None\n"
            "con.execute('BEGIN IMMEDIATE')\n"
            "con.execute('INSERT INTO batches(batch,events) VALUES(?,?)', (int(sys.argv[2]), 1))\n"
            "con.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',\n"
            "            ('ghost', int(sys.argv[2]), 'role', 'ghost', 1, 'upsert', '{}'))\n"
            "os._exit(1)\n")
        result = subprocess.run([sys.executable, '-I', str(script), str(self.db), '2'],
                                capture_output=True)
        self.assertEqual(result.returncode, 1)
        # after the crash the ledger is untouched: no batch 2, no ghost event
        self.assertEqual(self.db_batches(), [1])
        self.assertEqual(self.db_event_count(), 3)
        self.assertEqual(self.snap(self.db, 'after.json').returncode, 0)
        self.assertEqual((Path(self.td) / 'before.json').read_bytes(),
                         (Path(self.td) / 'after.json').read_bytes())
        # and the next real ingest still gets the contiguous batch number 2
        self.committed(self.ingest(self.db, [ev('e4', 'role', 'editor', 10, 'upsert', role('editor'))]),
                       batch=2, ingested=1)

    def test_snapshot_cutoffs_guards_and_determinism(self):
        self.committed(self.ingest(self.db, base_events()), batch=1, ingested=3)
        # batch out of range / negative cut-offs
        self.assertEqual(self.snap(self.db, 'x.json', '--batch', '2').returncode, 2)
        self.assertEqual(self.snap(self.db, 'x.json', '--batch', '-1').returncode, 2)
        self.assertEqual(self.snap(self.db, 'x.json', '--at', '-5').returncode, 2)
        self.assertEqual(self.snap(self.db, 'x.json', '--at', str(2**63)).returncode, 2)
        # missing ledger
        missing = self.run_cli('snapshot', '--db', str(Path(self.td) / 'nope.db'),
                               '--output', str(Path(self.td) / 'x.json'))
        self.assertEqual(missing.returncode, 2)
        # db and output must differ; output symlink rejected
        self.assertEqual(self.run_cli('snapshot', '--db', str(self.db),
                                      '--output', str(self.db)).returncode, 2)
        link = Path(self.td) / 'link.json'; link.symlink_to(self.db)
        self.assertEqual(self.snap(self.db, 'link.json').returncode, 2)
        # db and input must differ for ingest
        self.assertEqual(self.run_cli('ingest', '--db', str(self.db),
                                      '--input', str(self.db)).returncode, 2)
        # repeated identical queries are byte-stable
        self.assertEqual(self.snap(self.db, 'd1.json').returncode, 0)
        self.assertEqual(self.snap(self.db, 'd2.json').returncode, 0)
        self.assertEqual((Path(self.td) / 'd1.json').read_bytes(),
                         (Path(self.td) / 'd2.json').read_bytes())

    def db_batches(self):
        con = sqlite3.connect(str(self.db))
        try: return [r[0] for r in con.execute('SELECT batch FROM batches ORDER BY batch')]
        finally: con.close()

    def db_event_count(self):
        con = sqlite3.connect(str(self.db))
        try: return con.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        finally: con.close()

class LedgerUnitTests(unittest.TestCase):
    def test_canonical_ignores_key_and_set_array_order(self):
        a = ev('e1', 'user', 'U', 1, 'upsert', user('U', ['r1', 'r2']))
        b = json.loads(json.dumps(a))
        b['value']['roles'] = ['r2', 'r1']
        self.assertEqual(ledger.canonical(a), ledger.canonical(b))
        c = json.loads(json.dumps(a)); c['at'] = 2
        self.assertNotEqual(ledger.canonical(a), ledger.canonical(c))

    def test_projection_takes_last_effective_event_per_object(self):
        entries = [('role', 'r', 1, 'upsert', role('r')),
                   ('role', 'r', 5, 'upsert', role('r', ['x'])),
                   ('role', 'x', 1, 'upsert', role('x')),
                   ('role', 'r', 9, 'delete', None)]
        self.assertEqual(ledger._project(entries, 4)['roles'], [role('r'), role('x')])
        self.assertEqual(ledger._project(entries, 5)['roles'], [role('r', ['x']), role('x')])
        self.assertEqual(ledger._project(entries, 9)['roles'], [role('x')])
        self.assertEqual(ledger._project(entries)['roles'], [role('x')])

    def test_event_validation_bounds(self):
        self.assertEqual(ledger.check_event(ev('e', 'role', 'r', 0, 'delete', None))['at'], 0)
        ledger.check_event(ev('e', 'role', 'r', 2**63 - 1, 'delete', None))
        with self.assertRaises(ValueError):
            ledger.check_event(ev('e', 'role', 'r', 2**63, 'delete', None))

if __name__ == '__main__': unittest.main()
