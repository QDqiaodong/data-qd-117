import hashlib, json, os, random, subprocess, sys, tempfile, unittest
from pathlib import Path
from access_audit import bulk
from access_audit.model import analyze, matches

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'fixtures' / 'input.json'

def write_json(path, obj):
    path.write_text(json.dumps(obj), encoding='utf-8')

def write_ndjson(path, rows):
    path.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')

def run_cli(*args, env=None):
    return subprocess.run([sys.executable, '-m', 'access_audit.cli', *args],
                          capture_output=True, text=True, env=env)

def load_report(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]

class GrantIndexTests(unittest.TestCase):
    def test_resource_keys_cover_exact_global_and_proper_prefixes_only(self):
        self.assertEqual(bulk.resource_keys('/docs'), ['*', '/docs', '/*'])
        self.assertEqual(bulk.resource_keys('/a/b/c'), ['*', '/a/b/c', '/a/*', '/a/b/*', '/*'])

    def test_index_equivalent_to_brute_force_scan(self):
        rng = random.Random(7)
        resources = ['/docs/*', '/docs/private/*', '/docs/private/deep/*', '/docs',
                     '/docs/private', '*', '/*', '/a', '/a/b']
        actions = ['read', 'write', '*']
        for _ in range(200):
            grants = [{'id': 'G%02d' % i, 'role': rng.choice(['r1', 'r2']),
                       'action': rng.choice(actions), 'resource': rng.choice(resources),
                       'effect': rng.choice(['allow', 'deny'])} for i in range(rng.randint(0, 10))]
            index = bulk.GrantIndex(grants)
            effective = {'r1'}
            for _ in range(20):
                action = rng.choice(['read', 'write', 'delete'])
                resource = rng.choice(['/docs', '/docs/x', '/docs/private/y', '/a', '/a/b', '/z'])
                expected = sorted(g['id'] for g in grants if g['role'] in effective
                                  and matches(g['action'], action) and matches(g['resource'], resource))
                got = sorted(g['id'] for g in index.candidates(action, resource)
                             if g['role'] in effective)
                self.assertEqual(got, expected)

def random_policy_and_requests(rng):
    roles = [{'id': 'reader', 'inherits': []},
             {'id': 'editor', 'inherits': ['reader']},
             {'id': 'auditor', 'inherits': []}]
    grant_resources = ['/docs/*', '/docs/private/*', '/docs/private/deep/*', '/docs',
                       '/docs/private', '*', '/*', '/a', '/a/b']
    grants = [{'id': 'G%02d' % i, 'role': rng.choice(['reader', 'editor', 'auditor']),
               'action': rng.choice(['read', 'write', 'delete', '*']),
               'resource': rng.choice(grant_resources),
               'effect': rng.choice(['allow', 'deny'])} for i in range(rng.randint(0, 12))]
    users = [{'id': 'Ada', 'roles': ['editor', 'auditor']},
             {'id': 'Bo', 'roles': ['reader']},
             {'id': 'Cy', 'roles': []}]
    policy = {'roles': roles, 'users': users, 'grants': grants,
              'exclusions': [['editor', 'auditor']], 'requests': []}
    request_resources = ['/docs', '/docs/x', '/docs/private/y', '/docs/private/deep/z',
                         '/a', '/a/b', '/a/b/c', '/other']
    requests = [{'id': 'Q%02d' % i, 'user': rng.choice(['Ada', 'Bo', 'Cy']),
                 'action': rng.choice(['read', 'write', 'delete']),
                 'resource': rng.choice(request_resources)} for i in range(rng.randint(0, 25))]
    return policy, requests

class BulkParityTests(unittest.TestCase):
    """Small-scale line-by-line parity with the existing analyze()."""
    def setUp(self):
        self.td_obj = tempfile.TemporaryDirectory()
        self.td = Path(self.td_obj.name)
    def tearDown(self):
        self.td_obj.cleanup()

    def run_bulk(self, policy, requests):
        src = self.td / 'policy.json'; req = self.td / 'requests.ndjson'; out = self.td / 'report.ndjson'
        write_json(src, policy); write_ndjson(req, requests)
        summary = bulk.run(src, req, out)
        return summary, load_report(out)

    def test_randomized_small_policies_match_analyze(self):
        rng = random.Random(117)
        for _ in range(40):
            policy, requests = random_policy_and_requests(rng)
            expected = analyze(dict(policy, requests=requests))
            summary, lines = self.run_bulk(policy, requests)
            self.assertEqual(summary['requests'], len(requests))
            self.assertEqual(lines[0]['schema_version'], 1)
            self.assertEqual(lines[1:-1], expected['requests'])
            self.assertEqual(lines[-1], {'total': len(requests),
                                         'separation_conflicts': expected['separation_conflicts']})

    def test_fixture_policy_via_cli_hashes_sources_and_denied_allow_origin(self):
        policy = json.loads(FIXTURE.read_text())
        requests = policy['requests']; policy['requests'] = []
        src = self.td / 'policy.json'; req = self.td / 'requests.ndjson'; out = self.td / 'report.ndjson'
        write_json(src, policy); write_ndjson(req, requests)
        result = run_cli('--source', str(src), '--requests-ndjson', str(req), '--output', str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {'schema_version': 1, 'requests': 4, 'candidate_matches': 4})
        lines = load_report(out)
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[0], {'schema_version': 1,
                                    'policy_sha256': hashlib.sha256(src.read_bytes()).hexdigest(),
                                    'requests_sha256': hashlib.sha256(req.read_bytes()).hexdigest()})
        expected = analyze(dict(policy, requests=requests))
        self.assertEqual(lines[1:-1], expected['requests'])
        self.assertEqual([e['id'] for e in lines[1:-1]], ['Q1', 'Q2', 'Q3', 'Q4'])
        # deny overrides allow, and the overridden allow source stays visible
        q2 = lines[2]
        self.assertEqual(q2['decision'], 'deny')
        self.assertEqual(q2['reason'], 'explicit_deny')
        self.assertEqual(q2['matching_grants'], [{'id': 'G2', 'role': 'editor', 'effect': 'allow'},
                                                 {'id': 'G3', 'role': 'editor', 'effect': 'deny'}])
        # /docs/* never covers /docs itself: path boundary kept
        self.assertEqual(lines[4]['reason'], 'default_deny')
        self.assertEqual(lines[4]['matching_grants'], [])
        self.assertEqual(lines[-1], {'total': 4,
                                     'separation_conflicts': [{'user': 'Ada', 'roles': ['auditor', 'finance']}]})

class BulkCLITests(unittest.TestCase):
    def setUp(self):
        self.td_obj = tempfile.TemporaryDirectory()
        td = Path(self.td_obj.name)
        self.src = td / 'policy.json'; self.req = td / 'requests.ndjson'; self.out = td / 'report.ndjson'
        self.tmp = td / 'tmp'; self.tmp.mkdir()
        policy = json.loads(FIXTURE.read_text())
        self.requests = policy['requests']; policy['requests'] = []
        write_json(self.src, policy); write_ndjson(self.req, self.requests)
        self.env = dict(os.environ, TMPDIR=str(self.tmp))
    def tearDown(self):
        self.td_obj.cleanup()

    def run_bulk_cli(self):
        return run_cli('--source', str(self.src), '--requests-ndjson', str(self.req),
                       '--output', str(self.out), env=self.env)

    def test_success_is_byte_stable_and_cleans_temporary_resources(self):
        self.assertEqual(self.run_bulk_cli().returncode, 0)
        first = self.out.read_bytes()
        self.assertEqual(self.run_bulk_cli().returncode, 0)
        self.assertEqual(first, self.out.read_bytes())
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_old_single_file_mode_is_unchanged(self):
        write_json(self.src, dict(json.loads(FIXTURE.read_text())))
        result = run_cli('--source', str(self.src), '--output', str(self.out))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(self.out.read_text())
        self.assertEqual(len(report['result']['requests']), 4)
        self.assertEqual(report['source_sha256'], hashlib.sha256(self.src.read_bytes()).hexdigest())

    def test_source_requests_must_be_empty_in_bulk_mode(self):
        write_json(self.src, json.loads(FIXTURE.read_text()))  # requests kept
        self.out.write_text('prior')
        result = self.run_bulk_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn('empty', result.stderr)
        self.assertEqual(self.out.read_text(), 'prior')

    def test_invalid_last_line_keeps_prior_report_and_cleans_up(self):
        with self.req.open('a') as stream:
            stream.write('{"id": "BROKEN", "user": ')  # illegal final line
        self.out.write_text('prior')
        result = self.run_bulk_cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.out.read_text(), 'prior')
        self.assertEqual(list(self.tmp.iterdir()), [])
        self.assertEqual(sorted(p.name for p in self.out.parent.iterdir()),
                         ['policy.json', 'report.ndjson', 'requests.ndjson', 'tmp'])

    def test_trailing_duplicate_id_keeps_prior_report_and_cleans_up(self):
        with self.req.open('a') as stream:
            stream.write(json.dumps(dict(self.requests[0], user='Bo')) + '\n')  # repeats Q1 at the tail
        self.out.write_text('prior')
        result = self.run_bulk_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn('duplicate request id', result.stderr)
        self.assertEqual(self.out.read_text(), 'prior')
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_line_over_8kib_rejected(self):
        write_ndjson(self.req, [{'id': 'Q1', 'user': 'Ada', 'action': 'read',
                                 'resource': '/docs/' + 'a' * 9000}])
        result = self.run_bulk_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn('8 KiB', result.stderr)

    def test_bad_request_lines_rejected(self):
        bad_lines = [
            {'id': 'Q1', 'user': 'Ghost', 'action': 'read', 'resource': '/a'},      # unknown user
            {'id': 'Q1', 'user': 'Ada', 'action': '*', 'resource': '/a'},           # wildcard action
            {'id': 'Q1', 'user': 'Ada', 'action': 'read', 'resource': '/a/*'},      # wildcard resource
            {'id': 'Q1', 'user': 'Ada', 'action': 'read'},                          # missing field
            {'id': 'Q1', 'user': 'Ada', 'action': 'read', 'resource': '/a', 'x': 1},  # extra field
            ['not', 'an', 'object'],
        ]
        for bad in bad_lines:
            write_ndjson(self.req, [bad])
            self.assertEqual(self.run_bulk_cli().returncode, 2, bad)
        self.req.write_text('{"id":"Q1","id":"Q2","user":"Ada","action":"read","resource":"/a"}\n')
        self.assertEqual(self.run_bulk_cli().returncode, 2)  # duplicate JSON key
        self.req.write_text('{"id":"Q1","user":"Ada","action":"read","resource":NaN}\n')
        self.assertEqual(self.run_bulk_cli().returncode, 2)  # non-finite number

    def test_empty_and_blank_lines_and_missing_final_newline(self):
        self.req.write_text('\n   \n' + json.dumps(self.requests[0]) + '\n\n' + ' ' * 8192 +
                            '\n' + json.dumps(self.requests[1]))  # no trailing newline
        result = self.run_bulk_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = load_report(self.out)
        self.assertEqual([e['id'] for e in lines[1:-1]], ['Q1', 'Q2'])
        self.assertEqual(lines[-1]['total'], 2)
        # a fully empty request file is a valid zero-request audit
        self.req.write_text('')
        self.assertEqual(self.run_bulk_cli().returncode, 0)
        lines = load_report(self.out)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[-1]['total'], 0)

    def test_missing_requests_file_and_path_collisions_rejected(self):
        self.req.unlink()
        self.out.write_text('prior')
        self.assertEqual(self.run_bulk_cli().returncode, 2)
        self.assertEqual(self.out.read_text(), 'prior')
        write_ndjson(self.req, self.requests)
        result = run_cli('--source', str(self.src), '--requests-ndjson', str(self.req),
                         '--output', str(self.req))
        self.assertEqual(result.returncode, 2)
        result = run_cli('--source', str(self.src), '--requests-ndjson', str(self.src),
                         '--output', str(self.out))
        self.assertEqual(result.returncode, 2)

    def test_output_symlink_rejected(self):
        self.out.symlink_to(self.src)
        self.assertEqual(self.run_bulk_cli().returncode, 2)
        self.assertTrue(self.out.is_symlink())

    def test_request_count_limit_enforced(self):
        write_ndjson(self.req, [{'id': 'Q%d' % i, 'user': 'Ada',
                                 'action': 'read', 'resource': '/docs/x'} for i in range(3)])
        self.out.write_text('prior')
        limit = bulk.MAX_REQUESTS
        bulk.MAX_REQUESTS = 2
        try:
            with self.assertRaisesRegex(ValueError, 'too many requests'):
                bulk.run(self.src, self.req, self.out)
        finally:
            bulk.MAX_REQUESTS = limit
        self.assertEqual(self.out.read_text(), 'prior')

def scale_policy(n_grants, n_users=2000, n_roles=500):
    roles = [{'id': 'r%03d' % i, 'inherits': []} for i in range(n_roles)]
    users = [{'id': 'u%04d' % i, 'roles': ['r%03d' % (i % n_roles)]} for i in range(n_users)]
    grants = [{'id': 'g%05d' % i, 'role': 'r%03d' % (i % n_roles), 'action': 'read',
               'resource': '/ns%05d/*' % i, 'effect': 'allow'} for i in range(n_grants)]
    return {'roles': roles, 'users': users, 'grants': grants, 'exclusions': [], 'requests': []}

def scale_requests(path, n_requests, n_grants, n_users=2000):
    with path.open('w') as stream:
        chunk = []
        for i in range(n_requests):
            chunk.append('{"id":"q%07d","user":"u%04d","action":"read","resource":"/ns%05d/x"}\n'
                         % (i, i % n_users, i % n_grants))
            if len(chunk) >= 10_000:
                stream.write(''.join(chunk)); chunk.clear()
        if chunk:
            stream.write(''.join(chunk))

def run_cli_measured(*args, env=None):
    """Run the CLI under a small relay process and return (result, peak RSS KiB).

    On Linux a child's ru_maxrss inherits the forking parent's peak watermark, so
    the real worker is spawned from a tiny relay and measured through
    RUSAGE_CHILDREN -- the reading is the worker's own kernel-reported peak.
    """
    relay = ('import resource,subprocess,sys;'
             'r=subprocess.run([sys.executable,"-m","access_audit.cli"]+sys.argv[1:]);'
             'print("PEAK_RSS_KB=%d"%resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'
             ' file=sys.stderr);sys.exit(r.returncode)')
    result = subprocess.run([sys.executable, '-c', relay, *args],
                            capture_output=True, text=True, env=env)
    peak = int(next(line.split('=')[1] for line in result.stderr.splitlines()
                    if line.startswith('PEAK_RSS_KB=')))
    return result, peak

class BulkScaleTests(unittest.TestCase):
    def test_million_requests_bounded_rss_and_indexed_candidates(self):
        n_requests, n_grants = 1_000_000, 5000
        with tempfile.TemporaryDirectory() as td:
            td = Path(td); tmp = td / 'tmp'; tmp.mkdir()
            src = td / 'policy.json'; req = td / 'requests.ndjson'; out = td / 'report.ndjson'
            write_json(src, scale_policy(n_grants))
            scale_requests(req, n_requests, n_grants)
            result, peak = run_cli_measured('--source', str(src), '--requests-ndjson', str(req),
                                            '--output', str(out),
                                            env=dict(os.environ, TMPDIR=str(tmp)))
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            self.assertLessEqual(peak, 128 * 1024)  # 128 MiB peak RSS on Linux
            summary = json.loads(result.stdout)
            self.assertEqual(summary['requests'], n_requests)
            # exactly one sparse bucket hit per request: candidates track the requests,
            # never the 1 000 000 x 5 000 product a full grant scan would cost
            self.assertEqual(summary['candidate_matches'], n_requests)
            self.assertEqual(list(tmp.iterdir()), [])
            # header, per-request lines in id order, and the trailing summary
            self.assertEqual(sum(1 for _ in out.open()), n_requests + 2)
            with out.open() as stream:
                header = json.loads(stream.readline())
                self.assertEqual(header, {'schema_version': 1,
                                          'policy_sha256': hashlib.sha256(src.read_bytes()).hexdigest(),
                                          'requests_sha256': hashlib.sha256(req.read_bytes()).hexdigest()})
                first = json.loads(stream.readline())
                self.assertEqual(first, {'id': 'q0000000', 'user': 'u0000', 'action': 'read',
                                         'resource': '/ns00000/x', 'decision': 'allow',
                                         'reason': 'allowed',
                                         'matching_grants': [{'id': 'g00000', 'role': 'r000',
                                                              'effect': 'allow'}]})
                for index, line in enumerate(stream, 1):
                    if index < n_requests:
                        self.assertIn('"id":"q%07d"' % index, line)
                    else:
                        self.assertEqual(json.loads(line),
                                         {'total': n_requests, 'separation_conflicts': []})

    def test_candidates_track_requests_not_the_requests_by_grants_product(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            counts = []
            for n_grants in (1000, 5000):
                src = td / 'policy.json'; req = td / 'requests.ndjson'
                write_json(src, scale_policy(n_grants))
                scale_requests(req, 50_000, n_grants)
                summary = bulk.run(src, req, td / ('report-%d.ndjson' % n_grants))
                counts.append(summary['candidate_matches'])
            # 5x the grants over the same requests: identical candidate counts,
            # where a per-request full scan would cost 5x more
            self.assertEqual(counts, [50_000, 50_000])

if __name__ == '__main__':
    unittest.main()
