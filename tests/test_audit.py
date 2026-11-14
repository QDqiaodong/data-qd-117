import json,unittest
from pathlib import Path
from access_audit.model import analyze,matches
ROOT=Path(__file__).resolve().parents[1]
class AuditTests(unittest.TestCase):
    def setUp(self):self.d=json.loads((ROOT/'fixtures/input.json').read_text())
    def test_known_decisions_and_conflict(self):
        r=analyze(self.d);self.assertEqual([q['reason'] for q in r['requests']],['allowed','explicit_deny','default_deny','default_deny'])
        self.assertEqual(r['separation_conflicts'],[{'user':'Ada','roles':['auditor','finance']}])
    def test_inherited_permission_explains_source(self):
        r=analyze(self.d);self.assertIn('reader',r['effective_roles']['Ada'])
        self.assertEqual(r['requests'][0]['matching_grants'],[{'id':'G1','role':'reader','effect':'allow'}])
    def test_deny_overrides_allow_and_reordering(self):
        self.d['requests'][1]['action']='read';r=analyze(self.d)
        self.assertEqual(len(r['requests'][1]['matching_grants']),2)
        self.d['grants'].reverse();self.d['roles'].reverse();self.assertEqual(r,analyze(self.d))
    def test_prefix_segment_boundary(self):
        self.assertFalse(matches('/docs/*','/docs2/a'));self.assertFalse(matches('/docs/*','/docs'))
        self.assertTrue(matches('/docs/*','/docs/a/b'))
    def test_cycle_unknown_role_and_duplicate(self):
        self.d['roles'][0]['inherits']=['editor']
        with self.assertRaisesRegex(ValueError,'cycle'):analyze(self.d)
        self.setUp();self.d['users'][0]['roles'].append('unknown')
        with self.assertRaises(ValueError):analyze(self.d)
    def test_invalid_resource_and_wildcard_request(self):
        for value in ['/docs/../private','/docs//a','/docs/*/a','/docs/']:
            self.d['requests'][0]['resource']=value
            with self.assertRaises(ValueError):analyze(self.d)
    def test_exclusions_do_not_change_policy_decision(self):
        before=analyze(self.d)['requests'];self.d['exclusions']=[]
        self.assertEqual(before,analyze(self.d)['requests'])
if __name__=='__main__':unittest.main()
