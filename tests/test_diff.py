import hashlib,json,random,subprocess,sys,tempfile,unittest
from pathlib import Path
from access_audit.diff import compile_snapshot,diff_snapshots,_evaluate,_probe_universe
from access_audit.model import matches

ROOT=Path(__file__).resolve().parents[1]

def snapshot(users,grants,roles=None,exclusions=None,requests=None):
    role_ids={r for row in (roles or [{'id':'r1','inherits':[]}]) for r in [row['id']]}
    role_ids|={g['role'] for g in grants}
    if roles is None:roles=[{'id':'r1','inherits':[]}]
    return {'roles':roles,
            'users':[{'id':u,'roles':ur} for u,ur in users],
            'grants':grants,
            'exclusions':exclusions or [],
            'requests':requests or []}

def grant(gid,role,action,resource,effect):
    return {'id':gid,'role':role,'action':action,'resource':resource,'effect':effect}

def change(report,user):
    return next(c for c in report['user_changes'] if c['user']==user)

class DiffUnitTests(unittest.TestCase):
    def test_deny_removal_grants_ability_and_deny_addition_revokes(self):
        g1=grant('G1','r1','read','/docs/*','allow')
        g2=grant('G2','r1','read','/docs/private/*','deny')
        before=snapshot([('U',['r1'])],[g1,g2])
        after=snapshot([('U',['r1'])],[g1])
        report=diff_snapshots(compile_snapshot(before),compile_snapshot(after),'b','a')
        entry=change(report,'U')
        self.assertEqual(entry['revoked'],[])
        self.assertEqual(entry['granted']['resource'],'/docs/private/access-diff-probe-1')
        self.assertEqual(entry['granted']['before']['decision'],'deny')
        self.assertEqual(entry['granted']['before']['reason'],'explicit_deny')
        self.assertEqual([h['id'] for h in entry['granted']['before']['matching_grants']],['G1','G2'])
        self.assertEqual(entry['granted']['after']['decision'],'allow')
        self.assertEqual([h['id'] for h in entry['granted']['after']['matching_grants']],['G1'])
        # reverse direction: adding the deny revokes the concrete ability
        reverse=diff_snapshots(compile_snapshot(after),compile_snapshot(before),'a','b')
        rev=change(reverse,'U')
        self.assertEqual(rev['granted'],[])
        self.assertEqual(rev['revoked']['resource'],'/docs/private/access-diff-probe-1')
        self.assertEqual(rev['revoked']['after']['reason'],'explicit_deny')
        self.assertEqual(rev['revoked']['before']['decision'],'allow')

    def test_prefix_full_shadow_boundary_and_leak(self):
        broad=snapshot([('U',['r1'])],[grant('G1','r1','read','/docs/*','allow')])
        narrow=snapshot([('U',['r1'])],[grant('G1','r1','read','/docs/public/*','allow')])
        report=diff_snapshots(compile_snapshot(broad),compile_snapshot(narrow),'b','a')
        entry=change(report,'U')
        self.assertEqual(entry['granted'],[])
        # the narrowed prefix leaks the sibling path that the broad prefix covered
        self.assertEqual(entry['revoked']['resource'],'/docs/access-diff-probe')
        self.assertEqual(entry['revoked']['before']['decision'],'allow')
        self.assertEqual(entry['revoked']['after']['decision'],'deny')
        self.assertEqual(entry['revoked']['after']['reason'],'default_deny')
        # boundary: a prefix never covers its own parent directory
        narrow_snap=compile_snapshot(narrow)
        self.assertEqual(_evaluate(narrow_snap['users']['U'],narrow_snap['grants'],
                                   'read','/docs/public')['decision'],'deny')
        broad_snap=compile_snapshot(broad)
        self.assertEqual(_evaluate(broad_snap['users']['U'],broad_snap['grants'],
                                   'read','/docs')['decision'],'deny')
        # fully shadowed narrower prefix stays allowed on both ends (no drift there)
        kept=_evaluate(narrow_snap['users']['U'],narrow_snap['grants'],
                       'read','/docs/public/access-diff-probe-1')
        self.assertEqual(kept['decision'],'allow')

    def test_unseen_action_and_unseen_path_witnessed(self):
        before=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow')])
        after=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow'),
                                       grant('G2','r1','*','/a','allow')])
        entry=change(diff_snapshots(compile_snapshot(before),compile_snapshot(after),'b','a'),'U')
        self.assertEqual(entry['granted']['action'],'access-diff-probe')
        self.assertEqual(entry['granted']['resource'],'/a')
        self.assertEqual(entry['granted']['before']['reason'],'default_deny')
        self.assertEqual(entry['granted']['after']['decision'],'allow')
        # global resource wildcard surfaces an ability on a path that never appears
        before_g=snapshot([('U',['r1'])],[])
        after_g=snapshot([('U',['r1'])],[grant('G1','r1','read','*','allow')])
        entry_g=change(diff_snapshots(compile_snapshot(before_g),compile_snapshot(after_g),'b','a'),'U')
        self.assertEqual(entry_g['granted']['resource'],'/access-diff-probe')
        self.assertEqual(entry_g['granted']['action'],'read')

    def test_user_addition_removal_and_empty_role_user(self):
        old=snapshot([('U1',['r1'])],[grant('G1','r1','read','/a','allow')])
        new=snapshot([('U1',['r1']),('U2',['r1'])],[grant('G1','r1','read','/a','allow')])
        forward=diff_snapshots(compile_snapshot(old),compile_snapshot(new),'b','a')
        self.assertEqual([c['user'] for c in forward['user_changes']],['U1','U2'])
        u1,u2=forward['user_changes']
        self.assertEqual(u1,{'user':'U1','granted':[],'revoked':[]})
        self.assertEqual(u2['granted']['before']['reason'],'absent_user')
        self.assertEqual(u2['granted']['after']['decision'],'allow')
        self.assertEqual(u2['revoked'],[])
        backward=diff_snapshots(compile_snapshot(new),compile_snapshot(old),'a','b')
        gone=change(backward,'U2')
        self.assertEqual(gone['revoked']['after']['reason'],'absent_user')
        self.assertEqual(gone['revoked']['before']['decision'],'allow')
        # an existing user with no roles can never gain an allow
        idle=snapshot([('U1',['r1']),('U3',[])],[grant('G1','r1','read','/a','allow')])
        rep=diff_snapshots(compile_snapshot(old),compile_snapshot(idle),'b','a')
        self.assertEqual(change(rep,'U3'),{'user':'U3','granted':[],'revoked':[]})

    def test_equivalent_policies_rename_and_restructure_do_not_report(self):
        base=snapshot([('U',['r1'])],[grant('G1','r1','read','/docs/*','allow'),
                                      grant('G2','r1','write','/docs/x','deny')])
        renamed=snapshot([('U',['r2'])],[grant('G9','r2','read','/docs/*','allow'),
                                         grant('G8','r2','write','/docs/x','deny')],
                         roles=[{'id':'r2','inherits':[]}])
        for first,second in ((base,renamed),(renamed,base)):
            rep=diff_snapshots(compile_snapshot(first),compile_snapshot(second),'s1','s2')
            self.assertEqual(change(rep,'U'),{'user':'U','granted':[],'revoked':[]})
        # same effective ability reached through inheritance instead of direct assignment
        layered=snapshot([('U',['child'])],[grant('G1','r1','read','/docs/*','allow'),
                                            grant('G2','r1','write','/docs/x','deny')],
                         roles=[{'id':'r1','inherits':[]},{'id':'child','inherits':['r1']}])
        rep=diff_snapshots(compile_snapshot(base),compile_snapshot(layered),'s1','s2')
        self.assertEqual(change(rep,'U'),{'user':'U','granted':[],'revoked':[]})

    def test_array_reordering_binds_raw_bytes_but_keeps_business_result(self):
        first=snapshot([('U1',['r1']),('U2',[])],[grant('G1','r1','read','/a','allow'),
                                                   grant('G2','r1','read','/b','deny')])
        second=json.loads(json.dumps(first))
        second['users'].reverse();second['grants'].reverse();second['roles'].reverse()
        c1=compile_snapshot(first);c2=compile_snapshot(second)
        rep=diff_snapshots(c1,c2,'hash-before','hash-after')
        self.assertEqual(rep['before_sha256'],'hash-before')
        self.assertEqual(rep['after_sha256'],'hash-after')
        self.assertTrue(all(c['granted']==[] and c['revoked']==[] for c in rep['user_changes']))
        # ordering of the probe universe itself is deterministic and sorted
        actions,resources=_probe_universe(first['grants'])
        self.assertEqual(actions,sorted(actions));self.assertEqual(resources,sorted(resources))

    def test_requests_are_validated_but_never_drive_comparison(self):
        data=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow')],
                      requests=[{'id':'Q1','user':'U','action':'read','resource':'/a'}])
        self.assertTrue(compile_snapshot(data))
        bad=json.loads(json.dumps(data));bad['requests'][0]['action']='*'
        with self.assertRaises(ValueError):compile_snapshot(bad)
        # requests mentioning a resource cannot create drift on their own
        other=json.loads(json.dumps(data))
        other['requests'].append({'id':'Q2','user':'U','action':'read','resource':'/totally/elsewhere'})
        rep=diff_snapshots(compile_snapshot(data),compile_snapshot(other),'b','a')
        self.assertEqual(change(rep,'U'),{'user':'U','granted':[],'revoked':[]})

    def test_invalid_snapshot_rejected_independently(self):
        good=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow')])
        compile_snapshot(good)
        for broken in ({},
                       snapshot([('U',['mystery'])],[]),
                       snapshot([('U',['r1'])],[grant('G1','r1','read','/a','maybe')]),
                       snapshot([('U',['r1'])],[grant('G1','r1','get*','/a','allow')])):
            with self.assertRaises(ValueError):compile_snapshot(broken)

    def test_probe_universe_is_complete_under_random_policies(self):
        rng=random.Random(117)
        concrete_actions=['read','write','share'];action_cells=concrete_actions+['*','access-diff-probe']
        exact=['/a','/b','/docs/x'];prefixes=['/docs/*','/p/*']
        resource_cells=exact+['/access-diff-probe','/docs','/docs/access-diff-probe',
                              '/p','/p/access-diff-probe']
        def random_snapshot():
            users=[('U%d'%i,['r1'] if rng.random()<0.8 else []) for i in range(rng.randint(1,4))]
            grants=[]
            for i in range(rng.randint(0,8)):
                resource=rng.choice(exact+prefixes+['*'])
                grants.append(grant('G%d'%i,'r1',rng.choice(concrete_actions+['*']),resource,
                                    rng.choice(['allow','deny'])))
            return snapshot(users,grants)
        def brute(snap,user,action,resource):
            effective=set(snap['users_dict'][user])
            hits=[g for g in snap['grants'] if g['role'] in effective
                  and matches(g['action'],action) and matches(g['resource'],resource)]
            if any(g['effect']=='deny' for g in hits):return 'deny'
            return 'allow' if hits else 'deny'
        for _ in range(25):
            raw_before,raw_after=random_snapshot(),random_snapshot()
            before,after=compile_snapshot(raw_before),compile_snapshot(raw_after)
            raw_before['users_dict']=dict((u['id'],u['roles']) for u in raw_before['users'])
            raw_after['users_dict']=dict((u['id'],u['roles']) for u in raw_after['users'])
            report=diff_snapshots(before,after,'b','a')
            for uid in sorted(set(raw_before['users_dict'])|set(raw_after['users_dict'])):
                expect_grant=expect_revoke=False
                for action in action_cells:
                    for resource in resource_cells:
                        d_before='deny' if uid not in raw_before['users_dict'] else brute(raw_before,uid,action,resource)
                        d_after='deny' if uid not in raw_after['users_dict'] else brute(raw_after,uid,action,resource)
                        expect_grant|=d_before=='deny' and d_after=='allow'
                        expect_revoke|=d_before=='allow' and d_after=='deny'
                entry=change(report,uid)
                if expect_grant:
                    self.assertNotEqual(entry['granted'],[])
                    self.assertEqual(entry['granted']['before']['decision'],'deny')
                    self.assertEqual(entry['granted']['after']['decision'],'allow')
                else:
                    self.assertEqual(entry['granted'],[])
                if expect_revoke:
                    self.assertNotEqual(entry['revoked'],[])
                    self.assertEqual(entry['revoked']['before']['decision'],'allow')
                    self.assertEqual(entry['revoked']['after']['decision'],'deny')
                else:
                    self.assertEqual(entry['revoked'],[])

class DiffCLITests(unittest.TestCase):
    def _run(self,td,before,after,output):
        return subprocess.run([sys.executable,'-m','access_audit.diff_cli',
                               '--before',str(Path(td)/before),'--after',str(Path(td)/after),
                               '--output',str(Path(td)/output)],capture_output=True,text=True)

    def test_success_hashes_and_idempotent_rerun(self):
        before=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow')])
        after=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow'),
                                       grant('G2','r1','write','/a','allow')])
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/'before.json').write_text(json.dumps(before))
            (Path(td)/'after.json').write_text(json.dumps(after))
            result=self._run(td,'before.json','after.json','report.json')
            self.assertEqual(result.returncode,0,result.stderr)
            report=json.loads((Path(td)/'report.json').read_text())
            self.assertEqual(report['before_sha256'],hashlib.sha256((Path(td)/'before.json').read_bytes()).hexdigest())
            self.assertEqual(report['after_sha256'],hashlib.sha256((Path(td)/'after.json').read_bytes()).hexdigest())
            expected=diff_snapshots(compile_snapshot(before),compile_snapshot(after),
                                    report['before_sha256'],report['after_sha256'])
            self.assertEqual(report,expected)
            first=(Path(td)/'report.json').read_bytes()
            self.assertEqual(self._run(td,'before.json','after.json','report.json').returncode,0)
            self.assertEqual(first,(Path(td)/'report.json').read_bytes())

    def test_invalid_either_side_nonzero_and_keeps_old_report(self):
        good=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow')])
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/'good.json').write_text(json.dumps(good))
            (Path(td)/'bad.json').write_text('{}')
            (Path(td)/'report.json').write_text('prior-report')
            for side in (('bad.json','good.json'),('good.json','bad.json')):
                result=self._run(td,side[0],side[1],'report.json')
                self.assertEqual(result.returncode,2)
                self.assertEqual((Path(td)/'report.json').read_text(),'prior-report')

    def test_output_cannot_overwrite_input_and_symlink_rejected(self):
        good=snapshot([('U',['r1'])],[grant('G1','r1','read','/a','allow')])
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/'before.json').write_text(json.dumps(good))
            (Path(td)/'after.json').write_text(json.dumps(good))
            raw=(Path(td)/'before.json').read_bytes()
            result=self._run(td,'before.json','after.json','before.json')
            self.assertEqual(result.returncode,2)
            self.assertEqual((Path(td)/'before.json').read_bytes(),raw)
            link=Path(td)/'link.json';link.symlink_to(Path(td)/'after.json')
            self.assertEqual(self._run(td,'before.json','after.json','link.json').returncode,2)

if __name__=='__main__':unittest.main()
