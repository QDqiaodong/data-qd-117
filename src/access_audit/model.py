from .common import require,ident,rows
from .roles import resolve

def pattern(v):
    ident(v)
    if v=='*':return v
    if not v.startswith('/') or '//' in v or any(x in ('.','..','') for x in v[1:].split('/')[:-1]):
        raise ValueError('resource must be canonical absolute logical path')
    if '*' in v and (not v.endswith('/*') or v.count('*')!=1):raise ValueError('only terminal /* wildcard supported')
    if v.endswith('/') or any(x in ('.','..') for x in v.split('/')):raise ValueError('invalid resource path')
    return v

def matches(rule,value):
    return rule=='*' or rule==value or rule.endswith('/*') and value.startswith(rule[:-1])

def analyze(data):
    require(data,'roles users grants exclusions requests');closure=resolve(data['roles']);users={};grants=[];seen=set();exclusions=[]
    for u in rows(data['users'],2000):
        require(u,'id roles');uid=ident(u['id'])
        if uid in users:raise ValueError('duplicate user')
        assigned=[ident(v) for v in rows(u['roles'],500)]
        if len(assigned)!=len(set(assigned)) or any(r not in closure for r in assigned):raise ValueError('duplicate or unknown assigned role')
        users[uid]=set().union(*(closure[r] for r in assigned)) if assigned else set()
    for g in rows(data['grants'],5000):
        require(g,'id role action resource effect');gid=ident(g['id']);ident(g['role']);ident(g['action']);pattern(g['resource'])
        if gid in seen or g['role'] not in closure or g['effect'] not in ('allow','deny'):raise ValueError('invalid/duplicate grant')
        if '*' in g['action'] and g['action']!='*':raise ValueError('action wildcard must be complete')
        seen.add(gid);grants.append(g)
    grants.sort(key=lambda g:g['id'])
    for pair in rows(data['exclusions'],500):
        pair=rows(pair,2)
        if len(pair)!=2 or pair[0]==pair[1] or any(r not in closure for r in pair):raise ValueError('exclusion requires two distinct known roles')
        exclusions.append(sorted(pair))
    requests=[];request_ids=set()
    for r in rows(data['requests'],10000):
        require(r,'id user action resource');rid=ident(r['id']);ident(r['action']);pattern(r['resource'])
        if rid in request_ids or r['user'] not in users or '*' in r['resource'] or '*' in r['action']:raise ValueError('invalid/duplicate concrete request')
        request_ids.add(rid);effective=users[r['user']]
        hits=[g for g in grants if g['role'] in effective and matches(g['action'],r['action']) and matches(g['resource'],r['resource'])]
        decision='deny' if any(g['effect']=='deny' for g in hits) or not hits else 'allow'
        requests.append(dict(r,decision=decision,reason='explicit_deny' if any(g['effect']=='deny' for g in hits) else ('allowed' if hits else 'default_deny'),
                             matching_grants=[{'id':g['id'],'role':g['role'],'effect':g['effect']} for g in hits]))
    conflicts=[{'user':u,'roles':pair} for u,effective in sorted(users.items()) for pair in sorted(exclusions) if set(pair)<=effective]
    return {'effective_roles':{u:sorted(rs) for u,rs in sorted(users.items())},'separation_conflicts':conflicts,
            'requests':sorted(requests,key=lambda r:r['id'])}
