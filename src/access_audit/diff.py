"""Offline permission drift analysis between two independently validated RBAC snapshots.

The comparison is capability based: for every user we decide whether the concrete
*allow* ability on a legal (action, resource) pair was granted or revoked.  It never
compares requests, grant identifiers or only resources that happen to appear in the
input; inheritance, deny-overrides, global ``*`` and terminal ``/*`` keep the exact
semantics defined by the JSON contract.
"""
from .model import load_policy, parse_requests, matches

_PROBE_ACTION='access-diff-probe'
_PROBE_PATH='/access-diff-probe'

def _fresh_token(base,taken):
    token=base;index=1
    while token in taken:
        token=f'{base}-{index}';index+=1
    return token

def _probe_universe(grants):
    """Deterministic legal concrete (action, resource) probes covering every rule.

    Exact actions and exact resources come from the rules.  A wildcard action gets a
    concrete action that never appears, a prefix resource contributes its parent path
    (the boundary the prefix deliberately does not cover) plus one concrete child, and
    the global resource gets a concrete path.  Wildcards therefore cannot hide the
    introduction or removal of an ability on an action/path that never appears.
    """
    concrete_actions=set();has_wildcard_action=False
    exact_resources=set();prefixes=set();has_global_resource=False
    for g in grants:
        if g['action']=='*':has_wildcard_action=True
        else:concrete_actions.add(g['action'])
        if g['resource']=='*':has_global_resource=True
        elif g['resource'].endswith('/*'):prefixes.add(g['resource'])
        else:exact_resources.add(g['resource'])
    if has_wildcard_action:
        concrete_actions.add(_fresh_token(_PROBE_ACTION,concrete_actions))
    resources=set(exact_resources)
    for prefix in sorted(prefixes):
        parent=prefix[:-2]
        if parent:resources.add(parent)
        token=_fresh_token(_PROBE_ACTION,{seg for res in resources for seg in res.split('/') if seg})
        resources.add(f'{parent}/{token}' if parent else f'/{token}')
    if has_global_resource:
        resources.add(_fresh_token(_PROBE_PATH,resources))
    return sorted(concrete_actions),sorted(resources)

def _evaluate(effective,grants,action,resource):
    """Deny-overrides decision for one concrete pair plus the matching rule source."""
    hits=[g for g in grants if g['role'] in effective and matches(g['action'],action) and matches(g['resource'],resource)]
    if any(g['effect']=='deny' for g in hits):decision,reason='deny','explicit_deny'
    elif hits:decision,reason='allow','allowed'
    else:decision,reason='deny','default_deny'
    return {'decision':decision,'reason':reason,
            'matching_grants':[{'id':g['id'],'role':g['role'],'effect':g['effect']} for g in hits]}

def compile_snapshot(data):
    """Fully validate one snapshot against the JSON contract, including requests."""
    _closure,users,grants,_exclusions=load_policy(data)
    parse_requests(data,users)  # requests are validated but never compared
    actions,resources=_probe_universe(grants)
    return {'users':users,'grants':grants,'actions':actions,'resources':resources}

def diff_snapshots(before,after,before_sha256,after_sha256):
    """Return the deterministic drift report for two compiled snapshots."""
    actions=sorted(set(before['actions'])|set(after['actions']))
    resources=sorted(set(before['resources'])|set(after['resources']))
    user_ids=sorted(set(before['users'])|set(after['users']))
    changes=[]
    for uid in user_ids:
        sides=[]
        for snap in (before,after):
            effective=snap['users'].get(uid)
            if effective is None:
                sides.append(None)
            else:
                sides.append((effective,snap['grants']))
        granted=None;revoked=None
        for action in actions:
            for resource in resources:
                witness={'action':action,'resource':resource}
                outcomes=[]
                for side in sides:
                    if side is None:
                        outcomes.append({'decision':'deny','reason':'absent_user','matching_grants':[]})
                    else:
                        effective,grants=side
                        outcomes.append(_evaluate(effective,grants,action,resource))
                before_decision,after_decision=outcomes[0]['decision'],outcomes[1]['decision']
                entry=dict(witness,before=outcomes[0],after=outcomes[1])
                if before_decision=='deny' and after_decision=='allow' and granted is None:
                    granted=entry
                elif before_decision=='allow' and after_decision=='deny' and revoked is None:
                    revoked=entry
                if granted is not None and revoked is not None:break
            if granted is not None and revoked is not None:break
        changes.append({'user':uid,'granted':granted if granted is not None else [],
                        'revoked':revoked if revoked is not None else []})
    return {'schema_version':1,'before_sha256':before_sha256,'after_sha256':after_sha256,
            'user_changes':changes}
