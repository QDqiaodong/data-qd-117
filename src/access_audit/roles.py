"""Resolve acyclic role inheritance, including provenance for inherited grants."""
from .common import require,ident,rows

def resolve(role_rows):
    roles={}
    for r in rows(role_rows,500):
        require(r,'id inherits');rid=ident(r['id'])
        if rid in roles:raise ValueError('duplicate role')
        parents=[ident(v) for v in rows(r['inherits'],500)]
        if len(set(parents))!=len(parents):raise ValueError('duplicate inherited role')
        roles[rid]=parents
    closure={};visiting=set()
    def visit(rid):
        if rid not in roles:raise ValueError('unknown inherited role')
        if rid in visiting:raise ValueError('role inheritance cycle')
        if rid in closure:return closure[rid]
        visiting.add(rid);result={rid}
        for parent in sorted(roles[rid]):result.update(visit(parent))
        visiting.remove(rid);closure[rid]=result;return result
    for rid in sorted(roles):visit(rid)
    return closure
