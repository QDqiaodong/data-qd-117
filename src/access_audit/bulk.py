"""Bounded-memory bulk request audit driven by an NDJSON request file.

The policy side of the source document is validated exactly as in the classic
single-file mode (its ``requests`` array must be empty here); the requests stream
in one JSON object per line (<=8 KiB per line, <=1 000 000 requests, globally
unique ids).  Grants are indexed once by their literal (action, resource) pattern
so each request only inspects the few buckets its concrete action and resource
can match -- never a full scan of every grant.  Requests are validated, hashed
and spilled to sorted temporary chunks, then merged back in id order, so sorting,
deduplication, hashing and publishing all run with bounded memory; temporary
files are removed on success and on failure, and any failure keeps the previous
report.
"""
from pathlib import Path
import hashlib, heapq, json, os, tempfile
from .common import require, ident, loads, read, save_stream
from .model import load_policy, parse_requests, pattern

MAX_LINE = 8192        # maximum bytes of one request line, terminator excluded
MAX_REQUESTS = 1_000_000
CHUNK = 50_000         # requests sorted and spilled per in-memory chunk

def resource_keys(value):
    """Grant resource patterns able to match a concrete request path: the global
    ``*``, the path itself, and every proper-prefix ``/*`` pattern (root included).
    A terminal-/* grant never covers its own parent, so only strict prefixes key."""
    keys = ['*', value]
    slash = value.find('/', 1)
    while slash != -1:
        keys.append(value[:slash] + '/*')
        slash = value.find('/', slash + 1)
    keys.append('/*')
    return keys

class GrantIndex:
    """Grants bucketed by their literal (action, resource) patterns.

    A concrete request only touches the buckets listed by ``resource_keys`` for
    its own action plus the ``*`` action, which is exactly the set of grants the
    contract's ``matches`` rule could accept.  ``examined`` counts the candidate
    grants actually inspected; it tracks the requests and their true matches,
    never the requests x grants product.
    """
    def __init__(self, grants):
        self.buckets = {}
        for grant in grants:
            self.buckets.setdefault((grant['action'], grant['resource']), []).append(grant)
        self.examined = 0
    def candidates(self, action, resource):
        found = []
        for rkey in resource_keys(resource):
            for akey in (action, '*'):
                bucket = self.buckets.get((akey, rkey))
                if bucket: found.extend(bucket)
        self.examined += len(found)
        return found

def evaluate(index, users, request):
    """Decide one concrete request; the row is identical to classic analyze()."""
    effective = users[request['user']]
    hits = sorted((g for g in index.candidates(request['action'], request['resource'])
                   if g['role'] in effective), key=lambda g: g['id'])
    deny = any(g['effect'] == 'deny' for g in hits)
    return dict(request,
                decision='deny' if deny or not hits else 'allow',
                reason='explicit_deny' if deny else ('allowed' if hits else 'default_deny'),
                matching_grants=[{'id': g['id'], 'role': g['role'], 'effect': g['effect']} for g in hits])

def check_request(line, users):
    """Validate one NDJSON line as a classic concrete request; return (id, request)."""
    data = loads(line.decode('utf-8'))
    require(data, 'id user action resource')
    rid = ident(data['id']); ident(data['user']); ident(data['action']); pattern(data['resource'])
    if data['user'] not in users or '*' in data['resource'] or '*' in data['action']:
        raise ValueError('invalid concrete request')
    return rid, {'id': rid, 'user': data['user'], 'action': data['action'], 'resource': data['resource']}

def _flush(chunk, spills, tempdir):
    chunk.sort(key=lambda record: record[0])
    fd, name = tempfile.mkstemp(prefix='requests-', dir=tempdir)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        for rid, payload in chunk:
            stream.write(rid + '\t' + payload + '\n')
    spills.append(name)
    chunk.clear()

def spill_requests(path, users, tempdir):
    """Stream the NDJSON file once: validate and hash every raw line and spill the
    normalized requests to sorted temporary chunks.  Returns (sha256, count, spills)."""
    hasher = hashlib.sha256(); count = 0; chunk = []; spills = []
    with Path(path).open('rb') as stream:
        while True:
            raw = stream.readline(MAX_LINE + 2)
            if raw == b'': break
            hasher.update(raw)
            line = raw[:-1] if raw.endswith(b'\n') else raw
            if len(line) > MAX_LINE: raise ValueError('request line exceeds 8 KiB')
            if not line.strip(): continue
            rid, request = check_request(line, users)
            payload = json.dumps(request, ensure_ascii=False, allow_nan=False,
                                 sort_keys=True, separators=(',', ':'))
            chunk.append((rid, payload)); count += 1
            if count > MAX_REQUESTS: raise ValueError('too many requests (limit %d)' % MAX_REQUESTS)
            if len(chunk) >= CHUNK: _flush(chunk, spills, tempdir)
    if chunk: _flush(chunk, spills, tempdir)
    return hasher.hexdigest(), count, spills

def _dump(stream, obj):
    stream.write(json.dumps(obj, sort_keys=True, ensure_ascii=False, allow_nan=False,
                            separators=(',', ':')) + '\n')

def run(source, requests_path, output):
    """Audit up to one million NDJSON requests against the source policy and
    atomically publish the NDJSON report; returns the stdout summary."""
    if Path(output).is_symlink(): raise ValueError('output cannot be a symlink')
    data, policy_digest = read(source)
    _closure, users, grants, exclusions = load_policy(data)
    if parse_requests(data, users):
        raise ValueError('source requests must be empty when --requests-ndjson is used')
    del data
    index = GrantIndex(grants)
    conflicts = [{'user': u, 'roles': pair} for u, effective in sorted(users.items())
                 for pair in sorted(exclusions) if set(pair) <= effective]
    with tempfile.TemporaryDirectory(prefix='access-audit-') as tempdir:
        requests_digest, count, spills = spill_requests(requests_path, users, tempdir)
        streams = [open(name, 'r', encoding='utf-8') for name in spills]
        try:
            merged = heapq.merge(*streams, key=lambda line: line.split('\t', 1)[0])
            def emit(stream):
                _dump(stream, {'schema_version': 1, 'policy_sha256': policy_digest,
                               'requests_sha256': requests_digest})
                previous = None
                for line in merged:
                    rid, payload = line.split('\t', 1)
                    if rid == previous: raise ValueError('duplicate request id: ' + rid)
                    previous = rid
                    _dump(stream, evaluate(index, users, loads(payload)))
                _dump(stream, {'total': count, 'separation_conflicts': conflicts})
            save_stream(output, emit)
        finally:
            for stream in streams: stream.close()
    return {'schema_version': 1, 'requests': count, 'candidate_matches': index.examined}
