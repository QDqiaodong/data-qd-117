"""SQLite event ledger for the RBAC policy contract.

The ledger starts from the empty policy.  NDJSON events (one JSON object per
line, exactly the fields ``event_id``, ``kind``, ``id``, ``at``, ``op``,
``value``) are ingested in atomic, strictly increasing batches.  An upsert
carries the existing contract object for its kind with a matching id; a delete
carries ``value: null`` and deleting an absent object is a no-op.

Replay/conflict rules: an ``event_id`` replayed with the same canonical content
is ignored (a pure replay adds no batch), replayed with different content the
ingest is rejected, and a different ``event_id`` at an already used
``(kind, id, at)`` instant is a conflict and rejected.  Events may arrive out
of order or late.  Before a batch commits, the visible version (all committed
events including the new batch) is projected at every effective boundary the
new events can influence and each projection must pass the existing policy
validation; any failure rolls back events, batch and projection.  Snapshots
project committed events under a dual cut-off (committed batch and effective
time) back into the five-field policy document with empty exclusions/requests,
so old batch queries are never affected by later imports.
"""
from pathlib import Path
import json, sqlite3
from .common import require, ident, rows
from .model import load_policy, pattern

SCHEMA_VERSION = '1'
MAX_AT = 2**63 - 1  # SQLite INTEGER bound
KINDS = ('role', 'user', 'grant')
VALUE_FIELDS = {'role': 'id inherits', 'user': 'id roles', 'grant': 'id role action resource effect'}
LIST_FIELDS = {'role': 'inherits', 'user': 'roles'}
MAX_EVENTS = 20000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS batches(batch INTEGER PRIMARY KEY, events INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY,
  batch INTEGER NOT NULL REFERENCES batches(batch),
  kind TEXT NOT NULL, id TEXT NOT NULL, at INTEGER NOT NULL,
  op TEXT NOT NULL, canonical TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_kind_id_at ON events(kind, id, at);
"""

def _unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result: raise ValueError('duplicate JSON key: ' + k)
        result[k] = v
    return result

def _invalid(v): raise ValueError('nonfinite JSON number: ' + v)

def _loads(text):
    return json.loads(text, object_pairs_hook=_unique, parse_constant=_invalid)

def _at(v):
    if type(v) is not int or not 0 <= v <= MAX_AT:
        raise ValueError('at must be a non-negative integer within SQLite range')
    return v

def _check_value(kind, value, oid):
    require(value, VALUE_FIELDS[kind])
    if value['id'] != oid: raise ValueError('event id and value id must agree')
    if kind == 'grant':
        ident(value['role']); ident(value['action']); pattern(value['resource'])
        if value['effect'] not in ('allow', 'deny'): raise ValueError('effect must be allow or deny')
        if '*' in value['action'] and value['action'] != '*':
            raise ValueError('action wildcard must be complete')
    else:
        for entry in rows(value[LIST_FIELDS[kind]], 500): ident(entry)

def check_event(ev):
    """Validate one event structurally, including object-local value semantics."""
    require(ev, 'event_id kind id at op value')
    ident(ev['event_id']); ident(ev['id'])
    if ev['kind'] not in KINDS: raise ValueError('kind must be role, user or grant')
    _at(ev['at'])
    if ev['op'] not in ('upsert', 'delete'): raise ValueError('op must be upsert or delete')
    if ev['op'] == 'delete':
        if ev['value'] is not None: raise ValueError('delete value must be null')
    else:
        _check_value(ev['kind'], ev['value'], ev['id'])
    return ev

def canonical(ev):
    """Canonical content of an event: sorted keys; set-arrays (inherits/roles) sorted."""
    value = ev['value']
    if ev['op'] == 'upsert':
        value = dict(value)
        field = LIST_FIELDS.get(ev['kind'])
        if field: value[field] = sorted(value[field])
    out = {'event_id': ev['event_id'], 'kind': ev['kind'], 'id': ev['id'],
           'at': ev['at'], 'op': ev['op'], 'value': value}
    return json.dumps(out, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':'))

def read_events(path):
    """Read one NDJSON event file (<=8 MB, <=20000 events), strictly parsed."""
    with Path(path).open('rb') as stream: raw = stream.read(8_000_001)
    if len(raw) > 8_000_000: raise ValueError('NDJSON exceeds 8 MB')
    events = []
    for number, line in enumerate(raw.decode('utf-8').splitlines(), 1):
        if not line.strip(): continue
        ev = _loads(line)
        if not isinstance(ev, dict): raise ValueError('event line %d must be a JSON object' % number)
        try: check_event(ev)
        except ValueError as error:
            raise ValueError('event line %d: %s' % (number, error)) from error
        events.append(ev)
    if len(events) > MAX_EVENTS: raise ValueError('too many events in one ingest')
    return events

def _connect(path):
    con = sqlite3.connect(str(path))
    con.isolation_level = None  # explicit transactions only
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=5000')
    con.execute('PRAGMA synchronous=FULL')
    return con

def _init(con):
    con.executescript(_SCHEMA)
    row = con.execute('SELECT value FROM meta WHERE key=?', ('schema_version',)).fetchone()
    if row is None:
        con.execute('INSERT INTO meta VALUES(?,?)', ('schema_version', SCHEMA_VERSION))
    elif row[0] != SCHEMA_VERSION:
        raise ValueError('unsupported ledger schema version: ' + row[0])

def _latest(con):
    return con.execute('SELECT COALESCE(MAX(batch),0) FROM batches').fetchone()[0]

def _entries(con, batch):
    """Committed (kind, id, at, op, value) tuples visible at a batch cut-off."""
    result = []
    for kind, oid, at, op, canon in con.execute(
            'SELECT kind,id,at,op,canonical FROM events WHERE batch<=? ORDER BY at,id', (batch,)):
        result.append((kind, oid, at, op, _loads(canon)['value']))
    return result

def _project(entries, at=None):
    """Last-effective-event projection into the five-field policy document."""
    best = {}
    for kind, oid, when, op, value in entries:
        if at is not None and when > at: continue
        key = (kind, oid)
        if key not in best or when > best[key][0]: best[key] = (when, op, value)
    policy = {'roles': [], 'users': [], 'grants': [], 'exclusions': [], 'requests': []}
    target = {'role': 'roles', 'user': 'users', 'grant': 'grants'}
    for (kind, _oid), (_when, op, value) in best.items():
        if op == 'upsert': policy[target[kind]].append(value)
    for field in ('roles', 'users', 'grants'): policy[field].sort(key=lambda item: item['id'])
    return policy

def ingest(db_path, input_path):
    """Atomically ingest one NDJSON file as the next batch; return a summary."""
    events = read_events(input_path)
    con = _connect(db_path)
    try:
        _init(con)
        con.execute('BEGIN IMMEDIATE')
        try:
            existing = dict(con.execute('SELECT event_id,canonical FROM events'))
            occupied = {}
            for kind, oid, at, eid in con.execute('SELECT kind,id,at,event_id FROM events'):
                occupied[(kind, oid, at)] = eid
            new = []; ignored = 0; seen = {}
            for ev in events:
                eid = ev['event_id']; canon = canonical(ev)
                prior = seen.get(eid)
                if prior is not None:
                    if prior != canon:
                        raise ValueError('event_id repeated with different content in input: ' + eid)
                    ignored += 1; continue
                seen[eid] = canon
                if eid in existing:
                    if existing[eid] != canon:
                        raise ValueError('event_id replayed with different content: ' + eid)
                    ignored += 1; continue
                key = (ev['kind'], ev['id'], ev['at'])
                if key in occupied:
                    raise ValueError('conflicting event for %s/%s at %d' % (ev['kind'], ev['id'], ev['at']))
                occupied[key] = eid; new.append((eid, canon, ev))
            if not new:
                con.execute('ROLLBACK')
                return {'status': 'replayed', 'batch': _latest(con), 'ingested': 0, 'ignored': ignored}
            batch = _latest(con) + 1
            con.execute('INSERT INTO batches(batch,events) VALUES(?,?)', (batch, len(new)))
            for eid, canon, ev in new:
                con.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                            (eid, batch, ev['kind'], ev['id'], ev['at'], ev['op'], canon))
            # Validate every effective boundary of the visible version that the new
            # events can influence.  Boundaries below the earliest new event are
            # projections of already-validated committed history and cannot change.
            earliest = min(ev['at'] for _, _, ev in new)
            entries = _entries(con, batch)
            for boundary in sorted({at for _, _, at, _, _ in entries if at >= earliest}):
                load_policy(_project(entries, boundary))
            con.execute('COMMIT')
            return {'status': 'committed', 'batch': batch, 'ingested': len(new), 'ignored': ignored}
        except BaseException:
            if con.in_transaction: con.execute('ROLLBACK')
            raise
    finally:
        con.close()

def snapshot(db_path, batch=None, at=None):
    """Project committed events under the dual batch/effective-time cut-off."""
    if not Path(db_path).is_file(): raise ValueError('ledger not found: ' + str(db_path))
    con = sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'meta', 'batches', 'events'} <= tables:
            raise ValueError('not an access-ledger database: ' + str(db_path))
        version = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if version is None or version[0] != SCHEMA_VERSION:
            raise ValueError('unsupported ledger schema version')
        latest = _latest(con)
        if batch is None: batch = latest
        if type(batch) is not int or not 0 <= batch <= latest:
            raise ValueError('batch out of range: 0..%d committed' % latest)
        if at is not None: _at(at)
        return _project(_entries(con, batch), at)
    finally:
        con.close()
