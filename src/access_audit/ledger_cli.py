DESCRIPTION = 'SQLite event ledger for the RBAC policy: atomic batched ingest and dual cut-off snapshots'
import argparse, json, sqlite3, sys
from pathlib import Path
from .common import save
from . import ledger

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    sub = parser.add_subparsers(dest='command', required=True)
    ing = sub.add_parser('ingest', help='atomically ingest one NDJSON event file as the next batch')
    ing.add_argument('--db', type=Path, required=True)
    ing.add_argument('--input', type=Path, required=True)
    snap = sub.add_parser('snapshot', help='project committed events into the five-field policy document')
    snap.add_argument('--db', type=Path, required=True)
    snap.add_argument('--batch', type=int, default=None, help='committed batch cut-off (default: latest)')
    snap.add_argument('--at', type=int, default=None, help='effective-time cut-off (default: none)')
    snap.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'ingest':
            if args.db.resolve() == args.input.resolve():
                raise ValueError('db and input must differ')
            report = ledger.ingest(args.db, args.input)
        else:
            if args.db.resolve() == args.output.resolve():
                raise ValueError('db and output must differ')
            report = ledger.snapshot(args.db, args.batch, args.at)
            save(args.output, report)
    except (ValueError, TypeError, KeyError, OSError, OverflowError, RecursionError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr); return 2
    print(json.dumps(report, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return 0

if __name__ == '__main__': raise SystemExit(main())
