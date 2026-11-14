DESCRIPTION='Offline allow-capability drift analysis between two RBAC snapshots'
import argparse, json, sys
from pathlib import Path
from .common import read, save
from .diff import compile_snapshot, diff_snapshots

def run(before_path,after_path):
    before_data,before_digest=read(before_path)
    after_data,after_digest=read(after_path)
    before=compile_snapshot(before_data)
    after=compile_snapshot(after_data)
    return diff_snapshots(before,after,before_digest,after_digest)

def main():
    parser=argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--before',type=Path,required=True)
    parser.add_argument('--after',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=None
    try:
        output=args.output.resolve()
        if output==args.before.resolve() or output==args.after.resolve():
            raise ValueError('output must differ from both inputs')
        if args.output.is_symlink():raise ValueError('output cannot be a symlink')
        report=run(args.before,args.after);save(args.output,report)
    except (ValueError,TypeError,KeyError,OSError,OverflowError,RecursionError) as error:
        print(str(error),file=sys.stderr);return 2
    print(json.dumps(report,sort_keys=True,ensure_ascii=False,allow_nan=False));return 0

if __name__=='__main__':raise SystemExit(main())
