DESCRIPTION='Offline minimal-cost separation-of-duty repair for an RBAC policy'
import argparse, json, sys
from pathlib import Path
from .common import save
from . import repair

def main():
    parser=argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        output=args.output.resolve()
        if output==args.source.resolve() or output==args.plan.resolve() \
                or args.source.resolve()==args.plan.resolve():
            raise ValueError('source, plan and output must be pairwise distinct')
        if args.output.is_symlink():raise ValueError('output cannot be a symlink')
        report=repair.run(args.source,args.plan);save(args.output,report)
    except (ValueError,TypeError,KeyError,OSError,OverflowError,RecursionError) as error:
        print(str(error),file=sys.stderr);return 2
    print(json.dumps(report,sort_keys=True,ensure_ascii=False,allow_nan=False));return 0

if __name__=='__main__':raise SystemExit(main())
