DESCRIPTION='Explainable role inheritance and deny-overrides access audit'
import argparse, json, sys
from pathlib import Path
from .common import read, save
from .model import analyze
from . import bulk

def run(source):
    data,digest=read(source)
    return {'schema_version':1,'source_sha256':digest,'result':analyze(data)}

def main():
    parser=argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--requests-ndjson',type=Path,default=None,
                        help='audit requests from this NDJSON file instead of the source document '
                             '(source requests must be empty); the report is NDJSON')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.source.resolve()==args.output.resolve():raise ValueError('input and output must differ')
        if args.requests_ndjson is None:
            report=run(args.source);save(args.output,report)
        else:
            if args.requests_ndjson.resolve()==args.output.resolve():raise ValueError('requests and output must differ')
            if args.requests_ndjson.resolve()==args.source.resolve():raise ValueError('requests and source must differ')
            report=bulk.run(args.source,args.requests_ndjson,args.output)
    except (ValueError,TypeError,KeyError,OSError,OverflowError,RecursionError) as error:
        print(str(error),file=sys.stderr);return 2
    print(json.dumps(report,sort_keys=True,ensure_ascii=False,allow_nan=False));return 0

if __name__=='__main__':raise SystemExit(main())
