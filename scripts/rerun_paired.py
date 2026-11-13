"""Create a new study directory; prepare only by default, generation requires --live."""
from pathlib import Path
from datetime import datetime,timezone
import argparse
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--live',action='store_true');parser.add_argument('--output-name')
    args=parser.parse_args()
    name=args.output_name or datetime.now(timezone.utc).strftime('deepseek-paired-%Y%m%dT%H%M%S%fZ')
    if Path(name).name!=name or '/' in name or '\\' in name:parser.error('Output name must be a single new directory name')
    output=ROOT/'outputs/experiments'/name
    output.mkdir(parents=True,exist_ok=False)
    template=ROOT/'outputs/experiments/deepseek-final-nothinking-20261112T143858Z/run_final.py'
    target=output/'run_final.py';shutil.copy2(template,target)
    subprocess.run([sys.executable,'-B',str(target),'prepare'],cwd=ROOT,check=True)
    if args.live:subprocess.run([sys.executable,'-B',str(target),'live'],cwd=ROOT,check=True)
    else:print('PREPARE_ONLY; 0 LLM calls. Generation was not requested.')


if __name__=='__main__':main()
