"""Download the exact public E5 revision, then verify every required file hash."""
from pathlib import Path
import argparse
import hashlib
import json
import os

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    from dotenv import load_dotenv
    load_dotenv(ROOT/'.env',override=True)
    manifest=json.loads((ROOT/'packaging/embedding_download.json').read_text(encoding='utf-8'))
    os.environ['HF_HUB_DISABLE_TELEMETRY']='1';os.environ['HF_HUB_DISABLE_IMPLICIT_TOKEN']='1'
    from huggingface_hub import hf_hub_download
    for entry in manifest['files']:
        path=Path(hf_hub_download(repo_id=manifest['model_id'],revision=manifest['revision'],filename=entry['path'],
            cache_dir=os.environ.get('HF_HUB_CACHE'),local_files_only=args.check,token=False))
        with path.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if path.stat().st_size!=entry['size_bytes'] or actual!=entry['sha256']:raise ValueError('Pinned model file mismatch: '+entry['path'])
    print('PINNED_E5_READY; exact revision and file hashes verified; 0 LLM calls')


if __name__=='__main__':main()
