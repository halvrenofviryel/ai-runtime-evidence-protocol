#!/usr/bin/env python3
"""Legacy CI producer-interop job; run after npm build in the disposable copy."""
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='airep-ts-interop-') as temp:
        chain=Path(temp)/'chain.jsonl'
        with chain.open('wb') as out:
            subprocess.run(['node','producers/typescript/dist/airep_producer.js'],cwd=ROOT,stdout=out,check=True)
        print('TypeScript producer emitted',len(chain.read_text().splitlines()),'records',flush=True)
        for runtime,script in [(sys.executable,'verify.py'),('node','verify.mjs')]:
            command=[runtime,'spec/airep/v0.1/conformance/'+script,str(chain),'--pubkey','spec/airep/v0.1/examples/test_public_key.txt']
            print('COMMAND',command,flush=True)
            subprocess.run(command,cwd=ROOT,check=True)


if __name__=='__main__':
    main()
