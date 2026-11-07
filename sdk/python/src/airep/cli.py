"""Evaluation completion and explicit local policy match have separate exit semantics."""
import argparse
from importlib.resources import files
import json
import math
import os
import subprocess
import sys

from . import __version__
from .io import read_bytes, write_bytes, encoded


def evaluate_in_worker(command, raw, trust, query=b'', *, timeout=15):
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('timeout must be greater than zero and at most 30 seconds')
    request = encoded({'command': command, 'raw': raw.hex(), 'trust': trust.hex(), 'query': query.hex()})
    environment = {k: v for k, v in os.environ.items() if k in {'PATH', 'LANG', 'LC_ALL', 'SYSTEMROOT'}}
    # -I excludes cwd and PYTHONPATH; the installed wheel supplies every module.
    result = subprocess.run([sys.executable, '-I', '-m', 'airep._worker'], input=request,
        capture_output=True, timeout=timeout, env=environment)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors='replace').strip())
    return result.stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('basis', help='print installed resource pins and native version')
    for name in ('verify', 'reconcile', 'consume'):
        item = sub.add_parser(name)
        item.add_argument('--input', required=True)
        item.add_argument('--trust', required=True, help='separate operator-controlled public trust JSON')
        item.add_argument('--out', help='new output file; never overwrite')
        item.add_argument('--timeout', type=float, default=15)
        if name == 'consume':
            item.add_argument('--query', required=True, help='explicit expected identity JSON')
            item.add_argument('--require-policy-match', action='store_true', help='return 3 on NO_MATCH; default 0 only means evaluation completed')
    args = parser.parse_args(argv)
    try:
        if args.command == 'basis':
            sys.stdout.buffer.write(files('airep').joinpath('SOURCE_MANIFEST.json').read_bytes())
            return 0
        raw, trust = read_bytes(args.input), read_bytes(args.trust)
        query = read_bytes(args.query) if args.command == 'consume' else b''
        output = evaluate_in_worker(args.command, raw, trust, query, timeout=args.timeout)
        if args.out:
            write_bytes(args.out, output)
        else:
            sys.stdout.buffer.write(output)
        if args.command == 'consume' and args.require_policy_match and json.loads(output)['consumer']['policy_result'] != 'MATCH':
            return 3
        return 0
    except subprocess.TimeoutExpired:
        print('evaluation timed out; no result emitted', file=sys.stderr)
        return 124
    except (OSError, ValueError, TypeError) as exc:
        print('evaluation rejected: ' + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
