"""Run from a clean clone: python3 -m tools.airep_v02 --help."""
import argparse
import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from .basis import verifier
from .json_input import loads, dumps, check_core_number_bounds
from .producer import Chain, digest_bytes
from .profiles import ProfileBases
from .reconcile import reconcile
from .verify import evaluate_request, operator_inputs


def read(path):
    raw = Path(path).read_bytes()
    value = loads(raw)
    # Only artifacts/arrays contain core sequence fields on this CLI surface;
    # family payloads, keys and scope inputs do not own a top-level sequence.
    if isinstance(value, list) or isinstance(value, dict) and 'airep_version' in value:
        check_core_number_bounds(raw)
    return value


def write(path, value, *, private=False):
    if path is None:
        sys.stdout.write(dumps(value))
        return
    # Do not overwrite keys, signed evidence or an earlier measurement by default.
    data = dumps(value).encode('utf-8')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def load_key(path):
    value = read(path)
    if not isinstance(value, dict) or set(value) != {'seed_hex'} or not isinstance(value['seed_hex'], str):
        raise ValueError('key file must contain exactly seed_hex (32-byte Ed25519 seed)')
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value['seed_hex']))


def main(argv=None):
    parser = argparse.ArgumentParser(description='AIREP v0.2 beta producer, verifier and lifecycle reconciler')
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command', required=True)
    keygen = sub.add_parser('keygen', help='generate a local test key (never production key management)')
    keygen.add_argument('--out', required=True)
    dig = sub.add_parser('digest', help='SHA-256 of exact input file bytes')
    dig.add_argument('--input', required=True)
    for family in ('decision', 'control', 'execution', 'effect'):
        emit = sub.add_parser('emit-' + family)
        for arg in ('key', 'producer', 'payload'):
            emit.add_argument('--' + arg, required=True)
        for arg in ('out', 'chain-id', 'record-id', 'previous', 'timestamp', 'scope'):
            emit.add_argument('--' + arg)
    for command in ('verify', 'reconcile'):
        p = sub.add_parser(command)
        if command == 'verify':
            group = p.add_mutually_exclusive_group(required=True)
            group.add_argument('--request', help='class-verifier evaluation envelope')
            group.add_argument('--input', help='one artifact or an array; related records supplied automatically')
        else:
            p.add_argument('--input', required=True, help='JSON array of artifacts')
        for arg in ('bindings','independence-policy','revocation','now','freshness-window','profile-bases','out'):
            p.add_argument('--' + arg)
    args = parser.parse_args(argv)
    try:
        if args.command == 'keygen':
            key = Ed25519PrivateKey.generate()
            seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            write(args.out, {'seed_hex':seed.hex()}, private=True)
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            print(json.dumps({'public_key_hex':public, 'suite':'ed25519'}))
        elif args.command == 'digest':
            print(digest_bytes(Path(args.input).read_bytes()))
        elif args.command.startswith('emit-'):
            chain = Chain(load_key(args.key), args.producer, chain_id=args.chain_id,
                          previous=read(args.previous) if args.previous else None)
            artifact = chain.emit(args.command[5:], read(args.payload), record_id=args.record_id,
                                  timestamp=args.timestamp, scope=read(args.scope) if args.scope else None)
            write(args.out, artifact)
        else:
            if args.command == 'verify' and args.request and args.out:
                raise verifier.UsageError('--request emits to stdout; --out is for --input batches')
            ops = operator_inputs(bindings=args.bindings, independence_policy=args.independence_policy,
                revocation=args.revocation, now=args.now, freshness_window=args.freshness_window)
            bases = ProfileBases(args.profile_bases)
            if args.command == 'reconcile':
                result = reconcile(read(args.input), ops=ops, profile_bases=bases)
            elif args.request:
                result = evaluate_request(Path(args.request).read_bytes(), ops=ops, profile_bases=bases)
            else:
                docs = read(args.input)
                docs = docs if isinstance(docs, list) else [docs]
                if not docs:
                    raise ValueError('empty verification batch')
                result = {'verdicts':[]}
                seen = set()
                for i, doc in enumerate(docs):
                    v = evaluate_request({'artifact':doc, 'related_artifacts':docs[:i]+docs[i+1:]}, ops=ops, profile_bases=bases)
                    identity = (v['artifact_ref']['chain_id'], v['artifact_ref']['record_id'])
                    if identity in seen:
                        raise ValueError('duplicate (chain_id, record_id) in verification batch')
                    seen.add(identity)
                    result['verdicts'].append(v)
                result['verdicts'].sort(key=verifier.verdict_sort_key)
            write(args.out, result)
        return 0
    except verifier.UsageError as exc:
        print('usage: ' + str(exc), file=sys.stderr)
        return 2
    except (ValueError, TypeError, KeyError, OSError, RecursionError, verifier.RunInvalid) as exc:
        print('invalid: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
