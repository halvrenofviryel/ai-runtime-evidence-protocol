#!/usr/bin/env python3
"""AIREP record producer (Python) — sign your OWN record with your OWN key.

This is the copy-paste path for emitting a conformant AIREP v0.1 record from your runtime.
It fills the ``integrity`` block exactly as the conformance verifiers re-derive it:

    body      = the record with integrity.current and integrity.signature removed
                (integrity.previous and canonical_json are RETAINED)
    current   = "sha256:" + SHA-256( jcs.canonicalize(body) )    # RFC 8785 canonical bytes
    signature = Ed25519 signature over the `current` string, hex-encoded

It signs with a CALLER-SUPPLIED key, never the published test key. To use it in your own
project, copy two files into it — this file and ``spec/airep/v0.1/conformance/jcs.py``
(stdlib-only) — and change the ``import jcs`` line below to point at your copy.

Quickstart (see EXPLAINER.md "Write your own record in 5 minutes"):

    # draft a record (copy an example and edit the fields), then sign it with a fresh key:
    python3 producers/python/airep_producer.py my_record.json
    # -> fills integrity in place, writes my_record.pub.hex + my_record.key.hex, and prints
    #    the exact verify command (you will see `sig=ok`).

Requires: cryptography (pip install cryptography).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The AIREP RFC 8785 canonicalizer. In-repo it lives in the conformance kit; a producer in
# another project copies jcs.py next to this file and uses `import jcs` directly.
_CONF = Path(__file__).resolve().parents[2] / "spec" / "airep" / "v0.1" / "conformance"
if str(_CONF) not in sys.path:
    sys.path.insert(0, str(_CONF))
import jcs  # noqa: E402  (RFC 8785 canonicalization; see conformance/jcs.py)

GENESIS = "sha256:" + "0" * 64


def build_record(record: dict, signing_key: Ed25519PrivateKey, previous: str = GENESIS) -> dict:
    """Return ``record`` with a complete ``integrity`` block.

    The hash is computed over the record's RFC 8785 canonical form with ``integrity.current``
    and ``integrity.signature`` removed and ``integrity.previous`` retained, so content is bound
    to chain position. ``previous`` defaults to the genesis constant; pass the prior record's
    ``integrity.current`` to extend a chain.
    """
    out = dict(record)
    integ = dict(out.get("integrity", {}))
    integ["previous"] = previous
    integ["canonical_json"] = True

    body = dict(out)
    body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
    current = "sha256:" + hashlib.sha256(jcs.canonicalize(body)).hexdigest()

    integ["current"] = current
    integ["signature"] = {"alg": "Ed25519", "value": signing_key.sign(current.encode("utf-8")).hex()}
    out["integrity"] = integ
    return out


def _pub_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fill an AIREP record's integrity block and sign it with your own Ed25519 key.")
    ap.add_argument("record", help="JSON record you drafted (subject/input/claim/output/evidence/"
                                    "directive/scope); copy an example from examples/ and edit it")
    ap.add_argument("--key", metavar="HEXFILE",
                    help="file holding a 32-byte Ed25519 seed in hex; a fresh key is generated if omitted")
    ap.add_argument("--previous", default=GENESIS,
                    help="integrity.previous — the prior record's current, or genesis (default)")
    args = ap.parse_args()

    generated = args.key is None
    if generated:
        sk = Ed25519PrivateKey.generate()
    else:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(args.key).read_text().strip()))

    rec_path = Path(args.record)
    signed = build_record(json.loads(rec_path.read_text()), sk, previous=args.previous)
    rec_path.write_text(json.dumps(signed, indent=2) + "\n")

    pub = _pub_hex(sk)
    pub_path = rec_path.with_suffix(".pub.hex")
    pub_path.write_text(pub + "\n")

    print(f"signed            -> {rec_path}")
    print(f"integrity.current  = {signed['integrity']['current']}")
    print(f"public key (hex)   -> {pub_path}")
    if generated:
        seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption()).hex()
        key_path = rec_path.with_suffix(".key.hex")
        key_path.write_text(seed + "\n")
        key_path.chmod(0o600)
        print(f"NEW private key    -> {key_path}  (chmod 600 — keep it out of git and out of records)")
    print("\nverify it:")
    print(f"  python3 {_CONF}/verify.py {rec_path} --pubkey {pub_path} --class")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
