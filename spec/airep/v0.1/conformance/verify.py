#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.1 verifier — run the full conformance check on ANY record or chain you provide.

`validate.py` checks the shipped example vectors; **this** verifies an input you pass: a single
record (`.json`) or a chain (`.jsonl`, one record per line, or a JSON array). For each record it
checks, per SPEC §6/§8:

  - schema validity against the core schema (closed top level, required members, closed enums);
  - neutrality (§8.2) — the record still validates against the core schema with `profiles` removed;
  - **integrity** — recompute `integrity.current` as SHA-256 over the canonical form with
    current+signature removed and previous retained; it must match;
  - **chain** — for a multi-record input, each `previous` links to the prior record's `current`
    (genesis for the first) and `decision_index` increments; a standalone `decision_index`-0 record
    must point at the genesis `previous`;
  - **signature** — if a public key is supplied, re-verify the Ed25519 signature over `current`;
  - **profiles** — any `profiles.<name>` block is validated against `profiles/<name>.schema.json`.

The Node verifier (`verify.mjs`) performs the same checks on an independent stack; the two agree.

Usage:
  python3 verify.py <record.json | chain.jsonl> [--pubkey <hex | path-to-key-file>]

Exit 0 if every record passes, 1 otherwise. Requires `jsonschema` (+ `cryptography` for the
optional signature check). Canonicalization is RFC 8785 (the JSON Canonicalization Scheme) via
`conformance/jcs.py`.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("FAIL: jsonschema not installed (pip install jsonschema)")
    sys.exit(1)

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent
GENESIS = "sha256:" + "0" * 64
CORE = jsonschema.Draft202012Validator(json.loads((SPEC / "core.schema.json").read_text()))
PROFILE_VALIDATORS = {
    sp.name[: -len(".schema.json")]: jsonschema.Draft202012Validator(json.loads(sp.read_text()))
    for sp in sorted((SPEC / "profiles").glob("*.schema.json"))
}


def _canonical(obj) -> bytes:
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import jcs
    return jcs.canonicalize(obj)  # RFC 8785 (JCS)


def _recompute(rec) -> str:
    integ = rec.get("integrity", {})
    body = dict(rec)
    body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
    return "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()


def _load_pubkey(s: str) -> str:
    if not s:
        return ""
    p = Path(s)
    if p.exists():
        lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
        return lines[-1] if lines else ""
    return s.strip()


def _verify_sig(integ, pub_hex):
    if not pub_hex:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(integ["signature"]["value"]), integ["current"].encode("utf-8"))
        return True
    except ImportError:
        return None
    except Exception:
        return False


def _load_records(path: str):
    p = Path(path)
    text = p.read_text()
    if p.suffix == ".jsonl":
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    obj = json.loads(text)
    return obj if isinstance(obj, list) else [obj]


def verify(path: str, pubkey: str = "") -> int:
    pub = _load_pubkey(pubkey)
    records = _load_records(path)
    is_chain = len(records) > 1
    fails = 0
    prev = GENESIS
    print(f"AIREP verify: {path}  ({len(records)} record(s){' — chain' if is_chain else ''})")
    for i, rec in enumerate(records):
        bad = []
        if list(CORE.iter_errors(rec)):
            bad.append("schema")
        if "profiles" in rec:
            stripped = {k: v for k, v in rec.items() if k != "profiles"}
            if list(CORE.iter_errors(stripped)):
                bad.append("neutrality")
        integ = rec.get("integrity", {})
        if _recompute(rec) != integ.get("current"):
            bad.append("hash")
        if is_chain:
            if integ.get("previous") != prev:
                bad.append("chain-link")
            if rec.get("subject", {}).get("decision_index") != i:
                bad.append("index")
        elif rec.get("subject", {}).get("decision_index") == 0 and integ.get("previous") != GENESIS:
            bad.append("genesis-previous")
        sig = _verify_sig(integ, pub)
        if sig is False:
            bad.append("signature")
        for pname, pv in PROFILE_VALIDATORS.items():
            block = rec.get("profiles", {}).get(pname)
            if block is not None and list(pv.iter_errors(block)):
                bad.append(f"profile:{pname}")
        prev = integ.get("current")
        sigstr = {True: "sig=ok", False: "sig=FAIL", None: "sig=skip"}[sig]
        status = "PASS" if not bad else "FAIL(" + ",".join(bad) + ")"
        print(f"  [{i}] {status}  {sigstr}  {str(integ.get('current', '?'))[:23]}...")
        if bad:
            fails += 1
    print(f"RESULT: {'all records OK' if not fails else f'{fails} record(s) FAILED'}")
    return 0 if not fails else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify an AIREP record or chain")
    ap.add_argument("path", help="a record .json or a chain .jsonl / JSON array")
    ap.add_argument("--pubkey", default="", help="Ed25519 public key (hex) or a path to a key file")
    args = ap.parse_args(argv)
    return verify(args.path, args.pubkey)


if __name__ == "__main__":
    raise SystemExit(main())
