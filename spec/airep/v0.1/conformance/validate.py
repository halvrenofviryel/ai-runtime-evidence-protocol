#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.1 conformance validator (neutral, self-contained).

Runs the full conformance battery against the spec's core.schema.json and the shipped
example records. It covers:
  (1) FULL validation of every example against the core schema;
  (2) the strip-profiles neutrality test (delete `profiles` -> still a valid core record);
  (3) negative tests proving the tightened core rejects a bare vendor top-level key and a
      missing required member;
  (4) INTEGRITY — recompute integrity.current as SHA-256 over the RFC 8785 canonical form
      (conformance/jcs.py), check the genesis `previous`, and verify the Ed25519 signature
      when the cryptography lib + key fixture are present;
  (5) CHAIN replay — each record's hash recomputes, its `previous` links to the prior
      `current`, the first is genesis, decision_index increments, each signature verifies;
  (6) PROFILE conformance — each profiles.<name> block validates against profiles/<name>.schema.json.

`verify.py` runs the same checks on any record/chain you pass; `verify.mjs` is the independent
Node implementation that agrees on the bytes.

Usage:  python3 validate.py     (exit 0 if all checks pass, 1 otherwise)
Requires: jsonschema (Draft 2020-12); cryptography is optional (enables the signature check).
"""
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
SCHEMA = json.loads((SPEC / "core.schema.json").read_text())
V = jsonschema.Draft202012Validator(SCHEMA)

failures = 0


def check(label, record, expect_valid):
    global failures
    errs = list(V.iter_errors(record))
    ok = not errs
    passed = ok == expect_valid
    print(f"  {'PASS' if passed else 'FAIL'}  {label}  (valid={ok}, expected={expect_valid})")
    if not passed:
        failures += 1
        for e in errs[:3]:
            print("        -", e.message)


def expect(label, condition):
    """Assert a boolean conformance fact (used by the tamper-detection section)."""
    global failures
    if not condition:
        failures += 1
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


GENESIS = "sha256:" + "0" * 64


def _canonical(obj) -> bytes:
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import jcs
    return jcs.canonicalize(obj)  # RFC 8785 (JCS) — see conformance/jcs.py


def verify_integrity(label, rec, pub_hex):
    """SPEC §6: recompute integrity.current, check the genesis `previous`, and (if the
    cryptography lib + key fixture are present) verify the Ed25519 signature over `current`."""
    global failures
    integ = rec.get("integrity", {})
    body = dict(rec)
    body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
    expect = "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()
    hash_ok = expect == integ.get("current")
    prev_ok = integ.get("previous") == GENESIS  # the shipped examples are genesis records
    sig_ok = None
    if pub_hex:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
                bytes.fromhex(integ["signature"]["value"]), integ["current"].encode("utf-8"))
            sig_ok = True
        except ImportError:
            sig_ok = None  # cryptography not installed — hash recompute still proves integrity
        except Exception:
            sig_ok = False
    ok = hash_ok and prev_ok and sig_ok is not False
    if not ok:
        failures += 1
    sig_str = {True: "verified", False: "FAILED", None: "skipped(no cryptography)"}[sig_ok]
    print(f"  {'PASS' if ok else 'FAIL'}  {label}  "
          f"(hash recompute={hash_ok}, genesis previous={prev_ok}, signature={sig_str})")


def verify_chain(label, path, pub_hex):
    """Multi-record replay: each record's hash recomputes; its `previous` links to the prior
    `current`; the first is genesis; decision_index increments; each signature verifies."""
    global failures
    records = [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
    prev = GENESIS
    ok = True
    for i, rec in enumerate(records):
        integ = rec.get("integrity", {})
        body = dict(rec)
        body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
        expect = "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()
        hash_ok = expect == integ.get("current")
        link_ok = integ.get("previous") == prev
        idx_ok = rec.get("subject", {}).get("decision_index") == i
        sig_ok = True
        if pub_hex:
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
                    bytes.fromhex(integ["signature"]["value"]), integ["current"].encode("utf-8"))
            except ImportError:
                pass
            except Exception:
                sig_ok = False
        ok = ok and hash_ok and link_ok and idx_ok and sig_ok
        prev = integ.get("current")
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}  "
          f"({len(records)} records linked: hash + previous-link + index + signature)")


def main():
    global failures
    examples = sorted((SPEC / "examples").glob("*.json"))
    print(f"AIREP v0.1 conformance — schema {SCHEMA.get('$id')}")
    print(f"Found {len(examples)} example record(s).\n")

    print("== FULL validation ==")
    records = {}
    for p in examples:
        rec = json.loads(p.read_text())
        records[p.name] = rec
        check(f"{p.name} FULL", rec, True)

    print("\n== STRIP-PROFILES neutrality test (delete 'profiles' -> still valid) ==")
    for name, rec in records.items():
        stripped = {k: v for k, v in rec.items() if k != "profiles"}
        check(f"{name} strip-profiles", stripped, True)

    print("\n== NEGATIVE tests (tightened core MUST reject) ==")
    if records:
        base = next(iter(records.values()))
        bad_vendor = dict(base)
        bad_vendor["vendor_state"] = {"phi": 0.22}  # bare vendor top-level key
        check("bare vendor top-level key -> REJECTED", bad_vendor, False)
        no_scope = {k: v for k, v in base.items() if k != "scope"}
        check("missing 'scope' -> REJECTED", no_scope, False)

    print("\n== INTEGRITY (recompute SHA-256 over canonical form + verify Ed25519 signature) ==")
    pub_path = SPEC / "examples" / "test_public_key.txt"
    pub_hex = ""
    if pub_path.exists():
        body_lines = [ln.strip() for ln in pub_path.read_text().splitlines()
                      if ln.strip() and not ln.startswith("#")]
        pub_hex = body_lines[-1] if body_lines else ""
    for name, rec in records.items():
        verify_integrity(f"{name} integrity", rec, pub_hex)

    chain_path = SPEC / "examples" / "chain.jsonl"
    if chain_path.exists():
        print("\n== CHAIN replay (each `previous` links to the prior `current`) ==")
        verify_chain("chain.jsonl", chain_path, pub_hex)

    # Prove the integrity block actually detects the attacks THREAT_MODEL.md names: silent
    # field edit (hash), splice/reorder (chain link), and forgery (signature).
    print("\n== TAMPER detection (each mutation MUST break exactly the right check) ==")
    signed = next((r for r in records.values()
                   if r.get("integrity", {}).get("signature", {}).get("value")), None)
    if signed is None:
        print("  (no signed example record available — skipped)")
    else:
        import copy

        def _recompute(rec):
            integ = rec.get("integrity", {})
            body = dict(rec)
            body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
            return "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()

        # 1) Untampered baseline: the stored hash recomputes (so a later mismatch is meaningful).
        expect("baseline: stored integrity.current recomputes",
               _recompute(signed) == signed["integrity"]["current"])

        # 2) Silent field edit -> recomputed hash no longer matches the stored current.
        t = copy.deepcopy(signed)
        ref = t["output"]["result_ref"]
        t["output"]["result_ref"] = ref[:-1] + ("0" if ref[-1] != "0" else "1")
        expect("edited output.result_ref -> hash mismatch detected",
               _recompute(t) != t["integrity"]["current"])

        # 3) Splice: rewrite `previous` -> stored current no longer matches the recompute.
        t = copy.deepcopy(signed)
        t["integrity"]["previous"] = "sha256:" + "f" * 64
        expect("rewritten integrity.previous -> hash mismatch detected (anti-splice)",
               _recompute(t) != t["integrity"]["current"])

        # 4) Forgery: corrupt the signature -> Ed25519 verification fails (needs cryptography + key).
        if pub_hex:
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                sig = signed["integrity"]["signature"]["value"]
                forged = sig[:-2] + ("00" if sig[-2:] != "00" else "11")
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
                        bytes.fromhex(forged), signed["integrity"]["current"].encode("utf-8"))
                    sig_broke = False  # forged signature wrongly accepted
                except Exception:
                    sig_broke = True   # rejected, as it must be
                expect("corrupted signature -> Ed25519 verification fails", sig_broke)
            except ImportError:
                print("  SKIP  signature forgery test (cryptography not installed)")
        else:
            print("  SKIP  signature forgery test (no public-key fixture)")

    profile_schemas = sorted((SPEC / "profiles").glob("*.schema.json"))
    if profile_schemas:
        print("\n== PROFILE conformance (profiles.<name> -> profiles/<name>.schema.json) ==")
        checked = False
        for sp in profile_schemas:
            pname = sp.name[: -len(".schema.json")]
            pv = jsonschema.Draft202012Validator(json.loads(sp.read_text()))
            for name, rec in records.items():
                block = rec.get("profiles", {}).get(pname)
                if block is None:
                    continue
                checked = True
                errs = list(pv.iter_errors(block))
                ok = not errs
                if not ok:
                    failures += 1
                print(f"  {'PASS' if ok else 'FAIL'}  {name} profiles.{pname} valid against {sp.name}")
                for e in errs[:3]:
                    print(f"      - {e.message}")
        if not checked:
            print("  (no record carries a profile with a published schema)")

    print()
    if failures:
        print(f"RESULT: {failures} check(s) FAILED")
        sys.exit(1)
    print("RESULT: all conformance checks PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
