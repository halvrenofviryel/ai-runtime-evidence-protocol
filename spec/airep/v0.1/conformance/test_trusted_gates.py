#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP-Trusted gate test — the top class MUST NOT be granted on witness PRESENCE.

`CONFORMANCE_CLASSES.md` §AIREP-Trusted requires three things beyond Verified:

  1. a head witness signed by a key **distinct from the producer's** (or a transparency-log
     inclusion proof);
  2. a **freshness anchor** (witness timestamp, nonce, or challenge response);
  3. `profiles.key_trust` carrying rotation + revocation state, **and the verifier honoring
     revocation**.

The reference verifiers do not re-verify the witness signature, cannot prove the witness key is
distinct from the producer key (a `witness_id` string is not a key), do not evaluate freshness
recency, and consult no revocation source. A class whose prerequisites are not enforced must be
**withheld and named**, never silently granted — so the top class is unreachable here and the
verifiers report `TRUSTED_NOT_IMPLEMENTED` instead.

This test builds records that carry structurally present but cryptographically meaningless witness
material and asserts that `--class` never returns `Trusted`, under BOTH reference verifiers.

Usage:
  python3 test_trusted_gates.py              run the battery (exit 0 all pass, 1 otherwise)
  python3 test_trusted_gates.py --emit DIR   also write each case record + the keys into DIR
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import jcs  # noqa: E402  (RFC 8785 canonicalization — conformance/jcs.py)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
    print("SKIP: cryptography not installed — the Trusted-gate battery needs a real signer")
    sys.exit(0)

# The same FIXED, PUBLISHED test seeds `examples/regenerate.py` uses. TEST ONLY.
PRODUCER_SEED = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
WITNESS_SEED = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
_sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRODUCER_SEED))
_pub_hex = _sk.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
_wsk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(WITNESS_SEED))
_wpub_hex = _wsk.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

GENESIS = "sha256:" + "0" * 64
PRODUCER_KEY_ID = "airep-test-key-1"
WITNESS_KEY_ID = "airep-test-witness-1"
CHAIN_ID = "airep:chain:trusted-gate-test"
# A witness signature that is a well-formed hex string and NOT a valid Ed25519 signature.
FORGED_WITNESS_SIG = "ab" * 64


def _ptr(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _sign_record(rec: dict) -> dict:
    """Real integrity: current = SHA-256 over the canonical body, signature = Ed25519 over current."""
    integ = dict(rec["integrity"])
    body = dict(rec)
    body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
    current = "sha256:" + hashlib.sha256(jcs.canonicalize(body)).hexdigest()
    integ["current"] = current
    integ["signature"] = {"alg": "Ed25519", "value": _sk.sign(current.encode("utf-8")).hex()}
    out = dict(rec)
    out["integrity"] = integ
    return out


def _real_witness_sig(head: dict) -> str:
    claim = {"chain_id": CHAIN_ID, "decision_index": head["decision_index"],
             "current": head["current"], "length": head["length"]}
    return _wsk.sign(jcs.canonicalize(claim)).hex()


def _checkpoint(key_trust: dict, chain_witness: dict) -> dict:
    """A standalone checkpoint record that already satisfies every AIREP-Verified requirement:
    a real Ed25519 signature, a real alg, no unanchored withheld evidence, and a key_trust block.
    Only the Trusted-tier prerequisites vary between cases."""
    rec = {
        "airep_version": "0.1",
        "subject": {"runtime": "phionyx-core", "producer": "phionyx/0.7.1", "decision_index": 2,
                    "trace_id": "trace-trusted-gate-test", "timestamp_utc": "2026-05-30T00:00:02Z"},
        "input": {"input_ref": _ptr("gate-input"),
                  "governance_state": {"policy_version": "p1", "prior_context_bound": True}},
        "claim": {"assertion": "checkpoint: witnesses a committed chain head",
                  "basis": ["safety_gate"]},
        "output": {"result_ref": _ptr("gate-output"), "redacted": False},
        "evidence": [{"type": "policy", "ref": "policy://safety/v1", "resolvable": True}],
        "directive": {"verb": "release", "policy_basis": ["safety_gate"]},
        "scope": {"covers": ["chain head pinned by a witness"],
                  "does_not_cover": ["witness key trust is asserted, not corroborated here"]},
        "integrity": {"previous": _ptr("gate-previous-head"), "canonical_json": True},
        "profiles": {"key_trust": key_trust, "chain_witness": chain_witness},
    }
    return _sign_record(rec)


def _key_trust(revocation=None) -> dict:
    kt = {
        "key_id": PRODUCER_KEY_ID, "issuer": "self", "algorithm": "Ed25519",
        "public_key": {"format": "raw_hex", "value": _pub_hex},
        "validity": {"not_before": "2026-05-30T00:00:00Z"},
    }
    if revocation is not None:
        kt["revocation"] = revocation
    return kt


def _head() -> dict:
    return {"decision_index": 1, "current": _ptr("gate-previous-head"), "length": 2}


def _chain_witness(witness_id=WITNESS_KEY_ID, sig=None, freshness="fresh") -> dict:
    head = _head()
    cw = {"chain_id": CHAIN_ID, "head": head,
          "witness": {"witness_id": witness_id, "alg": "Ed25519",
                      "value": sig if sig is not None else _real_witness_sig(head)},
          "revocation_checked": True}
    if freshness == "fresh":
        cw["freshness"] = {"witness_timestamp_utc": "2026-05-30T00:00:05Z"}
    elif freshness == "stale":
        cw["freshness"] = {"witness_timestamp_utc": "1999-01-01T00:00:00Z"}
    elif freshness == "absent":
        pass
    return cw


# name -> (record, why it must not reach Trusted)
def build_cases() -> dict:
    ok_rev = {"revoked": False}
    return {
        # THE REPRODUCER: a witness signature that is not a signature. Structurally present,
        # cryptographically meaningless. Every other Trusted prerequisite is structurally present.
        "forged_witness_signature": (
            _checkpoint(_key_trust(ok_rev), _chain_witness(sig=FORGED_WITNESS_SIG)),
            "witness.value is not a valid Ed25519 signature; no verifier re-verifies it"),
        # A "witness" that names the producer's own key -> no truncation defense at all.
        "witness_is_the_producer": (
            _checkpoint(_key_trust(ok_rev), _chain_witness(witness_id=PRODUCER_KEY_ID)),
            "witness_id equals the producer key_id — not an independent witness"),
        # No freshness anchor -> 'valid' cannot be read as 'current'.
        "no_freshness_anchor": (
            _checkpoint(_key_trust(ok_rev), _chain_witness(freshness="absent")),
            "no witness timestamp / nonce / challenge response"),
        # A freshness anchor that is present but ancient. NOTE: no verifier evaluates recency;
        # the top class is withheld because the freshness gate is NOT IMPLEMENTED, not because
        # staleness was detected. This case documents that boundary; it does not close it.
        "stale_freshness_anchor": (
            _checkpoint(_key_trust(ok_rev), _chain_witness(freshness="stale")),
            "witness timestamp is ancient; recency is never evaluated"),
        # Producer key explicitly revoked.
        "revoked_producer_key": (
            _checkpoint(_key_trust({"revoked": True, "revoked_at": "2026-05-29T00:00:00Z"}),
                        _chain_witness()),
            "key_trust.revocation.revoked is true"),
        # key_trust carries no revocation state at all -> requirement 3 cannot even be read.
        "no_revocation_state": (
            _checkpoint(_key_trust(None), _chain_witness()),
            "key_trust carries no revocation block"),
        # THE HONESTY CONTROL: every structurally checkable prerequisite passes and the witness
        # signature is genuinely valid under the independent witness key. It STILL must not be
        # Trusted, because the verifier does not check the witness signature, key distinctness,
        # freshness recency, or revocation.
        "structurally_perfect_witness": (
            _checkpoint(_key_trust(ok_rev), _chain_witness()),
            "all gates structurally present, but none of the Trusted checks actually run"),
    }


CLASS_RE = re.compile(r"^CLASS:\s*(\S+)", re.M)


def _run_class(cmd, path) -> str:
    r = subprocess.run(cmd + [str(path), "--pubkey", str(SPEC / "examples" / "test_public_key.txt"),
                              "--class"], capture_output=True, text=True)
    m = CLASS_RE.search(r.stdout)
    if r.returncode != 0:
        return f"EXIT{r.returncode}:{m.group(1) if m else '?'}"
    return m.group(1) if m else "NO-CLASS-LINE"


def main() -> int:
    ap = argparse.ArgumentParser(description="AIREP-Trusted gate battery")
    ap.add_argument("--emit", default="", help="also write the case records into this directory")
    args = ap.parse_args()

    have_node = shutil.which("node") is not None
    cases = build_cases()
    tmp = Path(tempfile.mkdtemp(prefix="airep-trusted-gates-"))
    emit = Path(args.emit) if args.emit else None
    if emit:
        emit.mkdir(parents=True, exist_ok=True)
        (emit / "producer_public_key.txt").write_text(_pub_hex + "\n")
        (emit / "witness_public_key.txt").write_text(_wpub_hex + "\n")

    fails = 0
    print(f"AIREP-Trusted gate battery  (node {'present' if have_node else 'ABSENT'})")
    print(f"  {'case':<30} | py                      | mjs                     | ok")
    print(f"  {'-' * 30}-|-------------------------|-------------------------|----")
    for name, (rec, _why) in cases.items():
        path = tmp / f"{name}.json"
        path.write_text(json.dumps(rec, indent=2) + "\n")
        if emit:
            (emit / f"{name}.json").write_text(json.dumps(rec, indent=2) + "\n")
        py = _run_class([sys.executable, str(HERE / "verify.py")], path)
        # (1) the top class must never be granted; (2) the record must still reach Verified's
        # floor, so a downgrade is a real ladder position and not an incidental failure.
        ok = py != "Trusted" and py in ("Verified", "TRUSTED_NOT_IMPLEMENTED")
        mjs = "—"
        if have_node:
            mjs = _run_class(["node", str(HERE / "verify.mjs")], path)
            ok = ok and mjs == py  # class-level parity (test_verifier_parity.py covers pass/fail only)
        if not ok:
            fails += 1
        print(f"  {name:<30} | {py:<23} | {mjs:<23} | {'PASS' if ok else 'FAIL'}")

    # The record whose every structural gate passes must be named TRUSTED_NOT_IMPLEMENTED, not
    # quietly reported as plain Verified — a withheld class has to say why it was withheld.
    perfect = _run_class([sys.executable, str(HERE / "verify.py")],
                         tmp / "structurally_perfect_witness.json")
    named = perfect == "TRUSTED_NOT_IMPLEMENTED"
    if not named:
        fails += 1
    print(f"  {'PASS' if named else 'FAIL'}  withheld class is NAMED "
          f"(structurally_perfect_witness -> TRUSTED_NOT_IMPLEMENTED, got {perfect})")

    if emit:
        print(f"  records written to {emit}")
    print(f"RESULT: {'no record reached Trusted on presence alone' if not fails else f'{fails} failure(s)'}")
    return 0 if not fails else 1


if __name__ == "__main__":
    raise SystemExit(main())
