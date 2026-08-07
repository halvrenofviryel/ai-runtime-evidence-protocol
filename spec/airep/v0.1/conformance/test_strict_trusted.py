#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP strict-Trusted battery (WP-10) — Trusted is granted ONLY when the four gates run and pass.

`CONFORMANCE_CLASSES.md` §AIREP-Trusted lists four prerequisites the reference verifiers leave
unevaluated by default (`TRUSTED_NOT_IMPLEMENTED`). WP-10 adds an OPT-IN strict mode: with the
operator supplying `--trust-store` + `--freshness-window` + `--revocation-source`, the four gates run
for real —

  1. the witness signature re-verifies under the key RESOLVED FROM THE TRUST STORE;
  2. the witness key is TRUSTED and INDEPENDENT of the producer, decided on resolved PUBLIC KEYS
     (not `witness_id` strings);
  3. the witness timestamp is FRESH within the operator's window (deterministic against `--now`);
  4. neither the producer nor the witness key is REVOKED per the external source.

A record earns `Trusted` iff every gate passes; any single failure drops the ceiling to `Verified`
with the specific reason named. Missing operator inputs → `TRUSTED_NOT_IMPLEMENTED` (never a silent
Trusted). This battery asserts, for BOTH verifiers, the class AND the reason set on each case — and
that the two verifiers agree byte-for-byte (parity is class AND reason).

v1 scope (matches the verifiers): exactly one independent trusted witness (no N-of-M quorum), local
JSON inputs (no transparency-log / no online CRL), timestamp freshness (no nonce/challenge).

Usage:  python3 test_strict_trusted.py    (exit 0 if every case matches under both verifiers)
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
except ImportError:  # pragma: no cover
    # NOT_RUN, and it must NOT read as a pass: a green no-op here would be the very "unmeasured reads
    # as passed" shape AIREP exists to catch, one level up in the harness.
    print("NOT_RUN: cryptography not installed — the strict-Trusted battery needs a real signer.")
    print("RESULT: NOT_RUN (0 cases measured). Install `cryptography` to run the battery.")
    sys.exit(2)

import test_trusted_gates as T  # noqa: E402  reuse the committed signer + fixed seeds

# Fixed operator inputs, written to a tempdir. The witness timestamp baked into _chain_witness()'s
# "fresh" anchor is 2026-05-30T00:00:05Z; NOW_OK sits just after it, inside a wide window.
NOW_OK = "2026-05-30T00:00:10Z"
NOW_BEFORE = "2026-05-30T00:00:00Z"       # earlier than the witness ts -> in future
NOW_FAR = "2027-01-01T00:00:00Z"          # far after -> stale for a tiny window
REVOKED_AT = "2026-05-29T00:00:00Z"       # before the record was signed

TRUST_GOOD = {T.WITNESS_KEY_ID: {"public_key_hex": T._wpub_hex, "trusted": True}}
TRUST_PRODPUB = {T.WITNESS_KEY_ID: {"public_key_hex": T._pub_hex, "trusted": True}}  # witness==producer key
TRUST_UNTRUSTED = {T.WITNESS_KEY_ID: {"public_key_hex": T._wpub_hex, "trusted": False}}
TRUST_EMPTY = {}
REV_EMPTY = {}
REV_PROD = {T.PRODUCER_KEY_ID: {"revoked_at": REVOKED_AT, "reason": "test"}}
REV_WIT = {T.WITNESS_KEY_ID: {"revoked_at": REVOKED_AT, "reason": "test"}}


def _perfect():
    """Structurally-perfect witness record: a REAL witness signature by the independent witness key,
    a fresh timestamp, revocation state present and revoked:false. Only the operator inputs vary."""
    return T._checkpoint(T._key_trust({"revoked": False}), T._chain_witness())


def _forged():
    return T._checkpoint(T._key_trust({"revoked": False}), T._chain_witness(sig=T.FORGED_WITNESS_SIG))


# name -> (record, trust_store | None, revocation | None, window | None, now | None,
#          expected_class, expected_reason_set)
# None inputs mean "do not pass the strict flags" (default mode).
def build_cases():
    return {
        "happy -> Trusted":
            (_perfect(), TRUST_GOOD, REV_EMPTY, 3600, NOW_OK, "Trusted", frozenset()),
        "forged witness sig":
            (_forged(), TRUST_GOOD, REV_EMPTY, 3600, NOW_OK, "Verified",
             frozenset({"witness-signature-invalid"})),
        "witness key == producer key (distinct ids)":
            (_perfect(), TRUST_PRODPUB, REV_EMPTY, 3600, NOW_OK, "Verified",
             frozenset({"witness-not-independent", "witness-signature-invalid"})),
        "freshness stale (tiny window, now far ahead)":
            (_perfect(), TRUST_GOOD, REV_EMPTY, 1, NOW_FAR, "Verified",
             frozenset({"freshness-stale"})),
        "freshness in the future (now before witness ts)":
            (_perfect(), TRUST_GOOD, REV_EMPTY, 3600, NOW_BEFORE, "Verified",
             frozenset({"freshness-in-future"})),
        "producer key revoked (external source)":
            (_perfect(), TRUST_GOOD, REV_PROD, 3600, NOW_OK, "Verified",
             frozenset({"producer-key-revoked"})),
        "witness key revoked (external source)":
            (_perfect(), TRUST_GOOD, REV_WIT, 3600, NOW_OK, "Verified",
             frozenset({"witness-key-revoked"})),
        "witness unknown (not in trust store)":
            (_perfect(), TRUST_EMPTY, REV_EMPTY, 3600, NOW_OK, "Verified",
             frozenset({"witness-unknown"})),
        "witness untrusted (trusted:false)":
            (_perfect(), TRUST_UNTRUSTED, REV_EMPTY, 3600, NOW_OK, "Verified",
             frozenset({"witness-untrusted"})),
        # No operator inputs at all -> the gates cannot run -> withheld, all four named. Never a
        # silent Trusted just because the witness material is structurally perfect.
        "no strict inputs -> TRUSTED_NOT_IMPLEMENTED":
            (_perfect(), None, None, None, None, "TRUSTED_NOT_IMPLEMENTED",
             frozenset({"witness-signature-not-verified", "witness-key-distinctness-unproven",
                        "freshness-recency-not-evaluated", "revocation-not-honored"})),
    }


REC_RE = re.compile(r"^\s*\[0\]\s.*?class=(\S+)(?:\s+trusted_withheld=(\S+))?", re.M)


def _run(cmd, rec_path, ts_path, window, rev_path, now):
    argv = [str(rec_path), "--class", "--pubkey", T._pub_hex]
    if ts_path is not None:
        argv += ["--trust-store", str(ts_path), "--freshness-window", str(window),
                 "--revocation-source", str(rev_path), "--now", now]
    r = subprocess.run(cmd + argv, capture_output=True, text=True)
    m = REC_RE.search(r.stdout)
    if not m:
        return ("NO-CLASS", frozenset(), r.returncode)
    cls, w = m.group(1), m.group(2)
    return (cls, frozenset(w.split(",")) if w else frozenset(), r.returncode)


def main():
    have_node = shutil.which("node") is not None
    tmp = Path(tempfile.mkdtemp(prefix="airep-strict-"))
    # Write the fixed operator-input files once.
    paths = {}
    for name, obj in (("trust_good", TRUST_GOOD), ("trust_prodpub", TRUST_PRODPUB),
                      ("trust_untrusted", TRUST_UNTRUSTED), ("trust_empty", TRUST_EMPTY),
                      ("rev_empty", REV_EMPTY), ("rev_prod", REV_PROD), ("rev_wit", REV_WIT)):
        p = tmp / f"{name}.json"
        p.write_text(json.dumps(obj))
        paths[id(obj)] = p

    fails = 0
    print(f"AIREP strict-Trusted battery  (node {'present' if have_node else 'ABSENT'})")
    print(f"  {'case':<44} | py                       | mjs                      | ok")
    print(f"  {'-' * 44}-|--------------------------|--------------------------|----")
    for i, (name, (rec, ts, rev, window, now, exp_cls, exp_reasons)) in enumerate(build_cases().items()):
        rec_path = tmp / f"rec_{i}.json"
        rec_path.write_text(json.dumps(rec))
        ts_path = paths[id(ts)] if ts is not None else None
        rev_path = paths[id(rev)] if rev is not None else None
        py_cls, py_r, _ = _run([sys.executable, str(HERE / "verify.py")], rec_path, ts_path, window, rev_path, now)
        ok = (py_cls == exp_cls and py_r == exp_reasons)
        mj_str = " — "
        if have_node:
            mj_cls, mj_r, _ = _run(["node", str(HERE / "verify.mjs")], rec_path, ts_path, window, rev_path, now)
            ok = ok and (mj_cls == py_cls and mj_r == py_r)
            mj_str = f"{mj_cls}"
        if not ok:
            fails += 1
        print(f"  {name:<44} | {py_cls:<24} | {mj_str:<24} | {'PASS' if ok else 'FAIL'}")
        if not ok:
            print(f"  {'':<44} | expected class={exp_cls} reasons={sorted(exp_reasons)}")
            print(f"  {'':<44} | py class={py_cls} reasons={sorted(py_r)}")
            if have_node:
                print(f"  {'':<44} | mjs class={mj_cls} reasons={sorted(mj_r)}")

    if not have_node:
        print("  NOT_RUN  Node half of the class/reason parity (node binary absent)")

    print(f"RESULT: {'strict-Trusted grants Trusted only when all four gates pass' if not fails else f'{fails} failure(s)'}")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
