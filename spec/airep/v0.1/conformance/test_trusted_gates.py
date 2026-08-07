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

**Shared corpus.** The cases are committed under `fixtures/trusted_gates/` and BOTH verifiers are
run over those exact files. Cross-implementation parity is only meaningful over an identical
positive/negative corpus, so the battery additionally re-derives every case from the fixed seeds and
fails if the committed bytes drifted — the corpus cannot rot away from the generator.

**Parity is class AND reason.** Agreeing on the class while disagreeing on *why* the class was
withheld is not parity: a consumer reads the reason set to decide what is missing. The battery
asserts both verifiers emit the same `class` and the same `trusted_withheld` set, and that each
equals the reason set named for that case in `EXPECTED`.

Usage:
  python3 test_trusted_gates.py                   run the battery (exit 0 all pass, 1 otherwise)
  python3 test_trusted_gates.py --emit DIR        also write each case record + the keys into DIR
  python3 test_trusted_gates.py --write-fixtures  rewrite the committed shared corpus in place
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
# The committed shared corpus. Both verifiers read THESE bytes, so parity is measured over one
# corpus rather than over two independently-generated ones.
FIXTURES = HERE / "fixtures" / "trusted_gates"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import jcs  # noqa: E402  (RFC 8785 canonicalization — conformance/jcs.py)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
    # NOT_RUN, and it must NOT read as a pass. Exiting 0 here would make the whole fail-closed
    # battery a green no-op on any machine lacking `cryptography` — the same "unmeasured reads as
    # passed" shape this battery exists to catch, one level up in the harness.
    print("NOT_RUN: cryptography not installed — the Trusted-gate battery needs a real signer.")
    print("RESULT: NOT_RUN (0 cases measured). Install `cryptography` to run the battery.")
    sys.exit(2)

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


def _alias_checkpoint(key_trust: dict, witness_block: dict) -> dict:
    """Same as _checkpoint but attaches the witness under the schema-free `freshness_witness`
    alias that both classifiers also accept (CONFORMANCE_CLASSES.md §AIREP-Trusted req 1)."""
    rec = _checkpoint(key_trust, {})
    prof = dict(rec["profiles"])
    prof.pop("chain_witness", None)
    prof["freshness_witness"] = witness_block
    out = dict(rec)
    out["profiles"] = prof
    return _sign_record(out)


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


def _chain_pair() -> list:
    """A 2-record CHAIN: an ordinary Verified record, then a checkpoint with a structurally perfect
    witness. Exists because the single-record fixtures never exercise the multi-record aggregation
    path — the empty-input `CLASS: Trusted` bug lived in exactly that uncovered path."""
    kt = _key_trust({"revoked": False})
    rec0 = _sign_record({
        "airep_version": "0.1",
        "subject": {"runtime": "phionyx-core", "producer": "phionyx/0.7.1", "decision_index": 0,
                    "trace_id": "trace-trusted-gate-chain", "timestamp_utc": "2026-05-30T00:00:00Z"},
        "input": {"input_ref": _ptr("chain-input-0"),
                  "governance_state": {"policy_version": "p1", "prior_context_bound": False}},
        "claim": {"assertion": "ordinary decision, no witness claimed", "basis": ["safety_gate"]},
        "output": {"result_ref": _ptr("chain-output-0"), "redacted": False},
        "evidence": [{"type": "policy", "ref": "policy://safety/v1", "resolvable": True}],
        "directive": {"verb": "release", "policy_basis": ["safety_gate"]},
        "scope": {"covers": ["one decision"], "does_not_cover": ["chain head freshness"]},
        "integrity": {"previous": GENESIS, "canonical_json": True},
        "profiles": {"key_trust": kt},
    })
    head = {"decision_index": 0, "current": rec0["integrity"]["current"], "length": 1}
    cw = {"chain_id": CHAIN_ID, "head": head,
          "witness": {"witness_id": WITNESS_KEY_ID, "alg": "Ed25519",
                      "value": _wsk.sign(jcs.canonicalize(
                          {"chain_id": CHAIN_ID, "decision_index": head["decision_index"],
                           "current": head["current"], "length": head["length"]})).hex()},
          "freshness": {"witness_timestamp_utc": "2026-05-30T00:00:05Z"},
          "revocation_checked": True}
    rec1 = dict(_checkpoint(kt, cw))
    rec1["subject"] = dict(rec1["subject"], decision_index=1)
    rec1["integrity"] = {"previous": rec0["integrity"]["current"], "canonical_json": True}
    return [rec0, _sign_record(rec1)]


# name -> (record(s), why it must not reach Trusted)
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
        # CROSS-RUNTIME TRUTHINESS: `witness: {}` is falsy in Python and truthy in JavaScript. With
        # truthiness-based presence tests the two verifiers returned DIFFERENT classes for these
        # exact bytes (py Verified / mjs TRUSTED_NOT_IMPLEMENTED). An empty witness object carries no
        # witness material, so both must read it as "no Trusted claim made" -> Verified.
        # Uses the schema-free `freshness_witness` alias on purpose: under `chain_witness` an empty
        # witness would trip that profile's schema in Python only, which is the SEPARATE Node
        # profile-validation gap. The alias isolates the truthiness question by itself.
        "empty_witness_object": (
            _alias_checkpoint(_key_trust(ok_rev),
                              {"chain_id": CHAIN_ID, "head": _head(), "witness": {},
                               "freshness": {"witness_timestamp_utc": "2026-05-30T00:00:05Z"}}),
            "witness object is empty; presence must be decided by type, not truthiness"),
        # MULTI-RECORD: the single-record fixtures never reach the chain aggregation path.
        "chain_verified_then_withheld": (
            _chain_pair(),
            "a chain is only as strong as its weakest record; the ceiling is never inherited"),
    }


# The four Trusted prerequisites neither classifier evaluates. Written out LITERALLY rather than
# imported from verify.py: a test that reads the implementation's own constant would still pass if
# that constant were silently emptied — which is exactly the regression this battery exists to catch.
NOT_IMPLEMENTED_GATES = frozenset({
    "witness-signature-not-verified",
    "witness-key-distinctness-unproven",
    "freshness-recency-not-evaluated",
    "revocation-not-honored",
})

# case -> (expected class, expected trusted_withheld set), asserted against BOTH verifiers.
# A structural prerequisite that DEFINITIVELY fails stops the ladder at Verified and names only that
# failure; a record with no structural failure left is withheld as TRUSTED_NOT_IMPLEMENTED and names
# all four unevaluated gates. Neither outcome is ever Trusted.
# Per-record expectations, in record order. The overall CLASS: line must equal the LOWEST-ranked
# record class, which the runner derives rather than restating.
_TNI = "TRUSTED_NOT_IMPLEMENTED"
EXPECTED = {
    "forged_witness_signature": [(_TNI, NOT_IMPLEMENTED_GATES)],
    "witness_is_the_producer": [("Verified", frozenset({"witness-not-independent"}))],
    "no_freshness_anchor": [("Verified", frozenset({"no-freshness-anchor"}))],
    "stale_freshness_anchor": [(_TNI, NOT_IMPLEMENTED_GATES)],
    "revoked_producer_key": [("Verified", frozenset({"producer-key-revoked"}))],
    "no_revocation_state": [("Verified", frozenset({"no-revocation-state"}))],
    "structurally_perfect_witness": [(_TNI, NOT_IMPLEMENTED_GATES)],
    # No witness material at all once `{}` is read by type -> no Trusted claim is being made.
    "empty_witness_object": [("Verified", frozenset())],
    # A chain: an ordinary Verified record, then a withheld checkpoint.
    "chain_verified_then_withheld": [("Verified", frozenset()), (_TNI, NOT_IMPLEMENTED_GATES)],
}
# Ranks mirror _CLASS_RANK / CLASS_RANK; written literally so the test states the ladder itself.
_RANK = {"INVALID": 0, "Core": 1, "Verified": 2, _TNI: 2, "Trusted": 3}

CLASS_RE = re.compile(r"^CLASS:\s*(\S+)", re.M)
# EVERY per-record verdict line, not just record 0 — the chain aggregation path is where the
# empty-input `CLASS: Trusted` bug lived, and a record-0-only regex is blind to it:
#   [i] PASS  sig=ok  class=<C>  trusted_withheld=<a,b,c>  sha256:...
RECORD_RE = re.compile(r"^\s*\[(\d+)\]\s.*?class=(\S+)(?:\s+trusted_withheld=(\S+))?", re.M)


def _run_verdict(cmd, path):
    """Return (chain_class, [(class, withheld_set) per record]). The chain-level CLASS: line is
    cross-checked against the weakest record class, so a verifier cannot report one class per
    record and a stronger one overall."""
    r = subprocess.run(cmd + [str(path), "--pubkey", str(SPEC / "examples" / "test_public_key.txt"),
                              "--class"], capture_output=True, text=True)
    if r.returncode != 0:
        return f"EXIT{r.returncode}", []
    cm = CLASS_RE.search(r.stdout)
    rows = RECORD_RE.findall(r.stdout)
    if not cm or not rows:
        return "NO-CLASS-LINE", []
    per = [(cls, frozenset(w.split(",")) if w else frozenset()) for _i, cls, w in rows]
    weakest = min((c for c, _ in per), key=lambda c: _RANK.get(c, -1))
    if cm.group(1) != weakest:
        return f"SPLIT:{cm.group(1)}/weakest={weakest}", per
    return cm.group(1), per


def _as_records(payload) -> list:
    return payload if isinstance(payload, list) else [payload]


def _fixture_name(name: str, payload) -> str:
    """Single records go to .json; chains to .jsonl (one record per line), the two input spellings
    the verifiers accept."""
    return f"{name}.jsonl" if isinstance(payload, list) else f"{name}.json"


def _serialize(payload) -> str:
    if isinstance(payload, list):
        return "".join(json.dumps(r, sort_keys=True) + "\n" for r in payload)
    return json.dumps(payload, indent=2) + "\n"


# Key files are part of the corpus and are drift-guarded like the records: an unguarded key file
# could drift from the seeds and silently change what a third party verifies against.
def _key_files() -> dict:
    return {"producer_public_key.txt": _pub_hex + "\n",
            "witness_public_key.txt": _wpub_hex + "\n"}


def sync_fixtures(cases) -> None:
    """Rewrite the committed shared corpus from the fixed seeds."""
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for fname, body in _key_files().items():
        (FIXTURES / fname).write_text(body)
    for name, (payload, _why) in cases.items():
        (FIXTURES / _fixture_name(name, payload)).write_text(_serialize(payload))


def check_fixture_drift(cases) -> list:
    """The committed corpus MUST equal what the generator produces. Parity measured over a corpus
    that has drifted from its generator proves nothing about the cases the corpus claims to encode."""
    drift = []
    for name, (payload, _why) in cases.items():
        p = FIXTURES / _fixture_name(name, payload)
        if not p.exists():
            drift.append(f"{p.name}: MISSING from {FIXTURES.name}/")
        elif p.read_text() != _serialize(payload):
            drift.append(f"{p.name}: committed bytes differ from the generated record(s)")
    for fname, body in _key_files().items():
        p = FIXTURES / fname
        if not p.exists():
            drift.append(f"{fname}: MISSING from {FIXTURES.name}/")
        elif p.read_text() != body:
            drift.append(f"{fname}: committed key differs from the fixed seed")
    return drift


def main() -> int:
    ap = argparse.ArgumentParser(description="AIREP-Trusted gate battery")
    ap.add_argument("--emit", default="", help="also write the case records into this directory")
    ap.add_argument("--write-fixtures", action="store_true",
                    help="rewrite the committed shared corpus under fixtures/trusted_gates/")
    args = ap.parse_args()

    have_node = shutil.which("node") is not None
    cases = build_cases()

    if args.write_fixtures:
        sync_fixtures(cases)
        print(f"shared corpus rewritten: {FIXTURES}")
        return 0

    emit = Path(args.emit) if args.emit else None
    if emit:
        emit.mkdir(parents=True, exist_ok=True)
        (emit / "producer_public_key.txt").write_text(_pub_hex + "\n")
        (emit / "witness_public_key.txt").write_text(_wpub_hex + "\n")
        for name, (rec, _why) in cases.items():
            (emit / f"{name}.json").write_text(_serialize(rec))

    fails = 0
    print(f"AIREP-Trusted gate battery  (node {'present' if have_node else 'ABSENT'})")

    # Gate 0: the shared corpus both verifiers will read must match its generator.
    drift = check_fixture_drift(cases)
    for d in drift:
        print(f"  FAIL  shared-corpus drift — {d}")
    if drift:
        print("  (regenerate with: python3 test_trusted_gates.py --write-fixtures)")
        fails += len(drift)
    else:
        print(f"  PASS  shared corpus matches its generator ({len(cases)} cases in "
              f"{FIXTURES.parent.name}/{FIXTURES.name}/)")

    print(f"  {'case':<30} | py                      | mjs                     | ok")
    print(f"  {'-' * 30}-|-------------------------|-------------------------|----")
    for name, (payload, _why) in cases.items():
        path = FIXTURES / _fixture_name(name, payload)  # BOTH verifiers read the same committed bytes
        if not path.exists():
            continue                                    # already counted as drift above
        exp_per = EXPECTED[name]
        exp_chain = min((c for c, _ in exp_per), key=lambda c: _RANK[c])
        py, py_per = _run_verdict([sys.executable, str(HERE / "verify.py")], path)
        # (1) the top class must never be granted, on ANY record; (2) every record must still reach
        # Verified's floor, so a downgrade is a real ladder position and not an incidental failure;
        # (3) the per-record classes and (4) their named reason sets must be the ones expected.
        ok = (py == exp_chain
              and all(c != "Trusted" and c in ("Verified", _TNI) for c, _ in py_per)
              and py_per == exp_per)
        mjs, mjs_per = "—", None
        if have_node:
            mjs, mjs_per = _run_verdict(["node", str(HERE / "verify.mjs")], path)
            # Parity is class AND reason, per record: agreeing on the verdict while disagreeing on
            # why it was withheld leaves a consumer two different answers about what is missing.
            ok = ok and mjs == py and mjs_per == py_per
        if not ok:
            fails += 1
        print(f"  {name:<30} | {py:<23} | {mjs:<23} | {'PASS' if ok else 'FAIL'}")
        if not ok:
            print(f"  {'':<30} | expected chain={exp_chain} per-record={[(c, sorted(w)) for c, w in exp_per]}")
            print(f"  {'':<30} | py  per-record={[(c, sorted(w)) for c, w in py_per]}")
            if mjs_per is not None:
                print(f"  {'':<30} | mjs per-record={[(c, sorted(w)) for c, w in mjs_per]}")

    # The record whose every structural gate passes must be named TRUSTED_NOT_IMPLEMENTED, not
    # quietly reported as plain Verified — a withheld class has to say why it was withheld.
    perfect, perfect_per = _run_verdict([sys.executable, str(HERE / "verify.py")],
                                        FIXTURES / "structurally_perfect_witness.json")
    perfect_why = perfect_per[0][1] if perfect_per else frozenset()
    named = perfect == "TRUSTED_NOT_IMPLEMENTED" and perfect_why == NOT_IMPLEMENTED_GATES
    if not named:
        fails += 1
    print(f"  {'PASS' if named else 'FAIL'}  withheld class is NAMED "
          f"(structurally_perfect_witness -> TRUSTED_NOT_IMPLEMENTED + all 4 gates named, "
          f"got {perfect} {sorted(perfect_why)})")

    # THE EMPTY-INPUT HOLE: zero records means zero checks ran. Both verifiers once initialised the
    # chain class to "Trusted" and printed it unchanged for an empty file — the top class awarded to
    # the maximally unmeasured input, at exit 0. An unmeasured input MUST NOT inherit a class.
    empty_dir = Path(tempfile.mkdtemp(prefix="airep-empty-input-"))
    empties = {"empty.jsonl": "", "empty.json": "[]\n"}
    for fname, body in empties.items():
        p = empty_dir / fname
        p.write_text(body)
        for label, cmd in (("py", [sys.executable, str(HERE / "verify.py")]),
                           *((("mjs", ["node", str(HERE / "verify.mjs")]),) if have_node else ())):
            r = subprocess.run(cmd + [str(p), "--class"], capture_output=True, text=True)
            m = CLASS_RE.search(r.stdout)
            cls = m.group(1) if m else "NO-CLASS-LINE"
            # Must be rejected outright: INVALID class AND a non-zero exit.
            ok = cls == "INVALID" and r.returncode != 0
            if not ok:
                fails += 1
            print(f"  {'PASS' if ok else 'FAIL'}  empty input rejected ({fname}, {label}) -> "
                  f"class={cls} exit={r.returncode}, expected class=INVALID exit!=0")

    if not have_node:
        # Node absent means half the parity claim was NOT MEASURED. Never let that read as a pass.
        print("  NOT_RUN  Node half of the class/reason parity check (node binary absent)")

    if emit:
        print(f"  records written to {emit}")
    print(f"RESULT: {'no record reached Trusted on presence alone' if not fails else f'{fails} failure(s)'}")
    return 0 if not fails else 1


if __name__ == "__main__":
    raise SystemExit(main())
