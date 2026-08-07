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

The Node verifier (`verify.mjs`) re-derives the same hashes and reaches the same verdict on an
independent stack — with one documented exception: it runs **no profile-schema validation**, so the
two can differ on records whose `profiles` block violates its schema.

Usage:
  python3 verify.py <record.json | chain.jsonl> [--pubkey <hex | path-to-key-file>] [--class]

`--class` reports the highest AIREP conformance class satisfied: Core, Verified, or (by default)
TRUSTED_NOT_IMPLEMENTED. **By default Trusted is never reported** — its four prerequisites
(witness-signature verification, witness-key distinctness, freshness recency, revocation) are
unevaluated, and an unenforced prerequisite can never be reported as satisfied. **`Trusted` is
reachable only in the opt-in STRICT mode (WP-10):** pass `--trust-store` + `--freshness-window` +
`--revocation-source` and the four gates run for real; a record earns Trusted iff every one passes,
else the ceiling is Verified with the specific reason named. Any input missing → the gates cannot run
→ TRUSTED_NOT_IMPLEMENTED (never a silent Trusted). See `CONFORMANCE_CLASSES.md` §AIREP-Trusted
(strict mode). v1: one independent trusted witness, local JSON inputs, timestamp freshness window.

A witness-less `Verified` record whose own `profiles.key_trust.revocation.revoked` is `true` is
still `Verified` (revocation is a Trusted gate, not a Verified requirement) but carries
`verified_withheld=producer-key-revoked` on its line — a self-declared revoked signing key is never
rendered as a clean Verified. `verified_withheld=` names caveats on a Verified record;
`trusted_withheld=` names why Trusted was withheld.

Exit code reflects RECORD VALIDITY ONLY, never the class: 0 when every record passed every check
this verifier ran, 1 when a record failed or the input could not be read, 2 on usage error
(`--help` exits 0 without verifying). A TRUSTED_NOT_IMPLEMENTED record exits 0 because it is a
valid record — exit 0 is NOT a statement that any particular class was reached. Note `verify.mjs`
runs no profile-schema validation, so the two verifiers' exit codes are NOT equivalent for records
with an invalid `profiles` block. Requires `jsonschema` (+ `cryptography` for the optional
signature check). Canonicalization is RFC 8785 (the JSON Canonicalization Scheme) via
`conformance/jcs.py`.
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
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


# --- conformance classes (CONFORMANCE_CLASSES.md) ---------------------------------------------
_REAL_ALGS = {"ed25519", "ecdsa", "rsa", "rsa-pss", "hmac-sha256"}
# TRUSTED_NOT_IMPLEMENTED sits at Verified's rank on purpose: it is NOT a class above Verified.
# It is Verified plus a NAMED statement that the Trusted prerequisites were never evaluated.
_CLASS_RANK = {"INVALID": 0, "Core": 1, "Verified": 2, "TRUSTED_NOT_IMPLEMENTED": 2, "Trusted": 3}

# The AIREP-Trusted prerequisites (CONFORMANCE_CLASSES.md §AIREP-Trusted) that this verifier does
# NOT evaluate. A prerequisite that is not enforced can never be reported as satisfied, so while
# this tuple is non-empty the top class is UNREACHABLE — presence of witness material downgrades
# to TRUSTED_NOT_IMPLEMENTED rather than granting Trusted. Implementing a check here means
# removing its entry AND adding the real check; removing an entry alone re-opens the hole.
_TRUSTED_GATES_NOT_IMPLEMENTED = (
    "witness-signature-not-verified",   # req 1: chain_witness.witness.value is never re-verified
    "witness-key-distinctness-unproven",  # req 1: a witness_id string is not a key
    "freshness-recency-not-evaluated",  # req 2: presence is checked, recency/nonce-challenge is not
    "revocation-not-honored",           # req 3: no revocation source is consulted
)


# Cross-runtime-stable predicates. Python and JavaScript disagree on the truthiness of `{}` and `[]`
# (falsy in Python, truthy in JS), so every presence test on the Trusted path is expressed as an
# explicit type + non-emptiness check that both languages evaluate identically.
def _nonempty_str(v) -> bool:
    return isinstance(v, str) and v != ""


def _nonempty_obj(v) -> bool:
    return isinstance(v, dict) and len(v) > 0


def _evidence_anchored(rec) -> bool:
    for e in rec.get("evidence", []) or []:
        if isinstance(e, dict) and e.get("resolvable") is False and not e.get("content_hash"):
            return False
    return True


def _key_trust_bound(rec) -> bool:
    kt = (rec.get("profiles") or {}).get("key_trust")
    return isinstance(kt, dict) and all(k in kt for k in ("key_id", "algorithm", "public_key"))


def _producer_key_revoked(rec) -> bool:
    """The record's own profiles.key_trust declares its signing key revoked. Self-declared and
    definitively checkable — it needs NO external revocation source (that source is the undefined
    Trusted-tier policy, WP-10). A revoked signing key undermines the authorship a Verified record
    asserts, so this caveat MUST be named, never rendered as a silent Verified. It does NOT change
    the class: CONFORMANCE_CLASSES.md §Verified does not gate on revocation (that is a Trusted
    gate), so the record stays Verified and carries `verified_withheld=producer-key-revoked`."""
    rev = ((rec.get("profiles") or {}).get("key_trust") or {}).get("revocation")
    return isinstance(rev, dict) and rev.get("revoked") is True


def _witness_present(rec) -> bool:
    """Witness material is PRESENT. Presence is not verification: this says a chain_witness block
    exists and is populated, NOT that the witness signature is valid, that the witness key is
    independent of the producer, or that the anchor is fresh. It is a necessary condition for
    Trusted, never a sufficient one."""
    prof = rec.get("profiles") or {}
    cw = prof.get("chain_witness") or prof.get("freshness_witness")
    if not isinstance(cw, dict):
        return False  # no head witness on this record → at most Verified (see chain_witness.schema.json)
    head = cw.get("head") or {}
    if not isinstance(head, dict):
        return False
    # Type-EXPLICIT, never truthiness: `witness: {}` is falsy in Python but truthy in JavaScript, so
    # a truthiness test made the two verifiers report different classes for identical bytes. Presence
    # predicates on the Trusted path must be decided by type + non-emptiness, which both languages
    # agree on. Kept in lockstep with verify.mjs::witnessPresent.
    return bool(_nonempty_str(cw.get("chain_id"))
                and _nonempty_str(head.get("current"))
                and _nonempty_obj(cw.get("witness")))


def _trusted_structural_failures(rec) -> list:
    """Trusted prerequisites that ARE structurally checkable and DEFINITIVELY fail on this record.

    These are cheap structural reads, not cryptography. Passing them earns nothing — the gates in
    _TRUSTED_GATES_NOT_IMPLEMENTED still never ran. Failing one is decisive: the record cannot be
    Trusted no matter what the unimplemented gates would have said."""
    prof = rec.get("profiles") or {}
    cw = prof.get("chain_witness") or prof.get("freshness_witness") or {}
    kt = prof.get("key_trust") or {}
    bad = []
    # req 1 (necessary, not sufficient): a "witness" naming the producer's own key is theater —
    # chain_witness.schema.json: witness_id "MUST be distinct from the producer". Distinct ids do
    # NOT prove distinct keys, so passing this leaves witness-key-distinctness-unproven standing.
    wit = cw.get("witness")
    wid = wit.get("witness_id") if isinstance(wit, dict) else None
    # Compared as strings only: an id is a string, and `{} == {}` is True in Python but
    # `{} === {}` is False in JS, so a loose comparison would diverge across the two verifiers.
    if _nonempty_str(wid) and wid == kt.get("key_id"):
        bad.append("witness-not-independent")
    # req 2: a freshness anchor must be PRESENT (timestamp, nonce, or challenge response), and be a
    # non-empty string — truthiness alone diverges across runtimes on {} / [].
    fr = cw.get("freshness")
    fr = fr if isinstance(fr, dict) else {}
    if not any(_nonempty_str(fr.get(k))
               for k in ("witness_timestamp_utc", "nonce", "challenge_response")):
        bad.append("no-freshness-anchor")
    # req 3: key_trust must CARRY revocation state, and a revoked key is untrusted.
    rev = kt.get("revocation")
    if not isinstance(rev, dict) or "revoked" not in rev:
        bad.append("no-revocation-state")
    elif rev.get("revoked") is True:
        bad.append("producer-key-revoked")
    return bad


# ---- WP-10 strict-Trusted: the four Trusted gates, run ONLY with operator-supplied inputs -------
# Default mode leaves these four gates unevaluated (TRUSTED_NOT_IMPLEMENTED). In strict mode the
# operator supplies --trust-store + --freshness-window + --revocation-source and the gates run for
# real; a record earns Trusted iff every one passes, else the ceiling is Verified with the specific
# failure named. Kept byte-for-byte in lockstep with verify.mjs. v1 scope: exactly ONE independent
# trusted witness (no N-of-M quorum), local JSON inputs (no transparency-log / no online CRL), a
# timestamp freshness window (no nonce/challenge). See docs WP10_STRICT_TRUSTED_DESIGN.
def _parse_iso(s):
    if not isinstance(s, str) or not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _producer_pubkey_hex(kt):
    """Resolve the producer's signing public key to lowercase hex. key_trust.public_key is either a
    {format, value} object (the profile shape) or a bare hex string."""
    pk = kt.get("public_key")
    if isinstance(pk, dict) and _nonempty_str(pk.get("value")):
        return pk["value"].strip().lower()
    if _nonempty_str(pk):
        return pk.strip().lower()
    return None


def _verify_witness_sig(cw, wit, wpub_hex):
    """Re-verify chain_witness.witness.value over the canonical head claim, under the witness key
    RESOLVED FROM THE TRUST STORE (not the witness_id string). Claim shape is byte-identical to the
    one validate.py and the fixtures sign: {chain_id, decision_index, current, length}."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return None  # NOT_MEASURED — caller treats None as "cannot evaluate"
    head = cw.get("head") or {}
    claim = {"chain_id": cw.get("chain_id"), "decision_index": head.get("decision_index"),
             "current": head.get("current"), "length": head.get("length")}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(wpub_hex)).verify(
            bytes.fromhex(wit.get("value", "")), _canonical(claim))
        return True
    except Exception:
        return False


def _key_revoked(revocation, key_id, relevant_time):
    """A key is revoked if the external revocation source lists it AND the record was signed at/after
    revoked_at (CONFORMANCE_CLASSES.md §Trusted req 3: 'a record signed after revoked_at by a revoked
    key is untrusted'). Missing revoked_at, or an unknown signing time, is treated conservatively as
    revoked — never as a silent pass."""
    if not isinstance(revocation, dict) or not _nonempty_str(key_id):
        return False
    entry = revocation.get(key_id)
    if not isinstance(entry, dict):
        return False
    ra = _parse_iso(entry.get("revoked_at"))
    if ra is None or relevant_time is None:
        return True
    return relevant_time >= ra


def _strict_trusted_failures(rec, strict):
    """The four Trusted gates run for real against operator inputs. Returns the named failures; an
    empty list means every gate passed and the record may be Trusted."""
    prof = rec.get("profiles") or {}
    cw = prof.get("chain_witness") or prof.get("freshness_witness") or {}
    kt = prof.get("key_trust") or {}
    wit = cw.get("witness") if isinstance(cw.get("witness"), dict) else {}
    bad = []
    trust_store, revocation, window, now = (
        strict["trust_store"], strict["revocation"], strict["freshness_window"], strict["now"])

    # gate 1+ (key resolution / trust / independence): resolve the witness key from the store by
    # witness_id and decide independence on the RESOLVED PUBLIC KEYS, never on id strings.
    wid = wit.get("witness_id")
    entry = trust_store.get(wid) if _nonempty_str(wid) else None
    wpub = None
    if not isinstance(entry, dict) or not _nonempty_str(entry.get("public_key_hex")):
        bad.append("witness-unknown")
    else:
        wpub = entry["public_key_hex"].strip().lower()
        if entry.get("trusted") is not True:
            bad.append("witness-untrusted")
        ppub = _producer_pubkey_hex(kt)
        if ppub is not None and wpub == ppub:
            bad.append("witness-not-independent")

    # gate: witness signature verifies under the resolved key
    if wpub is not None:
        ok = _verify_witness_sig(cw, wit, wpub)
        if ok is None:
            bad.append("witness-signature-not-evaluated")  # cryptography missing → NOT measured
        elif ok is False:
            bad.append("witness-signature-invalid")

    # gate: freshness recency within the operator's window (deterministic against --now)
    fr = cw.get("freshness") if isinstance(cw.get("freshness"), dict) else {}
    wts = _parse_iso(fr.get("witness_timestamp_utc"))
    if wts is None:
        bad.append("no-freshness-anchor")
    elif wts > now:
        bad.append("freshness-in-future")
    elif (now - wts).total_seconds() > window:
        bad.append("freshness-stale")

    # gate: revocation, consulted for BOTH the producer key and the witness key
    rec_ts = _parse_iso((rec.get("subject") or {}).get("timestamp_utc"))
    if _key_revoked(revocation, kt.get("key_id"), rec_ts):
        bad.append("producer-key-revoked")
    if _key_revoked(revocation, wid, wts):
        bad.append("witness-key-revoked")
    return bad


def _classify(rec, sig_ok, strict=None):
    """Highest class of a record that already satisfies Core (see CONFORMANCE_CLASSES.md).

    Returns (class, withheld_reasons). AIREP-Trusted is FAIL-CLOSED: it is granted only when every
    normative prerequisite is actually enforced and passes. Without operator trust inputs (default
    mode) the Trusted-tier gates cannot run, so the top class is withheld and named. With them
    (strict mode: `strict` is a context dict) the four gates run for real."""
    alg = ((rec.get("integrity") or {}).get("signature") or {}).get("alg", "").lower()
    verified = (
        sig_ok is True                # signature actually re-verified against a supplied key
        and alg in _REAL_ALGS         # a real signer, not 'unsigned'/placeholder
        and _evidence_anchored(rec)   # withheld evidence is hash-anchored
        and _key_trust_bound(rec)     # the signing key is bound via profiles.key_trust
    )
    if not verified:
        return "Core", []
    if not _witness_present(rec):
        return "Verified", []  # no Trusted claim is being made at all
    structural = _trusted_structural_failures(rec)
    if structural:
        # A Trusted prerequisite demonstrably fails → the ladder stops at Verified.
        return "Verified", structural
    if strict is None:
        # Witness material is present and structurally coherent, but with no operator trust inputs
        # the four gates cannot run. Never grant on presence.
        return "TRUSTED_NOT_IMPLEMENTED", list(_TRUSTED_GATES_NOT_IMPLEMENTED)
    # STRICT MODE: the four gates run for real against the operator's trust inputs.
    gate_failures = _strict_trusted_failures(rec, strict)
    if gate_failures:
        return "Verified", gate_failures
    return "Trusted", []  # every gate ran and passed


def _build_strict(trust_store_path, freshness_window, revocation_path, now_iso):
    """Assemble the strict-Trusted context, or None when strict mode is not (fully) requested.
    Strict mode engages ONLY when all three operator inputs are present; a partial set falls back to
    default (TRUSTED_NOT_IMPLEMENTED) with a printed note, never to a silent Trusted."""
    supplied = [bool(trust_store_path), freshness_window is not None, bool(revocation_path)]
    if not any(supplied):
        return None, None
    if not all(supplied):
        return None, ("strict-Trusted needs all three of --trust-store, --freshness-window, "
                      "--revocation-source; falling back to default (Trusted withheld)")
    now = _parse_iso(now_iso) if now_iso else datetime.now(timezone.utc)
    if now is None:
        return None, f"--now is not a valid ISO-8601 timestamp: {now_iso!r} (Trusted withheld)"
    return {
        "trust_store": json.loads(Path(trust_store_path).read_text()),
        "revocation": json.loads(Path(revocation_path).read_text()),
        "freshness_window": float(freshness_window),
        "now": now,
    }, None


def verify(path: str, pubkey: str = "", show_class: bool = False,
           trust_store: str = "", freshness_window=None, revocation_source: str = "",
           now_iso: str = "") -> int:
    pub = _load_pubkey(pubkey)
    strict, strict_note = _build_strict(trust_store, freshness_window, revocation_source, now_iso)
    records = _load_records(path)
    # An empty input is not a vacuously perfect chain. Zero records means zero checks ran, and the
    # unmeasured case must never inherit a class — reporting the top class here would be the purest
    # form of the fail-open bug this classifier exists to prevent.
    if not records:
        print(f"AIREP verify: {path}  (0 record(s))")
        print("  FAIL(no-records)  an AIREP input MUST contain at least one record")
        print("RESULT: 1 input FAILED")
        if show_class:
            print("CLASS: INVALID")
        return 1
    is_chain = len(records) > 1
    fails = 0
    prev = GENESIS
    # Starts UNSET, not at the top class: the ceiling is earned by the records, never inherited from
    # an initial value. A chain is only as strong as its weakest record.
    chain_class = None
    print(f"AIREP verify: {path}  ({len(records)} record(s){' — chain' if is_chain else ''})")
    if strict_note:
        print(f"  NOTE  {strict_note}")
    if strict is not None:
        print(f"  strict-Trusted mode: now={strict['now'].isoformat()} "
              f"freshness_window={int(strict['freshness_window'])}s")
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
        cls, withheld = None, []
        if show_class:
            cls, withheld = ("INVALID", []) if bad else _classify(rec, sig, strict)
        if cls is not None and (chain_class is None or _CLASS_RANK[cls] < _CLASS_RANK[chain_class]):
            chain_class = cls
        clspart = f"  class={cls}" if show_class else ""
        # Never downgrade silently: say which Trusted prerequisite was unmet or unevaluated.
        if withheld:
            clspart += "  trusted_withheld=" + ",".join(withheld)
        # WP-09: a witness-less Verified record whose own key_trust declares the key revoked must
        # not read as a clean Verified. Name the self-declared caveat; the class stays Verified per
        # contract. (Witness-present revoked records already name producer-key-revoked above, on the
        # Trusted path via _trusted_structural_failures.)
        if show_class and cls == "Verified" and not _witness_present(rec) and _producer_key_revoked(rec):
            clspart += "  verified_withheld=producer-key-revoked"
        print(f"  [{i}] {status}  {sigstr}{clspart}  {str(integ.get('current', '?'))[:23]}...")
        if bad:
            fails += 1
    print(f"RESULT: {'all records OK' if not fails else f'{fails} record(s) FAILED'}")
    if show_class:
        print(f"CLASS: {'INVALID' if fails else (chain_class or 'INVALID')}"
              f"{'  (pass --pubkey to assess Verified)' if not pub and not fails else ''}")
    return 0 if not fails else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify an AIREP record or chain",
        epilog="Exit code reflects record validity only, never the class: 0 when every record "
               "passed every check this verifier ran, 1 when a record failed or the input could not "
               "be read, 2 on usage error. Exit 0 must NOT be read as 'Trusted' — the class is "
               "reported on stdout and is a separate channel. See CONFORMANCE_CLASSES.md.")
    ap.add_argument("path", help="a record .json or a chain .jsonl / JSON array")
    ap.add_argument("--pubkey", default="", help="Ed25519 public key (hex) or a path to a key file")
    ap.add_argument("--class", dest="show_class", action="store_true",
                    help="report the highest AIREP conformance class satisfied: Core | Verified | "
                         "TRUSTED_NOT_IMPLEMENTED (default), or Trusted in strict mode. By default "
                         "Trusted is withheld: its four prerequisites are unevaluated, and an "
                         "unenforced prerequisite is never reported as satisfied. Pass "
                         "--trust-store + --freshness-window + --revocation-source to run the gates "
                         "and reach Trusted. Withheld classes name the unmet/unevaluated "
                         "prerequisites as trusted_withheld=...")
    # WP-10 strict-Trusted (opt-in). Trusted is attempted ONLY when all three are supplied AND a
    # witness is present; otherwise the default withheld behaviour stands. v1: one independent
    # trusted witness, local JSON inputs, timestamp freshness window.
    ap.add_argument("--trust-store", default="",
                    help="JSON {witness_id: {public_key_hex, trusted}} — resolves + trusts witness keys")
    ap.add_argument("--freshness-window", type=int, default=None,
                    help="max seconds between the witness timestamp and --now for a fresh witness")
    ap.add_argument("--revocation-source", default="",
                    help="JSON {key_id: {revoked_at, reason}} — consulted for producer AND witness keys")
    ap.add_argument("--now", default="",
                    help="ISO-8601 evaluation time for the freshness gate (deterministic; default: system clock)")
    args = ap.parse_args(argv)
    return verify(args.path, args.pubkey, show_class=args.show_class,
                  trust_store=args.trust_store, freshness_window=args.freshness_window,
                  revocation_source=args.revocation_source, now_iso=args.now)


if __name__ == "__main__":
    raise SystemExit(main())
