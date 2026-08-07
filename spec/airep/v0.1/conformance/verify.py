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
  python3 verify.py <record.json | chain.jsonl> [--pubkey <hex | path-to-key-file>] [--class]

`--class` reports the highest AIREP conformance class satisfied: Core, Verified, or
TRUSTED_NOT_IMPLEMENTED. **Trusted is never reported by this verifier** — its prerequisites
(witness-signature verification, witness-key distinctness, freshness recency, revocation) are not
implemented here, and an unenforced prerequisite can never be reported as satisfied. See
`CONFORMANCE_CLASSES.md` §TRUSTED_NOT_IMPLEMENTED.

Exit code reflects RECORD VALIDITY ONLY, never the class: 0 if every record passes, 1 otherwise. A
TRUSTED_NOT_IMPLEMENTED record exits 0 because it is a valid record — exit 0 is NOT a statement
that any particular class was reached. Requires `jsonschema` (+ `cryptography` for the optional
signature check). Canonicalization is RFC 8785 (the JSON Canonicalization Scheme) via
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


def _evidence_anchored(rec) -> bool:
    for e in rec.get("evidence", []) or []:
        if isinstance(e, dict) and e.get("resolvable") is False and not e.get("content_hash"):
            return False
    return True


def _key_trust_bound(rec) -> bool:
    kt = (rec.get("profiles") or {}).get("key_trust")
    return isinstance(kt, dict) and all(k in kt for k in ("key_id", "algorithm", "public_key"))


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
    return bool(cw.get("chain_id") and head.get("current") and cw.get("witness"))


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
    wid = (cw.get("witness") or {}).get("witness_id")
    if wid is not None and wid == kt.get("key_id"):
        bad.append("witness-not-independent")
    # req 2: a freshness anchor must be PRESENT (timestamp, nonce, or challenge response).
    fr = cw.get("freshness") or {}
    if not any(fr.get(k) for k in ("witness_timestamp_utc", "nonce", "challenge_response")):
        bad.append("no-freshness-anchor")
    # req 3: key_trust must CARRY revocation state, and a revoked key is untrusted.
    rev = kt.get("revocation")
    if not isinstance(rev, dict) or "revoked" not in rev:
        bad.append("no-revocation-state")
    elif rev.get("revoked") is True:
        bad.append("producer-key-revoked")
    return bad


def _classify(rec, sig_ok):
    """Highest class of a record that already satisfies Core (see CONFORMANCE_CLASSES.md).

    Returns (class, withheld_reasons). AIREP-Trusted is FAIL-CLOSED: it is granted only when every
    normative prerequisite is actually enforced and passes. Because this verifier enforces none of
    the Trusted-tier cryptographic checks, the top class is withheld and the reason is named."""
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
    if _TRUSTED_GATES_NOT_IMPLEMENTED:
        # Witness material is present and structurally coherent, but the checks that would make it
        # mean anything do not run here. Never grant on presence.
        return "TRUSTED_NOT_IMPLEMENTED", list(_TRUSTED_GATES_NOT_IMPLEMENTED)
    return "Trusted", []  # unreachable until every gate above is actually implemented


def verify(path: str, pubkey: str = "", show_class: bool = False) -> int:
    pub = _load_pubkey(pubkey)
    records = _load_records(path)
    is_chain = len(records) > 1
    fails = 0
    prev = GENESIS
    chain_class = "Trusted"  # a chain is only as strong as its weakest record
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
        cls, withheld = None, []
        if show_class:
            cls, withheld = ("INVALID", []) if bad else _classify(rec, sig)
        if cls is not None and _CLASS_RANK[cls] < _CLASS_RANK[chain_class]:
            chain_class = cls
        clspart = f"  class={cls}" if show_class else ""
        # Never downgrade silently: say which Trusted prerequisite was unmet or unevaluated.
        if withheld:
            clspart += "  trusted_withheld=" + ",".join(withheld)
        print(f"  [{i}] {status}  {sigstr}{clspart}  {str(integ.get('current', '?'))[:23]}...")
        if bad:
            fails += 1
    print(f"RESULT: {'all records OK' if not fails else f'{fails} record(s) FAILED'}")
    if show_class:
        print(f"CLASS: {'INVALID' if fails else chain_class}"
              f"{'  (pass --pubkey to assess Verified)' if not pub and not fails else ''}")
    return 0 if not fails else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify an AIREP record or chain",
        epilog="Exit code reflects record validity only, never the class: 0 if every record passes "
               "the Core checks, 1 otherwise. Exit 0 must NOT be read as 'Trusted' — the class is "
               "reported on stdout and is a separate channel. See CONFORMANCE_CLASSES.md.")
    ap.add_argument("path", help="a record .json or a chain .jsonl / JSON array")
    ap.add_argument("--pubkey", default="", help="Ed25519 public key (hex) or a path to a key file")
    ap.add_argument("--class", dest="show_class", action="store_true",
                    help="report the highest AIREP conformance class satisfied: Core | Verified | "
                         "TRUSTED_NOT_IMPLEMENTED. Trusted is NEVER reported: its prerequisites "
                         "(witness signature, witness-key distinctness, freshness recency, "
                         "revocation) are unimplemented, and an unenforced prerequisite is never "
                         "reported as satisfied. Withheld classes name the unmet/unevaluated "
                         "prerequisites as trusted_withheld=...")
    args = ap.parse_args(argv)
    return verify(args.path, args.pubkey, show_class=args.show_class)


if __name__ == "__main__":
    raise SystemExit(main())
