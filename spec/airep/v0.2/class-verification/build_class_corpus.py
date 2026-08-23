#!/usr/bin/env python3
"""AIREP v0.2 class-verification deterministic corpus builder (third-context harness).

Builds the 45-case adversarial corpus pinned in CLASS_VERIFIER_CONTRACT.md s7, from the
frozen construction in ../INTEGRITY.md and the accepted schemas in ../schemas/.

WHAT THIS IS: harness code. It constructs each case's artifacts and operator inputs, applies
exactly the one tamper the appendix row names (everything else clean and supplied), and
transcribes the appendix row VERBATIM into cases/<CASE_ID>/expected.json.

WHAT THIS IS NOT: a class verifier. It contains no ladder evaluation, no reason derivation,
no channel computation. Expected values are COPIED from the contract table (EXPECTED_APPENDIX
below), never computed. The two class verifiers are authored later, in separate isolated
contexts, and are forbidden from reading this file or any expected.json.

Self-validation performed here is construction-fidelity only (does the sealed `current` match
the frozen hash preimage; does the signature verify / fail to verify under the key the case
intends; does head_ref resolve to the number of artifacts the case intends; is every artifact
schema-valid; is the transcription sorted/deduplicated/registry-legal and consistent with the
s2 envelope invariants).

If any case cannot be produced from the frozen text as written, the builder STOPS with
MAINTAINER_FINDING and exits 3 rather than adjusting anything.

Deterministic: fixed inputs, published TEST-ONLY seeds, RFC 8032 Ed25519 (deterministic
signatures), sorted-key JSON with trailing newline. Two runs produce byte-identical files.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
SCHEMAS = HERE.parent / "schemas"
V01_CONF = HERE.parent.parent / "v0.1" / "conformance"

# RFC 8785 via the pre-existing v0.1 implementation (reused, not reimplemented).
_spec = importlib.util.spec_from_file_location("jcs", V01_CONF / "jcs.py")
_jcs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_jcs)


def jcs(obj) -> bytes:
    return _jcs.canonicalize(obj)


def stop(msg: str) -> None:
    print(f"MAINTAINER_FINDING: {msg}", file=sys.stderr)
    sys.exit(3)


# --------------------------------------------------------------------------------------
# TEST-ONLY key material (published seeds; never production)
# --------------------------------------------------------------------------------------
LF = b"\x0a"
SUITE = b"ed25519"

PRODUCER_SEED = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
WITNESS_SEED = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
# Third key (executor) derived deterministically so it is reproducible from this line alone:
EXECUTOR_SEED_INPUT = "AIREP/0.2/class-verification/TEST-ONLY/executor"
EXECUTOR_SEED = hashlib.sha256(EXECUTOR_SEED_INPUT.encode("ascii")).hexdigest()

_psk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRODUCER_SEED))
_wsk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(WITNESS_SEED))
_xsk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(EXECUTOR_SEED))


def pub_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


P_PUB, W_PUB, X_PUB = pub_hex(_psk), pub_hex(_wsk), pub_hex(_xsk)

GENESIS = "sha256:" + "0" * 64
NOW = "2026-08-23T12:00:00Z"
WINDOW = 3600
FRESH_AT = "2026-08-23T11:30:00Z"          # 1800s before NOW  -> inside window
STALE_PAST = "2026-08-23T10:00:00Z"        # 7200s before NOW  -> outside window
STALE_FUTURE = "2026-08-23T14:00:00Z"      # 7200s after NOW   -> outside window
BOUNDARY_AT = "2026-08-23T11:00:00Z"       # exactly 3600s before NOW -> boundary-equal

# Wire-carried (opaque, never grammar-constrained) identifiers
PRODUCER_WIRE = "acme-runtime/1.4"
EXECUTOR_WIRE = "orbit-executor/2.0"
WITNESS_WIRE = "NOTARY-WITNESS #1"

# Verifier-side (namespaced grammar) identifiers
B_PRODUCER = "airep.producer-a"
B_WITNESS = "airep.witness-a"
B_EXECUTOR = "airep.executor-a"
B_WITNESS_SAMEKEY = "airep.witness-same-key"
B_WITNESS_SAMEID = "airep.witness-same-id"
ID_PRODUCER = "acme.runtime-a"
ID_WITNESS = "notary.witness-a"
ID_EXECUTOR = "orbit.executor-a"
SNAPSHOT_ID = "airep.snapshot-1"


# --------------------------------------------------------------------------------------
# Frozen construction (INTEGRITY.md s1-s4) — consumed exactly, never redesigned
# --------------------------------------------------------------------------------------
def tag(version: str, op: str, ctx: str) -> bytes:
    return f"AIREP/{version}/{op}/{ctx}".encode("ascii")


def hash_preimage(body: dict, ht: bytes) -> bytes:
    return ht + LF + jcs(body)


def current_for(body: dict, ht: bytes) -> str:
    return "sha256:" + hashlib.sha256(hash_preimage(body, ht)).hexdigest()


def sig_preimage(st: bytes, current: str, suite: bytes = SUITE) -> bytes:
    return st + LF + suite + LF + current.encode("ascii")


def witness_preimage(version: str, claim: dict, suite: bytes = SUITE) -> bytes:
    return tag(version, "sig", "head-witness") + LF + suite + LF + jcs(claim)


def seal(body: dict, sk: Ed25519PrivateKey = _psk, alg_label: str = "Ed25519") -> dict:
    """Seal a body per INTEGRITY s2/s3: current over the hash preimage, signature over the
    record-signature preimage. `sk` selects WHICH key signs (a wrong key yields a genuinely
    invalid signature over the correct preimage)."""
    ctx, ver = body["artifact_type"], body["airep_version"]
    cur = current_for(body, tag(ver, "hash", ctx))
    sig = sk.sign(sig_preimage(tag(ver, "sig", ctx), cur)).hex()
    art = json.loads(json.dumps(body))
    art["integrity"]["current"] = cur
    art["integrity"]["signature"] = {"alg": alg_label, "value": sig}
    return art


def sign_witness(version: str, claim: dict, sk: Ed25519PrivateKey = _wsk) -> str:
    return sk.sign(witness_preimage(version, claim)).hex()


def verify_record_sig(art: dict, pub: str) -> bool:
    ctx, ver = art["artifact_type"], art["airep_version"]
    pre = sig_preimage(tag(ver, "sig", ctx), art["integrity"]["current"])
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(art["integrity"]["signature"]["value"]), pre)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_witness_sig(version: str, claim: dict, sig_hex: str, pub: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(sig_hex), witness_preimage(version, claim))
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------------------
# Artifact bodies (accepted schemas in ../schemas/)
# --------------------------------------------------------------------------------------
def core_members(ctx: str, chain_id: str, record_id: str, sequence: int,
                 producer: str, previous: str) -> dict:
    return {
        "airep_version": "0.2",
        "artifact_type": ctx,
        "chain_id": chain_id,
        "record_id": record_id,
        "sequence": sequence,
        "subject": {"producer": producer, "timestamp_utc": "2026-08-23T09:00:00Z"},
        "scope": {"covers": ["this record's own contents"],
                  "does_not_cover": ["truth of the recorded content"]},
        "integrity": {"previous": previous},
    }


def decision_body(chain_id: str, record_id: str, sequence: int = 0,
                  producer: str = PRODUCER_WIRE, previous: str = GENESIS,
                  profiles: dict | None = None) -> dict:
    b = core_members("decision", chain_id, record_id, sequence, producer, previous)
    b["input"] = {"input_ref": "ref:input-1",
                  "input_digest": "sha256:" + "ab" * 32}
    b["claim"] = {"assertion": "released after gates passed", "basis": ["gate-1"]}
    b["directive"] = {"verb": "release", "policy_basis": ["policy-1"]}
    b["output"] = {"result_ref": "ref:result-1",
                   "result_digest": "sha256:" + "cd" * 32}
    b["evidence"] = [{"type": "policy", "ref": "ref:policy-1", "resolvable": False,
                      "content_hash": "sha256:" + "ef" * 32}]
    if profiles is not None:
        b["profiles"] = profiles
    return b


def execution_body(chain_id: str, record_id: str, sequence: int = 0,
                   producer: str = EXECUTOR_WIRE, previous: str = GENESIS,
                   decision_record_id: str = "cv-rec-decision-1") -> dict:
    b = core_members("execution", chain_id, record_id, sequence, producer, previous)
    b["decision_ref"] = {"chain_id": chain_id, "record_id": decision_record_id}
    b["instruction_id"] = "instr-1"
    b["instruction_digest"] = "sha256:" + "ab" * 32
    b["executed_action_digest"] = "sha256:" + "ab" * 32
    b["execution_event"] = "executed"
    return b


def effect_body(chain_id: str, record_id: str, execution_ref: dict,
                observer_relationship: str, sequence: int = 0,
                producer: str = PRODUCER_WIRE, previous: str = GENESIS,
                decision_record_id: str = "cv-rec-decision-1") -> dict:
    b = core_members("effect", chain_id, record_id, sequence, producer, previous)
    b["decision_ref"] = {"chain_id": chain_id, "record_id": decision_record_id}
    b["execution_ref"] = execution_ref
    b["observer_relationship"] = observer_relationship
    b["observed_state"] = {"description": "valve closed",
                           "state_digest": "sha256:" + "cd" * 32}
    return b


# --------------------------------------------------------------------------------------
# Operator inputs (CLASS_VERIFIER_CONTRACT s1.1 / s1.2 / s1.3 / s1.4)
# --------------------------------------------------------------------------------------
def binding(subject_identity: str, role: str, key: str, suite: str = "ed25519",
            trusted=True) -> dict:
    e = {"subject_identity": subject_identity, "role": role,
         "public_key_hex": key, "suite": suite}
    if trusted is not _OMIT:
        e["trusted"] = trusted
    return e


class _Omit:
    pass


_OMIT = _Omit()


def bindings_doc(witness: bool = True, executor: bool = False) -> dict:
    d = {
        "bindings": {B_PRODUCER: binding(ID_PRODUCER, "producer", P_PUB)},
        "producer_bindings": {PRODUCER_WIRE: B_PRODUCER},
        "witness_bindings": {},
    }
    if witness:
        d["bindings"][B_WITNESS] = binding(ID_WITNESS, "witness", W_PUB)
        d["witness_bindings"][WITNESS_WIRE] = B_WITNESS
    if executor:
        d["bindings"][B_EXECUTOR] = binding(ID_EXECUTOR, "producer", X_PUB)
        d["producer_bindings"][EXECUTOR_WIRE] = B_EXECUTOR
    return d


def revocation_doc(binding_ids, states=None) -> dict:
    states = states or {}
    return {"snapshot_id": SNAPSHOT_ID,
            "bindings": {b: {"state": states.get(b, "active")} for b in binding_ids}}


def independence_doc(independent=(), non_independent=()) -> dict:
    return {"independent_pairs": [{"a": a, "b": b} for a, b in independent],
            "non_independent_pairs": [{"a": a, "b": b} for a, b in non_independent]}


def clock_doc(now: str = NOW, window: int = WINDOW) -> dict:
    return {"now": now, "freshness_window_seconds": window}


def head_ref(art: dict, with_chain: bool = True) -> dict:
    r = {"record_id": art["record_id"]}
    if with_chain:
        r["chain_id"] = art["chain_id"]
    return r


def claim_for(art: dict, length: int = 1, witnessed_at: str = FRESH_AT) -> dict:
    return {"chain_id": art["chain_id"], "sequence": art["sequence"],
            "current": art["integrity"]["current"], "length": length,
            "witnessed_at": witnessed_at}


def witness_block(ref: dict, claim: dict, sig_hex: str,
                  witness_id: str = WITNESS_WIRE, alg_label: str = "Ed25519") -> dict:
    return {"head_ref": ref, "witness_id": witness_id, "claim": claim,
            "signature": {"alg": alg_label, "value": sig_hex}}


def request(artifact: dict, related=(), head_witness: dict | None = None) -> dict:
    r = {"artifact": artifact, "related_artifacts": list(related)}
    if head_witness is not None:
        r["head_witness"] = head_witness
    return r


# --------------------------------------------------------------------------------------
# The pinned expected-outcome appendix (CLASS_VERIFIER_CONTRACT s7) — TRANSCRIBED VERBATIM.
# Column order: class, A-fail, A-withheld, A-caveats, W-fail, W-withheld, observer.
# The appendix legend fixes `-` as the empty array, and states `observer` is
# `not_applicable` except on Effect artifacts, where it is stated.
# --------------------------------------------------------------------------------------
NA = "not_applicable"
NWS = ["no-witness-supplied"]
EXPECTED_APPENDIX = {
    "P1":   ("AIREP-Authenticated", [], [], [], [], NWS, NA),
    "P2":   ("AIREP-Witnessed", [], [], [], [], [], NA),
    "P3":   ("AIREP-Authenticated", [], [], [], [], NWS, "independent"),
    "PB1":  ("AIREP-Core", ["producer-binding-revoked"], [], [], [], NWS, NA),
    "PB2":  ("AIREP-Core", [], ["producer-binding-missing"], [], [], NWS, NA),
    "PB3":  ("AIREP-Core", ["producer-binding-not-trusted"], [], [], [], NWS, NA),
    "PB4":  ("AIREP-Core", [], ["producer-binding-malformed"], [], [], NWS, NA),
    "PB5":  ("AIREP-Core", [], ["producer-suite-unsupported"], [], [], NWS, NA),
    "PB6":  ("AIREP-Core", [], ["producer-revocation-state-missing"], [], [], NWS, NA),
    "PB7":  ("AIREP-Core", [], ["producer-revocation-state-malformed"], [], [], NWS, NA),
    "PS1":  ("AIREP-Core", ["producer-signature-invalid"], [], [], [], NWS, NA),
    "PS2":  ("AIREP-Authenticated", [], [], ["wire-alg-mismatch"], [], NWS, NA),
    "PS3":  ("AIREP-Authenticated", [], [], ["producer-key-self-revoked"], [], NWS, NA),
    "WB1":  ("AIREP-Authenticated", [], [], [], ["witness-binding-revoked"], [], NA),
    "WB2":  ("AIREP-Authenticated", [], [], [], [], ["witness-binding-missing"], NA),
    "WB3":  ("AIREP-Authenticated", [], [], [], ["witness-binding-not-trusted"], [], NA),
    "WB4":  ("AIREP-Authenticated", [], [], [], [], ["witness-binding-malformed"], NA),
    "WB5":  ("AIREP-Authenticated", [], [], [], [], ["witness-suite-unsupported"], NA),
    "WB6":  ("AIREP-Authenticated", [], [], [], [], ["witness-revocation-state-missing"], NA),
    "WB7":  ("AIREP-Authenticated", [], [], [], [], ["witness-revocation-state-malformed"], NA),
    "IND1": ("AIREP-Authenticated", [], [], [], ["witness-key-not-distinct"], [], NA),
    "IND2": ("AIREP-Authenticated", [], [], [], ["witness-identity-not-distinct"], [], NA),
    "IND3": ("AIREP-Authenticated", [], [], [], [], ["independence-relation-absent"], NA),
    "IND4": ("AIREP-Authenticated", [], [], [], ["independence-explicitly-denied"], [], NA),
    "IND5": ("AIREP-Authenticated", [], [], [], [], ["independence-policy-malformed"], NA),
    "IND6": ("AIREP-Authenticated", [], [], [], [], ["independence-policy-missing"], NA),
    "WM1":  ("AIREP-Authenticated", [], [], [], ["witness-claim-invalid"], [], NA),
    "WM2":  ("AIREP-Authenticated", [], [], [], ["witness-signature-invalid"], [], NA),
    "WM3":  ("AIREP-Authenticated", [], [], [], ["witness-head-unresolved"], [], NA),
    "WM4":  ("AIREP-Authenticated", [], [], [], ["witness-head-mismatch"], [], NA),
    "WM5":  ("AIREP-Authenticated", [], [], [], ["witness-head-mismatch"], [], NA),
    "WM6":  ("AIREP-Authenticated", [], [], [], ["witness-head-unresolved"], [], NA),
    "FR1":  ("AIREP-Authenticated", [], [], [], ["witness-freshness-outside-window"], [], NA),
    "FR2":  ("AIREP-Authenticated", [], [], [], ["witness-freshness-outside-window"], [], NA),
    "FR3":  ("AIREP-Witnessed", [], [], [], [], [], NA),
    "FR4":  ("AIREP-Authenticated", [], [], [], [], ["freshness-inputs-missing"], NA),
    "PI1":  ("AIREP-Core", [], ["producer-revocation-state-missing"], [], [],
             ["freshness-inputs-missing", "witness-revocation-state-missing"], NA),
    "PI2":  ("AIREP-Authenticated", [], [], [], [], ["independence-policy-missing"], NA),
    "PI3":  ("AIREP-Authenticated", [], [], [], [], ["freshness-inputs-missing"], NA),
    "OB1":  ("AIREP-Authenticated", [], [], [], [], NWS, "independent"),
    "OB2":  ("AIREP-Authenticated", [], [], [], [], NWS, "unknown"),
    "OB3":  ("AIREP-Authenticated", [], [], [], [], NWS, "same_executor"),
    "OB4":  ("AIREP-Authenticated", [], [], [], [], NWS, "unknown"),
    "OB5":  ("AIREP-Authenticated", [], [], [], [], NWS, "unknown"),
    "XT1":  ("AIREP-Core", ["producer-binding-revoked"], [], [], [], [], NA),
}

CASE_ORDER = ["P1", "P2", "P3",
              "PB1", "PB2", "PB3", "PB4", "PB5", "PB6", "PB7",
              "PS1", "PS2", "PS3",
              "WB1", "WB2", "WB3", "WB4", "WB5", "WB6", "WB7",
              "IND1", "IND2", "IND3", "IND4", "IND5", "IND6",
              "WM1", "WM2", "WM3", "WM4", "WM5", "WM6",
              "FR1", "FR2", "FR3", "FR4",
              "PI1", "PI2", "PI3",
              "OB1", "OB2", "OB3", "OB4", "OB5",
              "XT1"]

# Closed reason registry (CLASS_VERIFIER_CONTRACT s5) — used ONLY to check that the
# transcription above names no reason outside the registry.
REASON_REGISTRY = {
    "producer-binding-missing", "producer-binding-not-trusted", "producer-binding-malformed",
    "producer-suite-unsupported", "producer-revocation-state-missing",
    "producer-revocation-state-malformed", "producer-binding-revoked",
    "producer-signature-invalid", "producer-key-self-revoked", "wire-alg-mismatch",
    "no-witness-supplied", "witness-binding-missing", "witness-binding-not-trusted",
    "witness-binding-malformed", "witness-suite-unsupported",
    "witness-revocation-state-missing", "witness-revocation-state-malformed",
    "independence-policy-missing", "independence-policy-malformed",
    "independence-relation-absent", "freshness-inputs-missing", "witness-binding-revoked",
    "witness-head-unresolved", "witness-head-mismatch", "witness-claim-invalid",
    "witness-identity-not-distinct", "witness-key-not-distinct",
    "independence-explicitly-denied", "witness-signature-invalid", "witness-time-invalid",
    "witness-freshness-outside-window",
}
AUTH_REASONS = {r for r in REASON_REGISTRY if r.startswith(("producer-", "wire-"))}
WIT_REASONS = REASON_REGISTRY - AUTH_REASONS

CASES: list[dict] = []
ASSERTIONS: list[dict] = []


def assert_(name: str, cond: bool, detail: str = "") -> None:
    ASSERTIONS.append({"assertion": name, "passed": bool(cond), "detail": detail})
    if not cond:
        stop(f"builder self-check failed: {name} ({detail})")


def emit(case_id: str, description: str, req: dict, *, bindings=None, independence=None,
         revocation=None, clock=None, sig_ok=True, witness_sig_ok=True,
         head_matches=None, head_is_primary=None, related_sig_ok=None) -> None:
    """Register a case. `sig_ok` / `witness_sig_ok` / `head_matches` are the case's OWN
    construction intent, checked below — not class evaluation."""
    if case_id not in EXPECTED_APPENDIX:
        stop(f"{case_id} is not a pinned appendix case")
    if any(c["case_id"] == case_id for c in CASES):
        stop(f"duplicate case id {case_id}")
    CASES.append({
        "case_id": case_id, "description": description, "request": req,
        "bindings": bindings, "independence": independence, "revocation": revocation,
        "clock": clock,
        "_intent": {"sig_ok": sig_ok, "witness_sig_ok": witness_sig_ok,
                    "head_matches": head_matches, "head_is_primary": head_is_primary,
                    "related_sig_ok": related_sig_ok or {}},
    })


def build_cases() -> None:
    # ---------------- P1: clean, no witness ----------------
    a = seal(decision_body("cv-chain-p1", "cv-rec-p1"))
    emit("P1", "clean Decision, all operator inputs supplied, no head_witness in the request",
         request(a),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    # ---------------- P2: clean + clean witness over this artifact ----------------
    a = seal(decision_body("cv-chain-p2", "cv-rec-p2"))
    cl = claim_for(a)
    emit("P2", "clean Decision plus a clean, fresh, independent witness over this artifact",
         request(a, head_witness=witness_block(head_ref(a), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # ---------------- P3: clean Effect, verified-independent observer, no witness --------
    dec = seal(decision_body("cv-chain-p3", "cv-rec-decision-1"))
    ex = seal(execution_body("cv-chain-p3", "cv-rec-execution-1", sequence=1,
                             previous=dec["integrity"]["current"]), sk=_xsk)
    eff = seal(effect_body("cv-chain-p3", "cv-rec-p3", head_ref(ex), "independent",
                           sequence=2, previous=ex["integrity"]["current"]))
    emit("P3", "clean Effect; referenced Execution is Authenticated in its own right under a "
               "distinct binding identity and key, and the pair is explicitly independent",
         request(eff, related=[dec, ex]),
         bindings=bindings_doc(executor=True),
         revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR]),
         independence=independence_doc([(B_PRODUCER, B_EXECUTOR)]), clock=clock_doc(),
         related_sig_ok={"cv-rec-decision-1": True, "cv-rec-execution-1": True})

    # ---------------- PB series: producer binding / revocation ----------------
    a = seal(decision_body("cv-chain-pb1", "cv-rec-pb1"))
    emit("PB1", "producer binding present and trusted, revocation snapshot marks it revoked",
         request(a), bindings=bindings_doc(),
         revocation=revocation_doc([B_PRODUCER, B_WITNESS], {B_PRODUCER: "revoked"}),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    a = seal(decision_body("cv-chain-pb2", "cv-rec-pb2"))
    b = bindings_doc()
    del b["producer_bindings"][PRODUCER_WIRE]   # no producer_bindings entry for the wire id
    emit("PB2", "producer_bindings carries no entry for the artifact's wire producer id",
         request(a), bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    a = seal(decision_body("cv-chain-pb3", "cv-rec-pb3"))
    b = bindings_doc()
    b["bindings"][B_PRODUCER]["trusted"] = False   # present, not literally true
    emit("PB3", "producer binding entry present with trusted:false (present, not literally true)",
         request(a), bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    a = seal(decision_body("cv-chain-pb4", "cv-rec-pb4"))
    b = bindings_doc()
    b["bindings"][B_PRODUCER]["role"] = "witness"   # wrong role for a producer_bindings target
    emit("PB4", "binding referenced from producer_bindings declares role:witness (s1.1 malformed)",
         request(a), bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    a = seal(decision_body("cv-chain-pb5", "cv-rec-pb5"))
    b = bindings_doc()
    b["bindings"][B_PRODUCER]["suite"] = "ed448"    # not in the closed suite registry
    emit("PB5", "producer binding names suite ed448, absent from the closed v0.2 suite registry",
         request(a), bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    a = seal(decision_body("cv-chain-pb6", "cv-rec-pb6"))
    emit("PB6", "revocation snapshot supplied but carries no entry for the producer binding",
         request(a), bindings=bindings_doc(), revocation=revocation_doc([B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    a = seal(decision_body("cv-chain-pb7", "cv-rec-pb7"))
    rev = revocation_doc([B_PRODUCER, B_WITNESS])
    rev["bindings"][B_PRODUCER]["state"] = "suspended"   # neither active nor revoked
    emit("PB7", "revocation entry for the producer binding has state:suspended (neither value)",
         request(a), bindings=bindings_doc(), revocation=rev,
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    # ---------------- PS series: producer signature / caveats ----------------
    a = seal(decision_body("cv-chain-ps1", "cv-rec-ps1"), sk=_wsk)  # signed by the WRONG key
    emit("PS1", "hash-consistent Decision whose record signature was produced by a different "
                "key than the producer binding's",
         request(a), bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         sig_ok=False)

    a = seal(decision_body("cv-chain-ps2", "cv-rec-ps2"), alg_label="ECDSA-P256")
    emit("PS2", "valid ed25519 record signature; wire integrity.signature.alg names ECDSA-P256",
         request(a), bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    a = seal(decision_body("cv-chain-ps3", "cv-rec-ps3",
                           profiles={"airep.key-trust": {"revocation": {"revoked": True}}}))
    emit("PS3", "valid signature; the artifact's airep.key-trust profile self-declares "
                "revocation.revoked=true while the operator snapshot says active",
         request(a), bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    # ---------------- WB series: witness binding / revocation ----------------
    def witness_case(cid: str, desc: str, *, bindings=None, revocation=None,
                     independence=None, clock=None, witness_id=WITNESS_WIRE,
                     witness_sk=_wsk, witness_sig_ok=True):
        art = seal(decision_body(f"cv-chain-{cid.lower()}", f"cv-rec-{cid.lower()}"))
        cl = claim_for(art)
        wb = witness_block(head_ref(art), cl, sign_witness("0.2", cl, sk=witness_sk),
                           witness_id=witness_id)
        emit(cid, desc, request(art, head_witness=wb),
             bindings=bindings if bindings is not None else bindings_doc(),
             revocation=revocation if revocation is not None
             else revocation_doc([B_PRODUCER, B_WITNESS]),
             independence=independence if independence is not None
             else independence_doc([(B_PRODUCER, B_WITNESS)]),
             clock=clock if clock is not None else clock_doc(),
             witness_sig_ok=witness_sig_ok, head_matches=1, head_is_primary=True)

    witness_case("WB1", "clean witness over this artifact; revocation snapshot marks the "
                        "witness binding revoked",
                 revocation=revocation_doc([B_PRODUCER, B_WITNESS], {B_WITNESS: "revoked"}))

    b = bindings_doc()
    del b["witness_bindings"][WITNESS_WIRE]
    witness_case("WB2", "witness_bindings carries no entry for the wire witness_id", bindings=b)

    b = bindings_doc()
    b["bindings"][B_WITNESS]["trusted"] = False
    witness_case("WB3", "witness binding entry present with trusted:false", bindings=b)

    b = bindings_doc()
    b["bindings"][B_WITNESS]["role"] = "producer"
    witness_case("WB4", "binding referenced from witness_bindings declares role:producer "
                        "(s1.1 malformed)", bindings=b)

    b = bindings_doc()
    b["bindings"][B_WITNESS]["suite"] = "ed448"
    witness_case("WB5", "witness binding names suite ed448, absent from the closed registry",
                 bindings=b)

    witness_case("WB6", "revocation snapshot supplied but carries no entry for the witness "
                        "binding", revocation=revocation_doc([B_PRODUCER]))

    rev = revocation_doc([B_PRODUCER, B_WITNESS])
    rev["bindings"][B_WITNESS]["state"] = "unknown"
    witness_case("WB7", "revocation entry for the witness binding has state:unknown", revocation=rev)

    # ---------------- IND series: independence ----------------
    # IND1 — witness binding resolves to the producer's public key (distinct binding ids,
    # distinct subject identities); the witness signature is genuinely made with that key.
    art = seal(decision_body("cv-chain-ind1", "cv-rec-ind1"))
    cl = claim_for(art)
    b = bindings_doc()
    del b["bindings"][B_WITNESS]
    b["bindings"][B_WITNESS_SAMEKEY] = binding(ID_WITNESS, "witness", P_PUB)
    b["witness_bindings"][WITNESS_WIRE] = B_WITNESS_SAMEKEY
    emit("IND1", "witness binding carries the producer's public key under a distinct binding "
                 "id and distinct subject_identity; the pair is listed independent",
         request(art, head_witness=witness_block(head_ref(art), cl,
                                                 sign_witness("0.2", cl, sk=_psk))),
         bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS_SAMEKEY]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS_SAMEKEY)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # IND2 — distinct keys, identical subject_identity.
    art = seal(decision_body("cv-chain-ind2", "cv-rec-ind2"))
    cl = claim_for(art)
    b = bindings_doc()
    del b["bindings"][B_WITNESS]
    b["bindings"][B_WITNESS_SAMEID] = binding(ID_PRODUCER, "witness", W_PUB)
    b["witness_bindings"][WITNESS_WIRE] = B_WITNESS_SAMEID
    emit("IND2", "witness binding carries a distinct key but the producer binding's "
                 "subject_identity; the pair is listed independent",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS_SAMEID]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS_SAMEID)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # IND3 — policy supplied and well-formed; it relates a different pair, not this one.
    b = bindings_doc(executor=True)
    witness_case("IND3", "independence policy supplied and well-formed but relates only an "
                         "unrelated pair; the producer/witness pair is absent from both lists",
                 bindings=b,
                 revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR]),
                 independence=independence_doc([(B_WITNESS, B_EXECUTOR)]))

    witness_case("IND4", "producer/witness pair listed in non_independent_pairs",
                 independence=independence_doc(non_independent=[(B_PRODUCER, B_WITNESS)]))

    witness_case("IND5", "producer/witness pair listed in BOTH independent_pairs and "
                         "non_independent_pairs (malformed policy)",
                 independence=independence_doc([(B_PRODUCER, B_WITNESS)],
                                               [(B_PRODUCER, B_WITNESS)]))

    witness_case("IND6", "no independence-policy input supplied at all",
                 independence=_OMIT)

    # ---------------- WM series: head resolution / claim / witness signature -------------
    # WM1 — claim carries a sixth member; the signature is genuine over that six-member JCS.
    art = seal(decision_body("cv-chain-wm1", "cv-rec-wm1"))
    cl = dict(claim_for(art), note="extra")
    emit("WM1", "head claim carries a sixth member beyond the frozen five; the witness "
                "signature is genuine over that six-member canonical claim",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # WM2 — valid five-member claim; signature made with a third key, not the witness binding's.
    witness_case("WM2", "valid claim over this artifact; the witness signature was produced "
                        "by a third key, not the witness binding's key",
                 witness_sk=_xsk, witness_sig_ok=False)

    # WM3 — head_ref names a record present nowhere in the request.
    art = seal(decision_body("cv-chain-wm3", "cv-rec-wm3"))
    cl = claim_for(art)
    emit("WM3", "head_ref names a record_id absent from artifact and related_artifacts",
         request(art, head_witness=witness_block(
             {"chain_id": "cv-chain-wm3", "record_id": "cv-rec-absent"}, cl,
             sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=0)

    # WM4 — head_ref resolves to the primary; claim.sequence does not reconcile.
    art = seal(decision_body("cv-chain-wm4", "cv-rec-wm4"))
    cl = dict(claim_for(art), sequence=art["sequence"] + 1)
    emit("WM4", "head_ref resolves uniquely to the primary artifact; the genuinely signed "
                "claim's sequence does not reconcile with that artifact",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # WM5 — head_ref resolves uniquely, but to a related artifact rather than the primary.
    art = seal(decision_body("cv-chain-wm5", "cv-rec-wm5"))
    other = seal(decision_body("cv-chain-wm5", "cv-rec-wm5-other", sequence=1,
                               previous=art["integrity"]["current"]))
    cl = claim_for(other, length=2)
    emit("WM5", "head_ref resolves uniquely to a related_artifacts member; the claim "
                "reconciles with that member and the signature is valid",
         request(art, related=[other],
                 head_witness=witness_block(head_ref(other), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=False,
         related_sig_ok={"cv-rec-wm5-other": True})

    # WM6 — head_ref (record_id only) matches two artifacts in different chains.
    art = seal(decision_body("cv-chain-wm6-a", "cv-rec-wm6-dup"))
    twin = seal(decision_body("cv-chain-wm6-b", "cv-rec-wm6-dup"))
    cl = claim_for(art)
    emit("WM6", "head_ref carries record_id only and matches both the primary artifact and a "
                "related artifact in a different chain (ambiguous)",
         request(art, related=[twin],
                 head_witness=witness_block({"record_id": "cv-rec-wm6-dup"}, cl,
                                            sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=2, related_sig_ok={"cv-rec-wm6-dup": True})

    # ---------------- FR series: freshness ----------------
    def freshness_case(cid: str, desc: str, witnessed_at: str, clock=None):
        art = seal(decision_body(f"cv-chain-{cid.lower()}", f"cv-rec-{cid.lower()}"))
        cl = claim_for(art, witnessed_at=witnessed_at)
        emit(cid, desc,
             request(art, head_witness=witness_block(head_ref(art), cl,
                                                     sign_witness("0.2", cl))),
             bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
             independence=independence_doc([(B_PRODUCER, B_WITNESS)]),
             clock=clock_doc() if clock is None else clock,
             head_matches=1, head_is_primary=True)

    freshness_case("FR1", f"signed witnessed_at {STALE_PAST} is 7200s before now "
                          f"(window {WINDOW}s)", STALE_PAST)
    freshness_case("FR2", f"signed witnessed_at {STALE_FUTURE} is 7200s after now "
                          f"(window {WINDOW}s)", STALE_FUTURE)
    freshness_case("FR3", f"signed witnessed_at {BOUNDARY_AT} is exactly {WINDOW}s before now "
                          f"(boundary-equal)", BOUNDARY_AT)
    freshness_case("FR4", "clean witness in every respect; no clock inputs supplied",
                   FRESH_AT, clock=_OMIT)

    # ---------------- PI series: partial operator input ----------------
    art = seal(decision_body("cv-chain-pi1", "cv-rec-pi1"))
    cl = claim_for(art)
    emit("PI1", "only the binding store supplied: no revocation snapshot, no independence "
                "policy, no clock; the head witness itself is clean",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=_OMIT, independence=_OMIT, clock=_OMIT,
         head_matches=1, head_is_primary=True)

    witness_case("PI2", "bindings and revocation supplied; no independence policy",
                 independence=_OMIT)
    witness_case("PI3", "bindings, revocation and independence policy supplied; no clock "
                        "inputs", clock=_OMIT)

    # ---------------- OB series: Effect observer assessment ----------------
    def effect_case(cid: str, desc: str, *, observer_wire: str, execution_producer: str,
                    execution_sk, execution_present: bool = True, independence=None,
                    bindings=None, revocation=None, exec_sig_ok: bool = True):
        chain = f"cv-chain-{cid.lower()}"
        dec = seal(decision_body(chain, "cv-rec-decision-1"))
        related = [dec]
        rel_ok = {"cv-rec-decision-1": True}
        if execution_present:
            ex = seal(execution_body(chain, "cv-rec-execution-1", sequence=1,
                                     producer=execution_producer,
                                     previous=dec["integrity"]["current"]), sk=execution_sk)
            related.append(ex)
            rel_ok["cv-rec-execution-1"] = exec_sig_ok
            exec_ref = head_ref(ex)
        else:
            exec_ref = {"chain_id": chain, "record_id": "cv-rec-execution-absent"}
        eff = seal(effect_body(chain, f"cv-rec-{cid.lower()}", exec_ref, observer_wire,
                               sequence=2,
                               previous=(related[-1]["integrity"]["current"])))
        emit(cid, desc, request(eff, related=related),
             bindings=bindings, revocation=revocation, independence=independence,
             clock=clock_doc(), related_sig_ok=rel_ok)

    effect_case("OB1", "Effect declares independent; referenced Execution is Authenticated "
                       "under a distinct binding identity and key, and the pair is listed "
                       "independent",
                observer_wire="independent", execution_producer=EXECUTOR_WIRE,
                execution_sk=_xsk, bindings=bindings_doc(executor=True),
                revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR]),
                independence=independence_doc([(B_PRODUCER, B_EXECUTOR)]))

    effect_case("OB2", "Effect declares independent; Execution is Authenticated under a "
                       "distinct key and identity, but the policy relates only an unrelated "
                       "pair",
                observer_wire="independent", execution_producer=EXECUTOR_WIRE,
                execution_sk=_xsk, bindings=bindings_doc(executor=True),
                revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR]),
                independence=independence_doc([(B_PRODUCER, B_WITNESS)]))

    effect_case("OB3", "Effect declares same_executor; referenced Execution is Authenticated "
                       "under the same producer binding",
                observer_wire="same_executor", execution_producer=PRODUCER_WIRE,
                execution_sk=_psk, bindings=bindings_doc(executor=True),
                revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR]),
                independence=independence_doc([(B_PRODUCER, B_EXECUTOR)]))

    effect_case("OB4", "Effect declares independent; the referenced Execution's record "
                       "signature was produced by a different key than its own producer "
                       "binding, so it does not reach Authenticated in its own right",
                observer_wire="independent", execution_producer=EXECUTOR_WIRE,
                execution_sk=_wsk, exec_sig_ok=False,
                bindings=bindings_doc(executor=True),
                revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR]),
                independence=independence_doc([(B_PRODUCER, B_EXECUTOR)]))

    effect_case("OB5", "Effect declares independent; execution_ref names a record absent "
                       "from artifact and related_artifacts",
                observer_wire="independent", execution_producer=EXECUTOR_WIRE,
                execution_sk=_xsk, execution_present=False,
                bindings=bindings_doc(executor=True),
                revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR]),
                independence=independence_doc([(B_PRODUCER, B_EXECUTOR)]))

    # ---------------- XT1: cross-tier ----------------
    art = seal(decision_body("cv-chain-xt1", "cv-rec-xt1"))
    cl = claim_for(art)
    emit("XT1", "producer binding revoked in the snapshot while a clean, fresh, independent "
                "witness vouches for this artifact's head",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(),
         revocation=revocation_doc([B_PRODUCER, B_WITNESS], {B_PRODUCER: "revoked"}),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)


# --------------------------------------------------------------------------------------
# Builder self-validation (construction fidelity only — no class evaluation)
# --------------------------------------------------------------------------------------
def load_validators():
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    docs = {n: json.loads((SCHEMAS / f"{n}.schema.json").read_text(encoding="utf-8"))
            for n in ("common", "decision", "control", "execution", "effect")}
    reg = Registry()
    for d in docs.values():
        reg = Resource.from_contents(d) @ reg
    return {f: Draft202012Validator(docs[f], registry=reg)
            for f in ("decision", "control", "execution", "effect")}


def resolve(ref: dict, req: dict) -> list[dict]:
    pool = [req["artifact"]] + list(req.get("related_artifacts", []))
    out = []
    for a in pool:
        if a["record_id"] != ref["record_id"]:
            continue
        if "chain_id" in ref and a["chain_id"] != ref["chain_id"]:
            continue
        out.append(a)
    return out


def self_validate() -> dict:
    validators = load_validators()
    probe = None
    for case in CASES:
        cid, req, intent = case["case_id"], case["request"], case["_intent"]
        arts = [req["artifact"]] + list(req["related_artifacts"])

        for art in arts:
            errs = list(validators[art["artifact_type"]].iter_errors(art))
            assert_(f"{cid}:schema-valid:{art['record_id']}", not errs,
                    "; ".join(f"{list(e.absolute_path)}:{e.validator}" for e in errs[:3]))
            body = json.loads(json.dumps(art))
            del body["integrity"]["current"]
            del body["integrity"]["signature"]
            recomputed = current_for(body, tag(art["airep_version"], "hash",
                                               art["artifact_type"]))
            assert_(f"{cid}:hash-consistent:{art['record_id']}",
                    recomputed == art["integrity"]["current"],
                    f"{recomputed} != {art['integrity']['current']}")

        # Primary record signature, against the key the case's producer binding names.
        prim = req["artifact"]
        prim_pub = expected_pub_for(case, prim)
        got = verify_record_sig(prim, prim_pub) if prim_pub else None
        if prim_pub:
            assert_(f"{cid}:record-signature-verifies=={intent['sig_ok']}",
                    got == intent["sig_ok"], f"observed {got}")

        for rec_id, ok in intent["related_sig_ok"].items():
            rel = [a for a in req["related_artifacts"] if a["record_id"] == rec_id]
            if len(rel) != 1:
                stop(f"{cid}: related_sig_ok names {rec_id}, found {len(rel)}")
            pub = expected_pub_for(case, rel[0])
            if pub:
                got = verify_record_sig(rel[0], pub)
                assert_(f"{cid}:related-signature-verifies:{rec_id}=={ok}", got == ok,
                        f"observed {got}")

        hw = req.get("head_witness")
        if hw is not None:
            n = len(resolve(hw["head_ref"], req))
            if intent["head_matches"] is not None:
                assert_(f"{cid}:head-resolution-count=={intent['head_matches']}",
                        n == intent["head_matches"], f"observed {n}")
            if intent["head_is_primary"] is not None and n == 1:
                is_prim = resolve(hw["head_ref"], req)[0] is req["artifact"]
                assert_(f"{cid}:head-is-primary=={intent['head_is_primary']}",
                        is_prim == intent["head_is_primary"], f"observed {is_prim}")
            wpub = witness_pub_for(case)
            if wpub:
                got = verify_witness_sig("0.2", hw["claim"], hw["signature"]["value"], wpub)
                assert_(f"{cid}:witness-signature-verifies=={intent['witness_sig_ok']}",
                        got == intent["witness_sig_ok"], f"observed {got}")
            if probe is None:
                probe = {"case_id": cid, "claim_jcs_hex": jcs(hw["claim"]).hex(),
                         "claim_jcs_sha256": hashlib.sha256(jcs(hw["claim"])).hexdigest(),
                         "witness_preimage_sha256":
                             hashlib.sha256(witness_preimage("0.2", hw["claim"])).hexdigest()}

    # Transcription checks (over the copied appendix, not over any evaluation).
    assert_("appendix:case-set-complete",
            sorted(EXPECTED_APPENDIX) == sorted(CASE_ORDER) ==
            sorted(c["case_id"] for c in CASES),
            f"{len(EXPECTED_APPENDIX)} pinned / {len(CASES)} built")
    for cid, row in EXPECTED_APPENDIX.items():
        klass, af, aw, ac, wf, ww, obs = row
        assert_(f"{cid}:class-legal",
                klass in ("AIREP-Core", "AIREP-Authenticated", "AIREP-Witnessed"), klass)
        assert_(f"{cid}:observer-legal",
                obs in ("same_executor", "independent", "unknown", "not_applicable"), obs)
        for name, arr, allowed in (("authenticated_failures", af, AUTH_REASONS),
                                   ("authenticated_withheld", aw, AUTH_REASONS),
                                   ("authenticated_caveats", ac, AUTH_REASONS),
                                   ("witnessed_failures", wf, WIT_REASONS),
                                   ("witnessed_withheld", ww, WIT_REASONS)):
            assert_(f"{cid}:{name}:sorted-deduplicated",
                    arr == sorted(set(arr)), str(arr))
            assert_(f"{cid}:{name}:registry-only", set(arr) <= allowed, str(arr))
        assert_(f"{cid}:invariant:auth-negative-implies-core",
                not (af or aw) or klass == "AIREP-Core", klass)
        assert_(f"{cid}:invariant:witness-negative-implies-not-witnessed",
                not (wf or ww) or klass != "AIREP-Witnessed", klass)
        assert_(f"{cid}:invariant:caveats-imply-not-core",
                not ac or klass != "AIREP-Core", klass)
        assert_(f"{cid}:invariant:witnessed-implies-all-clean",
                klass != "AIREP-Witnessed" or not (af or aw or wf or ww), klass)

    # Tag-divergence probe: identical body bytes under two hash tags must differ.
    tb = decision_body("cv-chain-probe", "cv-rec-probe")
    d_cur = current_for(tb, tag("0.2", "hash", "decision"))
    c_cur = current_for(tb, tag("0.2", "hash", "control"))
    assert_("probe:hash-tag-divergence", d_cur != c_cur, "identical current under two tags")

    return {"witness_claim_probe": probe,
            "hash_tag_divergence_probe": {"body": "cv-rec-probe decision body",
                                          "current_under_hash_decision": d_cur,
                                          "current_under_hash_control": c_cur,
                                          "distinct": d_cur != c_cur}}


def expected_pub_for(case: dict, art: dict) -> str | None:
    """The public key the case's OWN binding store maps the artifact's wire producer to."""
    b = case["bindings"]
    if b is None or isinstance(b, _Omit):
        return None
    bid = b["producer_bindings"].get(art["subject"]["producer"])
    if bid is None:
        return None
    entry = b["bindings"].get(bid)
    return entry["public_key_hex"] if entry else None


def witness_pub_for(case: dict) -> str | None:
    b = case["bindings"]
    hw = case["request"].get("head_witness")
    if b is None or isinstance(b, _Omit) or hw is None:
        return None
    bid = b["witness_bindings"].get(hw["witness_id"])
    if bid is None:
        return None
    entry = b["bindings"].get(bid)
    return entry["public_key_hex"] if entry else None


# --------------------------------------------------------------------------------------
# Emission
# --------------------------------------------------------------------------------------
def dump(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=1) + "\n"


def write_corpus() -> dict:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    (CORPUS / "cases").mkdir(parents=True)

    files: dict[str, str] = {}

    def put(rel: str, text: str) -> None:
        p = CORPUS / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        files[rel] = hashlib.sha256(text.encode("utf-8")).hexdigest()

    index = []
    by_id = {c["case_id"]: c for c in CASES}
    for cid in CASE_ORDER:
        case = by_id[cid]
        entry_files = {}
        for name, doc in (("request", case["request"]), ("bindings", case["bindings"]),
                          ("independence", case["independence"]),
                          ("revocation", case["revocation"]), ("clock", case["clock"])):
            if doc is None or isinstance(doc, _Omit):
                continue          # file omitted entirely: that input was not supplied
            rel = f"cases/{cid}/{name}.json"
            put(rel, dump(doc))
            entry_files[name] = rel
        klass, af, aw, ac, wf, ww, obs = EXPECTED_APPENDIX[cid]
        put(f"cases/{cid}/expected.json", dump({
            "class": klass,
            "authenticated_failures": af,
            "authenticated_withheld": aw,
            "authenticated_caveats": ac,
            "witnessed_failures": wf,
            "witnessed_withheld": ww,
            "observer_assessment": obs,
        }))
        index.append({"case_id": cid, "description": case["description"],
                      "files": entry_files})

    put("case_index.json", dump(index))

    agg = "".join(f"{files[n]}  {n}\n" for n in sorted(files))
    return {"files": files, "aggregate_sha256": hashlib.sha256(agg.encode("utf-8")).hexdigest()}


def main() -> int:
    build_cases()
    probes = self_validate()
    out = write_corpus()
    failed = [a for a in ASSERTIONS if not a["passed"]]
    manifest = {
        "corpus": "AIREP v0.2 class-verification adversarial corpus (CLASS_VERIFIER_CONTRACT s7)",
        "builder": "build_class_corpus.py (third-context harness; NOT a class verifier)",
        "aggregate_sha256": out["aggregate_sha256"],
        "aggregate_rule": "sha256 of concatenated ASCII-sorted UTF-8 lines "
                          "'<sha256>  <relative-path>\\n' relative to class-verification/corpus/",
        "case_count": len(CASE_ORDER),
        "file_count": len(out["files"]),
        "files": out["files"],
        "keys": {
            "note": "TEST-ONLY key material. These seeds are published in this repository; "
                    "no fixture here is a cryptographically meaningful artifact and no key "
                    "below may ever be used outside conformance fixtures.",
            "producer": {"seed_hex": PRODUCER_SEED, "public_key_hex": P_PUB,
                         "source": "Stage-3/Stage-4 published TEST-ONLY producer seed"},
            "witness": {"seed_hex": WITNESS_SEED, "public_key_hex": W_PUB,
                        "source": "Stage-3/Stage-4 published TEST-ONLY witness seed"},
            "executor": {"seed_hex": EXECUTOR_SEED, "public_key_hex": X_PUB,
                         "source": f"sha256(ASCII '{EXECUTOR_SEED_INPUT}') — derived "
                                   f"deterministically for the observer-path cases"},
            "suite": "ed25519 (the only entry in the closed v0.2 suite registry)",
        },
        "builder_assertions": {
            "count": len(ASSERTIONS),
            "failed": len(failed),
            "kinds": sorted({a["assertion"].split(":", 1)[-1].split("=")[0]
                             for a in ASSERTIONS}),
            "probes": probes,
        },
        "expected_values_note": "cases/<CASE_ID>/expected.json is a verbatim transcription of "
                                "the CLASS_VERIFIER_CONTRACT s7 appendix row; case_index.json "
                                "deliberately carries no expected values.",
    }
    (HERE / "corpus_manifest.json").write_text(dump(manifest), encoding="utf-8")
    print(f"class corpus: {len(CASE_ORDER)} cases, {len(out['files'])} files, "
          f"{len(ASSERTIONS)} self-checks ({len(failed)} failed)")
    print(f"aggregate_sha256 = {out['aggregate_sha256']}")
    return 0 if not failed else 3


if __name__ == "__main__":
    sys.exit(main())
