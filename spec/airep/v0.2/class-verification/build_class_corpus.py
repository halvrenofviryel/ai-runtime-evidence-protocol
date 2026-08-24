#!/usr/bin/env python3
"""AIREP v0.2 class-verification deterministic corpus builder (third-context harness).

Builds the 45-case adversarial corpus pinned in CLASS_VERIFIER_CONTRACT.md s7, from the
frozen construction in ../INTEGRITY.md and the accepted schemas in ../schemas/, plus the
strictly additive C1 adversarial coverage extension (15 further verdict cases, 12 CLI /
process-exit probes and the s2 batch-ordering expectation). C0 bytes are unchanged and the
build proves it: see C0_AGGREGATE_SHA256_PRE_C1 and the c0-preservation assertions.

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
         head_matches=None, head_is_primary=None, related_sig_ok=None,
         claim_semantic=None, raw_check=None) -> None:
    """Register a case. `sig_ok` / `witness_sig_ok` / `head_matches` are the case's OWN
    construction intent, checked below — not class evaluation."""
    if case_id not in EXPECTED_ALL:
        stop(f"{case_id} is not a pinned appendix case nor a declared C1 case")
    if any(c["case_id"] == case_id for c in CASES):
        stop(f"duplicate case id {case_id}")
    CASES.append({
        "case_id": case_id, "description": description, "request": req,
        "bindings": bindings, "independence": independence, "revocation": revocation,
        "clock": clock,
        "_intent": {"sig_ok": sig_ok, "witness_sig_ok": witness_sig_ok,
                    "head_matches": head_matches, "head_is_primary": head_is_primary,
                    "related_sig_ok": related_sig_ok or {},
                    "claim_semantic": claim_semantic, "raw_check": raw_check},
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
    # PI3 is the contract's "everything except --now": the clock input IS supplied but
    # carries only the window, so the case tests its own named tamper rather than
    # degenerating into FR4's "clock inputs absent" shape (maintainer, 2026-08-23).
    witness_case("PI3", "bindings, revocation and independence policy supplied; clock input "
                        "present but carrying only the freshness window, no `now`",
                 clock={"freshness_window_seconds": WINDOW})

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


# ======================================================================================
# C1 ADVERSARIAL COVERAGE EXTENSION (strictly additive; C0 untouched)
# ======================================================================================
#
# PROVENANCE OF C1 EXPECTED VALUES — read this before changing anything below.
#
# The 45 C0 rows in EXPECTED_APPENDIX are a VERBATIM TRANSCRIPTION of the
# CLASS_VERIFIER_CONTRACT.md s7 table. The C1 rows in EXPECTED_C1 are NOT in that table.
# They are MANUALLY DERIVED FROM CITED NORMATIVE CLAUSES, WITHOUT EXECUTING EVALUATION
# LOGIC: for each case the derivation chain (input/tamper -> clause -> dependency rule ->
# expected class/channels) is written out in C1_COVERAGE.md, and every derivation is
# anchored either on an explicit s9 ruling or on an existing pinned s7 row of the same
# shape. No expected class, reason set or observer value below was produced by running a
# class verifier, a comparator, or any ladder-evaluation code. This file still contains no
# ladder evaluation, no reason derivation and no channel computation.
#
# C1 also adds two NON-VERDICT artefact groups, deliberately outside corpus/cases/:
#   corpus/probes/   - CLI / process-exit probes (run-validity surfaces; NO expected.json,
#                      so no scoring harness can mistake them for verdict cases)
#   corpus/ordering/ - the batch results-file ordering expectation (s2)

# The pre-C1 corpus_manifest.json aggregate, over exactly the 265 C0 files
# (case_index.json + cases/<C0 case id>/*). Asserted below to prove C0 immutability.
C0_AGGREGATE_SHA256_PRE_C1 = (
    "55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4")
C0_FILE_COUNT_PRE_C1 = 265

# --- C1 identifiers ------------------------------------------------------------------
# Ordering discriminator (C1 item 1). Both are VALID Unicode scalar values; no lone
# surrogate is used anywhere (a lone surrogate is not UTF-8 encodable and would raise a
# separate Unicode-validity question that is not what this fixture tests).
ORD_CHAIN = "cv-chain-ord"
ORD_SUPP_REC = "cv-rec-ord-\U00010000"   # ends U+10000, UTF-8 f0 90 80 80
ORD_BMP_REC = "cv-rec-ord-＀"        # ends U+FF00,  UTF-8 ef bc 80

BAD_GREGORIAN_AT = "2026-02-30T12:00:00Z"   # matches the fixed format, February 30 does
                                            # not exist (INTEGRITY s4.2)

# Raw-source-token machinery: some C1 cases need a JSON number written with a specific
# SOURCE SPELLING (s9 E-1) that json.dumps cannot produce. A marker string is emitted and
# replaced with the raw token in dump(); the marker never occurs in C0 content.
_RAW_RE = __import__("re").compile(r'"@@RAW:(.*?):RAW@@"')


def raw_token(tok: str) -> str:
    return f"@@RAW:{tok}:RAW@@"


# --------------------------------------------------------------------------------------
# C1 expected values — MANUALLY DERIVED from cited clauses (see C1_COVERAGE.md).
# Column order matches EXPECTED_APPENDIX:
#   class, A-fail, A-withheld, A-caveats, W-fail, W-withheld, observer
# --------------------------------------------------------------------------------------
EXPECTED_C1 = {
    # item 1 - UTF-8 vs UTF-16 batch ordering. Verdict shape is the pinned s7 P1 row.
    "ORD1": ("AIREP-Authenticated", [], [], [], [], NWS, NA),
    "ORD2": ("AIREP-Authenticated", [], [], [], [], NWS, NA),
    # item 9 - Control-family Authenticated positive. Verdict shape is the pinned s7 P1
    # row, carried to the control family by design s7 ("Core and Authenticated apply to
    # every artifact family identically").
    "CTL1": ("AIREP-Authenticated", [], [], [], [], NWS, NA),
    # item 10 - non-genesis Witnessed head. Verdict shape is the pinned s7 P2 row.
    "NG1": ("AIREP-Witnessed", [], [], [], [], [], NA),
    # item 5 - E-1 source-token rule on sequence/length. s9 R-2 6a + retained E-1:
    # violation is witness-claim-invalid ALONE (6b/6c do not run), and s4's dependency
    # rule suppresses every stage 7-10 reason. Same shape as the pinned s7 WM1 row.
    "LEX1": ("AIREP-Authenticated", [], [], [], ["witness-claim-invalid"], [], NA),
    "LEX2": ("AIREP-Authenticated", [], [], [], ["witness-claim-invalid"], [], NA),
    "LEX3": ("AIREP-Authenticated", [], [], [], ["witness-claim-invalid"], [], NA),
    # item 6 - witnessed_at Gregorian-invalid. s9 R-2 6c (clock inputs play no part);
    # s4 dependency: stage 10 needs stage 6 CLEAN, so freshness-inputs-missing must NOT
    # appear in TI1 even though no clock was supplied. TI1/TI2 differ only in whether the
    # clock is supplied and are pinned to the same expected value - that pairing IS the
    # clock-independence proof.
    "TI1": ("AIREP-Authenticated", [], [], [], ["witness-time-invalid"], [], NA),
    "TI2": ("AIREP-Authenticated", [], [], [], ["witness-time-invalid"], [], NA),
    # item 7 - wire observer_relationship "independent" while the referenced Execution
    # fails authentication for a NON-signature reason. s0 observer path + design s4/s2;
    # effective assessment unknown, primary Effect class unaffected. Verdict shape is the
    # pinned s7 OB4 row.
    "OBX1": ("AIREP-Authenticated", [], [], [], [], NWS, "unknown"),
    "OBX2": ("AIREP-Authenticated", [], [], [], [], NWS, "unknown"),
    # item 8 - operator-document closure / container variants (s9 E-4, R-3, R-8).
    "MC1": ("AIREP-Core", [], ["producer-binding-malformed"], [], [],
            ["witness-binding-malformed"], NA),
    "MC2": ("AIREP-Authenticated", [], [], [], [], ["independence-policy-malformed"], NA),
    "MC3": ("AIREP-Core", [], ["producer-revocation-state-malformed"], [], [],
            ["witness-revocation-state-malformed"], NA),
    "MC4": ("AIREP-Core", [], ["producer-binding-malformed"], [], [], NWS, NA),
}

C1_ORDER = ["ORD1", "ORD2", "CTL1", "NG1",
            "LEX1", "LEX2", "LEX3",
            "TI1", "TI2",
            "OBX1", "OBX2",
            "MC1", "MC2", "MC3", "MC4"]

PROBES: list[dict] = []


def control_body(chain_id: str, record_id: str, sequence: int = 0,
                 producer: str = PRODUCER_WIRE, previous: str = GENESIS,
                 decision_record_id: str = "cv-rec-decision-1") -> dict:
    b = core_members("control", chain_id, record_id, sequence, producer, previous)
    b["decision_ref"] = {"chain_id": chain_id, "record_id": decision_record_id}
    b["instruction_id"] = "instr-1"
    b["instruction_digest"] = "sha256:" + "ab" * 32
    b["authorized_action_digest"] = "sha256:" + "ab" * 32
    b["control_event"] = "dispatched"
    b["boundary_side"] = "issuer"
    b["authority"] = {"issuer_id": "acme-control-plane",
                      "writable_by_controlled_system": False}
    b["evidence"] = [{"type": "policy", "ref": "ref:policy-1", "resolvable": False,
                      "content_hash": "sha256:" + "ef" * 32}]
    return b


def build_c1_cases() -> None:
    # ============ item 1: UTF-8 byte order vs JavaScript UTF-16 code-unit order ========
    # Two records in ONE chain whose record_ids differ first at the discriminating scalar.
    # UTF-8:  ...ef bc 80  (U+FF00)  <  ...f0 90 80 80 (U+10000)   -> ORD2 before ORD1
    # UTF-16: ...ff00      (U+FF00)  >  ...d800 dc00   (U+10000)   -> ORD1 before ORD2
    # The corpus-directory order (ORD1, ORD2) deliberately AGREES with the wrong (UTF-16)
    # order, so a directory-order emitter fails the same gate.
    ord1 = seal(decision_body(ORD_CHAIN, ORD_SUPP_REC))
    emit("ORD1", "clean Decision whose record_id ends U+10000 (UTF-8 f0 90 80 80); the "
                 "batch results file must order it AFTER ORD2 under the s2 UTF-8 byte rule",
         request(ord1),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    ord2 = seal(decision_body(ORD_CHAIN, ORD_BMP_REC, sequence=1,
                              previous=ord1["integrity"]["current"]))
    emit("ORD2", "clean Decision in the SAME chain whose record_id ends U+FF00 (UTF-8 "
                 "ef bc 80); the batch results file must order it BEFORE ORD1",
         request(ord2),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    # ============ item 9: Control-family Authenticated positive =======================
    ctl = seal(control_body("cv-chain-ctl1", "cv-rec-ctl1"))
    emit("CTL1", "clean Control Evidence artifact, all operator inputs supplied, no "
                 "head_witness in the request (the corpus's first control-family case)",
         request(ctl),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())

    # ============ item 10: non-genesis Witnessed head (sequence > 0, length > 1) =======
    ng_prev = seal(decision_body("cv-chain-ng1", "cv-rec-ng1-prev"))
    ng_head = seal(decision_body("cv-chain-ng1", "cv-rec-ng1", sequence=1,
                                 previous=ng_prev["integrity"]["current"]))
    ng_claim = claim_for(ng_head, length=2)
    emit("NG1", "clean witness over a NON-GENESIS chain head: claim.sequence=1 and "
                "claim.length=2 (the referenced head included), the predecessor supplied "
                "as a related artifact",
         request(ng_head, related=[ng_prev],
                 head_witness=witness_block(head_ref(ng_head), ng_claim,
                                            sign_witness("0.2", ng_claim))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True,
         related_sig_ok={"cv-rec-ng1-prev": True})

    # ============ item 5: E-1 witness-claim source-token spellings ====================
    # The signature is genuine over the claim's CANONICAL bytes: RFC 8785 / ES6 number
    # serialization renders 1e0, 1.0 and -0 to exactly the digits of 1, 1 and 0, so the
    # wire claim and the semantic claim canonicalize identically. The ONLY defect is the
    # source spelling - which is precisely what a post-parse integer check cannot see.
    def lexical_case(cid: str, member: str, token: str, desc: str) -> None:
        art = seal(decision_body(f"cv-chain-{cid.lower()}", f"cv-rec-{cid.lower()}"))
        semantic = claim_for(art)
        wire = dict(semantic)
        wire[member] = raw_token(token)
        emit(cid, desc,
             request(art, head_witness=witness_block(head_ref(art), wire,
                                                     sign_witness("0.2", semantic))),
             bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
             independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
             head_matches=1, head_is_primary=True, claim_semantic=semantic,
             raw_check={"member": member, "token": token,
                        "semantic_value": semantic[member]})

    lexical_case("LEX1", "length", "1e0",
                 "witness claim whose length is written 1e0 - semantically 1, but the "
                 "source token fails ^(0|[1-9][0-9]*)$ (s9 E-1)")
    lexical_case("LEX2", "length", "1.0",
                 "witness claim whose length is written 1.0 - semantically 1, but the "
                 "source token fails ^(0|[1-9][0-9]*)$ (s9 E-1)")
    lexical_case("LEX3", "sequence", "-0",
                 "witness claim whose sequence is written -0 - semantically 0, but the "
                 "source token carries a sign and fails ^(0|[1-9][0-9]*)$ (s9 E-1)")

    # ============ item 6: Gregorian-invalid witnessed_at, with and without a clock =====
    def time_case(cid: str, desc: str, clock) -> None:
        art = seal(decision_body(f"cv-chain-{cid.lower()}", f"cv-rec-{cid.lower()}"))
        cl = claim_for(art, witnessed_at=BAD_GREGORIAN_AT)
        emit(cid, desc,
             request(art, head_witness=witness_block(head_ref(art), cl,
                                                     sign_witness("0.2", cl))),
             bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
             independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock,
             head_matches=1, head_is_primary=True)

    time_case("TI1", f"claim.witnessed_at is {BAD_GREGORIAN_AT} (format-conformant, "
                     f"February 30 is not a Gregorian date); NO clock input supplied",
              _OMIT)
    time_case("TI2", f"identical Gregorian-invalid claim.witnessed_at {BAD_GREGORIAN_AT} "
                     f"with the clock input fully supplied - the paired control that "
                     f"makes 6c's clock-independence measurable", clock_doc())

    # ============ item 7: wire `independent` over a non-Authenticated Execution ========
    # OB4 already covers the invalid-signature route. These two cover the OTHER two ways
    # the referenced Execution fails to reach Authenticated in its own right.
    def observer_case(cid: str, desc: str, *, bindings, revocation, independence) -> None:
        chain = f"cv-chain-{cid.lower()}"
        dec = seal(decision_body(chain, "cv-rec-decision-1"))
        ex = seal(execution_body(chain, "cv-rec-execution-1", sequence=1,
                                 producer=EXECUTOR_WIRE,
                                 previous=dec["integrity"]["current"]), sk=_xsk)
        eff = seal(effect_body(chain, f"cv-rec-{cid.lower()}", head_ref(ex), "independent",
                               sequence=2, previous=ex["integrity"]["current"]))
        emit(cid, desc, request(eff, related=[dec, ex]),
             bindings=bindings, revocation=revocation, independence=independence,
             clock=clock_doc(),
             related_sig_ok={"cv-rec-decision-1": True, "cv-rec-execution-1": True})

    observer_case("OBX1",
                  "Effect declares independent; the referenced Execution is hash-consistent "
                  "and correctly signed under its own binding, but the revocation snapshot "
                  "marks that executor binding revoked, so it cannot reach Authenticated",
                  bindings=bindings_doc(executor=True),
                  revocation=revocation_doc([B_PRODUCER, B_WITNESS, B_EXECUTOR],
                                            {B_EXECUTOR: "revoked"}),
                  independence=independence_doc([(B_PRODUCER, B_EXECUTOR)]))

    observer_case("OBX2",
                  "Effect declares independent; the referenced Execution is hash-consistent "
                  "and correctly signed, but producer_bindings carries no entry for its wire "
                  "producer id, so its Authenticated tier is not evaluable",
                  bindings=bindings_doc(executor=False),
                  revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
                  independence=independence_doc([(B_PRODUCER, B_WITNESS)]))

    # ============ item 8: operator-document closure / container variants ===============
    # MC1 - unknown member at the TOP LEVEL of the binding store. s9 E-4 closes the whole
    # document; s9 R-8 states in terms that the producer path still "does reach the gate"
    # on a malformed store, and R-8 7b that a malformed store yields the witness reason.
    art = seal(decision_body("cv-chain-mc1", "cv-rec-mc1"))
    cl = claim_for(art)
    b = bindings_doc()
    b["note"] = "member foreign to the s1.1 binding-store document"
    emit("MC1", "binding store carrying an unknown top-level member; artifact, witness, "
                "revocation, policy and clock are otherwise clean and supplied",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # MC2 - required container ABSENT from the independence policy document (s1.2 + E-4).
    art = seal(decision_body("cv-chain-mc2", "cv-rec-mc2"))
    cl = claim_for(art)
    ind = independence_doc([(B_PRODUCER, B_WITNESS)])
    del ind["non_independent_pairs"]
    emit("MC2", "independence policy document missing its required non_independent_pairs "
                "container; everything else clean and supplied",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=ind, clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # MC3 - unknown member at the top level of the revocation snapshot document (E-4).
    art = seal(decision_body("cv-chain-mc3", "cv-rec-mc3"))
    cl = claim_for(art)
    rev = revocation_doc([B_PRODUCER, B_WITNESS])
    rev["note"] = "member foreign to the s1.3 revocation-snapshot document"
    emit("MC3", "revocation snapshot carrying an unknown top-level member; bindings, "
                "policy, clock and the witness itself are clean",
         request(art, head_witness=witness_block(head_ref(art), cl, sign_witness("0.2", cl))),
         bindings=bindings_doc(), revocation=rev,
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc(),
         head_matches=1, head_is_primary=True)

    # MC4 - s9 R-3 worked example: unknown member INSIDE the referenced binding entry AND
    # trusted:false on that same entry. No head_witness is supplied, so the witness path
    # never resolves a binding and the case isolates the producer-side precedence question.
    art = seal(decision_body("cv-chain-mc4", "cv-rec-mc4"))
    b = bindings_doc()
    b["bindings"][B_PRODUCER]["trusted"] = False
    b["bindings"][B_PRODUCER]["note"] = "member foreign to the s1.1 binding entry"
    emit("MC4", "producer binding entry carrying BOTH an unknown member and trusted:false "
                "(s9 R-3 worked example); no head_witness supplied",
         request(art), bindings=b, revocation=revocation_doc([B_PRODUCER, B_WITNESS]),
         independence=independence_doc([(B_PRODUCER, B_WITNESS)]), clock=clock_doc())


# --------------------------------------------------------------------------------------
# C1 probe fixtures — CLI / process-exit surfaces. NOT verdict cases: no expected.json is
# ever written under corpus/probes/, and probes live outside corpus/cases/, so a scoring
# harness that enumerates cases cannot pick them up.
# --------------------------------------------------------------------------------------
def probe(probe_id: str, description: str, kind: str, clauses: list[str],
          argv: list[str], expected_exit: int, *, files: dict | None = None,
          raw_files: dict | None = None, expected_results_file: bool = False,
          must_not_create: list[str] | None = None) -> None:
    if any(p["probe_id"] == probe_id for p in PROBES):
        stop(f"duplicate probe id {probe_id}")
    PROBES.append({"probe_id": probe_id, "description": description, "kind": kind,
                   "clauses": clauses, "argv": argv, "expected_exit": expected_exit,
                   "expected_results_file": expected_results_file,
                   "must_not_create": must_not_create or [],
                   "_files": files or {}, "_raw_files": raw_files or {}})


def _clean_operator_files() -> dict:
    return {"bindings.json": bindings_doc(),
            "revocation.json": revocation_doc([B_PRODUCER, B_WITNESS]),
            "independence.json": independence_doc([(B_PRODUCER, B_WITNESS)])}


def _single_request_argv(extra: list[str] | None = None) -> list[str]:
    return ["${VERIFIER}",
            "--request", "${PROBE}/request.json",
            "--bindings", "${PROBE}/bindings.json",
            "--revocation", "${PROBE}/revocation.json",
            "--independence-policy", "${PROBE}/independence.json",
            "--now", NOW, "--freshness-window", str(WINDOW)] + (extra or [])


def build_probes() -> None:
    # ---- item 2: duplicate (chain_id, record_id) tuple in one batch (s9 R-10) ---------
    dup_files = {}
    dup_index = []
    for suffix, assertion in (("D1", "first record under the duplicated tuple"),
                              ("D2", "second, byte-different record under the SAME tuple")):
        body = decision_body("cv-chain-dup", "cv-rec-dup")
        body["claim"]["assertion"] = assertion
        art = seal(body)
        entry = {}
        for name, doc in (("request", request(art)),
                          ("bindings", bindings_doc()),
                          ("revocation", revocation_doc([B_PRODUCER, B_WITNESS])),
                          ("independence", independence_doc([(B_PRODUCER, B_WITNESS)])),
                          ("clock", clock_doc())):
            rel = f"corpus/cases/{suffix}/{name}.json"
            dup_files[rel] = doc
            entry[name] = f"cases/{suffix}/{name}.json"
        dup_index.append({"case_id": suffix,
                          "description": f"clean Decision; {assertion}",
                          "files": entry})
    dup_files["corpus/case_index.json"] = dup_index
    probe("PRB-DUP-TUPLE",
          "batch of two individually clean cases whose primary artifacts carry the SAME "
          "(chain_id, record_id) tuple with different bytes",
          "run_invalidity",
          ["CLASS_VERIFIER_CONTRACT.md s2 (results file / duplicate tuple)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 1: batch-level run-identity invariant)",
           "CLASS_VERIFIER_CONTRACT.md s9 R-10"],
          ["${VERIFIER}", "--corpus", "${PROBE}/corpus", "--out", "${OUT}"],
          1, files=dup_files, must_not_create=["${OUT}"])

    # ---- item 3: stage-0 schema-invalid ---------------------------------------------
    # The `claim` member (decision.schema.json required) is removed BEFORE sealing, so the
    # artifact is hash-consistent for the bytes as presented: the only defect is schema.
    body = decision_body("cv-chain-prb-schema", "cv-rec-prb-schema")
    del body["claim"]
    probe("PRB-SCHEMA-INVALID",
          "primary artifact is hash-consistent but omits the schema-required `claim` "
          "member, so it is not a well-formed v0.2 Decision Receipt",
          "run_invalidity",
          ["CLASS_VERIFIER_CONTRACT.md s3 stage 0",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 1: stage-0 artifact validity failed)"],
          _single_request_argv(), 1,
          files=dict(_clean_operator_files(), **{"request.json": request(seal(body))}))

    # ---- item 3: stage-1 hash-invalid ------------------------------------------------
    art = seal(decision_body("cv-chain-prb-hash", "cv-rec-prb-hash"))
    art["claim"]["assertion"] = "mutated after sealing"   # inside the hash preimage
    probe("PRB-HASH-INVALID",
          "primary artifact is schema-valid and its signature is well-formed, but a hashed "
          "member was mutated after sealing, so integrity.current does not recompute",
          "run_invalidity",
          ["CLASS_VERIFIER_CONTRACT.md s3 stage 1",
           "../INTEGRITY.md s2 (hash preimage) and s5 (tag selection is a function)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 1: stage-1 artifact validity failed)"],
          _single_request_argv(), 1,
          files=dict(_clean_operator_files(), **{"request.json": request(art)}))

    # ---- item 4: exit 1 - unparseable evaluation request -----------------------------
    probe("PRB-REQUEST-UNPARSEABLE",
          "the evaluation request file is not parseable JSON",
          "run_invalidity",
          ["CLASS_VERIFIER_CONTRACT.md s6.4 (exit 1: the evaluation request could not be "
           "parsed)"],
          _single_request_argv(), 1,
          files=_clean_operator_files(),
          raw_files={"request.json": '{"artifact": {"airep_version": "0.2",\n'})

    # ---- item 4: exit 1 - s9 R-7 / R-4 harness closure -------------------------------
    art = seal(decision_body("cv-chain-prb-hwnull", "cv-rec-prb-hwnull"))
    req = request(art)
    req["head_witness"] = None
    probe("PRB-HEADWITNESS-NULL",
          "head_witness is present but null (R-7: present-but-not-an-object is run-invalid, "
          "distinct from `entirely absent`, which is the no-witness-supplied WITHHELD path)",
          "run_invalidity",
          ["CLASS_VERIFIER_CONTRACT.md s9 R-7 (input table)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 1)"],
          _single_request_argv(), 1,
          files=dict(_clean_operator_files(), **{"request.json": req}))

    art = seal(decision_body("cv-chain-prb-hwunk", "cv-rec-prb-hwunk"))
    cl = claim_for(art)
    wb = witness_block(head_ref(art), cl, sign_witness("0.2", cl))
    wb["nonce"] = "member foreign to the s0 head_witness object"
    probe("PRB-HEADWITNESS-UNKNOWN-MEMBER",
          "an otherwise perfect head_witness carrying one member foreign to the s0 envelope",
          "run_invalidity",
          ["CLASS_VERIFIER_CONTRACT.md s0 (the envelope is closed)",
           "CLASS_VERIFIER_CONTRACT.md s9 R-7 (unknown member inside head_witness)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 1)"],
          _single_request_argv(), 1,
          files=dict(_clean_operator_files(),
                     **{"request.json": request(art, head_witness=wb)}))

    art = seal(decision_body("cv-chain-prb-hrunk", "cv-rec-prb-hrunk"))
    cl = claim_for(art)
    hr = head_ref(art)
    hr["hint"] = "member foreign to the s0 head_ref object"
    probe("PRB-HEADREF-UNKNOWN-MEMBER",
          "head_ref carrying an unknown member (R-4 keeps the nested closure on head_ref "
          "and signature, and only on those two)",
          "run_invalidity",
          ["CLASS_VERIFIER_CONTRACT.md s9 R-4",
           "CLASS_VERIFIER_CONTRACT.md s9 R-7 (final row of the input table)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 1)"],
          _single_request_argv(), 1,
          files=dict(_clean_operator_files(),
                     **{"request.json": request(art, head_witness=witness_block(
                         hr, cl, sign_witness("0.2", cl)))}))

    # ---- item 4: exit 2 - CLI usage / config surfaces --------------------------------
    clean = seal(decision_body("cv-chain-prb-cli", "cv-rec-prb-cli"))
    clean_files = dict(_clean_operator_files(), **{"request.json": request(clean)})

    probe("PRB-CLI-REQUEST-WITH-OUT",
          "single-request mode invoked together with --out; R-9 makes this a usage error, "
          "and the destination must be neither created nor modified",
          "cli_usage",
          ["CLASS_VERIFIER_CONTRACT.md s9 R-9 (invocation table, row 2)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 2: CLI usage error)"],
          _single_request_argv(["--out", "${OUT}"]), 2,
          files=clean_files, must_not_create=["${OUT}"])

    probe("PRB-CLI-CORPUS-NO-OUT",
          "batch mode invoked without --out",
          "cli_usage",
          ["CLASS_VERIFIER_CONTRACT.md s9 R-9 (invocation table, row 4)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 2)"],
          ["${VERIFIER}", "--corpus", "${CORPUS}"], 2)

    probe("PRB-CLI-REQUEST-AND-CORPUS",
          "--request and --corpus supplied together",
          "cli_usage",
          ["CLASS_VERIFIER_CONTRACT.md s9 R-9 (invocation table, row 5)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 2)"],
          ["${VERIFIER}", "--request", "${PROBE}/request.json",
           "--corpus", "${CORPUS}", "--out", "${OUT}"], 2,
          files=clean_files, must_not_create=["${OUT}"])

    probe("PRB-CLI-NOW-STRUCTURAL",
          "--now is structurally invalid (no T separator, no trailing Z)",
          "cli_usage",
          ["CLASS_VERIFIER_CONTRACT.md s1.4 (present but malformed => exit 2, no verdict)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 2)"],
          ["${VERIFIER}", "--request", "${PROBE}/request.json",
           "--bindings", "${PROBE}/bindings.json",
           "--revocation", "${PROBE}/revocation.json",
           "--independence-policy", "${PROBE}/independence.json",
           "--now", "2026-08-23 12:00:00", "--freshness-window", str(WINDOW)], 2,
          files=clean_files)

    probe("PRB-CLI-NOW-NOT-GREGORIAN",
          f"--now is {BAD_GREGORIAN_AT}: format-conformant but not a valid Gregorian "
          f"datetime. Pairs with verdict cases TI1/TI2, which carry the SAME bad date "
          f"inside the signed claim - there it is witness-time-invalid, here it is exit 2",
          "cli_usage",
          ["CLASS_VERIFIER_CONTRACT.md s1.4 (`--now` ... not a valid Gregorian datetime "
           "=> exit 2)",
           "CLASS_VERIFIER_CONTRACT.md s6.4 (exit 2)"],
          ["${VERIFIER}", "--request", "${PROBE}/request.json",
           "--bindings", "${PROBE}/bindings.json",
           "--revocation", "${PROBE}/revocation.json",
           "--independence-policy", "${PROBE}/independence.json",
           "--now", BAD_GREGORIAN_AT, "--freshness-window", str(WINDOW)], 2,
          files=clean_files)

    probe("PRB-CLI-WINDOW-NEGATIVE",
          "--freshness-window is negative",
          "cli_usage",
          ["CLASS_VERIFIER_CONTRACT.md s1.4 (`--freshness-window` non-integer or negative "
           "=> exit 2)"],
          ["${VERIFIER}", "--request", "${PROBE}/request.json",
           "--bindings", "${PROBE}/bindings.json",
           "--revocation", "${PROBE}/revocation.json",
           "--independence-policy", "${PROBE}/independence.json",
           "--now", NOW, "--freshness-window", "-1"], 2,
          files=clean_files)

    probe("PRB-CLI-WINDOW-NONINTEGER",
          "--freshness-window is not an integer",
          "cli_usage",
          ["CLASS_VERIFIER_CONTRACT.md s1.4 (`--freshness-window` non-integer or negative "
           "=> exit 2)"],
          ["${VERIFIER}", "--request", "${PROBE}/request.json",
           "--bindings", "${PROBE}/bindings.json",
           "--revocation", "${PROBE}/revocation.json",
           "--independence-policy", "${PROBE}/independence.json",
           "--now", NOW, "--freshness-window", "3600.5"], 2,
          files=clean_files)

    # ---- item 4: --help --------------------------------------------------------------
    probe("PRB-CLI-HELP",
          "--help: exit 0, nothing evaluated, no verdict emitted",
          "help",
          ["CLASS_VERIFIER_CONTRACT.md s6.4 (`--help` - 0, with nothing evaluated and no "
           "verdict emitted)"],
          ["${VERIFIER}", "--help"], 0, must_not_create=["${OUT}"])


# Combined view used by emit()/write_corpus(): C0 rows are transcription, C1 rows are
# derivation. The two dicts stay separate so provenance is never blurred.
EXPECTED_ALL = dict(EXPECTED_APPENDIX)
EXPECTED_ALL.update(EXPECTED_C1)
ALL_ORDER = CASE_ORDER + C1_ORDER


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
            claim_for_sig = intent.get("claim_semantic") or hw["claim"]
            if wpub:
                got = verify_witness_sig("0.2", claim_for_sig, hw["signature"]["value"],
                                         wpub)
                assert_(f"{cid}:witness-signature-verifies=={intent['witness_sig_ok']}",
                        got == intent["witness_sig_ok"], f"observed {got}")
            if probe is None:
                probe = {"case_id": cid, "claim_jcs_hex": jcs(claim_for_sig).hex(),
                         "claim_jcs_sha256":
                             hashlib.sha256(jcs(claim_for_sig)).hexdigest(),
                         "witness_preimage_sha256": hashlib.sha256(
                             witness_preimage("0.2", claim_for_sig)).hexdigest()}

    # Transcription checks (over the copied appendix, not over any evaluation).
    assert_("appendix:c0-case-set-complete",
            sorted(EXPECTED_APPENDIX) == sorted(CASE_ORDER),
            f"{len(EXPECTED_APPENDIX)} pinned / {len(CASE_ORDER)} ordered")
    assert_("appendix:c1-case-set-complete",
            sorted(EXPECTED_C1) == sorted(C1_ORDER),
            f"{len(EXPECTED_C1)} derived / {len(C1_ORDER)} ordered")
    assert_("appendix:c0-c1-disjoint",
            not (set(EXPECTED_APPENDIX) & set(EXPECTED_C1)), "C1 must add, never redefine")
    assert_("appendix:case-set-complete",
            sorted(EXPECTED_ALL) == sorted(ALL_ORDER) ==
            sorted(c["case_id"] for c in CASES),
            f"{len(EXPECTED_ALL)} pinned+derived / {len(CASES)} built")
    # Every verdict case's primary artifact must carry a UNIQUE (chain_id, record_id):
    # a duplicate would make the whole batch run-invalid under s9 R-10. The duplicate
    # tuple lives ONLY inside the PRB-DUP-TUPLE probe corpus, deliberately.
    tuples = [(c["request"]["artifact"]["chain_id"], c["request"]["artifact"]["record_id"])
              for c in CASES]
    assert_("corpus:verdict-tuples-unique", len(set(tuples)) == len(tuples),
            f"{len(tuples) - len(set(tuples))} duplicate tuple(s)")
    for cid, row in EXPECTED_ALL.items():
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
    """Serialize a corpus document.

    The only non-obvious step is the raw-source-token substitution: a few C1 cases must
    pin the SOURCE SPELLING of a JSON number (s9 E-1), which json.dumps cannot emit. The
    builder carries those as marker STRINGS and this replaces `"@@RAW:1e0:RAW@@"` with the
    bare token `1e0`. The marker grammar occurs nowhere in C0 content, so C0 bytes are
    provably unaffected (asserted by the c0-preservation checks below).
    """
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=1) + "\n"
    return _RAW_RE.sub(lambda m: m.group(1), text)


def _check_raw_token(cid: str, text: str, case: dict) -> None:
    """Construction fidelity for the s9 E-1 lexical cases. Verifies that (a) the raw token
    reached the file, (b) it parses to the case's semantic value, (c) the wire claim and
    the signed semantic claim canonicalize to the SAME bytes — so the signature is valid
    and the ONLY defect is the source spelling — and (d) the token really does violate
    ^(0|[1-9][0-9]*)$. None of this evaluates the ladder."""
    import re as _re
    rc = case["_intent"]["raw_check"]
    member, token = rc["member"], rc["token"]
    assert_(f"{cid}:raw-marker-substituted", "@@RAW:" not in text, "marker left in file")
    assert_(f"{cid}:raw-token-present:{member}", f'"{member}": {token}' in text,
            f'expected literal `"{member}": {token}`')
    parsed = json.loads(text)["head_witness"]["claim"]
    assert_(f"{cid}:raw-token-parses-to-semantic-value",
            parsed[member] == rc["semantic_value"],
            f"{parsed[member]!r} != {rc['semantic_value']!r}")
    assert_(f"{cid}:wire-claim-canonicalizes-identically",
            jcs(parsed) == jcs(case["_intent"]["claim_semantic"]),
            "wire and semantic claims differ after RFC 8785")
    assert_(f"{cid}:raw-token-violates-E1-grammar",
            _re.fullmatch(r"(0|[1-9][0-9]*)", token) is None, token)


def _write_ordering(put, by_id) -> None:
    """The s2 batch results-file ordering expectation.

    This is a MECHANICAL application of the s2 sort rule (unsigned lexicographic order over
    each string's UTF-8 bytes, no Unicode normalization) to the corpus's own identifiers —
    it derives no class, no reason and no observer value. The discriminating pair is
    additionally pinned by hand, with its UTF-8 bytes written out, and cross-checked here.
    """
    rows = []
    for cid in ALL_ORDER:
        art = by_id[cid]["request"]["artifact"]
        rows.append({"case_id": cid, "chain_id": art["chain_id"],
                     "record_id": art["record_id"],
                     "chain_id_utf8_hex": art["chain_id"].encode("utf-8").hex(),
                     "record_id_utf8_hex": art["record_id"].encode("utf-8").hex()})
    rows.sort(key=lambda r: (r["chain_id"].encode("utf-8"),
                             r["record_id"].encode("utf-8")))
    for i, r in enumerate(rows):
        r["index"] = i

    pos = {r["case_id"]: r["index"] for r in rows}
    # Hand-pinned, from the byte values written out below — not from any sort.
    assert_("ordering:discriminating-pair-utf8-order", pos["ORD2"] < pos["ORD1"],
            "U+FF00 (ef bc 80) must precede U+10000 (f0 90 80 80) in UTF-8 byte order")
    assert_("ordering:discriminating-pair-utf16-would-invert",
            ORD_BMP_REC.encode("utf-16-be") > ORD_SUPP_REC.encode("utf-16-be"),
            "the pair must actually separate UTF-8 order from UTF-16 code-unit order")
    assert_("ordering:discriminating-pair-same-chain",
            by_id["ORD1"]["request"]["artifact"]["chain_id"] ==
            by_id["ORD2"]["request"]["artifact"]["chain_id"],
            "the pair must be separated by record_id, not chain_id")
    assert_("ordering:corpus-directory-order-is-the-wrong-order",
            ALL_ORDER.index("ORD1") < ALL_ORDER.index("ORD2"),
            "directory order must NOT accidentally equal the required order")

    put("ordering/expected_verdict_order.json", dump({
        "rule": "Results file: {\"verdicts\": [ ... ]} — a deterministically ordered "
                "array sorted by (chain_id, record_id) under unsigned lexicographic order "
                "over each string's UTF-8 byte sequence, with no Unicode normalization.",
        "clause": "CLASS_VERIFIER_CONTRACT.md s2 (Results file)",
        "scope": "A batch run over corpus/cases/ (all C0 + C1 verdict cases). For any "
                 "sub-batch the expected order is the induced subsequence of `order`. "
                 "corpus/probes/ is NOT part of a scored batch.",
        "derivation": "Mechanical application of the s2 rule to the corpus's own "
                      "identifiers. No class, reason set or observer value is involved. "
                      "The discriminating pair below is pinned by hand from its UTF-8 "
                      "bytes and cross-checked by builder assertions "
                      "ordering:discriminating-pair-*.",
        "discriminating_pair": {
            "purpose": "Separate UTF-8 byte order from JavaScript's native UTF-16 "
                       "code-unit order. Code-point order and UTF-8 byte order agree for "
                       "ALL valid Unicode scalar values (UTF-8 is order-preserving by "
                       "construction), so UTF-16 code-unit order is the only one of the "
                       "three that diverges: this fixture is a naive-JavaScript-sort "
                       "detector, which is the requirement's real runtime risk.",
            "unicode_validity": "Both record_ids end in a valid Unicode SCALAR value. No "
                                "lone surrogate is used anywhere in this corpus.",
            "chain_id": ORD_CHAIN,
            "first_expected": {
                "case_id": "ORD2", "record_id": ORD_BMP_REC,
                "final_scalar": "U+FF00",
                "record_id_utf8_hex": ORD_BMP_REC.encode("utf-8").hex(),
                "final_scalar_utf8_hex": "efbc80",
                "final_scalar_utf16be_hex": "ff00"},
            "second_expected": {
                "case_id": "ORD1", "record_id": ORD_SUPP_REC,
                "final_scalar": "U+10000",
                "record_id_utf8_hex": ORD_SUPP_REC.encode("utf-8").hex(),
                "final_scalar_utf8_hex": "f0908080",
                "final_scalar_utf16be_hex": "d800dc00"},
            "required_relative_order": ["ORD2", "ORD1"],
            "utf8_reasoning": "The two record_ids share the prefix `cv-rec-ord-`; the "
                              "first differing byte is ef (0xEF) against f0 (0xF0). "
                              "0xEF < 0xF0, so ORD2 precedes ORD1.",
            "utf16_reasoning": "In UTF-16 code units the first differing unit is ff00 "
                               "against the high surrogate d800. 0xD800 < 0xFF00, so a "
                               "native JavaScript string comparison yields ORD1 before "
                               "ORD2 — the OPPOSITE order, and a detectable failure.",
            "corpus_directory_order": ["ORD1", "ORD2"],
            "note": "The corpus-directory order deliberately AGREES with the wrong "
                    "(UTF-16) order, so emitting verdicts in directory order fails the "
                    "same gate."},
        "order": rows}))


def _write_probes(put) -> list:
    """CLI / process-exit probe fixtures. These are NOT verdict cases: no expected.json is
    written under corpus/probes/, and they live outside corpus/cases/."""
    entries = []
    for pr in PROBES:
        pid = pr["probe_id"]
        rels = []
        for rel, doc in sorted(pr["_files"].items()):
            put(f"probes/{pid}/{rel}", dump(doc))
            rels.append(rel)
        for rel, text in sorted(pr["_raw_files"].items()):
            put(f"probes/{pid}/{rel}", text)
            rels.append(rel)
        entries.append({k: pr[k] for k in
                        ("probe_id", "description", "kind", "clauses", "argv",
                         "expected_exit", "expected_results_file", "must_not_create")}
                       | {"files": sorted(rels)})
    put("probes/probe_index.json", dump({
        "note": "CLI / process-exit probes for the AIREP v0.2 class verifier. These "
                "fixtures assert PROCESS behaviour (exit code, whether a results file is "
                "emitted), never a class verdict. They carry no expected.json and live "
                "outside corpus/cases/ so no scoring harness can mistake them for scored "
                "cases. Expected exits are MANUALLY DERIVED FROM THE CITED NORMATIVE "
                "CLAUSES, WITHOUT EXECUTING EVALUATION LOGIC.",
        "placeholders": {
            "${VERIFIER}": "the class-verifier invocation under test (argv[0] and any "
                           "interpreter prefix); the probes assume nothing about it",
            "${PROBE}": "the absolute path of this probe's own directory, "
                        "corpus/probes/<probe_id>",
            "${CORPUS}": "the absolute path of the main corpus directory "
                         "(class-verification/corpus)",
            "${OUT}": "a results-file destination path that does NOT exist before the run"},
        "pass_criteria": "The process exit code equals expected_exit; a results file "
                         "exists afterwards iff expected_results_file is true; every path "
                         "in must_not_create is absent after the run.",
        "probes": entries}))
    return entries


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

    index, c1_index = [], []
    by_id = {c["case_id"]: c for c in CASES}
    for cid in ALL_ORDER:
        case = by_id[cid]
        entry_files = {}
        for name, doc in (("request", case["request"]), ("bindings", case["bindings"]),
                          ("independence", case["independence"]),
                          ("revocation", case["revocation"]), ("clock", case["clock"])):
            if doc is None or isinstance(doc, _Omit):
                continue          # file omitted entirely: that input was not supplied
            rel = f"cases/{cid}/{name}.json"
            text = dump(doc)
            put(rel, text)
            entry_files[name] = rel
            if name == "request" and case["_intent"].get("raw_check"):
                _check_raw_token(cid, text, case)
        klass, af, aw, ac, wf, ww, obs = EXPECTED_ALL[cid]
        put(f"cases/{cid}/expected.json", dump({
            "class": klass,
            "authenticated_failures": af,
            "authenticated_withheld": aw,
            "authenticated_caveats": ac,
            "witnessed_failures": wf,
            "witnessed_withheld": ww,
            "observer_assessment": obs,
        }))
        entry = {"case_id": cid, "description": case["description"],
                 "files": entry_files}
        (index if cid in EXPECTED_APPENDIX else c1_index).append(entry)

    # case_index.json stays the C0 index, byte-for-byte. C1 cases are discoverable through
    # their own index, so no pre-existing corpus file changes.
    put("case_index.json", dump(index))
    put("c1_case_index.json", dump({
        "note": "C1 adversarial coverage extension. These case directories live alongside "
                "the C0 45 under cases/ and are scored exactly the same way; they are "
                "indexed separately only so that case_index.json stays byte-identical to "
                "its pre-C1 bytes. Expected values here are MANUALLY DERIVED FROM CITED "
                "NORMATIVE CLAUSES, WITHOUT EXECUTING EVALUATION LOGIC (see "
                "../C1_COVERAGE.md); the C0 45 are verbatim transcriptions of "
                "CLASS_VERIFIER_CONTRACT.md s7.",
        "cases": c1_index}))

    _write_ordering(put, by_id)
    probe_entries = _write_probes(put)

    # ---- C0 immutability proof (machine-checked, not asserted in prose) --------------
    c0_paths = sorted(n for n in files
                      if n == "case_index.json"
                      or (n.startswith("cases/") and n.split("/")[1] in EXPECTED_APPENDIX))
    c0_agg = hashlib.sha256(
        "".join(f"{files[n]}  {n}\n" for n in c0_paths).encode("utf-8")).hexdigest()
    assert_("c0-preservation:file-count", len(c0_paths) == C0_FILE_COUNT_PRE_C1,
            f"{len(c0_paths)} != {C0_FILE_COUNT_PRE_C1}")
    assert_("c0-preservation:aggregate-unchanged",
            c0_agg == C0_AGGREGATE_SHA256_PRE_C1,
            f"{c0_agg} != {C0_AGGREGATE_SHA256_PRE_C1}")

    agg = "".join(f"{files[n]}  {n}\n" for n in sorted(files))
    return {"files": files, "c0_paths": c0_paths, "c0_aggregate_sha256": c0_agg,
            "probes": probe_entries,
            "aggregate_sha256": hashlib.sha256(agg.encode("utf-8")).hexdigest()}


def main() -> int:
    build_cases()
    build_c1_cases()
    build_probes()
    probes = self_validate()
    out = write_corpus()
    failed = [a for a in ASSERTIONS if not a["passed"]]
    manifest = {
        "corpus": "AIREP v0.2 class-verification adversarial corpus (CLASS_VERIFIER_CONTRACT s7)",
        "builder": "build_class_corpus.py (third-context harness; NOT a class verifier)",
        "aggregate_sha256": out["aggregate_sha256"],
        "aggregate_rule": (
            "sha256 of the concatenation, in ASCII-ascending order of corpus-relative "
            "path strings, of UTF-8 lines '<sha256>  <relative-path>\\n', where "
            "<sha256> is the recorded digest for that path. The sort key is the "
            "relative path, NOT the assembled line and NOT the hash prefix; each line "
            "is built AFTER the sort. Paths are relative to class-verification/corpus/."
        ),
        "case_count": len(ALL_ORDER),
        "c0_case_count": len(CASE_ORDER),
        "c1_case_count": len(C1_ORDER),
        "probe_count": len(PROBES),
        "file_count": len(out["files"]),
        "c0_preservation": {
            "claim": "The C0 45 cases and their expected values are bit-for-bit unchanged; "
                     "C1 is strictly additive.",
            "c0_paths": "case_index.json + cases/<C0 case id>/* (the exact file set the "
                        "pre-C1 manifest covered)",
            "c0_file_count": len(out["c0_paths"]),
            "c0_file_count_pre_c1": C0_FILE_COUNT_PRE_C1,
            "c0_aggregate_sha256": out["c0_aggregate_sha256"],
            "c0_aggregate_sha256_pre_c1": C0_AGGREGATE_SHA256_PRE_C1,
            "unchanged": out["c0_aggregate_sha256"] == C0_AGGREGATE_SHA256_PRE_C1,
            "method": "The C0 subset of `files` is aggregated under the SAME aggregate_rule "
                      "and compared against the pre-C1 manifest's aggregate_sha256, which "
                      "covered exactly those 265 paths. Enforced by builder assertions "
                      "c0-preservation:file-count and c0-preservation:aggregate-unchanged; "
                      "a mismatch stops the build with MAINTAINER_FINDING.",
        },
        "extension": {
            "name": "C1 adversarial coverage extension",
            "c1_cases": C1_ORDER,
            "c1_probes": [pr["probe_id"] for pr in PROBES],
            "expected_value_provenance": {
                "c0": "verbatim transcription of the CLASS_VERIFIER_CONTRACT.md s7 "
                      "appendix rows",
                "c1": "manually derived from cited normative clauses, without executing "
                      "evaluation logic; derivation chains in C1_COVERAGE.md",
            },
            "coverage_document": "C1_COVERAGE.md",
        },
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
        "expected_values_note": "For the 45 C0 cases, cases/<CASE_ID>/expected.json is a "
                                "verbatim transcription of the CLASS_VERIFIER_CONTRACT s7 "
                                "appendix row. For the 15 C1 cases it is manually derived "
                                "from cited normative clauses, without executing evaluation "
                                "logic (derivation chains: C1_COVERAGE.md). Neither index "
                                "file carries expected values.",
    }
    (HERE / "corpus_manifest.json").write_text(dump(manifest), encoding="utf-8")
    print(f"class corpus: {len(ALL_ORDER)} cases "
          f"({len(CASE_ORDER)} C0 + {len(C1_ORDER)} C1), {len(PROBES)} probes, "
          f"{len(out['files'])} files, {len(ASSERTIONS)} self-checks "
          f"({len(failed)} failed)")
    print(f"C0 aggregate_sha256 = {out['c0_aggregate_sha256']} "
          f"({'UNCHANGED' if out['c0_aggregate_sha256'] == C0_AGGREGATE_SHA256_PRE_C1 else 'CHANGED'})")
    print(f"aggregate_sha256 = {out['aggregate_sha256']}")
    return 0 if not failed else 3


if __name__ == "__main__":
    sys.exit(main())
