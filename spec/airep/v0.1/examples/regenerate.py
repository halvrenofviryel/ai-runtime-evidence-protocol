#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the AIREP v0.1 example records with REAL integrity values.

The example records ship with genuinely computed hashes and signatures so a reader can
verify them — not placeholder digests. This script is the reproducible generator:

  integrity.current   = "sha256:" + SHA-256( canonical_form(record without current+signature) )
  integrity.signature = Ed25519 signature over the `current` string, hex-encoded

Canonicalization is RFC 8785 (JCS). These records are float-free or use simple decimals
whose Python `json.dumps` serialization is byte-identical to the ES6 Number-to-String form
JCS mandates, and all object keys are ASCII (so code-point order == UTF-16 order); therefore
`json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)` IS the JCS form here.
A full RFC 8785 library is a v0.2 item for arbitrary records (see STATUS.md).

The signing key is a FIXED, PUBLISHED test seed — for test vectors only, never production.
Run:  python3 regenerate.py   (rewrites the *_record.json files + test_public_key.txt)
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent

# FIXED published test seed (32 bytes). TEST ONLY — anyone can reproduce + verify.
TEST_SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
_sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(TEST_SEED_HEX))
_pub_hex = _sk.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

# A SECOND, DISTINCT published test seed for the chain_witness profile. The whole point of a
# head witness is that it is signed by a key INDEPENDENT of the producer (a producer-signed
# witness gives no truncation defense). This key models that independent witness.
WITNESS_SEED_HEX = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
_wsk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(WITNESS_SEED_HEX))
_wpub_hex = _wsk.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def canonical(obj) -> bytes:
    import sys
    cdir = str(HERE.parent / "conformance")
    if cdir not in sys.path:
        sys.path.insert(0, cdir)
    import jcs
    return jcs.canonicalize(obj)  # RFC 8785 (JCS) — see conformance/jcs.py


def compute_integrity(record: dict) -> dict:
    """Return the record with REAL integrity.current + integrity.signature."""
    integ = dict(record["integrity"])
    body = dict(record)
    # hash over the record with current+signature removed, previous (+canonical_json) retained
    body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
    current = "sha256:" + hashlib.sha256(canonical(body)).hexdigest()
    signature = _sk.sign(current.encode("utf-8")).hex()
    integ["current"] = current
    integ["signature"] = {"alg": "Ed25519", "value": signature}
    out = dict(record)
    out["integrity"] = integ
    return out


GENESIS = "sha256:" + "0" * 64


def _ptr(label: str) -> str:
    """A realistic out-of-band content pointer (sha256 of a label, not a placeholder)."""
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _chain_base():
    """A coherent governed-agent trajectory: release -> redact -> escalate -> defer -> release.
    Each record is a single governance decision; together they form one signed hash chain."""
    runtime, producer, trace = "phionyx-core", "phionyx/0.7.1", "trace-chain-example"

    def rec(i, verb, assertion, basis, evidence, covers, dnc, redacted=False):
        return {
            "airep_version": "0.1",
            "subject": {"runtime": runtime, "producer": producer, "decision_index": i,
                        "trace_id": trace, "timestamp_utc": f"2026-05-30T00:00:0{i}Z"},
            "input": {"input_ref": _ptr(f"chain-input-{i}"),
                      "governance_state": {"policy_version": "p1", "prior_context_bound": True}},
            "claim": {"assertion": assertion, "basis": basis},
            "output": {"result_ref": _ptr(f"chain-output-{i}"), "redacted": redacted},
            "evidence": evidence,
            "directive": {"verb": verb, "policy_basis": basis},
            "scope": {"covers": covers, "does_not_cover": dnc},
            "integrity": {"previous": GENESIS, "canonical_json": True},  # previous set in build_chain
        }

    return [
        rec(0, "release", "initial output released after safety+ethics gates passed",
            ["safety_gate", "ethics_gate"],
            [{"type": "policy", "ref": "policy://safety/v1", "resolvable": True}],
            ["safety gate fired", "ethics gate fired"], ["reasoning faithfulness not attested"]),
        rec(1, "redact", "a PII span in the follow-up output was redacted",
            ["pii_policy"],
            [{"type": "policy", "ref": "policy://pii/v2", "resolvable": True}],
            ["pii span redacted"], ["completeness of redaction not attested"], redacted=True),
        rec(2, "escalate_to_human", "a high-risk tool action was escalated to a human reviewer",
            ["risk_gate"],
            [{"type": "eval", "ref": "eval://risk_score/0.82", "resolvable": True},
             {"type": "policy", "ref": "policy://risk/v1", "resolvable": True}],
            ["risk score 0.82 exceeded threshold"], ["human decision not yet recorded"]),
        rec(3, "defer", "the action was deferred while awaiting human approval",
            ["hitl_queue"],
            [{"type": "policy", "ref": "policy://hitl/v1", "resolvable": True}],
            ["action held in review queue"], ["outcome pending"]),
        rec(4, "release", "the action was released after a human approved it",
            ["human_approval", "safety_gate"],
            [{"type": "human_approval", "ref": "approval://reviewer-7/ticket-1042", "resolvable": True},
             {"type": "policy", "ref": "policy://safety/v1", "resolvable": True}],
            ["human approval recorded", "safety gate re-fired"], ["reasoning faithfulness not attested"]),
    ]


def build_chain() -> None:
    """Compute each record's integrity in sequence (previous = prior current), sign, write chain.jsonl."""
    records = _chain_base()
    prev = GENESIS
    head = None
    out_lines = []
    for r in records:
        r["integrity"]["previous"] = prev
        r = compute_integrity(r)
        cur = r["integrity"]["current"]
        head = head or cur
        prev = cur
        out_lines.append(json.dumps(r, separators=(",", ":"), ensure_ascii=True))
    (HERE / "chain.jsonl").write_text("\n".join(out_lines) + "\n")
    print(f"chain.jsonl -> {len(records)} records, head={head[:23]}…, tail={prev[:23]}…")


def build_key_trust_example() -> None:
    """A record that declares its own signer's trust metadata inline under profiles.key_trust.
    Self-consistent: profiles.key_trust.public_key is the very key that signed integrity.signature."""
    rec = {
        "airep_version": "0.1",
        "subject": {"runtime": "any-runtime", "producer": "acme-governor/1.0",
                    "decision_index": 0, "timestamp_utc": "2026-05-30T00:00:00Z"},
        "input": {"input_ref": _ptr("kt-input"),
                  "governance_state": {"policy_version": "p1", "prior_context_bound": True}},
        "claim": {"assertion": "output released; the signer's key trust is declared inline",
                  "basis": ["safety_gate"]},
        "output": {"result_ref": _ptr("kt-output"), "redacted": False},
        "evidence": [{"type": "policy", "ref": "policy://safety/v1", "resolvable": True}],
        "directive": {"verb": "release", "policy_basis": ["safety_gate"]},
        "scope": {"covers": ["safety gate fired"],
                  "does_not_cover": ["key issuer not independently corroborated"]},
        "integrity": {"previous": GENESIS, "canonical_json": True},
        "profiles": {"key_trust": {
            "key_id": "airep-test-key-1",
            "issuer": "self",
            "algorithm": "Ed25519",
            "public_key": {"format": "raw_hex", "value": _pub_hex},
            "validity": {"not_before": "2026-05-30T00:00:00Z"},
            "transparency_log": {"log_url": "https://example.org/airep-log", "log_id": "demo-log",
                                 "leaf_index": 0, "inclusion_proof": _ptr("kt-inclusion")},
            "revocation": {"revoked": False},
        }},
    }
    rec = compute_integrity(rec)
    (HERE / "key_trust_record.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(f"key_trust_record.json -> {rec['integrity']['current']}")


def _witness_head(chain_id: str, head: dict) -> dict:
    """Sign the head claim {chain_id, decision_index, current, length} with the INDEPENDENT
    witness key, returning the profiles.chain_witness.witness object. The claim is canonicalized
    (RFC 8785) so the witness signs the exact bytes a verifier re-derives."""
    claim = {"chain_id": chain_id, "decision_index": head["decision_index"],
             "current": head["current"], "length": head["length"]}
    value = _wsk.sign(canonical(claim)).hex()
    return {"witness_id": "airep-test-witness-1", "alg": "Ed25519", "value": value}


def build_chain_witness_example() -> None:
    """A 3-record chain whose TAIL is a checkpoint carrying profiles.chain_witness — an absolute,
    independently-signed witness of the committed chain head (decision_index 1, length 2). This is
    the additional check AIREP-Trusted requires: the core only binds each record to its predecessor
    (relative), so dropping the tail is invisible; the witness pins length + head hash with a key
    DISTINCT from the producer, making truncation detectable. The checkpoint also carries key_trust,
    so it classifies AIREP-Trusted. rec0/rec1 are ordinary Verified-or-below records."""
    runtime, producer, trace = "phionyx-core", "phionyx/0.7.1", "trace-witness-example"
    chain_id = "airep:chain:witness-demo"

    def base(i, verb, assertion, covers, dnc):
        return {
            "airep_version": "0.1",
            "subject": {"runtime": runtime, "producer": producer, "decision_index": i,
                        "trace_id": trace, "timestamp_utc": f"2026-05-30T00:00:0{i}Z"},
            "input": {"input_ref": _ptr(f"witness-input-{i}"),
                      "governance_state": {"policy_version": "p1", "prior_context_bound": True}},
            "claim": {"assertion": assertion, "basis": ["safety_gate"]},
            "output": {"result_ref": _ptr(f"witness-output-{i}"), "redacted": False},
            "evidence": [{"type": "policy", "ref": "policy://safety/v1", "resolvable": True}],
            "directive": {"verb": verb, "policy_basis": ["safety_gate"]},
            "scope": {"covers": covers, "does_not_cover": dnc},
            "integrity": {"previous": GENESIS, "canonical_json": True},
        }

    rec0 = base(0, "release", "first governed decision; genesis of the witnessed chain",
                ["input safety gate passed"], ["downstream effects not tracked here"])
    rec1 = base(1, "release", "second governed decision; becomes the witnessed head",
                ["policy p1 satisfied"], ["model answer correctness not asserted"])

    # Compute rec0, rec1 integrity in sequence (the committed chain the witness attests).
    prev = GENESIS
    committed = []
    for r in (rec0, rec1):
        r["integrity"]["previous"] = prev
        r = compute_integrity(r)
        prev = r["integrity"]["current"]
        committed.append(r)
    head = {"decision_index": 1, "current": committed[1]["integrity"]["current"], "length": 2}

    # rec2 = the checkpoint. It does NOT witness itself (that would be circular); it witnesses the
    # committed chain rec0..rec1. Its own integrity is computed normally over the whole body.
    rec2 = base(2, "release", "checkpoint: independently witnesses the committed chain head",
                ["chain head pinned by an independent witness"],
                ["witness key trust is asserted, not externally corroborated here"])
    rec2["integrity"]["previous"] = head["current"]
    rec2["profiles"] = {
        "key_trust": {
            "key_id": "airep-test-key-1", "issuer": "self", "algorithm": "Ed25519",
            "public_key": {"format": "raw_hex", "value": _pub_hex},
            "validity": {"not_before": "2026-05-30T00:00:00Z"},
            "revocation": {"revoked": False},
        },
        "chain_witness": {
            "chain_id": chain_id,
            "head": head,
            "witness": _witness_head(chain_id, head),
            "freshness": {"witness_timestamp_utc": "2026-05-30T00:00:05Z"},
            "revocation_checked": True,
        },
    }
    rec2 = compute_integrity(rec2)

    out = committed + [rec2]
    lines = [json.dumps(r, separators=(",", ":"), ensure_ascii=True) for r in out]
    (HERE / "chain_witness.jsonl").write_text("\n".join(lines) + "\n")
    (HERE / "witness_public_key.txt").write_text(_wpub_hex + "\n")
    print(f"chain_witness.jsonl -> 3 records; witnessed head={head['current'][:23]}… length={head['length']}")
    print(f"witness_public_key.txt -> {_wpub_hex}")


def build_eu_ai_act_example() -> None:
    """A high-risk system decision carrying EU AI Act record-keeping fields under
    profiles.eu_ai_act_log. No raw personal data — the verifier is a pseudonymous role."""
    rec = {
        "airep_version": "0.1",
        "subject": {"runtime": "any-runtime", "producer": "acme-hiring-ai/2.1",
                    "decision_index": 0, "timestamp_utc": "2026-05-30T09:00:00Z"},
        "input": {"input_ref": _ptr("euaa-input"),
                  "governance_state": {"policy_version": "hr-screening-v3", "prior_context_bound": True}},
        "claim": {"assertion": "CV-screening output released after human oversight confirmed it",
                  "basis": ["bias_gate", "human_oversight"]},
        "output": {"result_ref": _ptr("euaa-output"), "redacted": False},
        "evidence": [
            {"type": "policy", "ref": "policy://bias_test/v3", "resolvable": True},
            {"type": "human_approval", "ref": "approval://hr-reviewer-2", "resolvable": True}],
        "directive": {"verb": "release", "policy_basis": ["bias_gate", "human_oversight"]},
        "scope": {"covers": ["bias test run", "human oversight applied"],
                  "does_not_cover": ["fairness across every protected class not exhaustively tested"]},
        "integrity": {"previous": GENESIS, "canonical_json": True},
        "profiles": {"eu_ai_act_log": {
            "articles": ["12", "14", "19"],
            "system": {"risk_tier": "high_risk", "annex_iii_point": "4(a)",
                       "provider": "acme-hiring-ai", "deployer": "example-employer"},
            "use_period": {"start": "2026-05-30T09:00:00Z", "end": "2026-05-30T09:00:05Z"},
            "human_oversight": {"verifier_role": "hr-reviewer-2", "oversight_outcome": "confirmed"},
            "logging": {"automatically_generated": True, "retention_months": 12},
        }},
    }
    rec = compute_integrity(rec)
    (HERE / "eu_ai_act_record.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(f"eu_ai_act_record.json -> {rec['integrity']['current']}")


def build_governance_example() -> None:
    """A 'block' decision carrying TWO framework profiles at once (nist_ai_rmf + owasp_threat):
    a prompt-injection attempt blocked, mapped to NIST MEASURE and OWASP LLM01."""
    rec = {
        "airep_version": "0.1",
        "subject": {"runtime": "any-runtime", "producer": "acme-governor/1.0",
                    "decision_index": 0, "timestamp_utc": "2026-05-30T00:00:00Z"},
        "input": {"input_ref": _ptr("gov-input"),
                  "governance_state": {"policy_version": "p1", "prior_context_bound": True}},
        "claim": {"assertion": "input blocked: a prompt-injection attempt was detected",
                  "basis": ["injection_gate"]},
        "output": {"result_ref": _ptr("gov-output"), "redacted": False},
        "evidence": [{"type": "eval", "ref": "eval://injection_detector/0.93", "resolvable": True}],
        "directive": {"verb": "block", "policy_basis": ["injection_gate"]},
        "scope": {"covers": ["prompt-injection pattern matched"],
                  "does_not_cover": ["novel injection variants not guaranteed caught"]},
        "integrity": {"previous": GENESIS, "canonical_json": True},
        "profiles": {
            "nist_ai_rmf": {
                "function": "MEASURE", "category": "MEASURE-2.7",
                "trustworthiness": ["secure_resilient", "safe"],
                "measurement": {"metric": "injection_detector_score", "method": "classifier", "result": "0.93"},
            },
            "owasp_threat": {
                "catalogue": "owasp_llm", "threat_id": "LLM01", "threat_name": "Prompt Injection",
                "control": "injection_gate", "status": "blocked", "severity": "high",
            },
        },
    }
    rec = compute_integrity(rec)
    (HERE / "governance_record.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(f"governance_record.json -> {rec['integrity']['current']}")


def build_observability_example() -> None:
    """A governance decision carried over an OpenInference GUARDRAIL span, correlated to a
    distributed trace via profiles.observability_transport (span carries the current hash)."""
    rec = {
        "airep_version": "0.1",
        "subject": {"runtime": "any-runtime", "producer": "acme-governor/1.0",
                    "decision_index": 0, "timestamp_utc": "2026-05-30T00:00:00Z"},
        "input": {"input_ref": _ptr("obs-input"),
                  "governance_state": {"policy_version": "p1", "prior_context_bound": True}},
        "claim": {"assertion": "a PII span was redacted; the decision was emitted as a guardrail span",
                  "basis": ["pii_gate"]},
        "output": {"result_ref": _ptr("obs-output"), "redacted": True},
        "evidence": [{"type": "policy", "ref": "policy://pii/v2", "resolvable": True}],
        "directive": {"verb": "redact", "policy_basis": ["pii_gate"]},
        "scope": {"covers": ["pii span redacted"], "does_not_cover": ["downstream propagation not attested"]},
        "integrity": {"previous": GENESIS, "canonical_json": True},
        "profiles": {"observability_transport": {
            "transport": "openinference",
            "trace_id": _ptr("obs-trace")[7:39],   # 32 hex
            "span_id": _ptr("obs-span")[7:23],     # 16 hex
            "span_name": "governance.decision",
            "record_carrier": {"attribute_key": "airep.current", "carries": "current_hash"},
            "openinference": {"span_kind": "GUARDRAIL"},
        }},
    }
    rec = compute_integrity(rec)
    (HERE / "observability_record.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(f"observability_record.json -> {rec['integrity']['current']}")


def main() -> int:
    for name in ("neutral_record.json", "phionyx_profile_record.json"):
        path = HERE / name
        rec = json.loads(path.read_text())
        rec = compute_integrity(rec)
        path.write_text(json.dumps(rec, indent=2) + "\n")
        print(f"{name} -> {rec['integrity']['current']}")
    build_chain()
    build_key_trust_example()
    build_chain_witness_example()
    build_eu_ai_act_example()
    build_governance_example()
    build_observability_example()
    (HERE / "test_public_key.txt").write_text(
        "# AIREP v0.1 example signing key — TEST ONLY (published, never production).\n"
        "# Ed25519 raw public key (hex). Verifies integrity.signature over integrity.current.\n"
        f"# seed (test only): {TEST_SEED_HEX}\n"
        f"{_pub_hex}\n")
    print(f"public_key -> {_pub_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
