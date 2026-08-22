#!/usr/bin/env python3
"""WP-a01 Stage-4 deterministic corpus builder.

Builds the fixture corpus of FIXTURES.md from the frozen construction in ../INTEGRITY.md:
constructs each VALID object first, then applies each fixture's named tamper. Writes
corpus/<fixture_id>.json, corpus_manifest.json (per-file SHA-256, pinned aggregate SHA-256,
and the A1/S1 harness-assertion measurements).

Harness code only: this builder is NOT one of the two Stage-4 integrity verifiers and shares
no code with them. If any fixture cannot be produced from the frozen text as written, the
builder STOPS with STAGE1_REREVIEW_REQUIRED (STAGE4_CONTRACT s5).

Deterministic: fixed inputs, published TEST-ONLY seeds, RFC 8032 Ed25519 (deterministic),
sorted-key JSON with trailing newline. Two runs produce byte-identical files.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
V01_CONF = HERE.parent.parent / "v0.1" / "conformance"
V01_EXAMPLES = HERE.parent.parent / "v0.1" / "examples"

# RFC 8785 via the pre-existing v0.1 implementation (predates Stage 4).
_spec = importlib.util.spec_from_file_location("jcs", V01_CONF / "jcs.py")
_jcs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_jcs)


def jcs(obj) -> bytes:
    return _jcs.canonicalize(obj)


LF = b"\x0a"
SUITE = b"ed25519"
PRODUCER_SEED = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
WITNESS_SEED = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
NOW = "2026-08-22T12:00:00Z"
WINDOW = 3600
FRESH_AT = "2026-08-22T11:30:00Z"

_psk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRODUCER_SEED))
_wsk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(WITNESS_SEED))


def _pub_hex(sk: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


PRODUCER_PUB = _pub_hex(_psk)
WITNESS_PUB = _pub_hex(_wsk)
GENESIS = "sha256:" + "0" * 64


def tag(version: str, op: str, ctx: str) -> bytes:
    return f"AIREP/{version}/{op}/{ctx}".encode("ascii")


def current_for(body: dict, hash_tag: bytes) -> str:
    return "sha256:" + hashlib.sha256(hash_tag + LF + jcs(body)).hexdigest()


def sign_record(sig_tag: bytes, cur: str, sk=_psk) -> str:
    return sk.sign(sig_tag + LF + SUITE + LF + cur.encode("ascii")).hex()


def sign_witness(version: str, claim: dict, sk=_wsk, suite: bytes = SUITE) -> str:
    return sk.sign(tag(version, "sig", "head-witness") + LF + suite + LF + jcs(claim)).hex()


def base_body(ctx: str, chain_id: str, record_id: str, sequence: int, previous: str,
              version: str = "0.2") -> dict:
    return {
        "airep_version": version,
        "artifact_type": ctx,
        "chain_id": chain_id,
        "record_id": record_id,
        "sequence": sequence,
        "integrity": {"previous": previous},
        "payload": {"note": f"stage4 construction-test body ({ctx})"},
    }


def seal(body: dict, *, hash_tag: bytes | None = None, sig_tag: bytes | None = None,
         sep: bytes = LF, alg_label: str = "Ed25519", sig_suite: bytes = SUITE) -> dict:
    ctx, ver = body["artifact_type"], body["airep_version"]
    ht = hash_tag if hash_tag is not None else tag(ver, "hash", ctx)
    st = sig_tag if sig_tag is not None else tag(ver, "sig", ctx)
    cur = "sha256:" + hashlib.sha256(ht + sep + jcs(body)).hexdigest()
    sig = _psk.sign(st + LF + sig_suite + LF + cur.encode("ascii")).hex()
    art = json.loads(json.dumps(body))
    art["integrity"]["current"] = cur
    art["integrity"]["signature"] = {"alg": alg_label, "value": sig}
    return art


def envelope(fid: str, case: str, desc: str, inputs: dict, verdict: str, reasons: list) -> dict:
    return {"fixture_id": fid, "normative_case": case, "description": desc,
            "inputs": inputs, "expected": {"verdict": verdict, "reasons": reasons}}


def art_inputs(artifact, binding=True, suite="ed25519"):
    inp = {"artifact": artifact, "now": NOW, "freshness_window_seconds": WINDOW}
    if binding:
        inp["producer_binding"] = {"public_key_hex": PRODUCER_PUB, "suite": suite}
    return inp


def wit_inputs(heads: dict, witness: dict) -> dict:
    return {"head_artifacts": heads, "witness": witness,
            "producer_binding": {"public_key_hex": PRODUCER_PUB, "suite": "ed25519"},
            "witness_trust_store": {"stage4-witness-1": {"public_key_hex": WITNESS_PUB,
                                                          "suite": "ed25519", "trusted": True}},
            "now": NOW, "freshness_window_seconds": WINDOW}


def witness_block(head_ref: str, claim: dict, sig_hex: str, alg_label: str = "Ed25519") -> dict:
    return {"head_ref": head_ref, "witness_id": "stage4-witness-1", "claim": claim,
            "signature": {"alg": alg_label, "value": sig_hex}}


def claim_for(head: dict, length: int, witnessed_at: str) -> dict:
    return {"chain_id": head["chain_id"], "sequence": head["sequence"],
            "current": head["integrity"]["current"], "length": length,
            "witnessed_at": witnessed_at}


def build() -> None:
    CORPUS.mkdir(exist_ok=True)
    fixtures: list[dict] = []
    ctxs = ["decision", "control", "execution", "effect"]

    # ---- Positive controls -------------------------------------------------------------
    p_arts = {}
    for i, ctx in enumerate(ctxs, start=1):
        body = base_body(ctx, "s4-chain-A", f"s4-rec-p{i}", i - 1,
                         GENESIS if i == 1 else "sha256:" + f"{i-1:x}" * 64)
        art = seal(body)
        p_arts[ctx] = art
        fixtures.append(envelope(f"P{i}", "P", f"valid {ctx} artifact",
                                 art_inputs(art), "PASS", ["OK"]))
    head = p_arts["decision"]
    cl = claim_for(head, 1, FRESH_AT)
    fixtures.append(envelope("P5", "P", "valid witness verification over resolvable head",
                             wit_inputs({"H1": head}, witness_block("H1", cl, sign_witness("0.2", cl))),
                             "PASS", ["OK"]))

    # ---- A cases -----------------------------------------------------------------------
    b = base_body("decision", "s4-chain-B", "s4-rec-a1", 0, GENESIS)
    a1 = seal(b, hash_tag=tag("0.2", "hash", "control"))  # wrong-tag current, own declared type
    fixtures.append(envelope("A1-1", "A1", "current computed under control hash tag, presented as decision",
                             art_inputs(a1), "REJECT", ["HASH_MISMATCH"]))

    a2 = json.loads(json.dumps(seal(base_body("decision", "s4-chain-B", "s4-rec-a2", 0, GENESIS))))
    a2["artifact_type"] = "execution"
    fixtures.append(envelope("A2-1", "A2", "artifact_type rewritten to execution after sealing",
                             art_inputs(a2), "REJECT", ["HASH_MISMATCH"]))

    a3b = base_body("control", "s4-chain-B", "s4-rec-a3", 0, GENESIS)
    a3 = seal(a3b, sig_tag=tag("0.2", "sig", "decision"))  # signature over sig/decision preimage
    fixtures.append(envelope("A3-1", "A3", "control artifact carrying a sig/decision-preimage signature",
                             art_inputs(a3), "REJECT", ["SIGNATURE_INVALID"]))

    a4 = seal(base_body("decision", "s4-chain-B", "s4-rec-a4", 0, GENESIS))
    a4["integrity"]["signature"]["value"] = sign_witness("0.2", cl)  # witness sig as record sig
    fixtures.append(envelope("A4-1", "A4", "witness signature bytes presented as record signature",
                             art_inputs(a4), "REJECT", ["SIGNATURE_INVALID"]))

    cl4 = claim_for(head, 1, FRESH_AT)
    wsig_wrong = sign_record(tag("0.2", "sig", "decision"), head["integrity"]["current"])
    fixtures.append(envelope("A4-2", "A4", "record signature bytes presented as witness signature",
                             wit_inputs({"H1": head}, witness_block("H1", cl4, wsig_wrong)),
                             "REJECT", ["WITNESS_SIGNATURE_INVALID"]))

    v01 = json.loads((V01_EXAMPLES / "neutral_record.json").read_text(encoding="utf-8"))
    fixtures.append(envelope("A5-1", "A5", "genuine v0.1 record presented as v0.2 (aux: v0.1 verify.py still accepts it under v0.1 rules)",
                             art_inputs(v01), "REJECT", ["UNSUPPORTED_VERSION"]))

    b6 = base_body("decision", "s4-chain-B", "s4-rec-a6", 0, GENESIS)
    b6["artifact_type"] = "decision2"
    a6 = seal(b6, hash_tag=tag("0.2", "hash", "decision2"), sig_tag=tag("0.2", "sig", "decision2"))
    fixtures.append(envelope("A6-1", "A6", "syntactically valid but unregistered context decision2",
                             art_inputs(a6), "REJECT", ["UNREGISTERED_TAG"]))

    b7 = base_body("decision", "s4-chain-B", "s4-rec-a7", 0, GENESIS)
    b7["artifact_type"] = "Decision"
    a7 = seal(b7, hash_tag=b"AIREP/0.2/HASH/Decision", sig_tag=b"AIREP/0.2/SIG/Decision")
    fixtures.append(envelope("A7-1", "A7", "case-variant tag/context (registry is case-sensitive)",
                             art_inputs(a7), "REJECT", ["UNREGISTERED_TAG"]))

    a8 = seal(base_body("decision", "s4-chain-B", "s4-rec-a8", 0, GENESIS), sep=b"\x0d\x0a")
    fixtures.append(envelope("A8-1", "A8", "current computed with CRLF separator at production time",
                             art_inputs(a8), "REJECT", ["HASH_MISMATCH"]))

    b9 = base_body("decision", "s4-chain-B", "s4-rec-a9", 0, GENESIS)
    a9 = seal(b9, hash_tag=tag("0.3", "hash", "decision"), sig_tag=tag("0.3", "sig", "decision"))
    fixtures.append(envelope("A9-1", "A9", "declares 0.2 but sealed under 0.3 tags",
                             art_inputs(a9), "REJECT", ["HASH_MISMATCH"]))

    a92 = json.loads(json.dumps(seal(base_body("decision", "s4-chain-B", "s4-rec-a9b", 0, GENESIS))))
    a92["airep_version"] = "0.3"
    fixtures.append(envelope("A9-2", "A9", "valid 0.2 artifact; declared version rewritten to 0.3 after sealing",
                             art_inputs(a92), "REJECT", ["UNSUPPORTED_VERSION"]))

    cl10 = claim_for(head, 1, "2026-08-01T00:00:00Z")  # stale, signed
    w10 = witness_block("H1", cl10, sign_witness("0.2", cl10))
    w10["freshness_hint"] = NOW  # unsigned field set to now — must change nothing
    fixtures.append(envelope("A10-1", "A10", "stale signed witnessed_at; unsigned freshness_hint set to now",
                             wit_inputs({"H1": head}, w10), "REJECT", ["WITNESS_STALE"]))

    a11a = seal(base_body("decision", "s4-chain-B", "s4-rec-a11a", 0, GENESIS), alg_label="ECDSA-P256")
    fixtures.append(envelope("A11a-1", "A11", "valid signature; wire alg label rewritten to another suite name",
                             art_inputs(a11a), "PASS_WITH_CAVEAT", ["WIRE_ALG_IGNORED"]))

    a11b = seal(base_body("decision", "s4-chain-B", "s4-rec-a11b", 0, GENESIS), sig_suite=b"ed448")
    fixtures.append(envelope("A11b-1", "A11", "signature preimage embeds suite-id ed448; binding suite is ed25519",
                             art_inputs(a11b), "REJECT", ["SIGNATURE_INVALID"]))

    cl12 = claim_for(head, 1, FRESH_AT)
    fixtures.append(envelope("A12-1", "A12", "witness signature produced under 0.3 tag; head declares 0.2",
                             wit_inputs({"H1": head}, witness_block("H1", cl12, sign_witness("0.3", cl12))),
                             "REJECT", ["WITNESS_SIGNATURE_INVALID"]))

    cl13a = claim_for(head, 1, FRESH_AT)
    fixtures.append(envelope("A13a-1", "A13", "valid witness; wire-carried witness alg label rewritten",
                             wit_inputs({"H1": head}, witness_block("H1", cl13a, sign_witness("0.2", cl13a),
                                                                    alg_label="ECDSA-P256")),
                             "PASS_WITH_CAVEAT", ["WIRE_ALG_IGNORED"]))

    cl13b = claim_for(head, 1, FRESH_AT)
    fixtures.append(envelope("A13b-1", "A13", "witness preimage embeds suite-id ed448; trust-store suite is ed25519",
                             wit_inputs({"H1": head}, witness_block("H1", cl13b,
                                                                    sign_witness("0.2", cl13b, suite=b"ed448"))),
                             "REJECT", ["WITNESS_SIGNATURE_INVALID"]))

    # ---- S cases -----------------------------------------------------------------------
    s1_body = base_body("decision", "s4-chain-S", "s4-rec-s1", 0, GENESIS)
    s1 = seal(s1_body)
    fixtures.append(envelope("S1-1", "S1", "present-member subtraction: sealed artifact containing current+signature",
                             art_inputs(s1), "PASS", ["OK"]))
    probe_canonical = jcs(s1_body)
    s1_probe = {"canonical_body_sha256": hashlib.sha256(probe_canonical).hexdigest(),
                "current": current_for(s1_body, tag("0.2", "hash", "decision"))}
    if s1_probe["current"] != s1["integrity"]["current"]:
        print("STAGE1_REREVIEW_REQUIRED: S1 probe and sealed current diverge")
        sys.exit(3)

    cl_s2 = claim_for(head, 1, FRESH_AT)
    fixtures.append(envelope("S2-1", "S", "witness head_ref names a head absent from head_artifacts",
                             wit_inputs({"H1": head}, witness_block("H-missing", cl_s2, sign_witness("0.2", cl_s2))),
                             "REJECT", ["WITNESS_HEAD_UNRESOLVED"]))

    cl_s3 = dict(claim_for(head, 1, FRESH_AT), sequence=head["sequence"] + 1)
    fixtures.append(envelope("S3-1", "S", "claim sequence does not reconcile with the resolved head",
                             wit_inputs({"H1": head}, witness_block("H1", cl_s3, sign_witness("0.2", cl_s3))),
                             "REJECT", ["WITNESS_HEAD_MISMATCH"]))

    cl_s4 = claim_for(head, 1, "2026-06-30T23:59:60Z")
    fixtures.append(envelope("S4-1", "S", "witnessed_at leap second :60 (forbidden in v0.2)",
                             wit_inputs({"H1": head}, witness_block("H1", cl_s4, sign_witness("0.2", cl_s4))),
                             "REJECT", ["WITNESS_TIME_INVALID"]))

    cl_s42 = claim_for(head, 1, "2026-02-30T12:00:00Z")
    fixtures.append(envelope("S4-2", "S", "witnessed_at invalid calendar date (Feb 30)",
                             wit_inputs({"H1": head}, witness_block("H1", cl_s42, sign_witness("0.2", cl_s42))),
                             "REJECT", ["WITNESS_TIME_INVALID"]))

    s5 = seal(base_body("decision", "s4-chain-S", "s4-rec-s5", 0, GENESIS))
    fixtures.append(envelope("S5-1", "S", "no producer binding supplied; wire alg present",
                             art_inputs(s5, binding=False), "REJECT", ["KEY_BINDING_UNAVAILABLE"]))

    s52 = seal(base_body("decision", "s4-chain-S", "s4-rec-s5b", 0, GENESIS))
    fixtures.append(envelope("S5-2", "S", "binding names unsupported suite ed448",
                             art_inputs(s52, suite="ed448"), "REJECT", ["SUITE_UNSUPPORTED"]))

    # ---- Fidelity-gate additions (2026-08-22) ------------------------------------------
    cl_s61 = dict(claim_for(head, 1, FRESH_AT), note="extra")  # sixth member, genuinely signed
    fixtures.append(envelope("S6-1", "S", "claim with a sixth member; signature over the six-member JCS",
                             wit_inputs({"H1": head}, witness_block("H1", cl_s61, sign_witness("0.2", cl_s61))),
                             "REJECT", ["WITNESS_CLAIM_INVALID"]))

    cl_s62 = claim_for(head, 1, FRESH_AT)
    cl_s62["current"] = "sha256:" + cl_s62["current"][7:].upper()
    fixtures.append(envelope("S6-2", "S", "claim current with uppercase hex (violates exact lowercase form)",
                             wit_inputs({"H1": head}, witness_block("H1", cl_s62, sign_witness("0.2", cl_s62))),
                             "REJECT", ["WITNESS_CLAIM_INVALID"]))

    cl_s63 = dict(claim_for(head, 1, FRESH_AT), sequence=-1)
    fixtures.append(envelope("S6-3", "S", "claim sequence negative (violates non-negative safe integer)",
                             wit_inputs({"H1": head}, witness_block("H1", cl_s63, sign_witness("0.2", cl_s63))),
                             "REJECT", ["WITNESS_CLAIM_INVALID"]))

    head03 = seal(base_body("decision", "s4-chain-V3", "s4-rec-s7", 0, GENESIS, version="0.3"))
    cl_s7 = claim_for(head03, 1, FRESH_AT)
    fixtures.append(envelope("S7-1", "S", "head declares 0.3, sealed under 0.3 tags; witness genuinely signed under the 0.3 witness tag",
                             wit_inputs({"H1": head03}, witness_block("H1", cl_s7, sign_witness("0.3", cl_s7))),
                             "REJECT", ["UNSUPPORTED_VERSION"]))

    cl_s8 = claim_for(head, 1, FRESH_AT)
    s8_inputs = wit_inputs({"H1": head}, witness_block("H1", cl_s8, sign_witness("0.2", cl_s8)))
    del s8_inputs["witness_trust_store"]["stage4-witness-1"]["trusted"]  # no default-trust
    fixtures.append(envelope("S8-1", "S", "trust-store entry without the trusted member",
                             s8_inputs, "REJECT", ["KEY_BINDING_UNAVAILABLE"]))

    cl_s9 = claim_for(head, 1, "0099-12-31T23:30:00Z")
    s9_inputs = wit_inputs({"H1": head}, witness_block("H1", cl_s9, sign_witness("0.2", cl_s9)))
    s9_inputs["now"] = "0100-01-01T00:00:00Z"  # 30 real Gregorian minutes later
    fixtures.append(envelope("S9-1", "S", "valid witness across the 99->100 year boundary, 30 minutes inside the window",
                             s9_inputs, "PASS", ["OK"]))

    cl_s10 = claim_for(head, 1, "2026-08-22T11:00:00Z")  # exactly window seconds before now
    fixtures.append(envelope("S10-1", "S", "freshness distance exactly equal to the window (boundary-equal is fresh)",
                             wit_inputs({"H1": head}, witness_block("H1", cl_s10, sign_witness("0.2", cl_s10))),
                             "PASS", ["OK"]))

    # ---- Numeric-lexeme fixtures (final fidelity blocker, 2026-08-22) ------------------
    # Otherwise-valid, genuinely signed claims whose sequence/length carry a forbidden
    # LEXICAL spelling in the fixture source. JCS canonicalizes 1.0/1e0/-0.0 to the same
    # numeric bytes, so each signature is valid over the canonical claim; the claim-structure
    # step must reject on the source spelling before signature is evaluated. json.dumps
    # writes 1.0 natively; 1e0 and -0 are patched into the serialized text below
    # (LEXEME_PATCHES), and the presence of each exact lexeme is asserted into the manifest.
    head_n1 = seal(base_body("decision", "s4-chain-N", "s4-rec-n1", 1,
                             "sha256:" + "3" * 64))
    cl_64a = dict(claim_for(head_n1, 2, FRESH_AT), sequence=1.0)  # canonical 1 == head sequence
    fixtures.append(envelope("S6-4a", "S", "otherwise-valid signed claim; sequence lexically 1.0 in source",
                             wit_inputs({"H1": head_n1}, witness_block("H1", cl_64a, sign_witness("0.2", cl_64a))),
                             "REJECT", ["WITNESS_CLAIM_INVALID"]))

    cl_64b = dict(claim_for(head, 1, FRESH_AT), length=1.0)  # canonical 1; patched to 1e0 in source
    fixtures.append(envelope("S6-4b", "S", "otherwise-valid signed claim; length lexically 1e0 in source",
                             wit_inputs({"H1": head}, witness_block("H1", cl_64b, sign_witness("0.2", cl_64b))),
                             "REJECT", ["WITNESS_CLAIM_INVALID"]))

    cl_64c = dict(claim_for(head, 1, FRESH_AT), sequence=-0.0)  # canonical 0 == head sequence; patched to -0
    fixtures.append(envelope("S6-4c", "S", "otherwise-valid signed claim; sequence lexically -0 in source",
                             wit_inputs({"H1": head}, witness_block("H1", cl_64c, sign_witness("0.2", cl_64c))),
                             "REJECT", ["WITNESS_CLAIM_INVALID"]))

    # ---- A1 harness assertion ----------------------------------------------------------
    a1_body = base_body("decision", "s4-chain-B", "s4-rec-a1", 0, GENESIS)
    cur_dec = current_for(a1_body, tag("0.2", "hash", "decision"))
    cur_ctl = current_for(a1_body, tag("0.2", "hash", "control"))
    if cur_dec == cur_ctl:
        print("STAGE1_REREVIEW_REQUIRED: A1 tag divergence failed — identical current under two tags")
        sys.exit(3)

    # ---- Write fixtures + manifest -----------------------------------------------------
    LEXEME_PATCHES = {
        "S6-4b": ('"length": 1.0', '"length": 1e0'),
        "S6-4c": ('"sequence": -0.0', '"sequence": -0'),
    }
    LEXEME_PROOF = {"S6-4a": '"sequence": 1.0', "S6-4b": '"length": 1e0',
                    "S6-4c": '"sequence": -0'}
    numeric_lexemes = {}
    files = {}
    for fx in fixtures:
        path = CORPUS / f"{fx['fixture_id']}.json"
        data = json.dumps(fx, sort_keys=True, ensure_ascii=False, indent=1) + "\n"
        if fx["fixture_id"] in LEXEME_PATCHES:
            old, new = LEXEME_PATCHES[fx["fixture_id"]]
            if data.count(old) != 1:
                print(f"STAGE1_REREVIEW_REQUIRED: lexeme patch target not unique in {fx['fixture_id']}")
                sys.exit(3)
            data = data.replace(old, new)
        if fx["fixture_id"] in LEXEME_PROOF:
            lex = LEXEME_PROOF[fx["fixture_id"]]
            if lex not in data:
                print(f"STAGE1_REREVIEW_REQUIRED: lexeme {lex!r} absent from {fx['fixture_id']}")
                sys.exit(3)
            numeric_lexemes[fx["fixture_id"]] = {"lexeme": lex, "present_in_source": True}
        path.write_text(data, encoding="utf-8")
        files[path.name] = hashlib.sha256(data.encode("utf-8")).hexdigest()

    agg_lines = "".join(f"{files[name]}  {name}\n" for name in sorted(files))
    manifest = {
        "aggregate_sha256": hashlib.sha256(agg_lines.encode("utf-8")).hexdigest(),
        "aggregate_rule": "sha256 of concatenated ASCII-sorted UTF-8 lines '<sha256>  <relative-path>\\n' relative to stage4/corpus/",
        "files": files,
        "fixture_count": len(files),
        "harness_assertions": {
            "A1_tag_divergence": {"body": "s4-rec-a1 body", "current_under_decision_tag": cur_dec,
                                   "current_under_control_tag": cur_ctl, "distinct": cur_dec != cur_ctl},
            "S1_probe": s1_probe,
            "numeric_lexemes": numeric_lexemes,
        },
        "keys": {"producer_pubkey_hex": PRODUCER_PUB, "witness_pubkey_hex": WITNESS_PUB,
                 "note": "published TEST-ONLY seeds (see vectors/VECTOR_PLAN.md); never production"},
        "fixture_kind_rule": "inputs.witness present => witness-path fixture; otherwise artifact-path fixture; witness.head_ref names the key in inputs.head_artifacts",
    }
    (HERE / "corpus_manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"corpus: {len(files)} fixtures; aggregate {manifest['aggregate_sha256']}")


if __name__ == "__main__":
    build()
