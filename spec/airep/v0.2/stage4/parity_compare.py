#!/usr/bin/env python3
"""WP-a01 Stage-4 parity/evidence comparator.

Independent of both integrity verifiers: shares no code with either beyond the Python
stdlib and the pre-existing v0.1 RFC 8785 implementation (jcs.py), which predates Stage 4
and is not verifier code. Never invokes, imports, or reads the verifiers.

Checks (any failure => exit 1; PARITY_MANIFEST.md always written):
 1. Fixture-set equality: corpus ids == python results ids == node results ids
    (missing/extra fixture in either results file fails).
 2. Normalized-result SHAPE per STAGE4_CONTRACT s1 + s4, both files: enclosing key ==
    fixture_id; exactly the three contract fields; valid verdict; reasons non-empty,
    deduplicated, ASCII-ascending, all from the closed registry; PASS => exactly ["OK"];
    REJECT => exactly one reason; verdict-class enforcement per REASON_CODES (a reason
    paired with the wrong verdict class fails).
 3. Python <-> Node exact verdict/reasons parity per fixture.
 4. Agreed result == the fixture's expected outcome (read here, in the comparator ONLY —
    the verifiers never consult expected).
 5. Harness assertions re-measured from primitives:
    - A1 tag divergence: recompute current under decision and control hash tags from the
      A1-1 body; assert distinct AND equal to the manifest's recorded values.
    - S1 subtraction: perform the mechanical subtraction on the sealed S1-1 artifact HERE,
      compare EXACT canonical bytes against S1_probe.canonical_body_hex (not digest
      equality alone), plus sha256 and recomputed current against the probe and the sealed
      artifact's own integrity.current.
    - Numeric lexemes: assert the exact source lexemes recorded in the manifest are
      present in the on-disk fixture bytes.
 6. Corpus aggregate SHA-256 recomputed per the pinned rule and compared to the manifest.

Exit codes: 0 = full parity + expectation equality + all assertions; 1 = any failure;
2 = missing/unreadable input file.
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
MANIFEST_IN = HERE / "corpus_manifest.json"
RES_PY = HERE / "results" / "results_python.json"
RES_NODE = HERE / "results" / "results_node.json"
OUT = HERE / "PARITY_MANIFEST.md"

_spec = importlib.util.spec_from_file_location(
    "jcs", HERE.parent.parent / "v0.1" / "conformance" / "jcs.py")
_jcs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_jcs)

VERDICTS = {"PASS", "PASS_WITH_CAVEAT", "REJECT"}
REASON_CLASS = {
    "OK": "PASS",
    "WIRE_ALG_IGNORED": "PASS_WITH_CAVEAT",
    "UNSUPPORTED_VERSION": "REJECT", "UNREGISTERED_TAG": "REJECT",
    "HASH_MISMATCH": "REJECT", "SIGNATURE_INVALID": "REJECT",
    "WITNESS_CLAIM_INVALID": "REJECT", "WITNESS_SIGNATURE_INVALID": "REJECT",
    "WITNESS_HEAD_UNRESOLVED": "REJECT", "WITNESS_HEAD_MISMATCH": "REJECT",
    "WITNESS_TIME_INVALID": "REJECT", "WITNESS_STALE": "REJECT",
    "KEY_BINDING_UNAVAILABLE": "REJECT", "SUITE_UNSUPPORTED": "REJECT",
}


def die2(msg: str):
    print(f"ERROR: {msg}")
    sys.exit(2)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die2(f"cannot read {path}: {e}")


def shape_errors(name: str, key: str, res) -> list:
    errs = []
    if not isinstance(res, dict):
        return [f"{name}/{key}: result is not an object"]
    if set(res.keys()) != {"fixture_id", "verdict", "reasons"}:
        errs.append(f"{name}/{key}: fields {sorted(res.keys())} != contract fields")
        return errs
    if res["fixture_id"] != key:
        errs.append(f"{name}/{key}: enclosing key != fixture_id {res['fixture_id']!r}")
    v, rs = res.get("verdict"), res.get("reasons")
    if v not in VERDICTS:
        errs.append(f"{name}/{key}: invalid verdict {v!r}")
        return errs
    if not isinstance(rs, list) or not rs or not all(isinstance(r, str) for r in rs):
        errs.append(f"{name}/{key}: reasons must be a non-empty list of strings")
        return errs
    if len(set(rs)) != len(rs):
        errs.append(f"{name}/{key}: duplicate reasons")
    if rs != sorted(rs):
        errs.append(f"{name}/{key}: reasons not ASCII-ascending")
    for r in rs:
        if r not in REASON_CLASS:
            errs.append(f"{name}/{key}: unregistered reason {r!r}")
        elif REASON_CLASS[r] != v:
            errs.append(f"{name}/{key}: reason {r} belongs to class {REASON_CLASS[r]}, verdict is {v}")
    if v == "PASS" and rs != ["OK"]:
        errs.append(f"{name}/{key}: PASS must carry exactly ['OK']")
    if v == "REJECT" and len(rs) != 1:
        errs.append(f"{name}/{key}: REJECT must carry exactly one reason")
    return errs


def main() -> int:
    manifest = load_json(MANIFEST_IN)
    res_py = load_json(RES_PY).get("results")
    res_node = load_json(RES_NODE).get("results")
    if res_py is None or res_node is None:
        die2("results file missing top-level 'results'")

    fixtures = {}
    for p in sorted(CORPUS.glob("*.json")):
        fx = load_json(p)
        fixtures[fx["fixture_id"]] = fx

    failures: list = []

    # 1. fixture-set equality
    ids_c, ids_p, ids_n = set(fixtures), set(res_py), set(res_node)
    for label, ids in (("python", ids_p), ("node", ids_n)):
        miss, extra = sorted(ids_c - ids), sorted(ids - ids_c)
        if miss:
            failures.append(f"{label}: missing fixtures {miss}")
        if extra:
            failures.append(f"{label}: extra fixtures {extra}")

    # 6. corpus aggregate per pinned rule
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(CORPUS.glob("*.json"))}
    agg_lines = "".join(f"{files[n]}  {n}\n" for n in sorted(files))
    agg = hashlib.sha256(agg_lines.encode("utf-8")).hexdigest()
    if agg != manifest["aggregate_sha256"]:
        failures.append(f"aggregate mismatch: recomputed {agg} != manifest {manifest['aggregate_sha256']}")
    if files != manifest["files"]:
        failures.append("per-file sha256 set differs from manifest")

    # 2-4. shape, parity, expectation
    per_fx = []
    for fid in sorted(ids_c & ids_p & ids_n):
        a, b, exp = res_py[fid], res_node[fid], fixtures[fid]["expected"]
        errs = shape_errors("python", fid, a) + shape_errors("node", fid, b)
        agree = (a.get("verdict"), a.get("reasons")) == (b.get("verdict"), b.get("reasons"))
        if not agree:
            errs.append(f"parity mismatch: python {a.get('verdict')}/{a.get('reasons')} != node {b.get('verdict')}/{b.get('reasons')}")
        elif [a.get("verdict"), a.get("reasons")] != [exp["verdict"], exp["reasons"]]:
            errs.append(f"expectation mismatch: agreed {a.get('verdict')}/{a.get('reasons')} != expected {exp['verdict']}/{exp['reasons']}")
        failures.extend(errs)
        per_fx.append((fid, a, b, exp, errs))

    # 5. harness assertions from primitives
    ha = manifest["harness_assertions"]
    cur_d = cur_c = None
    a1 = fixtures.get("A1-1")
    if a1:
        body = json.loads(json.dumps(a1["inputs"]["artifact"]))
        body["integrity"] = {k: v for k, v in body["integrity"].items()
                             if k not in ("current", "signature")}
        cb = _jcs.canonicalize(body)
        cur_d = "sha256:" + hashlib.sha256(b"AIREP/0.2/hash/decision\n" + cb).hexdigest()
        cur_c = "sha256:" + hashlib.sha256(b"AIREP/0.2/hash/control\n" + cb).hexdigest()
        rec = ha["A1_tag_divergence"]
        if cur_d == cur_c:
            failures.append("A1: currents identical under two tags")
        if (cur_d, cur_c) != (rec["current_under_decision_tag"], rec["current_under_control_tag"]):
            failures.append("A1: recomputed currents differ from manifest record")
    else:
        failures.append("A1-1 fixture missing")

    s1_ok = False
    s1 = fixtures.get("S1-1")
    if s1:
        art = json.loads(json.dumps(s1["inputs"]["artifact"]))
        if "current" not in art["integrity"] or "signature" not in art["integrity"]:
            failures.append("S1-1: sealed artifact does not contain both members")
        sealed_current = art["integrity"].get("current")
        art["integrity"] = {k: v for k, v in art["integrity"].items()
                            if k not in ("current", "signature")}
        cb = _jcs.canonicalize(art)
        probe = ha["S1_probe"]
        s1_ok = True
        if cb.hex() != probe["canonical_body_hex"]:
            failures.append("S1: canonical bytes differ from probe (exact-byte comparison)")
            s1_ok = False
        if hashlib.sha256(cb).hexdigest() != probe["canonical_body_sha256"]:
            failures.append("S1: canonical body sha256 differs from probe")
            s1_ok = False
        cur = "sha256:" + hashlib.sha256(b"AIREP/0.2/hash/decision\n" + cb).hexdigest()
        if cur != probe["current"] or cur != sealed_current:
            failures.append("S1: recomputed current differs from probe/sealed artifact")
            s1_ok = False
    else:
        failures.append("S1-1 fixture missing")

    for fid, rec in ha.get("numeric_lexemes", {}).items():
        text = (CORPUS / f"{fid}.json").read_text(encoding="utf-8")
        if rec["lexeme"] not in text:
            failures.append(f"{fid}: recorded lexeme {rec['lexeme']!r} absent from fixture bytes")

    # ---- emit manifest ----
    sha_py = hashlib.sha256(RES_PY.read_bytes()).hexdigest()
    sha_node = hashlib.sha256(RES_NODE.read_bytes()).hexdigest()
    verdict = "FULL PARITY + EXPECTATION EQUALITY" if not failures else f"{len(failures)} FAILURE(S)"
    lines = ["# WP-α01 Stage-4 — Parity / evidence manifest", "",
             "> Generated by `parity_compare.py` (independent of both integrity verifiers).",
             "> The verifiers never consulted fixtures' `expected` members; the",
             "> expected-outcome comparison happens here only.", "",
             f"**Result: {verdict}** across {len(ids_c)} fixtures.", "",
             f"- corpus aggregate (recomputed, pinned rule): `{agg}`",
             f"- sha256(results_python.json): `{sha_py}`",
             f"- sha256(results_node.json): `{sha_node}`"]
    if cur_d and cur_c:
        lines.append(f"- A1 tag divergence (recomputed from primitives; matches manifest): decision `{cur_d}` ≠ control `{cur_c}`")
    if s1_ok:
        lines.append("- S1: comparator re-performed the mechanical subtraction on the sealed artifact; canonical bytes byte-identical to `S1_probe.canonical_body_hex`; recomputed `current` equals probe and sealed value")
    lines.append(f"- numeric lexemes verified in fixture bytes: {sorted(ha.get('numeric_lexemes', {}).keys())}")
    lines.append("")
    if failures:
        lines += ["## Failures", ""] + [f"- {f}" for f in failures] + [""]
    lines += ["## Per-fixture parity", "",
              "| fixture | python | node | expected | status |", "|---|---|---|---|---|"]
    for fid, a, b, exp, errs in per_fx:
        fa = f"{a.get('verdict')} {a.get('reasons')}"
        fb = f"{b.get('verdict')} {b.get('reasons')}"
        fe = f"{exp['verdict']} {exp['reasons']}"
        lines.append(f"| {fid} | {fa} | {fb} | {fe} | {'OK' if not errs else 'FAIL'} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{verdict}; manifest: {OUT}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
