#!/usr/bin/env python3
"""Schema-validation comparator (VALIDATION_CONTRACT s4). Independent of both runner scripts'
engine code (stdlib only). Hard gates: (1) verdict parity — both engines equal AND equal to
expected; (2) correct-failure matching — every INVALID fixture must, in EACH engine, carry at
least one violation with (instance_path startswith expected_error_scope) AND (keyword in
expected_error_keywords). Cross-engine violation-set equality is NOT required. Also gated:
fixture-set equality vs the corpus, results-file envelope shape (root exactly {"results"},
sorted result keys in the serialized file, trailing newline, no duplicate keys, no extra
fields per record), violations well-formed (sorted, deduplicated, tuple fields only), and the
corpus manifest (per-file sha256 + pinned aggregate).

Output: SCHEMA_PARITY_MANIFEST.md (always written). Exit 0/1/2.
Optional argv override (used by the committed negative proofs):
  compare_schema_results.py [corpus_dir py_results node_results manifest_out]
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "corpus"
RES_PY = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "results" / "results_python_schema.json"
RES_NODE = Path(sys.argv[3]) if len(sys.argv) > 3 else HERE / "results" / "results_node_schema.json"
OUT = Path(sys.argv[4]) if len(sys.argv) > 4 else HERE / "SCHEMA_PARITY_MANIFEST.md"
MANIFEST_IN = CORPUS.parent / "schema_corpus_manifest.json"

RECORD_FIELDS = {"schema", "expected", "actual", "violations"}


def die2(msg):
    print(f"ERROR: {msg}")
    sys.exit(2)


def load_results(name, path, failures):
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        die2(f"cannot read {path}: {e}")
    if not text.endswith("\n"):
        failures.append(f"{name}: no trailing newline")
    orders = []

    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            failures.append(f"{name}: duplicate keys in an object")
        orders.append(keys)
        return dict(pairs)

    doc = json.loads(text, object_pairs_hook=hook)
    if not isinstance(doc, dict) or (orders and orders[-1] != ["results"]):
        failures.append(f"{name}: root keys != ['results']")
        return {}
    results = doc.get("results")
    if not isinstance(results, dict) or not results:
        failures.append(f"{name}: results missing/empty")
        return {}
    cand = [o for o in orders if set(o) == set(results.keys()) and len(o) == len(results)]
    if len(cand) != 1 or cand[0] != sorted(cand[0]):
        failures.append(f"{name}: results map keys not uniquely ASCII-sorted in file")
    return results


def check_record(name, fid, rec, fixture, failures):
    if not isinstance(rec, dict) or set(rec.keys()) != RECORD_FIELDS:
        failures.append(f"{name}/{fid}: record fields != contract fields")
        return False
    if rec["schema"] not in ("decision", "control", "execution", "effect"):
        failures.append(f"{name}/{fid}: invalid schema value {rec['schema']!r}")
        return False
    if rec["expected"] not in ("VALID", "INVALID"):
        failures.append(f"{name}/{fid}: invalid expected value {rec['expected']!r}")
        return False
    if rec["actual"] not in ("VALID", "INVALID"):
        failures.append(f"{name}/{fid}: invalid actual verdict")
        return False
    # Fixture binding (final hardening): the result's metadata must equal the fixture
    # envelope — a record cannot claim a different target schema or expectation than the
    # corpus it is evidence about.
    if rec["schema"] != fixture["target_schema"]:
        failures.append(f"{name}/{fid}: schema {rec['schema']!r} != fixture target {fixture['target_schema']!r}")
    if rec["expected"] != fixture["expected"]:
        failures.append(f"{name}/{fid}: expected {rec['expected']!r} != fixture expected {fixture['expected']!r}")
    vs = rec["violations"]
    if not isinstance(vs, list):
        failures.append(f"{name}/{fid}: violations not a list")
        return False
    tuples = []
    for v in vs:
        if (not isinstance(v, dict) or set(v.keys()) != {"instance_path", "keyword"}
                or not isinstance(v["instance_path"], str) or not isinstance(v["keyword"], str)):
            failures.append(f"{name}/{fid}: malformed violation tuple")
            return False
        tuples.append((v["instance_path"], v["keyword"]))
    if tuples != sorted(set(tuples)):
        failures.append(f"{name}/{fid}: violations not sorted/deduplicated")
    if rec["actual"] == "VALID" and tuples:
        failures.append(f"{name}/{fid}: VALID with violations")
    if rec["actual"] == "INVALID" and not tuples:
        failures.append(f"{name}/{fid}: INVALID with no violations")
    return True


def matches(rec, scope, keywords):
    return any(v["instance_path"].startswith(scope) and v["keyword"] in keywords
               for v in rec["violations"])


def main() -> int:
    failures: list = []
    fixtures = {}
    for p in sorted(CORPUS.glob("*.json")):
        fx = json.loads(p.read_text(encoding="utf-8"))
        fixtures[fx["fixture_id"]] = fx

    manifest = json.loads(MANIFEST_IN.read_text(encoding="utf-8")) if MANIFEST_IN.exists() else None
    if manifest is None:
        failures.append("corpus manifest missing")
    else:
        files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(CORPUS.glob("*.json"))}
        agg = hashlib.sha256("".join(f"{files[n]}  {n}\n" for n in sorted(files)).encode()).hexdigest()
        if files != manifest["files"] or agg != manifest["aggregate_sha256"]:
            failures.append("corpus manifest / aggregate mismatch")

    res_py = load_results("python", RES_PY, failures)
    res_node = load_results("node", RES_NODE, failures)

    ids_c, ids_p, ids_n = set(fixtures), set(res_py), set(res_node)
    for label, ids in (("python", ids_p), ("node", ids_n)):
        if sorted(ids_c - ids):
            failures.append(f"{label}: missing fixtures {sorted(ids_c - ids)}")
        if sorted(ids - ids_c):
            failures.append(f"{label}: extra fixtures {sorted(ids - ids_c)}")

    rows = []
    for fid in sorted(ids_c & ids_p & ids_n):
        fx, a, b = fixtures[fid], res_py[fid], res_node[fid]
        errs = []
        ok_a = check_record("python", fid, a, fx, failures)
        ok_b = check_record("node", fid, b, fx, failures)
        if ok_a and ok_b:
            if a["actual"] != b["actual"]:
                errs.append(f"verdict parity: python {a['actual']} != node {b['actual']}")
            elif a["actual"] != fx["expected"]:
                errs.append(f"verdict vs expected: {a['actual']} != {fx['expected']}")
            elif fx["expected"] == "INVALID":
                scope = fx["expected_error_scope"]
                kws = set(fx["expected_error_keywords"])
                for label, rec in (("python", a), ("node", b)):
                    if not matches(rec, scope, kws):
                        errs.append(f"correct-failure: {label} has no violation matching scope {scope!r} + keywords {sorted(kws)}")
        failures.extend(f"{fid}: {e}" for e in errs)
        rows.append((fid, fx, a, b, errs))

    verdict = "ALL GATES PASSED" if not failures else f"{len(failures)} FAILURE(S)"
    lines = ["# AIREP v0.2 — Schema-validation parity manifest", "",
             "> Schema-validation harness evidence only — NOT AIREP conformance. Generated by",
             "> `compare_schema_results.py`. Hard gates: verdict parity; correct-failure",
             "> matching on {instance_path, keyword} tuples. Cross-engine violation-set",
             "> equality is deliberately not required.", "",
             f"**Result: {verdict}** across {len(ids_c)} fixtures.", ""]
    if manifest:
        lines.append(f"- corpus aggregate (recomputed, pinned rule): `{manifest['aggregate_sha256']}`")
    lines += [f"- sha256(results_python_schema.json): `{hashlib.sha256(RES_PY.read_bytes()).hexdigest()}`",
              f"- sha256(results_node_schema.json): `{hashlib.sha256(RES_NODE.read_bytes()).hexdigest()}`", ""]
    if failures:
        lines += ["## Failures", ""] + [f"- {f}" for f in failures] + [""]
    lines += ["## Per-fixture", "", "| fixture | expected | py | node | py violations | node violations | status |",
              "|---|---|---|---|---|---|---|"]
    for fid, fx, a, b, errs in rows:
        fmt = lambda r: "; ".join(f"{v['instance_path'] or '/'}·{v['keyword']}" for v in r.get("violations", [])) or "—"
        lines.append(f"| {fid} | {fx['expected']} | {a.get('actual')} | {b.get('actual')} | {fmt(a)} | {fmt(b)} | {'OK' if not errs else 'FAIL'} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{verdict}; manifest: {OUT}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
