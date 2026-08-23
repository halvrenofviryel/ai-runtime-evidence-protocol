#!/usr/bin/env python3
"""Deterministic schema-validation corpus builder (VALIDATION_CONTRACT s5).

Harness code only. The accepted schemas are read BUT NEVER MODIFIED; deletion negatives are
derived programmatically from the schemas' own `required` lists (core + family), so there is
no hand-kept duplicate list to drift. Placeholder digests/signatures are syntactically valid
only — fixtures are never presented as cryptographically valid artifacts.

Two runs are byte-identical (sorted keys, trailing newline, no timestamps, no randomness).
Exit 3 = a fixture cannot be built from the accepted schemas as written (maintainer finding).
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMAS = HERE.parent / "schemas"
CORPUS = HERE / "corpus"

FAMILIES = ("decision", "control", "execution", "effect")
D = "sha256:" + "ab" * 32
D2 = "sha256:" + "cd" * 32
SIG = "a1" * 64
TS = "2026-08-23T10:00:00Z"
TS_FRAC = "2026-08-23T10:00:00.123456789Z"


def subject(frac=False, principal=False, runtime=False):
    s = {"producer": "schema-harness/1.0", "timestamp_utc": TS_FRAC if frac else TS}
    if runtime:
        s["runtime"] = "harness-runtime"
    if principal:
        s["principal"] = {"service": "svc-1", "scope": ["read"], "established_by": "verified_credential"}
    return s


def core(family, **kw):
    return {
        "airep_version": "0.2", "artifact_type": family,
        "chain_id": "sv-chain-1", "record_id": f"sv-rec-{family}-1", "sequence": 1,
        "subject": subject(**kw),
        "scope": {"covers": ["schema shape"], "does_not_cover": ["cryptographic validity"]},
        "integrity": {"previous": "sha256:" + "0" * 64, "current": D,
                      "signature": {"alg": "Ed25519", "value": SIG}},
    }


def positive(family):
    a = core(family,
             frac=(family == "execution"), principal=(family == "decision"),
             runtime=(family == "execution"))
    if family == "decision":
        a.update({
            "input": {"input_ref": "ref:input-1", "input_digest": D, "digest_projection": "airep.projection-a"},
            "claim": {"assertion": "released after gates passed", "basis": ["gate-1"]},
            "directive": {"verb": "release", "policy_basis": ["gate-1"]},
            "output": {"result_ref": "ref:result-1", "result_digest": D2, "redacted": True},
            "evidence": [{"type": "policy", "ref": "ref:policy-1", "resolvable": False, "content_hash": D2}],
            "profiles": {"airep.migration": {"note": "harness placeholder"}},
        })
    elif family == "control":
        a.update({
            "decision_ref": {"record_id": "sv-rec-decision-1", "chain_id": "sv-chain-1"},
            "instruction_id": "instr-1", "instruction_digest": D,
            "authorized_action_digest": D2,
            "control_event": "dispatched", "boundary_side": "issuer",
            "authority": {"issuer_id": "issuer-1", "writable_by_controlled_system": False},
            "evidence": [{"type": "tool_call", "ref": "ref:dispatch-log", "resolvable": True, "content_hash": D}],
        })
    elif family == "execution":
        a.update({
            "decision_ref": {"record_id": "sv-rec-decision-1"},
            "instruction_id": "instr-1", "instruction_digest": D,
            "executed_action_digest": D2, "execution_event": "executed",
        })
    else:
        a.update({
            "decision_ref": {"record_id": "sv-rec-decision-1"},
            "execution_ref": {"record_id": "sv-rec-execution-1"},
            "observer_relationship": "independent",
            "observed_state": {"description": "valve closed", "state_digest": D},
        })
    return a


def deep(obj):
    return json.loads(json.dumps(obj))


def set_path(obj, path, value):
    o = obj
    for k in path[:-1]:
        o = o[k]
    o[path[-1]] = value
    return obj


def del_path(obj, path):
    o = obj
    for k in path[:-1]:
        o = o[k]
    del o[path[-1]]
    return obj


def main() -> int:
    CORPUS.mkdir(exist_ok=True)
    schemas = {f: json.loads((SCHEMAS / f"{f}.schema.json").read_text()) for f in FAMILIES}
    common = json.loads((SCHEMAS / "common.schema.json").read_text())
    core_required = common["$defs"]["artifact_core"]["required"]

    fixtures = []

    def add(fid, target, expected, instance, desc, scope=None, keywords=None):
        fx = {"fixture_id": fid, "target_schema": target, "expected": expected,
              "description": desc, "instance": instance}
        if expected == "INVALID":
            if scope is None or not keywords:
                print(f"STAGE1_REREVIEW_REQUIRED-equivalent: INVALID fixture {fid} without scope/keywords")
                sys.exit(3)
            fx["expected_error_scope"] = scope
            fx["expected_error_keywords"] = sorted(keywords)
        fixtures.append(fx)

    positives = {f: positive(f) for f in FAMILIES}

    # --- positives -------------------------------------------------------------------
    for f in FAMILIES:
        add(f"{f}-pos-canonical", f, "VALID", positives[f], f"canonical {f} instance")

    # --- required-member deletions (programmatic from the schemas' own required lists) -
    for f in FAMILIES:
        members = list(core_required) + [m for m in schemas[f]["required"] if m not in core_required]
        for m in members:
            add(f"{f}-neg-del-{m.replace('_','-')}", f, "INVALID",
                del_path(deep(positives[f]), [m]),
                f"{f} with required top-level member {m} deleted", "", ["required"])

    # --- type/const gates ------------------------------------------------------------
    add("decision-neg-wrong-artifact-type", "decision", "INVALID",
        set_path(deep(positives["decision"]), ["artifact_type"], "control"),
        "decision instance declaring artifact_type control", "/artifact_type", ["const"])
    add("decision-neg-wrong-version", "decision", "INVALID",
        set_path(deep(positives["decision"]), ["airep_version"], "0.3"),
        "airep_version 0.3", "/airep_version", ["const"])

    # --- closure: unknown top-level per family + EVERY distinct closed surface --------
    for f in FAMILIES:
        add(f"{f}-neg-unknown-top-level", f, "INVALID",
            set_path(deep(positives[f]), ["extra_member"], "x"),
            f"unknown top-level member on {f}", "", ["unevaluatedProperties"])
    nested_closure = [
        ("decision", ["subject"], "/subject"),
        ("decision", ["subject", "principal"], "/subject/principal"),
        ("decision", ["scope"], "/scope"),
        ("decision", ["integrity"], "/integrity"),
        ("decision", ["integrity", "signature"], "/integrity/signature"),
        ("decision", ["evidence", 0], "/evidence/0"),
        ("control", ["decision_ref"], "/decision_ref"),
        ("decision", ["input"], "/input"),
        ("decision", ["claim"], "/claim"),
        ("decision", ["directive"], "/directive"),
        ("decision", ["output"], "/output"),
        ("control", ["authority"], "/authority"),
        ("effect", ["observed_state"], "/observed_state"),
    ]
    for fam, path, scope in nested_closure:
        inst = deep(positives[fam])
        set_path(inst, list(path) + ["extra_member"], "x")
        slug = scope.strip("/").replace("/", "-")
        add(f"{fam}-neg-unknown-{slug}", fam, "INVALID", inst,
            f"unknown member inside {scope} on {fam}", scope, ["additionalProperties"])

    # --- lexical / pattern gates -----------------------------------------------------
    for slug, val in (("digest-uppercase", "sha256:" + "AB" * 32),
                      ("digest-wrong-prefix", "md5:" + "ab" * 32),
                      ("digest-short-hex", "sha256:" + "ab" * 8)):
        add(f"decision-neg-{slug}", "decision", "INVALID",
            set_path(deep(positives["decision"]), ["input", "input_digest"], val),
            f"input_digest {slug}", "/input/input_digest", ["pattern"])
    for slug, val in (("sig-short", "a1" * 32), ("sig-uppercase", "A1" * 64)):
        add(f"decision-neg-{slug}", "decision", "INVALID",
            set_path(deep(positives["decision"]), ["integrity", "signature", "value"], val),
            f"signature value {slug}", "/integrity/signature/value", ["pattern"])
    add("decision-neg-sequence-negative", "decision", "INVALID",
        set_path(deep(positives["decision"]), ["sequence"], -1),
        "sequence -1", "/sequence", ["minimum"])
    add("decision-neg-sequence-overflow", "decision", "INVALID",
        set_path(deep(positives["decision"]), ["sequence"], 9007199254740992),
        "sequence 2^53", "/sequence", ["maximum"])
    for slug, val in (("ts-offset", "2026-08-23T10:00:00+00:00"),
                      ("ts-month-13", "2026-13-01T10:00:00Z"),
                      ("ts-missing-seconds", "2026-08-23T10:00Z"),
                      ("ts-10-digit-fraction", "2026-08-23T10:00:00.1234567890Z")):
        add(f"decision-neg-{slug}", "decision", "INVALID",
            set_path(deep(positives["decision"]), ["subject", "timestamp_utc"], val),
            f"timestamp {slug}", "/subject/timestamp_utc", ["pattern"])
    inst = deep(positives["decision"])
    inst["profiles"] = {"singlesegment": {}}
    add("decision-neg-profile-key-single-segment", "decision", "INVALID", inst,
        "profiles key with a single namespace segment", "/profiles", ["propertyNames", "pattern"])
    inst = deep(positives["decision"])
    inst["profiles"] = {"Airep.Migration": {}}
    add("decision-neg-profile-key-uppercase", "decision", "INVALID", inst,
        "profiles key with uppercase characters", "/profiles", ["propertyNames", "pattern"])
    add("decision-neg-digest-projection-single-segment", "decision", "INVALID",
        set_path(deep(positives["decision"]), ["input", "digest_projection"], "projection"),
        "digest_projection with a single segment", "/input/digest_projection", ["pattern"])

    # --- sub-object gates ------------------------------------------------------------
    inst = deep(positives["decision"])
    del inst["subject"]["principal"]["established_by"]
    add("decision-neg-principal-without-established-by", "decision", "INVALID", inst,
        "principal present but established_by absent", "/subject/principal", ["required"])
    inst = deep(positives["decision"])
    del inst["evidence"][0]["content_hash"]
    add("decision-neg-evidence-missing-content-hash", "decision", "INVALID", inst,
        "evidence item without content_hash", "/evidence/0", ["required"])
    inst = deep(positives["control"])
    del inst["decision_ref"]["record_id"]
    add("control-neg-ref-missing-record-id", "control", "INVALID", inst,
        "cross-artifact reference without record_id", "/decision_ref", ["required"])

    # --- family-specific -------------------------------------------------------------
    add("decision-neg-empty-basis", "decision", "INVALID",
        set_path(deep(positives["decision"]), ["claim", "basis"], []),
        "empty claim.basis", "/claim/basis", ["minItems"])
    add("decision-neg-invalid-verb", "decision", "INVALID",
        set_path(deep(positives["decision"]), ["directive", "verb"], "approve"),
        "invalid directive verb", "/directive/verb", ["enum"])
    add("control-neg-empty-instruction-id", "control", "INVALID",
        set_path(deep(positives["control"]), ["instruction_id"], ""),
        "empty instruction_id", "/instruction_id", ["minLength"])
    add("control-neg-invalid-control-event", "control", "INVALID",
        set_path(deep(positives["control"]), ["control_event"], "acknowledged"),
        "invalid control_event", "/control_event", ["enum"])
    add("control-neg-invalid-boundary-side", "control", "INVALID",
        set_path(deep(positives["control"]), ["boundary_side"], "middle"),
        "invalid boundary_side", "/boundary_side", ["enum"])
    inst = deep(positives["control"])
    del inst["authority"]["writable_by_controlled_system"]
    add("control-neg-authority-missing-writable", "control", "INVALID", inst,
        "authority without writable_by_controlled_system", "/authority", ["required"])
    add("execution-neg-empty-instruction-id", "execution", "INVALID",
        set_path(deep(positives["execution"]), ["instruction_id"], ""),
        "empty instruction_id", "/instruction_id", ["minLength"])
    add("execution-neg-retired-completed", "execution", "INVALID",
        set_path(deep(positives["execution"]), ["execution_event"], "completed"),
        "retired execution_event value completed", "/execution_event", ["enum"])
    add("effect-neg-invalid-observer-relationship", "effect", "INVALID",
        set_path(deep(positives["effect"]), ["observer_relationship"], "third_party"),
        "invalid observer_relationship", "/observer_relationship", ["enum"])
    inst = deep(positives["effect"])
    del inst["execution_ref"]["record_id"]
    add("effect-neg-execution-ref-missing-record-id", "effect", "INVALID", inst,
        "execution_ref without record_id", "/execution_ref", ["required"])
    inst = deep(positives["effect"])
    del inst["observed_state"]["description"]
    add("effect-neg-observed-state-missing-description", "effect", "INVALID", inst,
        "observed_state without description", "/observed_state", ["required"])

    # --- cross-family rejection (all 12 pairs) ----------------------------------------
    for src in FAMILIES:
        for tgt in FAMILIES:
            if src == tgt:
                continue
            add(f"cross-neg-{src}-as-{tgt}", tgt, "INVALID", deep(positives[src]),
                f"valid {src} instance presented to the {tgt} schema", "/artifact_type", ["const"])

    # --- write + manifest -------------------------------------------------------------
    ids = [fx["fixture_id"] for fx in fixtures]
    if len(ids) != len(set(ids)):
        print("duplicate fixture ids")
        sys.exit(3)
    files = {}
    for fx in fixtures:
        path = CORPUS / f"{fx['fixture_id']}.json"
        data = json.dumps(fx, sort_keys=True, ensure_ascii=False, indent=1) + "\n"
        path.write_text(data, encoding="utf-8")
        files[path.name] = hashlib.sha256(data.encode()).hexdigest()
    agg = hashlib.sha256("".join(f"{files[n]}  {n}\n" for n in sorted(files)).encode()).hexdigest()
    manifest = {"aggregate_sha256": agg,
                "aggregate_rule": "sha256 of concatenated ASCII-sorted UTF-8 lines '<sha256>  <relative-path>\\n' relative to schema-validation/corpus/",
                "files": files, "fixture_count": len(files)}
    (HERE / "schema_corpus_manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"corpus: {len(files)} fixtures; aggregate {agg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
