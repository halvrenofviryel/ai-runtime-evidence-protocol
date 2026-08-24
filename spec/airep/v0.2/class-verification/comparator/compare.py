#!/usr/bin/env python3
"""AIREP v0.2 class-verifier parity comparator.

A parity measurement tool authored in a THIRD INTEGRATION CONTEXT: independent
of both verifier implementations (it reads neither one's source as a source of
truth and imports no code from either), but NOT an external third party -- not
an outside organisation, not an independent auditor, and not an acceptance
authority. It is same-project measurement evidence. Do not restate this as
"third-party" review; the only correct use of "third-party" in this directory
is the dependency sense (no third-party PACKAGE is imported).

stdlib only. Imports NOTHING from either verifier: canonicalisation, ordering,
digesting, the reason registry and the envelope invariants are implemented here
from CLASS_VERIFIER_CONTRACT.md, so that agreement between the two runtimes is a
measurement rather than a consequence of shared code.

Outcome vocabulary: PASS / FAIL / NOT_MEASURED (a required measurement did not
execute). Nothing unmeasured is ever mapped to PASS.

Exit contract:
  0  all hard gates PASS, none unmeasured
  1  one or more hard gates FAIL
  2  one or more hard gates NOT_MEASURED
  3  harness / environment error
  4  evidence bundle invalid or incomplete
"""

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from registry import (  # noqa: E402
    REASON_REGISTRY, REGISTRY_SIZE, CHANNELS, CHANNEL_ORDER,
    LEGAL_CLASSES, LEGAL_OBSERVER,
    VERDICT_MEMBERS, ARTIFACT_REF_MEMBERS, EVIDENCE_MEMBERS,
)

COMPARATOR_VERSION = "1.0.0"
EXPECTED_CASE_COUNT = 45

NOW_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class HarnessError(Exception):
    pass


# ---------------------------------------------------------------- primitives

def sha256_bytes(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    return json.loads(read_bytes(path).decode("utf-8"))


def utf8_key(s):
    """Unsigned lexicographic order over the string's UTF-8 byte sequence.

    Contract section 2: no Unicode normalisation; byte order is the one both
    runtimes can implement identically. Implemented here independently.
    """
    return s.encode("utf-8") if isinstance(s, str) else b""


def tuple_key(ref):
    return (utf8_key(ref.get("chain_id")), utf8_key(ref.get("record_id")))


def is_ascending_unique(items):
    """ASCII-ascending, deduplicated -- checked over UTF-8 bytes."""
    keys = [utf8_key(x) for x in items]
    return all(keys[i] < keys[i + 1] for i in range(len(keys) - 1))


def stable_json(obj):
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


# ------------------------------------------------------------------- results

class Result:
    def __init__(self, mode):
        self.mode = mode
        self.gates = []
        self.aux = []
        self.inputs = {}
        self.counts = {}

    def gate(self, gid, name, surface, outcome, findings=None, note=None,
             kind="hard"):
        entry = {
            "id": gid, "name": name, "surface": surface, "kind": kind,
            "outcome": outcome, "findings": findings or [],
        }
        if note:
            entry["note"] = note
        self.gates.append(entry)
        return entry

    def auxiliary(self, aid, name, observation, detail=None):
        entry = {"id": aid, "name": name, "observation": observation}
        if detail is not None:
            entry["detail"] = detail
        self.aux.append(entry)
        return entry

    def all_findings(self):
        out = []
        for g in self.gates:
            for f in g["findings"]:
                item = dict(f)
                item["gate"] = g["id"]
                out.append(item)
        return out

    def outcome(self):
        hard = [g for g in self.gates if g["kind"] == "hard"]
        if any(g["outcome"] == "FAIL" for g in hard):
            return "FAIL"
        if any(g["outcome"] in ("NOT_MEASURED", "INCONCLUSIVE", "ERROR")
               for g in hard):
            return "NOT_MEASURED"
        return "PASS"

    def exit_code(self):
        o = self.outcome()
        return {"PASS": 0, "FAIL": 1, "NOT_MEASURED": 2}[o]

    def to_json(self):
        return {
            "comparator": {
                "name": "airep-v0.2-class-parity-comparator",
                "version": COMPARATOR_VERSION,
                "mode": self.mode,
                "independent_of": ["verifier_py", "verifier_node_r2"],
            },
            "inputs": self.inputs,
            "measurement_counts": self.counts,
            "gates": self.gates,
            "auxiliary_observations": self.aux,
            "findings": self.all_findings(),
            "outcome": self.outcome(),
        }


def F(code, **kw):
    d = {"code": code}
    d.update(kw)
    return d


# --------------------------------------------------------------- corpus model

def load_corpus_model(root):
    """Independently derive, from the frozen corpus, everything the comparator
    needs: the case list, each case's operator-input digests, its clock inputs,
    its (chain_id, record_id) tuple and its expected verdict."""
    corpus_dir = os.path.join(root, "corpus")
    index = read_json(os.path.join(corpus_dir, "case_index.json"))
    if not isinstance(index, list):
        raise HarnessError("corpus/case_index.json is not an array")

    cases = {}
    problems = []
    for entry in index:
        cid = entry.get("case_id")
        files = entry.get("files") or {}
        paths = {}
        for key in ("bindings", "clock", "independence", "request", "revocation"):
            rel = files.get(key)
            if rel is None:
                paths[key] = None
                continue
            full = os.path.join(corpus_dir, rel)
            if not os.path.exists(full):
                problems.append(F("case-file-listed-but-absent",
                                  case_id=cid, key=key, path=rel))
                paths[key] = None
            else:
                paths[key] = full

        if paths["request"] is None:
            problems.append(F("case-request-missing", case_id=cid))
            continue

        request = read_json(paths["request"])
        artifact = request.get("artifact") or {}
        ref = {"chain_id": artifact.get("chain_id"),
               "record_id": artifact.get("record_id")}

        now = window = None
        if paths["clock"] is not None:
            clock = read_json(paths["clock"])
            now = clock.get("now")
            window = clock.get("freshness_window_seconds")

        expected_path = os.path.join(corpus_dir, "cases", cid, "expected.json")
        expected = read_json(expected_path) if os.path.exists(expected_path) else None
        if expected is None:
            problems.append(F("case-expected-missing", case_id=cid))

        cases[cid] = {
            "case_id": cid,
            "artifact_ref": ref,
            "expected": expected,
            "evidence": {
                "now": now,
                "freshness_window_seconds": window,
                "bindings_digest": (sha256_bytes(read_bytes(paths["bindings"]))
                                    if paths["bindings"] else None),
                "independence_policy_digest": (sha256_bytes(read_bytes(paths["independence"]))
                                               if paths["independence"] else None),
                "revocation_digest": (sha256_bytes(read_bytes(paths["revocation"]))
                                      if paths["revocation"] else None),
            },
        }
    return cases, problems


def verify_corpus_manifest(root):
    """Recompute every recorded digest and the aggregate rule."""
    manifest = read_json(os.path.join(root, "corpus_manifest.json"))
    corpus_dir = os.path.join(root, "corpus")
    findings = []
    files = manifest.get("files") or {}
    for rel in sorted(files):
        full = os.path.join(corpus_dir, rel)
        if not os.path.exists(full):
            findings.append(F("corpus-file-absent", path=rel))
            continue
        got = hashlib.sha256(read_bytes(full)).hexdigest()
        if got != files[rel]:
            findings.append(F("corpus-file-digest-mismatch", path=rel,
                              manifest=files[rel], recomputed=got))
    blob = b"".join(("%s  %s\n" % (files[rel], rel)).encode("utf-8")
                    for rel in sorted(files))
    agg = hashlib.sha256(blob).hexdigest()
    if agg != manifest.get("aggregate_sha256"):
        findings.append(F("corpus-aggregate-digest-mismatch",
                          manifest=manifest.get("aggregate_sha256"),
                          recomputed=agg))
    return manifest, findings


# ------------------------------------------------------- envelope inspection

def check_envelope(doc, impl):
    """Contract section 2: shape, closed membership, types, registry-only
    reasons in the correct (tier, channel), sorted+deduplicated arrays, legal
    class / observer values, and the four consistency invariants."""
    findings = []

    if not isinstance(doc, dict) or set(doc.keys()) != {"verdicts"}:
        findings.append(F("envelope-top-level-shape", impl=impl,
                          members=sorted(doc.keys()) if isinstance(doc, dict) else None))
        return findings
    verdicts = doc["verdicts"]
    if not isinstance(verdicts, list):
        findings.append(F("envelope-verdicts-not-array", impl=impl))
        return findings

    for idx, v in enumerate(verdicts):
        where = {"impl": impl, "index": idx}
        if not isinstance(v, dict):
            findings.append(F("envelope-verdict-not-object", **where))
            continue
        ref = v.get("artifact_ref")
        if isinstance(ref, dict):
            where["chain_id"] = ref.get("chain_id")
            where["record_id"] = ref.get("record_id")

        members = set(v.keys())
        for extra in sorted(members - VERDICT_MEMBERS):
            findings.append(F("envelope-unknown-member", member=extra, **where))
        for missing in sorted(VERDICT_MEMBERS - members):
            findings.append(F("envelope-missing-member", member=missing, **where))

        if not isinstance(ref, dict) or set(ref.keys()) != ARTIFACT_REF_MEMBERS \
                or not all(isinstance(ref.get(k), str) for k in ARTIFACT_REF_MEMBERS):
            findings.append(F("envelope-artifact-ref-shape", **where))

        klass = v.get("class")
        if klass not in LEGAL_CLASSES:
            findings.append(F("class-value-illegal", value=klass, **where))

        obs = v.get("observer_assessment")
        if obs not in LEGAL_OBSERVER:
            findings.append(F("observer-value-illegal", value=obs, **where))

        for chan in CHANNEL_ORDER:
            arr = v.get(chan)
            if not isinstance(arr, list):
                findings.append(F("envelope-channel-not-array", channel=chan, **where))
                continue
            if not all(isinstance(x, str) for x in arr):
                findings.append(F("envelope-channel-bad-item-type", channel=chan, **where))
                continue
            tier, kind = CHANNELS[chan]
            for reason in arr:
                if reason not in REASON_REGISTRY:
                    findings.append(F("reason-not-in-registry", channel=chan,
                                      reason=reason, **where))
                elif REASON_REGISTRY[reason] != (tier, kind):
                    findings.append(F("reason-wrong-channel", channel=chan,
                                      reason=reason,
                                      registry=list(REASON_REGISTRY[reason]), **where))
            if len(set(arr)) != len(arr):
                findings.append(F("reason-duplicated", channel=chan, value=arr, **where))
            elif not is_ascending_unique(arr):
                findings.append(F("reason-not-sorted", channel=chan, value=arr, **where))

        # section 2 consistency invariants
        af, aw = v.get("authenticated_failures"), v.get("authenticated_withheld")
        ac = v.get("authenticated_caveats")
        wf, ww = v.get("witnessed_failures"), v.get("witnessed_withheld")
        if all(isinstance(x, list) for x in (af, aw, ac, wf, ww)):
            if (af or aw) and klass != "AIREP-Core":
                findings.append(F("invariant-violation",
                                  invariant="auth-negative-implies-core",
                                  value=klass, **where))
            if (wf or ww) and klass == "AIREP-Witnessed":
                findings.append(F("invariant-violation",
                                  invariant="witness-negative-implies-not-witnessed",
                                  value=klass, **where))
            if ac and klass == "AIREP-Core":
                findings.append(F("invariant-violation",
                                  invariant="caveats-imply-not-core",
                                  value=klass, **where))
            if klass == "AIREP-Witnessed" and (af or aw or wf or ww):
                findings.append(F("invariant-violation",
                                  invariant="witnessed-implies-all-clean",
                                  value=klass, **where))

        ev = v.get("evidence")
        if not isinstance(ev, dict) or set(ev.keys()) != EVIDENCE_MEMBERS:
            findings.append(F("envelope-evidence-shape", **where))
            continue
        now = ev.get("now")
        if now is not None and (not isinstance(now, str) or not NOW_RE.match(now)):
            findings.append(F("envelope-evidence-now-malformed", value=now, **where))
        win = ev.get("freshness_window_seconds")
        if win is not None and (isinstance(win, bool) or not isinstance(win, int) or win < 0):
            findings.append(F("envelope-evidence-window-malformed", value=win, **where))
        for k in ("bindings_digest", "independence_policy_digest", "revocation_digest"):
            d = ev.get(k)
            if d is not None and (not isinstance(d, str) or not DIGEST_RE.match(d)):
                findings.append(F("envelope-evidence-digest-malformed",
                                  member=k, value=d, **where))
    return findings


def check_order_and_uniqueness(doc, impl):
    findings = []
    verdicts = doc.get("verdicts") if isinstance(doc, dict) else None
    if not isinstance(verdicts, list):
        return [F("order-uncheckable", impl=impl)]
    keys = []
    for v in verdicts:
        ref = v.get("artifact_ref") if isinstance(v, dict) else None
        keys.append(tuple_key(ref if isinstance(ref, dict) else {}))
    for i in range(len(keys) - 1):
        if keys[i] > keys[i + 1]:
            findings.append(F("order-violation", impl=impl, index=i,
                              left=[k.decode("utf-8", "replace") for k in keys[i]],
                              right=[k.decode("utf-8", "replace") for k in keys[i + 1]]))
    seen = {}
    for i, k in enumerate(keys):
        if k in seen:
            findings.append(F("duplicate-tuple", impl=impl,
                              first_index=seen[k], second_index=i,
                              chain_id=k[0].decode("utf-8", "replace"),
                              record_id=k[1].decode("utf-8", "replace")))
        else:
            seen[k] = i
    return findings


# --------------------------------------------------------------- comparisons

def index_by_tuple(doc):
    out = {}
    for v in doc.get("verdicts", []):
        ref = v.get("artifact_ref") or {}
        out[(ref.get("chain_id"), ref.get("record_id"))] = v
    return out


def compare_field(py_idx, nd_idx, case_by_tuple, field, code):
    findings = []
    for key in sorted(set(py_idx) | set(nd_idx), key=lambda t: (utf8_key(t[0]), utf8_key(t[1]))):
        p, n = py_idx.get(key), nd_idx.get(key)
        if p is None or n is None:
            continue  # coverage gate reports one-sided tuples
        if p.get(field) != n.get(field):
            findings.append(F(code, case_id=case_by_tuple.get(key),
                              chain_id=key[0], record_id=key[1], field=field,
                              python=p.get(field), node=n.get(field)))
    return findings


def compare_evidence(py_idx, nd_idx, cases, case_by_tuple):
    """Cross-implementation equality AND independent recomputation."""
    cross, recomputed = [], []
    for key in sorted(set(py_idx) & set(nd_idx),
                      key=lambda t: (utf8_key(t[0]), utf8_key(t[1]))):
        p, n = py_idx[key]["evidence"], nd_idx[key]["evidence"]
        cid = case_by_tuple.get(key)
        for member in sorted(EVIDENCE_MEMBERS):
            if p.get(member) != n.get(member):
                cross.append(F("evidence-mismatch", case_id=cid,
                               chain_id=key[0], record_id=key[1], member=member,
                               python=p.get(member), node=n.get(member)))
        if cid is None or cid not in cases:
            continue
        truth = cases[cid]["evidence"]
        for member in sorted(EVIDENCE_MEMBERS):
            for impl, block in (("python", p), ("node", n)):
                if block.get(member) != truth[member]:
                    recomputed.append(F("evidence-recompute-mismatch",
                                        impl=impl, case_id=cid,
                                        chain_id=key[0], record_id=key[1],
                                        member=member, reported=block.get(member),
                                        comparator_recomputed=truth[member]))
    return cross, recomputed


EXPECTED_FIELDS = ["class", "observer_assessment"] + CHANNEL_ORDER


def compare_expected(idx, impl, cases, case_by_tuple):
    findings = []
    for key in sorted(idx, key=lambda t: (utf8_key(t[0]), utf8_key(t[1]))):
        cid = case_by_tuple.get(key)
        if cid is None or cid not in cases or cases[cid]["expected"] is None:
            continue
        exp = cases[cid]["expected"]
        got = idx[key]
        for field in EXPECTED_FIELDS:
            if got.get(field) != exp.get(field):
                findings.append(F("expected-mismatch", impl=impl, case_id=cid,
                                  chain_id=key[0], record_id=key[1], field=field,
                                  expected=exp.get(field), actual=got.get(field)))
    return findings


def check_coverage(py_idx, nd_idx, cases, case_by_tuple):
    findings = []
    if len(cases) != EXPECTED_CASE_COUNT:
        findings.append(F("corpus-case-count-unexpected",
                          expected=EXPECTED_CASE_COUNT, actual=len(cases)))
    expected_tuples = {(c["artifact_ref"]["chain_id"], c["artifact_ref"]["record_id"])
                       for c in cases.values()}
    for impl, idx in (("python", py_idx), ("node", nd_idx)):
        if len(idx) != len(cases):
            findings.append(F("verdict-count-mismatch", impl=impl,
                              cases=len(cases), verdicts=len(idx)))
        for key in sorted(expected_tuples - set(idx),
                          key=lambda t: (utf8_key(t[0]), utf8_key(t[1]))):
            findings.append(F("case-not-evaluated", impl=impl,
                              case_id=case_by_tuple.get(key),
                              chain_id=key[0], record_id=key[1]))
        for key in sorted(set(idx) - expected_tuples,
                          key=lambda t: (utf8_key(t[0]), utf8_key(t[1]))):
            findings.append(F("verdict-not-in-corpus", impl=impl,
                              chain_id=key[0], record_id=key[1]))
    return findings


# ------------------------------------------------------------ verifier driver

def file_state(path):
    """Fingerprint a path so that 'neither created nor modified' is measurable.

    Records existence, exact bytes digest, size and mtime_ns. A sentinel file
    written before the probe makes the 'nor modified' half provable: an
    unchanged digest AND an unchanged mtime_ns together rule out a rewrite with
    identical content.
    """
    if not os.path.exists(path):
        return {"exists": False}
    st = os.stat(path)
    return {"exists": True, "size": st.st_size, "mtime_ns": st.st_mtime_ns,
            "sha256": sha256_bytes(read_bytes(path))}


def side_effect_findings(code_created, code_modified, impl, path, before, after, **extra):
    """Compare two file_state() fingerprints and name what actually happened."""
    out = []
    if not before["exists"] and after["exists"]:
        out.append(F(code_created, impl=impl, path=os.path.basename(path),
                     created_size=after["size"], **extra))
    elif before["exists"] and after["exists"] and (
            before["sha256"] != after["sha256"] or before["mtime_ns"] != after["mtime_ns"]):
        out.append(F(code_modified, impl=impl, path=os.path.basename(path),
                     before_sha256=before["sha256"], after_sha256=after["sha256"],
                     mtime_ns_changed=before["mtime_ns"] != after["mtime_ns"], **extra))
    elif before["exists"] and not after["exists"]:
        out.append(F(code_modified, impl=impl, path=os.path.basename(path),
                     before_sha256=before["sha256"], after_sha256=None,
                     note="the sentinel was deleted", **extra))
    return out


SENTINEL = b"comparator sentinel: this file must be neither created nor modified\n"


class Runner:
    def __init__(self, root):
        self.root = root
        self.py = [os.path.join(root, "offline-python-deps", ".venv", "bin", "python"),
                   os.path.join(root, "verifier_py", "class_verifier.py")]
        self.nd = ["node", os.path.join(root, "verifier_node_r2", "class_verifier.mjs")]
        for p in (self.py[0], self.py[1], self.nd[1]):
            if not os.path.exists(p):
                raise HarnessError("missing verifier component: %s" % p)

    def _run(self, base, args):
        proc = subprocess.run(base + args, cwd=self.root, capture_output=True)
        return {
            "argv": [os.path.relpath(a, self.root) if a.startswith(self.root) else a
                     for a in base + args],
            "exit": proc.returncode,
            "stdout_bytes": len(proc.stdout),
            "stdout_head": proc.stdout.decode("utf-8", "replace")[:200],
            "stderr_head": proc.stderr.decode("utf-8", "replace")[:200],
        }

    def python(self, args):
        return self._run(self.py, args)

    def node(self, args):
        return self._run(self.nd, args)


# ----------------------------------------------------------- exit-code matrix

def build_probes(root, probe_dir):
    """Author probe inputs for exit paths the 45-case corpus cannot reach.

    Every probe is written into the run directory from a COPY of frozen corpus
    material. Nothing frozen is modified.
    """
    os.makedirs(probe_dir, exist_ok=True)
    cases = os.path.join(root, "corpus", "cases")
    p1 = read_json(os.path.join(cases, "P1", "request.json"))
    p2 = read_json(os.path.join(cases, "P2", "request.json"))

    def write(name, obj):
        path = os.path.join(probe_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(stable_json(obj))
        return path

    out = {}
    with open(os.path.join(probe_dir, "unparseable.json"), "w") as fh:
        fh.write("{ this is not json\n")
    out["unparseable"] = os.path.join(probe_dir, "unparseable.json")
    out["absent"] = os.path.join(probe_dir, "does-not-exist.json")

    a = copy.deepcopy(p1); a["unknown_member"] = 1
    out["envelope_unknown"] = write("req_envelope_unknown.json", a)
    a = copy.deepcopy(p1); a["head_witness"] = None
    out["hw_null"] = write("req_hw_null.json", a)
    a = copy.deepcopy(p2); a["head_witness"]["bogus"] = 1
    out["hw_unknown"] = write("req_hw_unknown.json", a)
    a = copy.deepcopy(p2); a["head_witness"]["head_ref"]["bogus"] = 1
    out["headref_unknown"] = write("req_headref_unknown.json", a)
    a = copy.deepcopy(p2); a["head_witness"]["signature"]["bogus"] = 1
    out["sig_unknown"] = write("req_signature_unknown.json", a)
    a = copy.deepcopy(p1); a["artifact"]["integrity"]["current"] = "sha256:" + "00" * 32
    out["hash_mismatch"] = write("req_stage1_hash_mismatch.json", a)
    a = copy.deepcopy(p1); a["artifact"].pop("claim", None)
    out["schema_fail"] = write("req_stage0_schema_fail.json", a)

    dup = os.path.join(probe_dir, "dup_corpus")
    os.makedirs(dup, exist_ok=True)
    rel = os.path.relpath(cases, dup)
    idx = [{"case_id": cid,
            "files": {k: os.path.join(rel, "P1", "%s.json" % k)
                      for k in ("bindings", "clock", "independence",
                                "request", "revocation")}}
           for cid in ("DUP-A", "DUP-B")]
    with open(os.path.join(dup, "case_index.json"), "w", encoding="utf-8") as fh:
        fh.write(stable_json(idx))
    out["dup_corpus"] = dup
    return out


def exit_code_matrix(runner, root, probes, corpus_dir):
    """Each row: (id, argv, contract_expected|None, pinned_by_contract).

    contract_expected is filled in only where CLASS_VERIFIER_CONTRACT.md
    section 6.4 / section 1.4 / R-1..R-7 pin the outcome. Rows with
    contract_expected None are CLI shapes the contract does not pin: agreement
    is still measured, and any divergence is reported, but it is labelled as
    unpinned so a maintainer can rule on it.
    """
    clean = ["--bindings", os.path.join(root, "corpus/cases/P2/bindings.json"),
             "--revocation", os.path.join(root, "corpus/cases/P2/revocation.json"),
             "--independence-policy", os.path.join(root, "corpus/cases/P2/independence.json"),
             "--now", "2026-08-23T12:00:00Z", "--freshness-window", "3600"]
    ok = os.path.join(root, "corpus/cases/P1/request.json")

    rows = [
        ("help", ["--help"], 0, True),
        ("valid-single-case", ["--request", ok] + clean, 0, True),
        ("unparseable-request", ["--request", probes["unparseable"]] + clean, 1, True),
        ("unreadable-request", ["--request", probes["absent"]] + clean, 1, True),
        ("stage0-schema-invalid", ["--request", probes["schema_fail"]] + clean, 1, True),
        ("stage1-hash-mismatch", ["--request", probes["hash_mismatch"]] + clean, 1, True),
        ("envelope-unknown-member", ["--request", probes["envelope_unknown"]] + clean, 1, True),
        ("head-witness-null", ["--request", probes["hw_null"]] + clean, 1, True),
        ("head-witness-unknown-member", ["--request", probes["hw_unknown"]] + clean, 1, True),
        ("head-ref-unknown-member", ["--request", probes["headref_unknown"]] + clean, 1, True),
        ("signature-unknown-member", ["--request", probes["sig_unknown"]] + clean, 1, True),
        ("now-malformed", ["--request", ok, "--now", "not-a-date",
                           "--freshness-window", "60"], 2, True),
        ("now-not-gregorian", ["--request", ok, "--now", "2026-02-30T12:00:00Z",
                               "--freshness-window", "60"], 2, True),
        ("window-negative", ["--request", ok, "--now", "2026-08-23T12:00:00Z",
                             "--freshness-window", "-5"], 2, True),
        ("window-non-integer", ["--request", ok, "--now", "2026-08-23T12:00:00Z",
                                "--freshness-window", "3.5"], 2, True),
        ("no-arguments", [], 2, True),
        ("unknown-option", ["--nope", "x"], 2, True),
        ("corpus-and-request", ["--corpus", corpus_dir, "--request", ok], 2, True),
        ("corpus-without-out", ["--corpus", corpus_dir], 2, True),
    ]
    # NOTE: the `--request FILE --out PATH` shape is NOT in this generic matrix.
    # Section 9 R-9 pins more than an exit code for it (no verdict emitted, and
    # PATH neither created nor modified), so it has its own probe with those
    # extra assertions -- see request_with_out_probe(). It is measured, pinned
    # and strict; it is not exempted.

    observations, div, contract = [], [], []
    for pid, argv, expected, pinned in rows:
        p = runner.python(argv)
        n = runner.node(argv)
        row = {"probe": pid, "argv": argv[:1] if pid == "no-arguments" else None,
               "contract_expected": expected, "contract_pinned": pinned,
               "python_exit": p["exit"], "node_exit": n["exit"],
               "agree": p["exit"] == n["exit"]}
        row.pop("argv")
        observations.append(row)
        if p["exit"] != n["exit"]:
            div.append(F("exit-code-divergence", probe=pid,
                         contract_pinned=pinned, contract_expected=expected,
                         python=p["exit"], node=n["exit"],
                         python_stderr=p["stderr_head"].strip(),
                         node_stderr=n["stderr_head"].strip()))
        if expected is not None:
            for impl, r in (("python", p), ("node", n)):
                if r["exit"] != expected:
                    contract.append(F("exit-code-contract-mismatch", probe=pid,
                                      impl=impl, expected=expected, actual=r["exit"],
                                      stderr=r["stderr_head"].strip()))
    return observations, div, contract


def request_with_out_probe(runner, root, probe_dir):
    """Section 9 R-9: `--request FILE --out PATH` is a CLI usage error, exit 2,
    no verdict emitted, and PATH is neither created nor modified.

    Four assertions per implementation, not one:
      exit == 2 -- pinned by R-9;
      stdout empty -- "no verdict is emitted";
      a NON-EXISTENT PATH is not created;
      a PRE-EXISTING sentinel PATH is not modified (digest AND mtime_ns).
    """
    ok = os.path.join(root, "corpus/cases/P1/request.json")
    observations, findings = [], []
    rows = []

    for impl, fn in (("python", runner.python), ("node", runner.node)):
        for variant in ("absent-path", "sentinel-path"):
            path = os.path.join(probe_dir, "r9_%s_%s.json" % (impl, variant))
            if variant == "sentinel-path":
                with open(path, "wb") as fh:
                    fh.write(SENTINEL)
            elif os.path.exists(path):
                os.remove(path)
            before = file_state(path)
            res = fn(["--request", ok, "--out", path])
            after = file_state(path)

            row = {"probe": "request-with-out", "impl": impl, "variant": variant,
                   "contract_pinned": True, "contract_expected": 2,
                   "exit": res["exit"], "stdout_bytes": res["stdout_bytes"],
                   "out_path_created": (not before["exists"]) and after["exists"],
                   "out_path_modified": before["exists"] and (
                       not after["exists"]
                       or before["sha256"] != after.get("sha256")
                       or before["mtime_ns"] != after.get("mtime_ns"))}
            rows.append(row)

            if res["exit"] != 2:
                findings.append(F("exit-code-contract-mismatch",
                                  probe="request-with-out", impl=impl,
                                  variant=variant, expected=2, actual=res["exit"],
                                  ruling="R-9", stderr=res["stderr_head"].strip()))
            if res["stdout_bytes"] != 0:
                findings.append(F("request-out-stdout-not-empty", impl=impl,
                                  variant=variant, ruling="R-9",
                                  stdout_bytes=res["stdout_bytes"],
                                  stdout_head=res["stdout_head"].strip()[:120]))
            findings.extend(side_effect_findings(
                "request-out-path-created", "request-out-path-modified",
                impl, path, before, after, variant=variant, ruling="R-9"))
            observations.append(row)

    by_impl = {}
    for row in rows:
        by_impl.setdefault(row["variant"], {})[row["impl"]] = row["exit"]
    for variant, exits in sorted(by_impl.items()):
        if exits.get("python") != exits.get("node"):
            findings.append(F("exit-code-divergence", probe="request-with-out",
                              variant=variant, contract_pinned=True,
                              contract_expected=2, ruling="R-9",
                              python=exits.get("python"), node=exits.get("node")))
    return observations, findings


def duplicate_rejection_probe(runner, probes, out_dir):
    """Section 2 as amended plus section 9 R-10: a duplicate
    (chain_id, record_id) tuple in the produced verdict set is VERIFIER
    run-invalidity -- exit 1, no results file emitted, not a class reason, not
    exit 2. The comparator must independently gate the same property.

    The frozen corpus contains no duplicate tuple, so the behaviour is measured
    on a comparator-authored two-case probe corpus that references the frozen P1
    fixture twice. Four assertions per implementation:
      exit == 1 -- pinned by R-10 and by the amended section 6.4;
      a NON-EXISTENT results path is not created;
      a PRE-EXISTING sentinel results path is not modified;
      no emitted file carries a duplicate tuple (checked when a file does exist).
    """
    obs, findings = {}, []
    for impl, fn in (("python", runner.python), ("node", runner.node)):
        obs[impl] = {}
        for variant in ("absent-path", "sentinel-path"):
            path = os.path.join(out_dir, "dup_%s_%s.json" % (impl, variant))
            if variant == "sentinel-path":
                with open(path, "wb") as fh:
                    fh.write(SENTINEL)
            elif os.path.exists(path):
                os.remove(path)
            before = file_state(path)
            res = fn(["--corpus", probes["dup_corpus"], "--out", path])
            after = file_state(path)

            d = {"contract_pinned": True, "contract_expected": 1,
                 "exit": res["exit"], "stderr_head": res["stderr_head"].strip(),
                 "results_file_present_after": after["exists"],
                 "results_file_created": (not before["exists"]) and after["exists"]}
            if after["exists"] and after["sha256"] != before.get("sha256"):
                try:
                    doc = read_json(path)
                    d["verdict_count"] = len(doc.get("verdicts", []))
                    d["duplicate_tuple_emitted"] = bool(
                        check_order_and_uniqueness(doc, "probe"))
                except (OSError, ValueError):
                    d["emitted_file_unparseable"] = True
            obs[impl][variant] = d

            if res["exit"] != 1:
                findings.append(F("exit-code-contract-mismatch",
                                  probe="duplicate-tuple", impl=impl,
                                  variant=variant, expected=1, actual=res["exit"],
                                  ruling="R-10", stderr=res["stderr_head"].strip()))
            findings.extend(side_effect_findings(
                "duplicate-results-file-created", "duplicate-results-file-modified",
                impl, path, before, after, variant=variant, ruling="R-10"))
            if d.get("duplicate_tuple_emitted"):
                findings.append(F("duplicate-tuple-emitted", impl=impl,
                                  variant=variant, ruling="R-10",
                                  verdict_count=d.get("verdict_count")))

    for variant in ("absent-path", "sentinel-path"):
        pe, ne = obs["python"][variant]["exit"], obs["node"][variant]["exit"]
        if pe != ne:
            findings.append(F("duplicate-rejection-divergence", variant=variant,
                              contract_pinned=True, contract_expected=1,
                              ruling="R-10", python_exit=pe, node_exit=ne,
                              python_stderr=obs["python"][variant]["stderr_head"],
                              node_stderr=obs["node"][variant]["stderr_head"]))
    return obs, findings


# ------------------------------------------------------------------ pipeline

def compare_outputs(result, root, py_doc, nd_doc, cases, case_by_tuple,
                    corpus_findings, dup_findings, dup_measured):
    py_idx, nd_idx = index_by_tuple(py_doc), index_by_tuple(nd_doc)

    cov = corpus_findings + check_coverage(py_idx, nd_idx, cases, case_by_tuple)
    result.gate("G1", "corpus coverage: 45 cases present, intact, and every case evaluated",
                "fixture-set", "FAIL" if cov else "PASS", cov,
                note=("every recorded corpus digest and the manifest aggregate rule are "
                      "recomputed by the comparator"))

    for gid, field, name in (
            ("G3", "class", "class parity"),
            ("G4", "authenticated_failures", "authenticated_failures parity"),
            ("G5", "authenticated_withheld", "authenticated_withheld parity"),
            ("G6", "authenticated_caveats", "authenticated_caveats parity"),
            ("G7", "witnessed_failures", "witnessed_failures parity"),
            ("G8", "witnessed_withheld", "witnessed_withheld parity"),
            ("G9", "observer_assessment", "observer_assessment parity")):
        code = "class-mismatch" if field == "class" else (
            "observer-mismatch" if field == "observer_assessment" else "reason-set-mismatch")
        f = compare_field(py_idx, nd_idx, case_by_tuple, field, code)
        result.gate(gid, name, "semantic-parity", "FAIL" if f else "PASS", f)

    cross, recomputed = compare_evidence(py_idx, nd_idx, cases, case_by_tuple)
    result.gate("G10", "evidence block parity and comparator-recomputed input digests",
                "evidence", "FAIL" if (cross or recomputed) else "PASS", cross + recomputed,
                note=("input digests recomputed by the comparator from the exact operator "
                      "input file bytes; the digests reported by the verifiers are not trusted"))

    env = check_envelope(py_doc, "python") + check_envelope(nd_doc, "node")
    result.gate("G11", "verdict envelope shape, closed membership, registry and invariants",
                "envelope", "FAIL" if env else "PASS", env)

    order = check_order_and_uniqueness(py_doc, "python") + \
        check_order_and_uniqueness(nd_doc, "node")
    py_keys = [tuple_key(v.get("artifact_ref") or {}) for v in py_doc.get("verdicts", [])]
    nd_keys = [tuple_key(v.get("artifact_ref") or {}) for v in nd_doc.get("verdicts", [])]
    if py_keys != nd_keys:
        order.append(F("order-divergence",
                       python=[[k.decode("utf-8", "replace") for k in t] for t in py_keys],
                       node=[[k.decode("utf-8", "replace") for k in t] for t in nd_keys]))
    order = order + list(dup_findings)
    result.gate("G12", "UTF-8 tuple ordering and duplicate (chain_id, record_id) rejection",
                "ordering", "FAIL" if order else "PASS", order,
                note=("output ordering and uniqueness are checked on both output files "
                      "(the comparator's independent gate, section 2 as amended); the "
                      "verifier's own duplicate-tuple REJECTION duty (section 9 R-10: "
                      "exit 1, no results file emitted) was "
                      + ("measured with a comparator-authored probe corpus, since the "
                         "frozen corpus contains no duplicate tuple" if dup_measured
                         else "NOT MEASURED in this mode")))

    exp = compare_expected(py_idx, "python", cases, case_by_tuple) + \
        compare_expected(nd_idx, "node", cases, case_by_tuple)
    result.gate("G13", "each implementation equals the frozen expected.json values",
                "expected-equality", "FAIL" if exp else "PASS", exp)

    paired = len(set(py_idx) & set(nd_idx))
    result.counts = {
        "cases_in_corpus": len(cases),
        "verdicts_python": len(py_idx),
        "verdicts_node": len(nd_idx),
        "verdict_pairs_compared": paired,
        "cross_impl_field_comparisons": paired * len(EXPECTED_FIELDS),
        "cross_impl_evidence_member_comparisons": paired * len(EVIDENCE_MEMBERS),
        "comparator_recomputed_digest_comparisons": paired * 3 * 2,
        "expected_value_comparisons": (len(py_idx) + len(nd_idx)) * len(EXPECTED_FIELDS),
        "corpus_files_digest_verified": 0,
    }

    non_ascii = any(not (k[0] + k[1]).isascii() for k in py_keys)
    result.auxiliary("A2", "ordering exercise strength",
                     "corpus identifiers are ASCII-only"
                     if not non_ascii else "corpus contains non-ASCII identifiers",
                     {"non_ascii_identifiers_present": non_ascii,
                      "consequence": ("UTF-8 byte order and UTF-16 code-unit order coincide on "
                                      "ASCII, so this run does NOT establish cross-runtime "
                                      "ordering agreement on non-ASCII identifiers")})


def main(argv=None):
    ap = argparse.ArgumentParser(description="AIREP v0.2 class-verifier parity comparator")
    ap.add_argument("--root", required=True,
                    help="the class-verification directory")
    ap.add_argument("--out-dir", help="run directory for outputs and evidence (mode=run)")
    ap.add_argument("--py-out", help="pre-existing python output (mode=compare-only)")
    ap.add_argument("--node-out", help="pre-existing node output (mode=compare-only)")
    ap.add_argument("--result", help="path for the machine-readable result file")
    ap.add_argument("--summary", help="path for the readable summary")
    ap.add_argument("--skip-probes", action="store_true",
                    help="skip the exit-code and duplicate-tuple probes (they are "
                         "then reported NOT_MEASURED, never PASS)")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    compare_only = args.py_out is not None or args.node_out is not None
    result = Result("compare-only" if compare_only else "run")

    try:
        manifest, corpus_findings = verify_corpus_manifest(root)
        manifest_file_count = len(manifest.get("files") or {})
        cases, model_problems = load_corpus_model(root)
        corpus_findings = corpus_findings + model_problems
        case_by_tuple = {(c["artifact_ref"]["chain_id"], c["artifact_ref"]["record_id"]): cid
                         for cid, c in cases.items()}
        result.inputs = {
            "root": root,
            "corpus_manifest_aggregate_sha256": manifest.get("aggregate_sha256"),
            "corpus_case_count": len(cases),
            "reason_registry_size": len(REASON_REGISTRY),
            "contract_sha256": sha256_bytes(read_bytes(
                os.path.join(root, "CLASS_VERIFIER_CONTRACT.md"))),
            "verifier_py_sha256": sha256_bytes(read_bytes(
                os.path.join(root, "verifier_py", "class_verifier.py"))),
            "verifier_node_sha256": sha256_bytes(read_bytes(
                os.path.join(root, "verifier_node_r2", "class_verifier.mjs"))),
        }
        if len(REASON_REGISTRY) != REGISTRY_SIZE:
            raise HarnessError("reason registry size drifted from the contract")

        dup_findings = []
        dup_measured = False
        if compare_only:
            if not (args.py_out and args.node_out):
                raise HarnessError("compare-only needs both --py-out and --node-out")
            py_raw, nd_raw = read_bytes(args.py_out), read_bytes(args.node_out)
            py_doc, nd_doc = json.loads(py_raw), json.loads(nd_raw)
            result.gate("G2", "exit semantics agree (Python vs Node)", "exit-semantics",
                        "NOT_MEASURED", [], note="compare-only mode does not run the verifiers")
            result.gate("G14", "per-implementation determinism", "determinism",
                        "NOT_MEASURED", [], note="compare-only mode does not run the verifiers")
        else:
            if not args.out_dir:
                raise HarnessError("mode=run needs --out-dir")
            out_dir = os.path.abspath(args.out_dir)
            os.makedirs(out_dir, exist_ok=True)
            runner = Runner(root)
            corpus_dir = os.path.join(root, "corpus")

            runs = {}
            det_findings = []
            for impl, fn in (("python", runner.python), ("node", runner.node)):
                digests, exits = [], []
                for i in (1, 2):
                    path = os.path.join(out_dir, "%s_out_run%d.json" % (impl, i))
                    r = fn(["--corpus", corpus_dir, "--out", path])
                    exits.append(r["exit"])
                    if r["exit"] != 0:
                        raise HarnessError("%s corpus run %d exited %d: %s"
                                           % (impl, i, r["exit"], r["stderr_head"]))
                    digests.append(sha256_bytes(read_bytes(path)))
                runs[impl] = {"exits": exits, "digests": digests,
                              "path": os.path.join(out_dir, "%s_out_run1.json" % impl)}
                if digests[0] != digests[1]:
                    det_findings.append(F("determinism-mismatch", impl=impl,
                                          run1=digests[0], run2=digests[1]))
            result.gate("G14", "per-implementation determinism (byte-identical repeat runs)",
                        "determinism", "FAIL" if det_findings else "PASS", det_findings)

            py_raw = read_bytes(runs["python"]["path"])
            nd_raw = read_bytes(runs["node"]["path"])
            py_doc, nd_doc = json.loads(py_raw), json.loads(nd_raw)

            if args.skip_probes:
                result.gate("G2", "exit semantics agree (Python vs Node)", "exit-semantics",
                            "NOT_MEASURED", [], note="--skip-probes was given")
            else:
                probe_dir = os.path.join(out_dir, "probes")
                probes = build_probes(root, probe_dir)
                obs, div, contract_mismatch = exit_code_matrix(runner, root, probes, corpus_dir)
                r9_obs, r9_findings = request_with_out_probe(runner, root, probe_dir)
                dup_obs, dup_findings = duplicate_rejection_probe(runner, probes, out_dir)
                dup_measured = True
                g2_findings = div + contract_mismatch + r9_findings
                g = result.gate("G2", "exit semantics agree (Python vs Node) across the "
                                      "contract-pinned matrix and the corpus run",
                                "exit-semantics",
                                "FAIL" if g2_findings else "PASS", g2_findings,
                                note=("the `--request FILE --out PATH` shape (section 9 R-9) "
                                      "additionally asserts an empty stdout and that PATH is "
                                      "neither created nor modified"))
                g["probe_matrix"] = obs
                g["request_with_out_probe"] = r9_obs
                g["corpus_run_exits"] = {"python": runs["python"]["exits"],
                                         "node": runs["node"]["exits"]}
                result.auxiliary("A3", "duplicate-tuple handling probe",
                                 "measured on a comparator-authored probe corpus "
                                 "(the frozen corpus contains no duplicate tuple)",
                                 dup_obs)

        compare_outputs(result, root, py_doc, nd_doc, cases, case_by_tuple,
                        corpus_findings, dup_findings, dup_measured)
        result.counts["corpus_files_digest_verified"] = manifest_file_count

        # auxiliary, NOT a gate: cross-runtime byte equality of the two files
        result.auxiliary("A1", "cross-runtime byte equality of the two output files",
                         "identical" if py_raw == nd_raw else "not identical",
                         {"python_sha256": sha256_bytes(py_raw),
                          "node_sha256": sha256_bytes(nd_raw),
                          "status": ("AUXILIARY ONLY -- byte equality is neither required nor "
                                     "sufficient for parity; the gate is semantic and envelope "
                                     "parity, measured by G1-G14")})

        # gate ids must be stable and ordered in the report
        result.gates.sort(key=lambda g: (int(g["id"][1:]),))

    except HarnessError as exc:
        payload = {"comparator": {"version": COMPARATOR_VERSION},
                   "outcome": "ERROR", "error": str(exc)}
        sys.stderr.write("harness error: %s\n" % exc)
        if args.result:
            with open(args.result, "w", encoding="utf-8") as fh:
                fh.write(stable_json(payload))
        return 3
    except (OSError, ValueError) as exc:
        sys.stderr.write("evidence bundle error: %s\n" % exc)
        return 4

    payload = result.to_json()
    text = stable_json(payload)
    if args.result:
        with open(args.result, "w", encoding="utf-8") as fh:
            fh.write(text)
    summary = render_summary(payload)
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as fh:
            fh.write(summary)
    sys.stdout.write(summary)
    return result.exit_code()


def render_summary(payload):
    lines = []
    lines.append("AIREP v0.2 class-verifier parity comparator %s (mode=%s)"
                 % (payload["comparator"]["version"], payload["comparator"]["mode"]))
    lines.append("=" * 78)
    lines.append("")
    lines.append("OUTCOME: %s" % payload["outcome"])
    lines.append("")
    lines.append("Hard gates")
    lines.append("-" * 78)
    for g in payload["gates"]:
        if g["kind"] != "hard":
            continue
        lines.append("  %-4s %-10s %s" % (g["id"], g["outcome"], g["name"]))
        for f in g["findings"]:
            lines.append("         ! %s" % json.dumps(f, sort_keys=True))
    lines.append("")
    lines.append("Auxiliary observations (NOT gates)")
    lines.append("-" * 78)
    for a in payload["auxiliary_observations"]:
        lines.append("  %-4s %s: %s" % (a["id"], a["name"], a["observation"]))
    lines.append("")
    n = len(payload["findings"])
    lines.append("%d finding(s)." % n)
    lines.append("")
    lines.append("This is implementer/measurement evidence, not acceptance.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
