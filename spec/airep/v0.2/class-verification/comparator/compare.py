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
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from registry import (  # noqa: E402
    REASON_REGISTRY, REGISTRY_SIZE, CHANNELS, CHANNEL_ORDER,
    LEGAL_CLASSES, LEGAL_OBSERVER,
    VERDICT_MEMBERS, ARTIFACT_REF_MEMBERS, EVIDENCE_MEMBERS,
)

COMPARATOR_VERSION = "1.1.0"

# C1 extension. Every C0 constant is PRESERVED as its own named value: the C1
# work is strictly additive, so a C0 property can still be asserted on its own
# terms rather than being folded into a looser combined number.
EXPECTED_C0_CASE_COUNT = 45
EXPECTED_C1_CASE_COUNT = 15
EXPECTED_CASE_COUNT = EXPECTED_C0_CASE_COUNT + EXPECTED_C1_CASE_COUNT     # 60
EXPECTED_MANIFEST_FILE_COUNT = 416
EXPECTED_PROBE_COUNT = 15
EXPECTED_C0_FILE_COUNT = 265

# Pinned by the maintainer / by the pre-C1 manifest. The comparator recomputes
# each of these from raw bytes; it never copies them from a committed file.
PINNED_C0_AGGREGATE = "55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4"
PINNED_COMBINED_INDEX_SHA256 = (
    "365c0a992c0cad09ae731d569f14cd064ba9218f6d3fd94a38dd69640a49803c")

# The C1 ordering fixture's whole point: ORD2 (record_id ending U+FF00, UTF-8
# ef bc 80) MUST precede ORD1 (record_id ending U+10000, UTF-8 f0 90 80 80).
# UTF-16 code-unit order gives the opposite, so this pair discriminates a naive
# JavaScript sort. Asserted explicitly, not merely implied by list equality.
ORDERING_DISCRIMINATOR = ("ORD2", "ORD1")

# Two distinct SHAs, with their roles named so a future reader never conflates
# them. Both are recorded in the evidence; only the properties marked "measured"
# below are established by this comparator, and the rest is labelled as relayed.
C1_EXECUTION_SEMANTIC_BASIS_SHA = "0cc95f5ce5426ca41e7a2c26c0f77a6ba842cd81"
COMPARATOR_OFFICIAL_RUN_CHECKOUT_SHA = "7c03438382f74ffabc123c08fdb9e1a5182e63d4"

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

def build_combined_index(root, run_dir):
    """Rebuild the combined 60-case index from raw bytes, then stage a run
    corpus around it.

    The committed c1_execution/combined_case_index.json is NOT read as truth.
    The two root index arrays are concatenated here, the result is asserted to
    carry exactly 60 unique case_ids, and its canonical serialisation must hash
    to the pinned digest. Only then is it written into a run directory whose
    `cases` entry points at the frozen corpus, so the verifiers can be driven
    over all 60 cases without a single frozen byte being touched.
    """
    corpus_dir = os.path.join(root, "corpus")
    c0 = read_json(os.path.join(corpus_dir, "case_index.json"))
    c1 = read_json(os.path.join(corpus_dir, "c1_case_index.json"))
    findings = []
    if not isinstance(c0, list) or not isinstance(c1, list):
        raise HarnessError("a corpus index file is not a root array")

    combined = list(c0) + list(c1)
    ids = [e.get("case_id") for e in combined]
    if len(c0) != EXPECTED_C0_CASE_COUNT:
        findings.append(F("c0-index-count-unexpected",
                          expected=EXPECTED_C0_CASE_COUNT, actual=len(c0)))
    if len(c1) != EXPECTED_C1_CASE_COUNT:
        findings.append(F("c1-index-count-unexpected",
                          expected=EXPECTED_C1_CASE_COUNT, actual=len(c1)))
    if len(combined) != EXPECTED_CASE_COUNT:
        findings.append(F("combined-index-count-unexpected",
                          expected=EXPECTED_CASE_COUNT, actual=len(combined)))
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        findings.append(F("combined-index-duplicate-case-id", case_ids=dupes))
    if len(set(ids)) != EXPECTED_CASE_COUNT:
        findings.append(F("combined-index-unique-case-id-count",
                          expected=EXPECTED_CASE_COUNT, actual=len(set(ids))))

    raw = stable_json(combined).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED_COMBINED_INDEX_SHA256:
        findings.append(F("combined-index-digest-mismatch",
                          pinned=PINNED_COMBINED_INDEX_SHA256, recomputed=digest))

    run_corpus = os.path.join(run_dir, "combined_corpus")
    os.makedirs(run_corpus, exist_ok=True)
    with open(os.path.join(run_corpus, "case_index.json"), "wb") as fh:
        fh.write(raw)
    link = os.path.join(run_corpus, "cases")
    frozen_cases = os.path.join(corpus_dir, "cases")
    if os.path.islink(link):
        os.remove(link)
    if not os.path.exists(link):
        os.symlink(frozen_cases, link)
    return run_corpus, combined, digest, findings


def load_corpus_model(root, index=None, c0_ids=frozenset()):
    """Independently derive, from the frozen corpus, everything the comparator
    needs: the case list, each case's operator-input digests, its clock inputs,
    its (chain_id, record_id) tuple and its expected verdict."""
    corpus_dir = os.path.join(root, "corpus")
    if index is None:
        index = read_json(os.path.join(corpus_dir, "case_index.json"))
    if not isinstance(index, list):
        raise HarnessError("the corpus case index is not an array")

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
            "cohort": "C0" if cid in c0_ids else "C1",
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


def _aggregate(files, paths):
    """The manifest's own aggregate rule, reimplemented here.

    Lines are '<sha256>  <relative-path>\n', sorted by the RELATIVE PATH (not
    the assembled line, not the hash prefix), each line built AFTER the sort.
    Sorted over UTF-8 bytes: identical to code-point order for the ASCII paths
    this corpus uses, and correct if a non-ASCII path is ever added.
    """
    blob = b"".join(("%s  %s\n" % (files[rel], rel)).encode("utf-8")
                    for rel in sorted(paths, key=utf8_key))
    return hashlib.sha256(blob).hexdigest()


def verify_corpus_manifest(root, c0_ids):
    """Recompute every recorded digest, the aggregate rule, the declared counts,
    and the C0-subset preservation claim.

    C0 preservation is the reason this is not just a bigger number: the 265
    pre-C1 paths must still hash to their pre-C1 values, and the aggregate over
    exactly that subset must still be the pinned pre-C1 aggregate. That is
    checked here independently of the manifest's own c0_preservation block.
    """
    manifest = read_json(os.path.join(root, "corpus_manifest.json"))
    corpus_dir = os.path.join(root, "corpus")
    findings = []
    files = manifest.get("files") or {}

    for rel in sorted(files, key=utf8_key):
        full = os.path.join(corpus_dir, rel)
        if not os.path.exists(full):
            findings.append(F("corpus-file-absent", path=rel))
            continue
        got = hashlib.sha256(read_bytes(full)).hexdigest()
        if got != files[rel]:
            findings.append(F("corpus-file-digest-mismatch", path=rel,
                              manifest=files[rel], recomputed=got))

    agg = _aggregate(files, files)
    if agg != manifest.get("aggregate_sha256"):
        findings.append(F("corpus-aggregate-digest-mismatch",
                          manifest=manifest.get("aggregate_sha256"),
                          recomputed=agg))

    # declared extension counts
    for member, expected in (("file_count", EXPECTED_MANIFEST_FILE_COUNT),
                             ("case_count", EXPECTED_CASE_COUNT),
                             ("c0_case_count", EXPECTED_C0_CASE_COUNT),
                             ("c1_case_count", EXPECTED_C1_CASE_COUNT),
                             ("probe_count", EXPECTED_PROBE_COUNT)):
        if manifest.get(member) != expected:
            findings.append(F("manifest-count-unexpected", member=member,
                              expected=expected, actual=manifest.get(member)))
    if len(files) != EXPECTED_MANIFEST_FILE_COUNT:
        findings.append(F("manifest-file-map-size-unexpected",
                          expected=EXPECTED_MANIFEST_FILE_COUNT, actual=len(files)))

    # C0-subset preservation, recomputed rather than believed
    c0_paths = [rel for rel in files
                if rel == "case_index.json"
                or (rel.startswith("cases/")
                    and rel.split("/", 2)[1] in c0_ids)]
    if len(c0_paths) != EXPECTED_C0_FILE_COUNT:
        findings.append(F("c0-subset-file-count-unexpected",
                          expected=EXPECTED_C0_FILE_COUNT, actual=len(c0_paths)))
    c0_agg = _aggregate(files, c0_paths)
    if c0_agg != PINNED_C0_AGGREGATE:
        findings.append(F("c0-preservation-aggregate-changed",
                          pinned_pre_c1=PINNED_C0_AGGREGATE, recomputed=c0_agg,
                          note=("the pre-C1 C0 file set no longer hashes to its "
                                "pre-C1 aggregate: C1 is not strictly additive")))
    return manifest, findings, {"c0_subset_file_count": len(c0_paths),
                                "c0_subset_aggregate": c0_agg,
                                "extended_aggregate": agg}


# ------------------------------------------------------- envelope inspection

def verify_execution_basis(root, measured):
    """Bind the two SHAs to an in-root MEASUREMENT rather than to trust.

    `c1_execution/basis.json` was written at the C1 execution semantic basis SHA
    and records the digests that held there. This comparator runs at a different
    checkout SHA and recomputes those same digests from the bytes in front of it.
    Equality across the two is direct evidence -- observable without a checkout
    or a commit graph -- that the semantic basis did not move between them.

    What this canNOT establish in-root is the SHAPE of the difference (which
    paths changed); that is relayed by the coordinator and is labelled as such,
    never restated as measured.
    """
    path = os.path.join(root, "c1_execution", "basis.json")
    findings = []
    if not os.path.exists(path):
        return {"prior_execution_basis_file": "absent"}, [
            F("c1-execution-basis-absent", path="c1_execution/basis.json")]
    recorded = read_json(path)

    checks = [
        ("verifier_py_sha256", "verifier_py/class_verifier.py",
         recorded.get("verifier_py_sha256"), measured["verifier_py"]),
        ("verifier_node_r2_sha256", "verifier_node_r2/class_verifier.mjs",
         recorded.get("verifier_node_r2_sha256"), measured["verifier_node"]),
        ("contract_sha256", "CLASS_VERIFIER_CONTRACT.md",
         recorded.get("contract_sha256"), measured["contract"]),
        ("extended_manifest_aggregate", "corpus_manifest.json aggregate",
         recorded.get("extended_manifest_aggregate"), measured["extended_aggregate"]),
        ("combined_case_index_sha256", "rebuilt 60-case index",
         recorded.get("combined_case_index_sha256"), measured["combined_index"]),
        ("case_count", "scored case count",
         recorded.get("case_count"), measured["case_count"]),
    ]
    comparisons = []
    for member, subject, at_basis, at_checkout in checks:
        agree = at_basis == at_checkout
        comparisons.append({"member": member, "subject": subject,
                            "at_execution_basis": at_basis,
                            "recomputed_at_comparator_checkout": at_checkout,
                            "identical": agree})
        if not agree:
            findings.append(F("execution-basis-drift", member=member, subject=subject,
                              at_execution_basis=at_basis,
                              recomputed_at_comparator_checkout=at_checkout,
                              note=("an artifact the first C1 execution was measured "
                                    "against is not byte-identical at the comparator's "
                                    "checkout: the semantic basis moved")))
    if recorded.get("integration_sha") != C1_EXECUTION_SEMANTIC_BASIS_SHA:
        findings.append(F("execution-basis-sha-mismatch",
                          expected=C1_EXECUTION_SEMANTIC_BASIS_SHA,
                          recorded=recorded.get("integration_sha")))

    return {
        "c1_execution_semantic_basis_sha": C1_EXECUTION_SEMANTIC_BASIS_SHA,
        "c1_execution_semantic_basis_role": (
            "the frozen basis under which the first unmodified dual-verifier execution "
            "against C1 was measured"),
        "comparator_official_run_checkout_sha": COMPARATOR_OFFICIAL_RUN_CHECKOUT_SHA,
        "comparator_official_run_checkout_role": (
            "the tree this comparator ran in and measured"),
        "semantic_basis_unchanged_across_them": not findings,
        "measured_here": comparisons,
        "measurement_method": (
            "each digest recorded in c1_execution/basis.json at the execution basis SHA is "
            "recomputed by this comparator from the bytes present at its own checkout SHA; "
            "equality is the evidence. No git, no network, no commit graph."),
        "relayed_not_measured": {
            "source": "coordinator",
            "claims": [
                "exactly 12 paths differ between the two SHAs: 11 under c1_execution/ "
                "and 1 is C1_COVERAGE.md",
                "the commits between them carry only measurement evidence and a "
                "documentation correction",
            ],
            "why_not_measured": (
                "the SHAPE of a difference between two commits is not derivable inside a "
                "single checkout without the commit graph, and git is not available here"),
            "corroboration_available_in_root": (
                "the documentation correction is visible in-root: C1_COVERAGE.md carries the "
                "live extended aggregate 55f5189e... and mentions 5b053183...b9b95 only as an "
                "explicitly superseded pre-remediation value"),
        },
    }, findings


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

def expected_order(cases):
    """Recompute the expected verdict order for ALL cases with the comparator's
    OWN UTF-8 byte comparator.

    utf8_key()/tuple_key() are implemented in this file from section 2; no
    ordering helper is imported from either verifier, and corpus/ordering/
    expected_verdict_order.json is NOT used to produce this list -- it is
    cross-checked against it separately, as a second opinion on the fixture.
    """
    keyed = [(tuple_key(c["artifact_ref"]), c["case_id"]) for c in cases.values()]
    keyed.sort(key=lambda kc: kc[0])
    return [cid for _, cid in keyed]


def check_ordering_surface(root, py_doc, nd_doc, cases, case_by_tuple):
    """G12's C1 extension: exact order equality against the comparator's own
    computation, an explicit ORD2-before-ORD1 discrimination assertion, and a
    cross-check of the pinned corpus fixture."""
    findings = []
    want = expected_order(cases)

    for impl, doc in (("python", py_doc), ("node", nd_doc)):
        got = []
        for v in doc.get("verdicts", []):
            ref = v.get("artifact_ref") or {}
            got.append(case_by_tuple.get((ref.get("chain_id"), ref.get("record_id"))))
        if got != want:
            first = next((i for i in range(max(len(got), len(want)))
                          if got[i:i + 1] != want[i:i + 1]), None)
            findings.append(F("order-not-utf8-expected", impl=impl,
                              first_divergent_index=first,
                              expected_at_index=want[first:first + 1],
                              actual_at_index=got[first:first + 1],
                              expected=want, actual=got))

        # Explicit discrimination: list equality above would also hold if the
        # discriminating pair were absent, so the pair is asserted by name.
        a, b = ORDERING_DISCRIMINATOR
        if a not in got or b not in got:
            findings.append(F("ordering-discriminator-absent", impl=impl,
                              missing=[x for x in (a, b) if x not in got],
                              note=("the UTF-8-vs-UTF-16 discriminating pair is not "
                                    "present, so the ordering rule is untested")))
        elif got.index(a) >= got.index(b):
            findings.append(F("ordering-discriminator-violated", impl=impl,
                              required="%s must precede %s" % (a, b),
                              index_of_first=got.index(a), index_of_second=got.index(b),
                              note=("UTF-8 byte order puts ef bc 80 before f0 90 80 80; "
                                    "UTF-16 code-unit order gives the opposite, so this "
                                    "is a naive-JavaScript-sort detection")))

    # second opinion on the pinned fixture (a corpus finding if it disagrees)
    pinned_path = os.path.join(root, "corpus", "ordering", "expected_verdict_order.json")
    if os.path.exists(pinned_path):
        pinned = read_json(pinned_path)
        pinned_ids = [e.get("case_id") for e in pinned.get("order", [])]
        if pinned_ids != want:
            findings.append(F("pinned-order-fixture-disagrees",
                              comparator_computed=want, corpus_fixture=pinned_ids,
                              note=("the comparator's own UTF-8 computation and the "
                                    "committed ordering fixture disagree; reported as a "
                                    "maintainer finding, never silently reconciled")))
    else:
        findings.append(F("pinned-order-fixture-absent", path="corpus/ordering/"
                                                              "expected_verdict_order.json"))
    return findings, want


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


def c1_probe_matrix(runner, root, out_dir):
    """Run the 15 committed C1 CLI / process-exit probes.

    Each probe pins `expected_exit`, `expected_results_file` and a
    `must_not_create` list; the probe index states its pass criteria as: the
    exit equals expected_exit, a results file exists afterwards iff
    expected_results_file is true, and every must_not_create path is absent
    after the run. All three are asserted, per implementation, plus
    cross-implementation exit agreement.

    Placeholders are substituted here: ${VERIFIER} is dropped (the Runner
    supplies argv[0] and any interpreter prefix), ${PROBE} is the probe's own
    frozen directory, ${CORPUS} is the frozen main corpus, and ${OUT} is a
    fresh non-existent destination inside the run directory.
    """
    index_path = os.path.join(root, "corpus", "probes", "probe_index.json")
    index = read_json(index_path)
    probes = index.get("probes") or []
    corpus_dir = os.path.join(root, "corpus")
    out_root = os.path.join(out_dir, "c1_probe_out")
    os.makedirs(out_root, exist_ok=True)

    observations, findings = [], []
    if len(probes) != EXPECTED_PROBE_COUNT:
        findings.append(F("c1-probe-count-unexpected",
                          expected=EXPECTED_PROBE_COUNT, actual=len(probes)))

    for spec in probes:
        pid = spec.get("probe_id")
        expected_exit = spec.get("expected_exit")
        expected_results_file = spec.get("expected_results_file")
        probe_dir = os.path.join(root, "corpus", "probes", pid)
        exits = {}

        for impl, fn in (("python", runner.python), ("node", runner.node)):
            out_path = os.path.join(out_root, "%s__%s.json" % (pid, impl))
            if os.path.exists(out_path):
                os.remove(out_path)

            def subst(tok):
                return (tok.replace("${PROBE}", probe_dir)
                           .replace("${CORPUS}", corpus_dir)
                           .replace("${OUT}", out_path))

            argv = [subst(t) for t in spec.get("argv", []) if t != "${VERIFIER}"]
            before = file_state(out_path)
            res = fn(argv)
            after = file_state(out_path)
            exits[impl] = res["exit"]

            row = {"probe_id": pid, "impl": impl, "kind": spec.get("kind"),
                   "contract_pinned": True,
                   "expected_exit": expected_exit, "exit": res["exit"],
                   "expected_results_file": expected_results_file,
                   "results_file_present": after["exists"]}
            observations.append(row)

            if res["exit"] != expected_exit:
                findings.append(F("c1-probe-exit-mismatch", probe_id=pid, impl=impl,
                                  expected=expected_exit, actual=res["exit"],
                                  clauses=spec.get("clauses"),
                                  stderr=res["stderr_head"].strip()))
            if bool(after["exists"]) != bool(expected_results_file):
                findings.append(F("c1-probe-results-file-mismatch", probe_id=pid,
                                  impl=impl, expected_results_file=expected_results_file,
                                  results_file_present=after["exists"],
                                  clauses=spec.get("clauses")))
            for must in spec.get("must_not_create", []):
                path = subst(must)
                if os.path.exists(path):
                    findings.append(F("c1-probe-must-not-create-violated",
                                      probe_id=pid, impl=impl,
                                      path=os.path.basename(path),
                                      clauses=spec.get("clauses")))
            if not expected_results_file:
                findings.extend(side_effect_findings(
                    "c1-probe-out-path-created", "c1-probe-out-path-modified",
                    impl, out_path, before, after, probe_id=pid))

        if exits.get("python") != exits.get("node"):
            findings.append(F("c1-probe-exit-divergence", probe_id=pid,
                              contract_pinned=True, expected=expected_exit,
                              python=exits.get("python"), node=exits.get("node"),
                              clauses=spec.get("clauses")))
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
                    corpus_findings, dup_findings, dup_measured, manifest_stats=None):
    py_idx, nd_idx = index_by_tuple(py_doc), index_by_tuple(nd_doc)

    cov = corpus_findings + check_coverage(py_idx, nd_idx, cases, case_by_tuple)
    g1 = result.gate("G1", "corpus coverage: 60 scored cases (45 C0 + 15 C1) present, "
                           "intact, C0 subset preserved, and every case evaluated",
                     "fixture-set", "FAIL" if cov else "PASS", cov,
                     note=("all 416 recorded corpus digests and the manifest aggregate rule "
                           "are recomputed by the comparator; the 60-case combined index is "
                           "rebuilt from the two root arrays and its digest checked against "
                           "the pinned value; the 265-path C0 subset is re-aggregated and "
                           "compared against the pre-C1 aggregate"))
    if manifest_stats:
        g1["manifest_stats"] = manifest_stats

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
    ord_findings, want_order = check_ordering_surface(root, py_doc, nd_doc,
                                                      cases, case_by_tuple)
    order = order + ord_findings + list(dup_findings)
    result.gate("G12", "UTF-8 tuple ordering and duplicate (chain_id, record_id) rejection",
                "ordering", "FAIL" if order else "PASS", order,
                note=("output ordering and uniqueness are checked on both output files "
                      "(the comparator's independent gate, section 2 as amended); the "
                      "verifier's own duplicate-tuple REJECTION duty (section 9 R-10: "
                      "exit 1, no results file emitted) was "
                      + ("measured with a comparator-authored probe corpus, since the "
                         "frozen corpus contains no duplicate tuple" if dup_measured
                         else "NOT MEASURED in this mode")
                      + ("; the exact order of all %d verdicts is recomputed with the "
                         "comparator's own UTF-8 byte comparator, and ORD2-precedes-ORD1 "
                         "is asserted explicitly" % len(cases))))

    exp = compare_expected(py_idx, "python", cases, case_by_tuple) + \
        compare_expected(nd_idx, "node", cases, case_by_tuple)
    result.gate("G13", "each implementation equals the frozen expected.json values, "
                       "separately, on all 60 cases",
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
        "c0_cases": sum(1 for c in cases.values() if c["cohort"] == "C0"),
        "c1_cases": sum(1 for c in cases.values() if c["cohort"] == "C1"),
        "expected_order_positions_checked": len(want_order) * 2,
    }

    non_ascii = sorted({(k[0] + k[1]).decode("utf-8", "replace")
                        for k in py_keys if not (k[0] + k[1]).isascii()})
    a, b = ORDERING_DISCRIMINATOR
    discriminator_present = a in want_order and b in want_order
    result.auxiliary("A2", "ordering exercise strength",
                     ("non-ASCII identifiers present AND the UTF-8-vs-UTF-16 discriminating "
                      "pair is exercised" if (non_ascii and discriminator_present)
                      else "corpus identifiers are ASCII-only" if not non_ascii
                      else "non-ASCII identifiers present but the discriminating pair is "
                           "absent"),
                     {"non_ascii_identifiers_present": bool(non_ascii),
                      "non_ascii_identifier_count": len(non_ascii),
                      "discriminating_pair": list(ORDERING_DISCRIMINATOR),
                      "discriminating_pair_exercised": discriminator_present,
                      "consequence": (
                          "the run-1/run-2 limitation is CLOSED: ORD1/ORD2 differ first at "
                          "UTF-8 ef vs f0 while UTF-16 gives d800 < ff00, so the two orders "
                          "disagree and a naive JavaScript sort is detectable"
                          if (non_ascii and discriminator_present) else
                          "UTF-8 byte order and UTF-16 code-unit order coincide on ASCII, so "
                          "this run does NOT establish cross-runtime ordering agreement on "
                          "non-ASCII identifiers")})


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
    temp_stage = None

    try:
        if args.out_dir:
            stage_dir = os.path.abspath(args.out_dir)
        else:
            temp_stage = stage_dir = tempfile.mkdtemp(prefix="airep-comparator-stage-")
        os.makedirs(stage_dir, exist_ok=True)
        run_corpus, combined_index, combined_digest, index_findings = \
            build_combined_index(root, stage_dir)
        c0_ids = frozenset(e.get("case_id") for e in
                           read_json(os.path.join(root, "corpus", "case_index.json")))

        manifest, corpus_findings, manifest_stats = verify_corpus_manifest(root, c0_ids)
        manifest_file_count = len(manifest.get("files") or {})
        cases, model_problems = load_corpus_model(root, combined_index, c0_ids)
        corpus_findings = corpus_findings + index_findings + model_problems
        case_by_tuple = {(c["artifact_ref"]["chain_id"], c["artifact_ref"]["record_id"]): cid
                         for cid, c in cases.items()}
        basis_block, basis_findings = verify_execution_basis(root, {
            "verifier_py": hashlib.sha256(read_bytes(
                os.path.join(root, "verifier_py", "class_verifier.py"))).hexdigest(),
            "verifier_node": hashlib.sha256(read_bytes(
                os.path.join(root, "verifier_node_r2", "class_verifier.mjs"))).hexdigest(),
            "contract": hashlib.sha256(read_bytes(
                os.path.join(root, "CLASS_VERIFIER_CONTRACT.md"))).hexdigest(),
            "extended_aggregate": manifest_stats["extended_aggregate"],
            "combined_index": combined_digest,
            "case_count": len(cases),
        })
        corpus_findings = corpus_findings + basis_findings

        result.inputs = {
            "root": root,
            "basis": basis_block,
            "corpus_manifest_aggregate_sha256": manifest.get("aggregate_sha256"),
            "corpus_manifest_file_count": manifest_file_count,
            "corpus_case_count": len(cases),
            "combined_case_index_sha256": combined_digest,
            "combined_case_index_rebuilt_by": ("the comparator, from corpus/case_index.json "
                                               "+ corpus/c1_case_index.json; the committed "
                                               "c1_execution/combined_case_index.json is not "
                                               "read as truth"),
            "c0_subset_aggregate_sha256": manifest_stats["c0_subset_aggregate"],
            "c0_subset_file_count": manifest_stats["c0_subset_file_count"],
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
                    r = fn(["--corpus", run_corpus, "--out", path])
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
                c1_obs, c1_findings = c1_probe_matrix(runner, root, out_dir)
                g2_findings = div + contract_mismatch + r9_findings + c1_findings
                g = result.gate("G2", "exit semantics agree (Python vs Node) across the "
                                      "contract-pinned matrix and the corpus run",
                                "exit-semantics",
                                "FAIL" if g2_findings else "PASS", g2_findings,
                note=("the run-2 matrix and the R-9 sentinel probe are retained unchanged; "
                      "the 15 committed C1 probes are ADDED on top, each asserting its "
                      "pinned expected_exit, expected_results_file and must_not_create"))
                g["probe_matrix"] = obs
                g["request_with_out_probe"] = r9_obs
                g["c1_probe_matrix"] = c1_obs
                g["corpus_run_exits"] = {"python": runs["python"]["exits"],
                                         "node": runs["node"]["exits"]}
                result.auxiliary("A3", "duplicate-tuple handling probe",
                                 "measured on a comparator-authored probe corpus "
                                 "(the frozen corpus contains no duplicate tuple)",
                                 dup_obs)

        compare_outputs(result, root, py_doc, nd_doc, cases, case_by_tuple,
                        corpus_findings, dup_findings, dup_measured, manifest_stats)
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

    finally:
        if temp_stage:
            shutil.rmtree(temp_stage, ignore_errors=True)

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
