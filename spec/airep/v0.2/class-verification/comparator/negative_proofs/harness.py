"""Shared plumbing for the committed negative proofs.

Every proof works on COPIES of a known-good output pair. Nothing frozen -- no
verifier source, corpus file, expected.json, manifest, contract or dependency
bundle -- is ever written by these proofs.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
COMPARATOR = os.path.join(os.path.dirname(HERE), "compare.py")
ROOT = os.path.normpath(os.path.join(os.path.dirname(HERE), os.pardir))
EVIDENCE = os.path.join(os.path.dirname(HERE), "evidence")


def _known_good_path():
    """Pick the known-good output pair explicitly, never implicitly.

    AIREP_COMPARATOR_GOOD overrides. Otherwise the LATEST official run
    directory is used (official_run_2 before official_run), because run 1's
    evidence is immutable and a proof must be run against the current HEAD's
    outputs. The chosen path is printed by run_all.py so the choice is on the
    record rather than inferred.
    """
    override = os.environ.get("AIREP_COMPARATOR_GOOD")
    if override:
        return override
    runs = sorted((d for d in os.listdir(EVIDENCE)
                   if d.startswith("official_run") and
                   os.path.isdir(os.path.join(EVIDENCE, d))),
                  key=lambda d: (len(d), d), reverse=True)
    for d in runs:
        candidate = os.path.join(EVIDENCE, d, "python_out_run1.json")
        if os.path.exists(candidate):
            return candidate
    return os.path.join(EVIDENCE, "official_run", "python_out_run1.json")


GOOD = _known_good_path()


class ProofFailure(AssertionError):
    pass


def known_good():
    if not os.path.exists(GOOD):
        raise ProofFailure(
            "no known-good output at %s -- run the official comparison first" % GOOD)
    with open(GOOD, "rb") as fh:
        return json.loads(fh.read())


def find_verdict(doc, record_id):
    for v in doc["verdicts"]:
        if v["artifact_ref"]["record_id"] == record_id:
            return v
    raise ProofFailure("no verdict for record_id %r" % record_id)


def run_comparator(py_doc, node_doc, workdir, tag):
    """Write the pair, run the comparator in compare-only mode, return
    (exit_code, result_payload)."""
    py_path = os.path.join(workdir, "%s_python.json" % tag)
    nd_path = os.path.join(workdir, "%s_node.json" % tag)
    res_path = os.path.join(workdir, "%s_result.json" % tag)
    for path, doc in ((py_path, py_doc), (nd_path, node_doc)):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False) + "\n")
    proc = subprocess.run(
        [sys.executable, COMPARATOR, "--root", ROOT,
         "--py-out", py_path, "--node-out", nd_path, "--result", res_path],
        capture_output=True)
    if not os.path.exists(res_path):
        raise ProofFailure("comparator produced no result file (exit %d): %s"
                           % (proc.returncode, proc.stderr.decode("utf-8", "replace")))
    with open(res_path, "rb") as fh:
        return proc.returncode, json.loads(fh.read())


def gate(payload, gid):
    for g in payload["gates"]:
        if g["id"] == gid:
            return g
    raise ProofFailure("no gate %s in the comparator result" % gid)


def expect_failure_because(payload, exit_code, gid, code, **fields):
    """A negative proof is only worth something if the comparator fails for the
    RIGHT reason. This checks the overall outcome, the exit code, the failing
    gate, the finding code, and every named field of that finding."""
    if payload["outcome"] != "FAIL":
        raise ProofFailure("expected outcome FAIL, got %s" % payload["outcome"])
    if exit_code != 1:
        raise ProofFailure("expected comparator exit 1, got %d" % exit_code)
    g = gate(payload, gid)
    if g["outcome"] != "FAIL":
        raise ProofFailure("expected gate %s to FAIL, it reported %s" % (gid, g["outcome"]))
    candidates = [f for f in g["findings"] if f.get("code") == code]
    if not candidates:
        raise ProofFailure(
            "gate %s failed, but not with code %r; codes present: %s"
            % (gid, code, sorted({f.get("code") for f in g["findings"]})))
    for f in candidates:
        if all(f.get(k) == v for k, v in fields.items()):
            return f
    raise ProofFailure(
        "gate %s reported %r but no finding matched %s; got %s"
        % (gid, code, json.dumps(fields, sort_keys=True),
           json.dumps(candidates, sort_keys=True)))


def expect_gate_clean(payload, gid):
    g = gate(payload, gid)
    if g["outcome"] not in ("PASS", "NOT_MEASURED"):
        raise ProofFailure("expected gate %s to stay clean, it reported %s with %s"
                           % (gid, g["outcome"], json.dumps(g["findings"], sort_keys=True)))


def workspace():
    return tempfile.mkdtemp(prefix="airep-negative-proof-")


def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)


def report(name, checks):
    print("PROOF %s" % name)
    for line in checks:
        print("   %s" % line)
    print("   RESULT: comparator failed for the expected cause")
