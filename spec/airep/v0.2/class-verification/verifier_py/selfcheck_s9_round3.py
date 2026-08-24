#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression probes for CLASS_VERIFIER_CONTRACT.md S9 ruling R-7, plus the
packaging obligation that the verifier runs from the committed repository.

Round-3 remediation. Every fixture is CONSTRUCTED IN THIS FILE by mutating a
corpus input in memory; nothing is written into the corpus and no expected.json
is read from anywhere. Each probe names the exact reason set and channel that
R-7 itself states, and fails loudly on any mismatch.

R-7's governing distinction, restated so the probes can be read against it:
absence of a KNOWN evidence field fails or withholds the tier evaluation;
structure FOREIGN to the harness invalidates the run.

Layout: this file lives at <v0.2>/class-verification/verifier_py/, the corpus at
<v0.2>/class-verification/corpus/ and the schemas at <v0.2>/schemas/.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CVDIR = os.path.normpath(os.path.join(HERE, os.pardir))
CORPUS = os.path.join(CVDIR, "corpus", "cases")
SCHEMAS = os.path.normpath(os.path.join(CVDIR, os.pardir, "schemas"))
VERIFIER = os.path.join(HERE, "class_verifier.py")

FAILURES = []


def run(request_text, *, bindings=None, independence=None, revocation=None,
        clock=None, schema_dir=SCHEMAS, cwd=None):
    """Invoke the verifier as a process; returns (exit_code, verdict_or_None)."""
    with tempfile.TemporaryDirectory(dir=HERE) as tmp:
        req = os.path.join(tmp, "request.json")
        with open(req, "w", encoding="utf-8") as fh:
            fh.write(request_text)
        argv = [sys.executable, VERIFIER, "--request", req]
        for flag, doc in (("--bindings", bindings),
                          ("--independence-policy", independence),
                          ("--revocation", revocation)):
            if doc is not None:
                path = os.path.join(tmp, flag.strip("-") + ".json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh)
                argv += [flag, path]
        if clock is not None:
            argv += ["--now", clock[0], "--freshness-window", str(clock[1])]
        if schema_dir is not None:
            argv += ["--schema-dir", schema_dir]
        proc = subprocess.run(argv, capture_output=True, text=True, cwd=cwd)
    verdict = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, verdict


def case(name):
    base = os.path.join(CORPUS, name)

    def load(fn):
        path = os.path.join(base, fn)
        return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else None

    return (open(os.path.join(base, "request.json"), encoding="utf-8").read(),
            load("bindings.json"), load("independence.json"), load("revocation.json"))


def check(label, condition, detail=""):
    print("[%s] %s%s" % ("ok  " if condition else "FAIL", label,
                         ("  -- " + detail) if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def channels(v):
    return (v["authenticated_failures"], v["authenticated_withheld"],
            v["authenticated_caveats"], v["witnessed_failures"], v["witnessed_withheld"])


CLOCK = ("2026-08-23T11:30:00Z", 3600)
REQ, BIND, INDEP, REVOC = case("P2")


def probe(doc):
    return run(json.dumps(doc), bindings=BIND, independence=INDEP,
               revocation=REVOC, clock=CLOCK)


def expect_failure_only(label, doc, reason):
    """FAILURE-channel row: `reason` alone in witnessed_failures, withheld empty,
    authenticated channels untouched, exit 0."""
    code, v = probe(doc)
    ok = (code == 0 and v is not None
          and v["witnessed_failures"] == [reason]
          and v["witnessed_withheld"] == []
          and v["authenticated_failures"] == []
          and v["authenticated_withheld"] == []
          and v["class"] == "AIREP-Authenticated")
    check(label, ok, "exit=%s %s" % (code, v))


def expect_withheld_only(label, doc, reason):
    """WITHHELD-channel row: `reason` alone in witnessed_withheld, failures empty,
    authenticated channels untouched, exit 0."""
    code, v = probe(doc)
    ok = (code == 0 and v is not None
          and v["witnessed_withheld"] == [reason]
          and v["witnessed_failures"] == []
          and v["authenticated_failures"] == []
          and v["authenticated_withheld"] == []
          and v["class"] == "AIREP-Authenticated")
    check(label, ok, "exit=%s %s" % (code, v))


def expect_run_invalid(label, doc):
    code, v = probe(doc)
    check(label, code == 1 and v is None, "exit=%s %s" % (code, v))


# =====================================================================
print("--- control: unmutated P2 is clean (probe substrate is sound) ---")
code, v = probe(json.loads(REQ))
check("P2 control -> AIREP-Witnessed, all five channels empty",
      code == 0 and v["class"] == "AIREP-Witnessed"
      and channels(v) == ([], [], [], [], []), str(v))

# =====================================================================
# R-7 table row 1: head_witness ENTIRELY ABSENT -> no-witness-supplied (WITHHELD)
# =====================================================================
print("--- R-7 row 1: head_witness entirely absent ---")
doc = json.loads(REQ)
doc.pop("head_witness")
expect_withheld_only("R-7 head_witness absent -> no-witness-supplied (WITHHELD) alone",
                     doc, "no-witness-supplied")

# =====================================================================
# R-7 table row 2: head_witness PRESENT but null / non-object -> run-invalid.
# `null` is the decisive one: a `doc.get(...) is None` test would silently
# collapse it into row 1 and emit no-witness-supplied instead.
# =====================================================================
print("--- R-7 row 2: head_witness present but null / non-object ---")
for label, value in (("null", None), ("string", "witness"), ("array", []),
                     ("number", 7), ("boolean", True)):
    doc = json.loads(REQ)
    doc["head_witness"] = value
    expect_run_invalid("R-7 head_witness present as %s -> run-invalid (exit 1, no verdict)"
                       % label, doc)

# =====================================================================
# R-7 table row 3: unknown member INSIDE head_witness -> run-invalid.
# =====================================================================
print("--- R-7 row 3: unknown member inside head_witness ---")
doc = json.loads(REQ)
doc["head_witness"]["note"] = "foreign to the harness"
expect_run_invalid("R-7 unknown member in head_witness -> run-invalid (exit 1, no verdict)", doc)

doc = json.loads(REQ)
doc["head_witness"].pop("claim")
doc["head_witness"]["note"] = "foreign to the harness"
expect_run_invalid("R-7 foreign member beats a missing known member -> run-invalid", doc)

# =====================================================================
# R-7 table row 4: claim absent / non-object / structurally invalid
#                  -> witness-claim-invalid (FAILURE)
# =====================================================================
print("--- R-7 row 4: claim absent / non-object / structurally invalid ---")
doc = json.loads(REQ)
doc["head_witness"].pop("claim")
expect_failure_only("R-7 claim ABSENT -> witness-claim-invalid (FAILURE) alone",
                    doc, "witness-claim-invalid")

for label, value in (("null", None), ("string", "claim"), ("array", []), ("number", 3)):
    doc = json.loads(REQ)
    doc["head_witness"]["claim"] = value
    expect_failure_only("R-7 claim as %s -> witness-claim-invalid (FAILURE) alone" % label,
                        doc, "witness-claim-invalid")

doc = json.loads(REQ)
doc["head_witness"]["claim"]["current"] = "not-a-digest"
expect_failure_only("R-7 claim structurally invalid -> witness-claim-invalid (FAILURE) alone",
                    doc, "witness-claim-invalid")

# =====================================================================
# R-7 table row 5: head_ref absent / non-object / no usable record_id
#                  -> witness-head-unresolved (FAILURE), if 6a is clean
# =====================================================================
print("--- R-7 row 5: head_ref absent / non-object / no usable record_id ---")
doc = json.loads(REQ)
doc["head_witness"].pop("head_ref")
expect_failure_only("R-7 head_ref ABSENT -> witness-head-unresolved (FAILURE) alone",
                    doc, "witness-head-unresolved")

for label, value in (("null", None), ("string", "ref"), ("array", []), ("number", 3)):
    doc = json.loads(REQ)
    doc["head_witness"]["head_ref"] = value
    expect_failure_only("R-7 head_ref as %s -> witness-head-unresolved (FAILURE) alone" % label,
                        doc, "witness-head-unresolved")

doc = json.loads(REQ)
doc["head_witness"]["head_ref"].pop("record_id")
expect_failure_only("R-7 head_ref without record_id -> witness-head-unresolved (FAILURE) alone",
                    doc, "witness-head-unresolved")

# 6a gates 5: a defective claim suppresses the head_ref reason entirely.
doc = json.loads(REQ)
doc["head_witness"].pop("head_ref")
doc["head_witness"].pop("claim")
expect_failure_only("R-7 claim AND head_ref absent -> witness-claim-invalid ALONE (6a gates 6b)",
                    doc, "witness-claim-invalid")

# =====================================================================
# R-7 table row 6: witness_id absent / non-string
#                  -> witness-binding-missing (WITHHELD), if stage 6 is clean
# This is the channel trap: witness_id is missing EVIDENCE, so the gate could
# not run -> WITHHELD, never a FAILURE.
# =====================================================================
print("--- R-7 row 6: witness_id absent / non-string (WITHHELD channel) ---")
doc = json.loads(REQ)
doc["head_witness"].pop("witness_id")
expect_withheld_only("R-7 witness_id ABSENT -> witness-binding-missing (WITHHELD) alone",
                     doc, "witness-binding-missing")

for label, value in (("null", None), ("number", 7), ("array", []), ("object", {})):
    doc = json.loads(REQ)
    doc["head_witness"]["witness_id"] = value
    expect_withheld_only("R-7 witness_id as %s -> witness-binding-missing (WITHHELD) alone"
                         % label, doc, "witness-binding-missing")

# S4 dependency: stage-7 withholding suppresses stages 8 and 9 outright.
doc = json.loads(REQ)
doc["head_witness"].pop("witness_id")
code, v = probe(doc)
check("R-7 witness_id absent suppresses independence + witness-signature reasons",
      code == 0 and v is not None
      and not any(r.startswith("independence-") or r.startswith("witness-key")
                  or r.startswith("witness-identity") or r == "witness-signature-invalid"
                  for r in v["witnessed_failures"] + v["witnessed_withheld"]), str(v))

# =====================================================================
# R-7 table row 7: signature absent / non-object, or signature.value absent /
#                  wrong-typed -> witness-signature-invalid (FAILURE),
#                  if stage 7 is clean
# =====================================================================
print("--- R-7 row 7: signature absent / non-object / value absent or wrong-typed ---")
doc = json.loads(REQ)
doc["head_witness"].pop("signature")
expect_failure_only("R-7 signature ABSENT -> witness-signature-invalid (FAILURE) alone",
                    doc, "witness-signature-invalid")

for label, value in (("null", None), ("string", "sig"), ("array", []), ("number", 3)):
    doc = json.loads(REQ)
    doc["head_witness"]["signature"] = value
    expect_failure_only("R-7 signature as %s -> witness-signature-invalid (FAILURE) alone"
                        % label, doc, "witness-signature-invalid")

doc = json.loads(REQ)
doc["head_witness"]["signature"].pop("value")
expect_failure_only("R-7 signature.value ABSENT -> witness-signature-invalid (FAILURE) alone",
                    doc, "witness-signature-invalid")

doc = json.loads(REQ)
doc["head_witness"]["signature"]["value"] = 12
expect_failure_only("R-7 signature.value wrong-typed -> witness-signature-invalid (FAILURE) alone",
                    doc, "witness-signature-invalid")

# =====================================================================
# R-7 table row 8: head_ref / signature present as an OBJECT carrying an unknown
#                  member -> run-invalid (R-4 unchanged). Non-object values are
#                  NOT closure violations (row 5 / row 7 above already proved the
#                  semantic path), so closure never widens into requiredness.
# =====================================================================
print("--- R-7 row 8: R-4 nested closure is unchanged ---")
for member in ("head_ref", "signature"):
    doc = json.loads(REQ)
    doc["head_witness"][member]["note"] = "unknown"
    expect_run_invalid("R-7/R-4 unknown member in head_witness.%s -> run-invalid" % member, doc)

# Closure applies to the object, not to its absence: an ABSENT head_ref/signature
# alongside a foreign member elsewhere still invalidates only on the foreign member.
doc = json.loads(REQ)
doc["head_witness"].pop("signature")
doc["head_witness"]["head_ref"]["note"] = "unknown"
expect_run_invalid("R-7/R-4 foreign member in head_ref + absent signature -> run-invalid", doc)

# =====================================================================
# DIVERGENCE RISK A -- channel assignment follows the closed S5 registry.
# Each reason is asserted present in its OWN channel and ABSENT from the other.
# =====================================================================
print("--- divergence risk A: S5 channel assignment (withheld vs failure) ---")
WITHHELD_ROWS = (
    ("head_witness absent", lambda d: d.pop("head_witness"), "no-witness-supplied"),
    ("witness_id absent", lambda d: d["head_witness"].pop("witness_id"), "witness-binding-missing"),
)
FAILURE_ROWS = (
    ("claim absent", lambda d: d["head_witness"].pop("claim"), "witness-claim-invalid"),
    ("head_ref absent", lambda d: d["head_witness"].pop("head_ref"), "witness-head-unresolved"),
    ("signature absent", lambda d: d["head_witness"].pop("signature"), "witness-signature-invalid"),
)
for label, mutate, reason in WITHHELD_ROWS:
    doc = json.loads(REQ)
    mutate(doc)
    code, v = probe(doc)
    check("A: %s -> %s in witnessed_withheld and NOT in witnessed_failures"
          % (label, reason),
          code == 0 and v is not None
          and reason in v["witnessed_withheld"]
          and reason not in v["witnessed_failures"], str(v))
for label, mutate, reason in FAILURE_ROWS:
    doc = json.loads(REQ)
    mutate(doc)
    code, v = probe(doc)
    check("A: %s -> %s in witnessed_failures and NOT in witnessed_withheld"
          % (label, reason),
          code == 0 and v is not None
          and reason in v["witnessed_failures"]
          and reason not in v["witnessed_withheld"], str(v))

# S2 invariant: a non-empty witnessed channel of EITHER kind denies Witnessed.
for label, mutate, _ in WITHHELD_ROWS + FAILURE_ROWS:
    doc = json.loads(REQ)
    mutate(doc)
    code, v = probe(doc)
    check("A: %s -> class != AIREP-Witnessed" % label,
          code == 0 and v is not None and v["class"] != "AIREP-Witnessed", str(v))

# =====================================================================
# DIVERGENCE RISK B -- R-2 dependency precedence: the reason emitted is the first
# one REACHABLE under the stage order, not every one that would independently
# apply. Each probe removes several known members at once; a verifier that
# evaluated the members independently would emit two or more reasons.
# =====================================================================
print("--- divergence risk B: R-2 precedence over several absent members ---")

doc = json.loads(REQ)
doc["head_witness"].pop("claim")
doc["head_witness"].pop("signature")
expect_failure_only("B: claim AND signature absent -> witness-claim-invalid ALONE",
                    doc, "witness-claim-invalid")

doc = json.loads(REQ)
doc["head_witness"] = {}
expect_failure_only("B: head_witness = {} (all four absent) -> witness-claim-invalid ALONE",
                    doc, "witness-claim-invalid")

doc = json.loads(REQ)
doc["head_witness"].pop("head_ref")
doc["head_witness"].pop("witness_id")
doc["head_witness"].pop("signature")
expect_failure_only("B: head_ref + witness_id + signature absent -> witness-head-unresolved ALONE",
                    doc, "witness-head-unresolved")

doc = json.loads(REQ)
doc["head_witness"].pop("witness_id")
doc["head_witness"].pop("signature")
expect_withheld_only("B: witness_id AND signature absent -> witness-binding-missing ALONE",
                     doc, "witness-binding-missing")

# Discrimination proof for the probes above: each suppressed member really does
# produce its own reason when it is the only thing missing, so the "ALONE"
# assertions cannot pass merely because a later stage is dead code.
for label, mutate, reason in (
    ("signature", lambda d: d["head_witness"].pop("signature"), "witness-signature-invalid"),
    ("head_ref", lambda d: d["head_witness"].pop("head_ref"), "witness-head-unresolved"),
):
    doc = json.loads(REQ)
    mutate(doc)
    code, v = probe(doc)
    check("B discriminates: %s absent ALONE really emits %s" % (label, reason),
          code == 0 and v is not None and v["witnessed_failures"] == [reason], str(v))

doc = json.loads(REQ)
doc["head_witness"].pop("witness_id")
code, v = probe(doc)
check("B discriminates: witness_id absent ALONE really emits witness-binding-missing",
      code == 0 and v is not None and v["witnessed_withheld"] == ["witness-binding-missing"],
      str(v))

# =====================================================================
# R-7 closing statement: the entirely-absent path is unchanged, and no absent
# sub-member is ever reported as `no-witness-supplied`.
# =====================================================================
print("--- R-7 closure: an absent sub-member is never no-witness-supplied ---")
for member in ("claim", "head_ref", "witness_id", "signature"):
    doc = json.loads(REQ)
    doc["head_witness"].pop(member)
    code, v = probe(doc)
    check("R-7 head_witness.%s absent -> NOT no-witness-supplied" % member,
          code == 0 and v is not None
          and "no-witness-supplied" not in (v["witnessed_failures"] + v["witnessed_withheld"]),
          str(v))

# =====================================================================
# PACKAGING (round-3 task 2): the verifier must execute from the committed
# repository with no installed `jcs` package and from any working directory.
# =====================================================================
print("--- packaging: repository JCS canonicalizer, offline, cwd-independent ---")

sys.path.insert(0, HERE)
sys.dont_write_bytecode = True     # write no __pycache__ into the repository
import class_verifier  # noqa: E402  (import after path setup, deliberately)

EXPECTED_JCS = os.path.normpath(
    os.path.join(CVDIR, os.pardir, os.pardir, "v0.1", "conformance", "jcs.py"))
check("JCS module loaded from <repo>/spec/airep/v0.1/conformance/jcs.py",
      os.path.abspath(getattr(class_verifier.jcs, "__file__", "")) == EXPECTED_JCS,
      "loaded=%s expected=%s" % (getattr(class_verifier.jcs, "__file__", None), EXPECTED_JCS))

check("JCS canonicalize() returns bytes (the interface class_verifier calls)",
      isinstance(class_verifier.jcs.canonicalize({"b": 1, "a": [1, 2]}), bytes))
check("JCS canonicalize() emits RFC 8785 form (sorted keys, no whitespace)",
      class_verifier.jcs.canonicalize({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}',
      repr(class_verifier.jcs.canonicalize({"b": 1, "a": [1, 2]})))

# No PyPI `jcs` is involved: the loaded module is a file path outside site-packages,
# and the verifier still runs when the process starts in an unrelated directory.
code, v = run(REQ, bindings=BIND, independence=INDEP, revocation=REVOC,
              clock=CLOCK, schema_dir=None, cwd=os.path.abspath(os.sep))
check("verifier runs with cwd=/ and no --schema-dir -> AIREP-Witnessed",
      code == 0 and v is not None and v["class"] == "AIREP-Witnessed",
      "exit=%s %s" % (code, v))

probe_env = subprocess.run([sys.executable, "-c", "import jcs"],
                           capture_output=True, text=True)
print("[obs ] `import jcs` in this environment: exit=%s (%s)"
      % (probe_env.returncode,
         "no installed package -- the repository loader is the only source"
         if probe_env.returncode != 0 else "a package IS installed; loader still wins above"))

# =====================================================================
print()
if FAILURES:
    print("PROBE FAILURES: %d" % len(FAILURES))
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("all S9 round-3 probes passed")
