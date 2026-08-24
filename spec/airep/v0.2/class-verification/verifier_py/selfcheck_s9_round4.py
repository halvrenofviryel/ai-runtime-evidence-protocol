#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression probes for CLASS_VERIFIER_CONTRACT.md S9 ruling R-8.

Round-4 remediation. R-8 pins Stage 7 as three DEPENDENT sub-steps:

  7a  witness identifier usability -- when stage 6 is clean, an absent or
      non-string `witness_id` emits `witness-binding-missing` (WITHHELD) and
      stage 7 STOPS THERE, even when the binding store is itself malformed;
  7b  witness binding-store resolution -- runs only when 7a is clean; a
      malformed store or entry is `witness-binding-malformed`, a well-formed
      store with no map entry for the id is `witness-binding-missing`;
  7c  witness revocation -- runs only after an accepted witness binding.

The governing combination is therefore: absent `witness_id` + malformed binding
store => `witness-binding-missing` ALONE.

Every fixture is CONSTRUCTED IN THIS FILE by mutating a corpus input in memory;
nothing is written into the corpus and no expected.json is read from anywhere.
Layout: this file lives at <v0.2>/class-verification/verifier_py/, the corpus at
<v0.2>/class-verification/corpus/ and the schemas at <v0.2>/schemas/.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
CVDIR = os.path.normpath(os.path.join(HERE, os.pardir))
CORPUS = os.path.join(CVDIR, "corpus", "cases")
SCHEMAS = os.path.normpath(os.path.join(CVDIR, os.pardir, "schemas"))
VERIFIER = os.path.join(HERE, "class_verifier.py")

FAILURES = []


def run(request_text, *, bindings=None, independence=None, revocation=None,
        clock=None, schema_dir=SCHEMAS):
    """Invoke the verifier as a process; returns (exit_code, verdict_or_None)."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
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
        proc = subprocess.run(argv, capture_output=True, text=True, env=env)
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


CLOCK = ("2026-08-23T11:30:00Z", 3600)
REQ, BIND, INDEP, REVOC = case("P2")

# --- the malformed binding store used throughout ---------------------------
# E-4 / R-3 closure: an UNKNOWN member at the store's top level makes the whole
# document malformed. Both role maps are otherwise intact and both wire ids
# still resolve in them -- so this store is malformed for BOTH paths, which is
# exactly what the discrimination probes need.
MALFORMED_STORE = copy.deepcopy(BIND)
MALFORMED_STORE["unexpected_member"] = {"x": 1}

# A second, structurally different malformation: a required container missing.
MALFORMED_STORE_2 = copy.deepcopy(BIND)
del MALFORMED_STORE_2["witness_bindings"]


def probe(doc, store):
    return run(json.dumps(doc), bindings=store, independence=INDEP,
               revocation=REVOC, clock=CLOCK)


def expect(label, doc, store, *, w_withheld, w_failures, a_withheld,
           a_failures=(), klass=None):
    code, v = probe(doc, store)
    ok = (code == 0 and v is not None
          and v["witnessed_withheld"] == list(w_withheld)
          and v["witnessed_failures"] == list(w_failures)
          and v["authenticated_withheld"] == list(a_withheld)
          and v["authenticated_failures"] == list(a_failures)
          and (klass is None or v["class"] == klass))
    check(label, ok, "exit=%s %s" % (code, v))


def with_witness_id(value, present=True):
    doc = json.loads(REQ)
    if present:
        doc["head_witness"]["witness_id"] = value
    else:
        doc["head_witness"].pop("witness_id")
    return doc


# =====================================================================
print("--- control: unmutated P2 with the UNMUTATED store is clean ---")
code, v = probe(json.loads(REQ), BIND)
check("P2 control -> AIREP-Witnessed, all five channels empty",
      code == 0 and v is not None and v["class"] == "AIREP-Witnessed"
      and (v["authenticated_failures"], v["authenticated_withheld"],
           v["authenticated_caveats"], v["witnessed_failures"],
           v["witnessed_withheld"]) == ([], [], [], [], []), str(v))

# =====================================================================
# R-8 GOVERNING COMBINATION: absent witness_id + malformed store.
# 7a fires; 7b is never reached; the witness channel carries
# `witness-binding-missing` ALONE. The producer path is unaffected by 7a and
# still reports `producer-binding-malformed` on the SAME store.
# =====================================================================
print("--- R-8 7a: absent witness_id + MALFORMED store (governing combination) ---")
expect("absent witness_id + malformed store -> witness-binding-missing ALONE",
       with_witness_id(None, present=False), MALFORMED_STORE,
       w_withheld=["witness-binding-missing"], w_failures=[],
       a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

expect("absent witness_id + malformed store (missing container) -> same",
       with_witness_id(None, present=False), MALFORMED_STORE_2,
       w_withheld=["witness-binding-missing"], w_failures=[],
       a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

# =====================================================================
# R-8 7a, non-string forms. `null` is the decisive one: a `.get(...) is None`
# test cannot tell it from absence, and both must land on the SAME reason.
# =====================================================================
print("--- R-8 7a: NON-STRING witness_id (several forms) + MALFORMED store ---")
for label, value in (("null", None), ("integer", 7), ("float", 1.5),
                     ("bool", True), ("array", ["airep.witness-a"]),
                     ("object", {"id": "airep.witness-a"})):
    expect("witness_id=%s + malformed store -> witness-binding-missing ALONE" % label,
           with_witness_id(value), MALFORMED_STORE,
           w_withheld=["witness-binding-missing"], w_failures=[],
           a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

# =====================================================================
# DISCRIMINATION: the same malformed store with a VALID, PRESENT witness_id
# must still reach 7b and report `witness-binding-malformed`. This is what
# proves the R-8 fix did not simply disable the malformed path.
# =====================================================================
print("--- R-8 discrimination: MALFORMED store + valid present witness_id ---")
expect("malformed store + valid witness_id -> witness-binding-malformed (7b alive)",
       json.loads(REQ), MALFORMED_STORE,
       w_withheld=["witness-binding-malformed"], w_failures=[],
       a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

expect("malformed store (missing container) + valid witness_id -> malformed",
       json.loads(REQ), MALFORMED_STORE_2,
       w_withheld=["witness-binding-malformed"], w_failures=[],
       a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

# =====================================================================
# PRODUCER PATH: the same malformed store still yields
# `producer-binding-malformed`. Asserted on its own, with the witness side
# entirely absent, so the claim rests on nothing but the producer path.
# =====================================================================
print("--- R-8: the producer path still reaches the store gate ---")
doc = json.loads(REQ)
doc.pop("head_witness")
expect("malformed store, no head_witness -> producer-binding-malformed",
       doc, MALFORMED_STORE,
       w_withheld=["no-witness-supplied"], w_failures=[],
       a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

doc = json.loads(REQ)
doc.pop("head_witness")
expect("malformed store (missing container), no head_witness -> producer-binding-malformed",
       doc, MALFORMED_STORE_2,
       w_withheld=["no-witness-supplied"], w_failures=[],
       a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

# =====================================================================
# 7b INTACT: a WELL-FORMED store with no map entry for a present, usable id is
# still `witness-binding-missing` -- 7b, not 7a. The two must not be collapsed
# into one path in a way that loses the distinction, so this probe pins the
# well-formed-store leg of the same reason code.
# =====================================================================
print("--- R-8 7b: WELL-FORMED store, present usable id, no map entry ---")
EMPTY_WITNESS_MAP = copy.deepcopy(BIND)
EMPTY_WITNESS_MAP["witness_bindings"] = {}
expect("well-formed store + present id absent from witness_bindings -> "
       "witness-binding-missing (7b), producer path untouched",
       json.loads(REQ), EMPTY_WITNESS_MAP,
       w_withheld=["witness-binding-missing"], w_failures=[],
       a_withheld=[], klass="AIREP-Authenticated")

UNKNOWN_ID = json.loads(REQ)
UNKNOWN_ID["head_witness"]["witness_id"] = "NO-SUCH-WITNESS"
expect("well-formed store + unknown-but-usable id -> witness-binding-missing (7b)",
       UNKNOWN_ID, BIND,
       w_withheld=["witness-binding-missing"], w_failures=[],
       a_withheld=[], klass="AIREP-Authenticated")

# =====================================================================
# 7a with a WELL-FORMED store: unchanged from before R-8, and pinned so a
# later edit cannot regress the absent-id leg while the store is clean.
# =====================================================================
print("--- R-8 7a with a well-formed store (unchanged behaviour, pinned) ---")
expect("absent witness_id + well-formed store -> witness-binding-missing",
       with_witness_id(None, present=False), BIND,
       w_withheld=["witness-binding-missing"], w_failures=[],
       a_withheld=[], klass="AIREP-Authenticated")

expect("witness_id=null + well-formed store -> witness-binding-missing",
       with_witness_id(None), BIND,
       w_withheld=["witness-binding-missing"], w_failures=[],
       a_withheld=[], klass="AIREP-Authenticated")

# =====================================================================
# DEPENDENCY: 7a is reached only when stage 6 is clean. A stage-6 failure with
# an absent witness_id AND a malformed store must still report the stage-6
# reason alone (R-2 / section 4 dependency rule), never a stage-7 reason.
# =====================================================================
print("--- R-8 dependency: stage 6 not clean suppresses 7a as well ---")
doc = with_witness_id(None, present=False)
doc["head_witness"].pop("claim")
expect("stage-6 failure + absent witness_id + malformed store -> "
       "witness-claim-invalid alone, no stage-7 reason",
       doc, MALFORMED_STORE,
       w_withheld=[], w_failures=["witness-claim-invalid"],
       a_withheld=["producer-binding-malformed"], klass="AIREP-Core")

# =====================================================================
# 7c ORDER: an absent witness_id must not produce a revocation reason either --
# 7c runs only after an ACCEPTED witness binding.
# =====================================================================
print("--- R-8 7c: no revocation reason when 7a stops stage 7 ---")
NO_WITNESS_REVOC = copy.deepcopy(REVOC)
NO_WITNESS_REVOC["bindings"] = {k: v for k, v in NO_WITNESS_REVOC["bindings"].items()
                                if "witness" not in k}
code, v = run(json.dumps(with_witness_id(None, present=False)),
              bindings=MALFORMED_STORE, independence=INDEP,
              revocation=NO_WITNESS_REVOC, clock=CLOCK)
check("absent witness_id + malformed store + witness-less revocation snapshot -> "
      "witness-binding-missing alone (no revocation reason)",
      code == 0 and v is not None
      and v["witnessed_withheld"] == ["witness-binding-missing"]
      and v["witnessed_failures"] == [], "exit=%s %s" % (code, v))

# =====================================================================
print()
if FAILURES:
    print("FAILED probes (%d):" % len(FAILURES))
    for f in FAILURES:
        print("  - " + f)
    sys.exit(1)
print("all S9 round-4 probes passed")
