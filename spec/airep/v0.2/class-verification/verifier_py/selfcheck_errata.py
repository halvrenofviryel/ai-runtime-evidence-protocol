#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Construction self-checks for the CLASS_VERIFIER_CONTRACT S9 errata.

Every fixture here is CONSTRUCTED IN THIS FILE by mutating a corpus input; no
expected verdict is read from anywhere. Each check asserts only the property the
errata item itself states, in the errata's own vocabulary.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile

# Round 3: paths corrected to the COMMITTED repository layout -- this file at
# <v0.2>/class-verification/verifier_py/, the corpus at
# <v0.2>/class-verification/corpus/, the schemas at <v0.2>/schemas/ and the
# frozen JCS canonicalizer at <airep>/v0.1/conformance/jcs.py. Path resolution
# only: no assertion in this file was added, removed or weakened.
HERE = os.path.dirname(os.path.abspath(__file__))
CVDIR = os.path.normpath(os.path.join(HERE, os.pardir))
CORPUS = os.path.join(CVDIR, "corpus", "cases")
SCHEMAS = os.path.normpath(os.path.join(CVDIR, os.pardir, "schemas"))
JCS_SRC = os.path.normpath(
    os.path.join(CVDIR, os.pardir, os.pardir, "v0.1", "conformance", "jcs.py"))
VERIFIER = os.path.join(HERE, "class_verifier.py")

FAILURES = []


def run(request_text, *, bindings=None, independence=None, revocation=None,
        clock=None, schema_dir=SCHEMAS, extra_args=()):
    """Invoke the verifier as a process; returns (exit_code, verdict_or_None)."""
    with tempfile.TemporaryDirectory(dir=HERE) as tmp:
        req = os.path.join(tmp, "request.json")
        with open(req, "w", encoding="utf-8") as fh:
            fh.write(request_text)
        argv = [sys.executable, VERIFIER, "--request", req]
        for flag, doc in (("--bindings", bindings), ("--independence-policy", independence),
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
        argv += list(extra_args)
        proc = subprocess.run(argv, capture_output=True, text=True)
    verdict = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, verdict


def case(name):
    """Load a corpus case's inputs as (request_text, bindings, indep, revocation)."""
    base = os.path.join(CORPUS, name)

    def load(fn):
        path = os.path.join(base, fn)
        return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else None

    return (open(os.path.join(base, "request.json"), encoding="utf-8").read(),
            load("bindings.json"), load("independence.json"), load("revocation.json"))


def check(label, condition, detail=""):
    status = "ok  " if condition else "FAIL"
    print("[%s] %s%s" % (status, label, ("  -- " + detail) if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def respell(request_text, member, lexeme):
    """Replace the head-witness claim's numeric token with a given SOURCE spelling.

    Textual, so the spelling survives verbatim into the request bytes -- which is
    exactly what E-1 is about.
    """
    marker = '"head_witness"'
    head = request_text.index(marker)
    needle = '"%s":' % member
    at = request_text.index(needle, head)
    start = at + len(needle)
    end = start
    while request_text[end] in ' \t\r\n':
        end += 1
    tok_start = end
    while request_text[end] not in ',}\r\n \t':
        end += 1
    return request_text[:tok_start] + lexeme + request_text[end:]


def retime(request_text, value):
    marker = '"head_witness"'
    head = request_text.index(marker)
    at = request_text.index('"witnessed_at":', head)
    start = request_text.index('"', at + len('"witnessed_at":'))
    end = request_text.index('"', start + 1)
    return request_text[:start] + json.dumps(value) + request_text[end + 1:]


CLOCK = ("2026-08-23T11:30:00Z", 3600)

# =====================================================================
print("--- E-1: numeric SOURCE lexeme rule (^(0|[1-9][0-9]*)$) ---")
req, b, i, r = case("P2")

code, v = run(req, bindings=b, independence=i, revocation=r, clock=CLOCK)
check("E-1 control: unmutated P2 emits no witness-claim-invalid",
      code == 0 and "witness-claim-invalid" not in v["witnessed_failures"], str(v))

# Discrimination proof: show that `-0` really is invisible to a value-only gate,
# so the check above cannot pass for the wrong reason.
_parsed = json.loads('{"sequence": -0, "length": 1}')
check("E-1 discriminates: `-0` parses to an int that passes every VALUE check",
      isinstance(_parsed["sequence"], int) and not isinstance(_parsed["sequence"], bool)
      and 0 <= _parsed["sequence"] <= 9007199254740991, repr(_parsed))

# `-0` parses to the int 0 and passes every post-parse value check; only the
# source spelling distinguishes it. This is the check a value-only verifier misses.
code, v = run(respell(req, "sequence", "-0"), bindings=b, independence=i, revocation=r, clock=CLOCK)
check("E-1 sequence spelled `-0` (parses to 0) -> witness-claim-invalid",
      code == 0 and v["witnessed_failures"] == ["witness-claim-invalid"], str(v))
check("E-1 `-0` suppresses all stage 7-10 reasons (S4 dependency rule)",
      code == 0 and v["witnessed_withheld"] == [], str(v))

for member, lexeme in (("sequence", "0.0"), ("sequence", "0e0"),
                       ("length", "1.0"), ("length", "1e0"), ("length", "1E+0")):
    code, v = run(respell(req, member, lexeme), bindings=b, independence=i,
                  revocation=r, clock=CLOCK)
    check("E-1 %s spelled `%s` -> witness-claim-invalid" % (member, lexeme),
          code == 0 and v["witnessed_failures"] == ["witness-claim-invalid"], str(v))

# The lexeme is re-derived from the request BYTES, so a canonical spelling with
# insignificant whitespace around it still passes.
code, v = run(respell(req, "sequence", "0"), bindings=b, independence=i, revocation=r, clock=CLOCK)
check("E-1 canonical `0` still clean",
      code == 0 and "witness-claim-invalid" not in v["witnessed_failures"], str(v))

# =====================================================================
print("--- E-2: witnessed_at structural validity is a stage-6 gate ---")
BAD_TIMES = ["2026-02-30T11:30:00Z",      # invalid Gregorian date
             "2026-08-23T11:30:60Z",      # leap second, not permitted in v0.2
             "2026-08-23T11:30:00.000Z",  # fractional seconds
             "2026-08-23T11:30:00+00:00",  # offset other than literal Z
             "2026-08-23T24:00:00Z"]      # hour out of range

for bad in BAD_TIMES:
    # (a) WITH clock inputs
    code, v = run(retime(req, bad), bindings=b, independence=i, revocation=r, clock=CLOCK)
    check("E-2 %-28s with clock -> witness-time-invalid" % bad,
          code == 0 and v["witnessed_failures"] == ["witness-time-invalid"], str(v))
    # (b) WITHOUT clock inputs -- the consequence E-2 states so it cannot be missed
    code, v = run(retime(req, bad), bindings=b, independence=i, revocation=r, clock=None)
    check("E-2 %-28s no clock  -> witness-time-invalid, NOT freshness-inputs-missing" % bad,
          code == 0
          and v["witnessed_failures"] == ["witness-time-invalid"]
          and "freshness-inputs-missing" not in v["witnessed_withheld"], str(v))

# A non-string witnessed_at is a member-TYPE defect -> witness-claim-invalid (E-5:
# witness-claim-invalid is reserved for intrinsic claim defects).
bad_type = json.loads(req)
bad_type["head_witness"]["claim"]["witnessed_at"] = 20260823
code, v = run(json.dumps(bad_type), bindings=b, independence=i, revocation=r, clock=CLOCK)
check("E-2 non-string witnessed_at -> witness-claim-invalid (type, not format)",
      code == 0 and v["witnessed_failures"] == ["witness-claim-invalid"], str(v))

# Stage 10 still does recency. Retiming invalidates the witness signature, so
# stage 9 also reports; assert on the freshness reason only.
code, v = run(retime(req, "2026-08-23T09:00:00Z"), bindings=b, independence=i,
              revocation=r, clock=CLOCK)
check("stage 10 still computes recency -> witness-freshness-outside-window",
      code == 0 and "witness-freshness-outside-window" in v["witnessed_failures"]
      and "witness-time-invalid" not in v["witnessed_failures"], str(v))
code, v = run(retime(req, "2026-08-23T10:30:00Z"), bindings=b, independence=i,
              revocation=r, clock=CLOCK)
check("stage 10 boundary-equal (3600s, window 3600s) is fresh",
      code == 0 and "witness-freshness-outside-window" not in v["witnessed_failures"], str(v))
# A structurally valid claim with no clock supplied is still WITHHELD at stage 10.
code, v = run(req, bindings=b, independence=i, revocation=r, clock=None)
check("stage 10 valid witnessed_at, no clock -> freshness-inputs-missing",
      code == 0 and v["witnessed_withheld"] == ["freshness-inputs-missing"], str(v))

# =====================================================================
print("--- E-3: wire `independent` requires the PRIMARY to be Authenticated ---")
req3, b3, i3, r3 = case("P3")
code, v = run(req3, bindings=b3, independence=i3, revocation=r3, clock=CLOCK)
check("E-3 control: P3 primary Authenticated -> observer_assessment independent",
      code == 0 and v["class"] == "AIREP-Authenticated"
      and v["observer_assessment"] == "independent", str(v))

# Revoke ONLY the primary Effect's producer binding. The referenced Execution
# artifact still authenticates in its own right under a distinct, active binding.
rev_primary = copy.deepcopy(r3)
rev_primary["bindings"]["airep.producer-a"]["state"] = "revoked"
code, v = run(req3, bindings=b3, independence=i3, revocation=rev_primary, clock=CLOCK)
check("E-3 primary revoked, Execution still Authenticated -> observer unknown",
      code == 0 and v["class"] == "AIREP-Core"
      and v["authenticated_failures"] == ["producer-binding-revoked"]
      and v["observer_assessment"] == "unknown", str(v))

# Same shape via a withheld (not failed) primary: drop the Effect producer's map entry.
b3_nomap = copy.deepcopy(b3)
del b3_nomap["producer_bindings"]["acme-runtime/1.4"]
code, v = run(req3, bindings=b3_nomap, independence=i3, revocation=r3, clock=CLOCK)
check("E-3 primary binding missing, Execution Authenticated -> observer unknown",
      code == 0 and v["class"] == "AIREP-Core"
      and v["observer_assessment"] == "unknown", str(v))

# =====================================================================
print("--- E-4: operator-input containers required + closed, fail-closed ---")
b4 = copy.deepcopy(b)

extra_top = copy.deepcopy(b4)
extra_top["note"] = "unknown member at the binding store's top level"
code, v = run(req, bindings=extra_top, independence=i, revocation=r, clock=CLOCK)
check("E-4 unknown member at binding-store top level -> *-binding-malformed",
      code == 0 and v["authenticated_withheld"] == ["producer-binding-malformed"], str(v))

for missing in ("bindings", "producer_bindings", "witness_bindings"):
    trimmed = copy.deepcopy(b4)
    del trimmed[missing]
    code, v = run(req, bindings=trimmed, independence=i, revocation=r, clock=CLOCK)
    check("E-4 binding store missing `%s` -> producer-binding-malformed" % missing,
          code == 0 and v["authenticated_withheld"] == ["producer-binding-malformed"], str(v))

unrelated = copy.deepcopy(b4)
some_other = [k for k in unrelated["bindings"]
              if k != unrelated["producer_bindings"].get("acme-runtime/1.4")][0]
unrelated["bindings"][some_other]["expires"] = "2027-01-01"
code, v = run(req, bindings=unrelated, independence=i, revocation=r, clock=CLOCK)
check("E-4 unknown member in an UNRELATED binding entry -> store malformed",
      code == 0 and v["authenticated_withheld"] == ["producer-binding-malformed"], str(v))

for missing in ("independent_pairs", "non_independent_pairs"):
    trimmed = copy.deepcopy(i)
    del trimmed[missing]
    code, v = run(req, bindings=b, independence=trimmed, revocation=r, clock=CLOCK)
    check("E-4 policy missing `%s` -> independence-policy-malformed (not empty)" % missing,
          code == 0 and "independence-policy-malformed" in v["witnessed_withheld"], str(v))

pol_extra = copy.deepcopy(i)
pol_extra["comment"] = "unknown member"
code, v = run(req, bindings=b, independence=pol_extra, revocation=r, clock=CLOCK)
check("E-4 unknown member in independence policy -> independence-policy-malformed",
      code == 0 and "independence-policy-malformed" in v["witnessed_withheld"], str(v))

rev_extra = copy.deepcopy(r)
rev_extra["issued_at"] = "2026-08-23T00:00:00Z"
code, v = run(req, bindings=b, independence=i, revocation=rev_extra, clock=CLOCK)
check("E-4 unknown member in revocation snapshot -> producer-revocation-state-malformed",
      code == 0 and v["authenticated_withheld"] == ["producer-revocation-state-malformed"], str(v))

# S0 envelope nested objects -> run-invalid (exit 1), no verdict.
for member, mutate in (
    ("head_ref", lambda d: d["head_witness"]["head_ref"].__setitem__("note", "x")),
    ("signature", lambda d: d["head_witness"]["signature"].__setitem__("note", "x")),
):
    doc = json.loads(req)
    mutate(doc)
    code, v = run(json.dumps(doc), bindings=b, independence=i, revocation=r, clock=CLOCK)
    check("E-4 unknown member in S0 head_witness.%s -> run-invalid (exit 1)" % member,
          code == 1 and v is None, "exit=%s" % code)

doc = json.loads(req)
doc["unknown_top"] = 1
code, v = run(json.dumps(doc), bindings=b, independence=i, revocation=r, clock=CLOCK)
check("E-4 unknown member at S0 envelope top level -> run-invalid (exit 1)",
      code == 1 and v is None, "exit=%s" % code)

# E-4 vs E-1/E-5: a SIXTH claim member stays an intrinsic claim defect at stage 6.
doc = json.loads(req)
doc["head_witness"]["claim"]["extra"] = "sixth member"
code, v = run(json.dumps(doc), bindings=b, independence=i, revocation=r, clock=CLOCK)
check("claim closure stays stage-6 witness-claim-invalid (E-1/E-5), not run-invalid",
      code == 0 and v is not None and v["witnessed_failures"] == ["witness-claim-invalid"],
      "exit=%s %s" % (code, v))

# =====================================================================
print("--- E-6: CONFIRMED, unchanged (missing/malformed revocation is not `revoked`) ---")
rev_nostate = copy.deepcopy(r)
p_bid = b["producer_bindings"]["acme-runtime/1.4"]
del rev_nostate["bindings"][p_bid]
code, v = run(req, bindings=b, independence=i, revocation=rev_nostate, clock=CLOCK)
check("E-6 revocation entry absent -> WITHHELD only, signature gate still ran",
      code == 0
      and v["authenticated_withheld"] == ["producer-revocation-state-missing"]
      and v["authenticated_failures"] == [], str(v))

rev_bad = copy.deepcopy(r)
rev_bad["bindings"][p_bid]["state"] = "suspended"
code, v = run(req, bindings=b, independence=i, revocation=rev_bad, clock=CLOCK)
check("E-6 revocation state neither value -> WITHHELD only, no producer-signature-invalid",
      code == 0
      and v["authenticated_withheld"] == ["producer-revocation-state-malformed"]
      and v["authenticated_failures"] == [], str(v))

# =====================================================================
print("--- S9 portability note: default --schema-dir in the committed layout ---")
with tempfile.TemporaryDirectory(dir=HERE) as tmp:
    root = os.path.join(tmp, "v0.2")
    vdir = os.path.join(root, "class-verification", "verifier_py")
    os.makedirs(vdir)
    os.makedirs(os.path.join(root, "schemas"))
    for fn in os.listdir(SCHEMAS):
        with open(os.path.join(SCHEMAS, fn), "rb") as src, \
                open(os.path.join(root, "schemas", fn), "wb") as dst:
            dst.write(src.read())
    with open(VERIFIER, "rb") as src, \
            open(os.path.join(vdir, "class_verifier.py"), "wb") as dst:
        dst.write(src.read())
    # The verifier loads the frozen canonicalizer from its repository-relative
    # location, so the synthetic tree must carry it there too (round 3).
    jcs_dir = os.path.join(tmp, "v0.1", "conformance")
    os.makedirs(jcs_dir)
    with open(JCS_SRC, "rb") as src, \
            open(os.path.join(jcs_dir, "jcs.py"), "wb") as dst:
        dst.write(src.read())
    reqpath = os.path.join(tmp, "request.json")
    with open(reqpath, "w", encoding="utf-8") as fh:
        fh.write(req)
    proc = subprocess.run(
        [sys.executable, os.path.join(vdir, "class_verifier.py"), "--request", reqpath],
        capture_output=True, text=True)
    check("default schema dir resolves at <v0.2>/class-verification/verifier_py/",
          proc.returncode == 0 and proc.stdout.strip().startswith("{"),
          "exit=%s stderr=%s" % (proc.returncode, proc.stderr.strip()[:200]))

print()
if FAILURES:
    print("SELF-CHECK FAILURES: %d" % len(FAILURES))
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("all construction self-checks passed")
