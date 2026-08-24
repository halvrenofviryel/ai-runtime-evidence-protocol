#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression probes for CLASS_VERIFIER_CONTRACT.md S9 rulings R-2, R-3, R-4.

Round-2 remediation. Every fixture is CONSTRUCTED IN THIS FILE by mutating a
corpus input in memory; nothing is written into the corpus and no expected
verdict is read from anywhere. Each probe names the exact reason set the ruling
itself states and fails loudly on any mismatch.

Layout: this file lives at <v0.2>/class-verification/verifier_py/, the corpus at
<v0.2>/class-verification/corpus/ and the schemas at <v0.2>/schemas/.
"""
import copy
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
        clock=None, schema_dir=SCHEMAS):
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
        proc = subprocess.run(argv, capture_output=True, text=True)
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


def retime(request_text, value):
    """Textually replace the head-witness claim's witnessed_at string."""
    head = request_text.index('"head_witness"')
    at = request_text.index('"witnessed_at":', head)
    start = request_text.index('"', at + len('"witnessed_at":'))
    end = request_text.index('"', start + 1)
    return request_text[:start] + json.dumps(value) + request_text[end + 1:]


CLOCK = ("2026-08-23T11:30:00Z", 3600)
REQ, BIND, INDEP, REVOC = case("P2")

# =====================================================================
print("--- control: unmutated P2 is clean (probe substrate is sound) ---")
code, v = run(REQ, bindings=BIND, independence=INDEP, revocation=REVOC, clock=CLOCK)
check("P2 control -> AIREP-Witnessed, all five channels empty",
      code == 0 and v["class"] == "AIREP-Witnessed"
      and channels(v) == ([], [], [], [], []), str(v))

# =====================================================================
# R-2: stage 6 is ONE gate with three DEPENDENT sub-steps.
#   6a shape/lexical -> witness-claim-invalid ALONE (6b, 6c do not run)
#   6b resolution/primary/reconciliation -> head-unresolved | head-mismatch ALONE
#      (6c does not run)
#   6c witnessed_at format + Gregorian -> witness-time-invalid
# Shape and time NEVER both report.
# =====================================================================
print("--- R-2: stage-6 dependent precedence ---")

BAD_TIME = "2026-02-30T11:30:00Z"          # syntactically well-formed, not a real date
GOOD_TIME = "2026-08-23T11:30:00Z"

# --- 6a beats 6c: an intrinsic claim defect AND an invalid witnessed_at.
# The decisive probe: both sub-steps would fire independently, so a verifier
# that ran them in parallel would emit BOTH reasons.
doc = json.loads(retime(REQ, BAD_TIME))
doc["head_witness"]["claim"]["extra"] = "sixth member"     # closed five-member set
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-2 6a+6c: sixth claim member + invalid Gregorian -> witness-claim-invalid ALONE",
      code == 0 and v["witnessed_failures"] == ["witness-claim-invalid"]
      and v["witnessed_withheld"] == [], str(v))

# Discrimination proof for the probe above: the SAME bad time with an otherwise
# clean claim really does produce witness-time-invalid, so the probe cannot pass
# because 6c is simply dead code.
code, v = run(retime(REQ, BAD_TIME), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-2 6c discriminates: invalid Gregorian alone -> witness-time-invalid",
      code == 0 and v["witnessed_failures"] == ["witness-time-invalid"]
      and v["witnessed_withheld"] == [], str(v))

# Same pairing via a member-TYPE defect rather than an extra member.
doc = json.loads(retime(REQ, BAD_TIME))
doc["head_witness"]["claim"]["chain_id"] = 7               # wrong member type
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-2 6a+6c: wrong-typed chain_id + invalid Gregorian -> witness-claim-invalid ALONE",
      code == 0 and v["witnessed_failures"] == ["witness-claim-invalid"]
      and v["witnessed_withheld"] == [], str(v))

# --- 6b beats 6c: head_ref resolves to nothing AND witnessed_at is invalid.
doc = json.loads(retime(REQ, BAD_TIME))
doc["head_witness"]["head_ref"]["record_id"] = "no-such-record"
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-2 6b+6c: unresolvable head_ref + invalid Gregorian -> witness-head-unresolved ALONE",
      code == 0 and v["witnessed_failures"] == ["witness-head-unresolved"]
      and v["witnessed_withheld"] == [], str(v))

# --- 6b beats 6c: reconciliation disagreement AND witnessed_at invalid.
doc = json.loads(retime(REQ, BAD_TIME))
doc["head_witness"]["claim"]["sequence"] = doc["head_witness"]["claim"]["sequence"] + 1
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-2 6b+6c: reconciliation mismatch + invalid Gregorian -> witness-head-mismatch ALONE",
      code == 0 and v["witnessed_failures"] == ["witness-head-mismatch"]
      and v["witnessed_withheld"] == [], str(v))

# --- 6a beats 6b: an intrinsic claim defect AND an unresolvable head_ref.
doc = json.loads(REQ)
doc["head_witness"]["claim"]["extra"] = "sixth member"
doc["head_witness"]["head_ref"]["record_id"] = "no-such-record"
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-2 6a+6b: sixth claim member + unresolvable head_ref -> witness-claim-invalid ALONE",
      code == 0 and v["witnessed_failures"] == ["witness-claim-invalid"]
      and v["witnessed_withheld"] == [], str(v))

# --- 6c runs only when 6a AND 6b are clean, and clock inputs play no part.
code, v = run(retime(REQ, BAD_TIME), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=None)
check("R-2 6c is clock-independent: no clock -> witness-time-invalid, no freshness reason",
      code == 0 and v["witnessed_failures"] == ["witness-time-invalid"]
      and v["witnessed_withheld"] == [], str(v))

# --- stage 6 failure suppresses stages 7-10 entirely (S4 dependency rule),
#     proven with every operator input deliberately withdrawn.
doc = json.loads(REQ)
doc["head_witness"]["claim"]["extra"] = "sixth member"
code, v = run(json.dumps(doc), bindings=BIND, independence=None,
              revocation=None, clock=None)
check("R-2 stage-6 failure suppresses all stage 7-10 reasons",
      code == 0 and v["witnessed_failures"] == ["witness-claim-invalid"]
      and v["witnessed_withheld"] == [], str(v))

# --- stage 6 clean with a valid time still reaches stage 10 (6c is not a wall).
code, v = run(retime(REQ, GOOD_TIME), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-2 6c clean -> stage 6 clean, stages 7-10 run (no witness-time-invalid)",
      code == 0 and "witness-time-invalid" not in v["witnessed_failures"], str(v))

# =====================================================================
# R-3: structural malformation precedes the semantic trust decision.
#   unknown member (or malformed container) + trusted:false -> *-binding-malformed ONLY
#   structurally clean entry + trusted not literally true   -> *-binding-not-trusted ONLY
# =====================================================================
print("--- R-3: binding precedence (structure before trust) ---")

P_BID = BIND["producer_bindings"]["acme-runtime/1.4"]
W_BID = BIND["witness_bindings"]["NOTARY-WITNESS #1"]

for role, bid, mal, nt in (("producer", P_BID, "producer-binding-malformed",
                            "producer-binding-not-trusted"),
                           ("witness", W_BID, "witness-binding-malformed",
                            "witness-binding-not-trusted")):
    # (a) clean entry, trusted:false -> not-trusted ONLY
    b = copy.deepcopy(BIND)
    b["bindings"][bid]["trusted"] = False
    code, v = run(REQ, bindings=b, independence=INDEP, revocation=REVOC, clock=CLOCK)
    got = v["authenticated_failures"] if role == "producer" else v["witnessed_failures"]
    other = v["authenticated_withheld"] if role == "producer" else v["witnessed_withheld"]
    check("R-3 %s clean entry + trusted:false -> %s ONLY" % (role, nt),
          code == 0 and got == [nt] and mal not in other, str(v))

    # (b) unknown member in the SAME entry + trusted:false -> malformed ONLY
    b = copy.deepcopy(BIND)
    b["bindings"][bid]["trusted"] = False
    b["bindings"][bid]["expires"] = "2027-01-01"        # unknown member
    code, v = run(REQ, bindings=b, independence=INDEP, revocation=REVOC, clock=CLOCK)
    check("R-3 %s unknown member + trusted:false -> %s ONLY" % (role, mal),
          code == 0 and mal in (v["authenticated_withheld"] + v["witnessed_withheld"])
          and nt not in (v["authenticated_failures"] + v["witnessed_failures"]), str(v))

    # (c) missing required container + trusted:false -> malformed ONLY
    b = copy.deepcopy(BIND)
    b["bindings"][bid]["trusted"] = False
    del b["bindings"]
    code, v = run(REQ, bindings=b, independence=INDEP, revocation=REVOC, clock=CLOCK)
    check("R-3 %s missing `bindings` container + trusted:false -> %s ONLY" % (role, mal),
          code == 0 and mal in (v["authenticated_withheld"] + v["witnessed_withheld"])
          and nt not in (v["authenticated_failures"] + v["witnessed_failures"]), str(v))

    # (d) member-closed entry whose FIELD VALUES are ill-formed + trusted:false.
    # S1.1 puts "malformed key" and "wrong role" in the *-binding-malformed
    # bucket, and R-3 says not-trusted applies only when the input is
    # structurally valid -- so these must report malformed, not not-trusted.
    for label, mutate in (
        ("malformed public_key_hex", lambda e: e.__setitem__("public_key_hex", "zz")),
        ("wrong role", lambda e: e.__setitem__("role", "auditor")),
        ("non-namespaced subject_identity", lambda e: e.__setitem__("subject_identity", "X")),
    ):
        b = copy.deepcopy(BIND)
        b["bindings"][bid]["trusted"] = False
        mutate(b["bindings"][bid])
        code, v = run(REQ, bindings=b, independence=INDEP, revocation=REVOC, clock=CLOCK)
        check("R-3 %s %s + trusted:false -> %s ONLY" % (role, label, mal),
              code == 0 and mal in (v["authenticated_withheld"] + v["witnessed_withheld"])
              and nt not in (v["authenticated_failures"] + v["witnessed_failures"]), str(v))

    # (e) `trusted` ABSENT stays malformed (WITHHELD), never not-trusted.
    b = copy.deepcopy(BIND)
    del b["bindings"][bid]["trusted"]
    code, v = run(REQ, bindings=b, independence=INDEP, revocation=REVOC, clock=CLOCK)
    check("R-3 %s `trusted` absent -> %s, never %s" % (role, mal, nt),
          code == 0 and mal in (v["authenticated_withheld"] + v["witnessed_withheld"])
          and nt not in (v["authenticated_failures"] + v["witnessed_failures"]), str(v))

    # (f) non-boolean `trusted` on a clean entry is still the definitive negative.
    b = copy.deepcopy(BIND)
    b["bindings"][bid]["trusted"] = "true"
    code, v = run(REQ, bindings=b, independence=INDEP, revocation=REVOC, clock=CLOCK)
    check("R-3 %s trusted:\"true\" (not literally true) -> %s" % (role, nt),
          code == 0 and nt in (v["authenticated_failures"] + v["witnessed_failures"]), str(v))

# =====================================================================
# R-4: S0 nested closure is limited to head_ref and signature, and creates NO
# new requiredness. Per R-1 the claim is never part of harness closure.
# =====================================================================
print("--- R-4: nested-closure scope and non-requiredness ---")

# (1) unknown member in head_ref / signature -> run-invalid (exit 1, no verdict)
for member in ("head_ref", "signature"):
    doc = json.loads(REQ)
    doc["head_witness"][member]["note"] = "unknown"
    code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
                  revocation=REVOC, clock=CLOCK)
    check("R-4 unknown member in head_witness.%s -> run-invalid (exit 1, no verdict)" % member,
          code == 1 and v is None, "exit=%s" % code)

# (2) claim is NOT harness closure: extra / missing / wrong-typed claim members
#     are NEVER run-invalid -- they are witness-claim-invalid.
doc = json.loads(REQ)
doc["head_witness"]["claim"]["sixth"] = "extra"
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-4/R-1 EXTRA claim member -> witness-claim-invalid, exit 0 (not run-invalid)",
      code == 0 and v is not None and v["witnessed_failures"] == ["witness-claim-invalid"],
      "exit=%s %s" % (code, v))

for member in ("chain_id", "sequence", "current", "length", "witnessed_at"):
    doc = json.loads(REQ)
    del doc["head_witness"]["claim"][member]
    code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
                  revocation=REVOC, clock=CLOCK)
    check("R-4/R-1 MISSING claim member `%s` -> witness-claim-invalid, exit 0" % member,
          code == 0 and v is not None and v["witnessed_failures"] == ["witness-claim-invalid"],
          "exit=%s %s" % (code, v))

for member, bad in (("chain_id", 1), ("sequence", "3"), ("current", 5),
                    ("length", None), ("witnessed_at", 20260823)):
    doc = json.loads(REQ)
    doc["head_witness"]["claim"][member] = bad
    code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
                  revocation=REVOC, clock=CLOCK)
    check("R-4/R-1 WRONG-TYPED claim member `%s` -> witness-claim-invalid, exit 0" % member,
          code == 0 and v is not None and v["witnessed_failures"] == ["witness-claim-invalid"],
          "exit=%s %s" % (code, v))

# (3) no new requiredness inside head_ref: a missing or unusable record_id is
#     witness-head-unresolved, NOT run-invalid.
for label, mutate in (
    ("record_id absent", lambda d: d["head_witness"]["head_ref"].pop("record_id")),
    ("record_id wrong-typed", lambda d: d["head_witness"]["head_ref"].__setitem__("record_id", 4)),
    ("record_id unmatched", lambda d: d["head_witness"]["head_ref"].__setitem__("record_id", "nope")),
):
    doc = json.loads(REQ)
    mutate(doc)
    code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
                  revocation=REVOC, clock=CLOCK)
    check("R-4 head_ref.%s -> witness-head-unresolved, exit 0" % label,
          code == 0 and v is not None
          and v["witnessed_failures"] == ["witness-head-unresolved"], "exit=%s %s" % (code, v))

# (4) no new requiredness inside signature: missing / wrong-typed / invalid
#     signature.value is witness-signature-invalid, NOT run-invalid.
for label, mutate in (
    ("value absent", lambda d: d["head_witness"]["signature"].pop("value")),
    ("value wrong-typed", lambda d: d["head_witness"]["signature"].__setitem__("value", 12)),
    ("value cryptographically invalid",
     lambda d: d["head_witness"]["signature"].__setitem__("value", "ab" * 64)),
):
    doc = json.loads(REQ)
    mutate(doc)
    code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
                  revocation=REVOC, clock=CLOCK)
    check("R-4 signature.%s -> witness-signature-invalid, exit 0" % label,
          code == 0 and v is not None
          and v["witnessed_failures"] == ["witness-signature-invalid"], "exit=%s %s" % (code, v))

# (5) signature.alg is informative-only: its ABSENCE affects neither the
#     cryptography nor the class, and its PRESENCE selects nothing.
doc = json.loads(REQ)
doc["head_witness"]["signature"].pop("alg")
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-4 signature.alg absent -> still AIREP-Witnessed, all channels empty",
      code == 0 and v is not None and v["class"] == "AIREP-Witnessed"
      and channels(v) == ([], [], [], [], []), "exit=%s %s" % (code, v))

doc = json.loads(REQ)
doc["head_witness"]["signature"]["alg"] = "ecdsa-p256-sha256"
code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
              revocation=REVOC, clock=CLOCK)
check("R-4 signature.alg naming another suite selects nothing -> still AIREP-Witnessed",
      code == 0 and v is not None and v["class"] == "AIREP-Witnessed"
      and channels(v) == ([], [], [], [], []), "exit=%s %s" % (code, v))

# =====================================================================
# FINDING NOW CLOSED BY S9 R-7 (round 3). This block was raised here as an open
# finding: R-1 and R-4 left unstated what happens when a WHOLE head_witness
# member is absent, and this implementation then required all four and aborted
# the run. R-7 settled it -- an absent known member fails or withholds the tier
# evaluation instead. The observations below are retained as a running record;
# the asserted probes for every R-7 row live in selfcheck_s9_round3.py.
print("--- R-7 (settled; asserted in round 3): whole head_witness member absent ---")
for member in ("claim", "head_ref", "signature", "witness_id"):
    doc = json.loads(REQ)
    doc["head_witness"].pop(member)
    code, v = run(json.dumps(doc), bindings=BIND, independence=INDEP,
                  revocation=REVOC, clock=CLOCK)
    print("[obs ] head_witness.%-11s absent -> exit=%s  witnessed_failures=%s"
          % (member, code, v["witnessed_failures"] if v else None))

# =====================================================================
print()
if FAILURES:
    print("PROBE FAILURES: %d" % len(FAILURES))
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("all S9 round-2 probes passed")
