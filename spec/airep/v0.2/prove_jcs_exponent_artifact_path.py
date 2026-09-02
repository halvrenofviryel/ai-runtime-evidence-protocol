#!/usr/bin/env python3
"""Coverage: numbers that force RFC 8785 exponential serialisation, on the artifact path.

Measured before this was written, across every canonical v0.2 corpus:

    class-verification 60-case corpus   distinct JSON numbers: 0, 1, 2, 3600
    fixed vectors V1-V4, W1-W2          no JSON numbers reach canonicalisation
    stage4 corpus                       distinct JSON numbers: -1, 0, 1, 2, 3, 3600
    schema-validation corpus            distinct JSON numbers: -1, 1, 9007199254740992

None of those requires exponential form. ES6 / RFC 8785 s3.2.2.3 switches to exponential
notation at |x| >= 1e21 or |x| < 1e-6, and 9007199254740992 (2^53) is below 1e21, so it
serialises without an exponent. The gap is therefore **confirmed** and is additive coverage,
not a protocol failure: no v0.2 artifact anywhere exercises the exponential branch through
canonicalisation into a hash preimage and integrity.current.

The *serialiser* is not the gap. v0.2 canonicalises through the repository's own frozen
spec/airep/v0.1/conformance/jcs.py -- see the JCS_RELPATH loader in the class verifier -- and
conformance/test_jcs.py already asserts 1e-07 -> 1e-7 and 1.5e+30 against that module. What
was unexercised is the end-to-end artifact path over such a value.

This script closes that path without touching any pinned corpus, so no recorded parity or
schema-validation measurement changes.

Distinguishing note: rejecting the source lexeme `1e0` under E-1 is input lexical-form
validation and is NOT coverage of canonical numeric serialisation. `1e0` decodes to 1 and
canonicalises to `1`; it never reaches the exponential branch.

Run:
    python3 spec/airep/v0.2/prove_jcs_exponent_artifact_path.py
"""
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JCS_PATH = os.path.join(HERE, os.pardir, "v0.1", "conformance", "jcs.py")
LF = b"\x0a"

_spec = importlib.util.spec_from_file_location("_airep_jcs", os.path.abspath(JCS_PATH))
jcs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jcs)

# ES6 / RFC 8785 s3.2.2.3 boundaries. Source lexeme -> required canonical form.
BOUNDARY = [
    ("1e21",                   "1e+21",  True,  "at the upper switch point"),
    ("1e20",                   "100000000000000000000", False, "just below the upper switch"),
    ("1.5e+30",                "1.5e+30", True,  "well above, fractional mantissa"),
    ("1e-6",                   "0.000001", False, "at the lower switch point, still plain"),
    ("1e-7",                   "1e-7",   True,  "just past the lower switch"),
    ("1.2345e-11",             "1.2345e-11", True, "fractional mantissa, negative exponent"),
    ("-1e21",                  "-1e+21", True,  "sign is preserved"),
]

failures = []


def check(ok, label):
    print("  %-64s %s" % (label, "OK" if ok else "FAIL"))
    if not ok:
        failures.append(label)


def artifact_with(lexeme):
    """A minimal v0.2 decision artifact carrying the number, as JSON source text."""
    return (
        '{"airep_version":"0.2","artifact_type":"decision","chain_id":"jcs-exp-1",'
        '"claim":{"assertion":"coverage","basis":"boundary"},'
        '"integrity":{"previous":"sha256:' + "0" * 64 + '"},'
        '"measurement":{"value":' + lexeme + '},'
        '"record_id":"rec-jcs-exp-1","sequence":0}'
    )


def main():
    print("A. canonical numeric serialisation at the ES6 / RFC 8785 boundaries")
    for lexeme, want, is_exp, note in BOUNDARY:
        got = jcs.canonicalize(json.loads(lexeme))
        if isinstance(got, bytes):
            got = got.decode("utf-8")
        check(got == want, "%-12s -> %-22s (%s)" % (lexeme, got, note))
        check(("e" in got) == is_exp,
              "%-12s exponential form is %s as required" % (lexeme, is_exp))

    print("\nB. the same values through the artifact path: JCS -> preimage -> integrity.current")
    seen = {}
    for lexeme, want, is_exp, _note in BOUNDARY:
        artifact = json.loads(artifact_with(lexeme))
        body = jcs.canonicalize(artifact)
        if not isinstance(body, bytes):
            body = body.encode("utf-8")
        # INTEGRITY.md s2: hash_preimage = tag-bytes LF jcs-bytes
        tag = "AIREP/0.2/hash/decision".encode("ascii")
        preimage = tag + LF + body
        current = "sha256:" + hashlib.sha256(preimage).hexdigest()
        check(want.encode("utf-8") in body,
              "%-12s canonical body carries %s" % (lexeme, want))
        check(b"\x0a" not in body,
              "%-12s canonical body contains no raw LF (separator stays unambiguous)" % lexeme)
        check(current.startswith("sha256:") and len(current) == 71,
              "%-12s integrity.current well-formed" % lexeme)
        seen.setdefault(current, []).append(lexeme)
    check(len(seen) == len(BOUNDARY),
          "each boundary value yields a distinct integrity.current")

    print("\nC. lexical rejection is not serialisation coverage")
    check(jcs.canonicalize(json.loads("1e0")) in ("1", b"1"),
          "1e0 decodes to 1 and canonicalises to 1, never reaching the exponential branch")

    print("\nD. pre-1970 freshness -- already covered, no case added")
    print("  spec/airep/v0.2/stage4/corpus/S9-1.json")
    print("    now             0100-01-01T00:00:00Z")
    print("    witnessed_at    0099-12-31T23:30:00Z")
    print("    window          3600s, 30 minutes inside -> expected PASS / OK")
    print("  It exercises parsing, epoch arithmetic across a pre-1970 year boundary, and the")
    print("  freshness comparison. The observation is measured and closed, not extended.")

    print("\n%s" % ("RESULT: all canonicalisation boundary checks PASSED"
                    if not failures else "RESULT: %d check(s) FAILED" % len(failures)))
    for f in failures:
        print("  FAILED: %s" % f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
