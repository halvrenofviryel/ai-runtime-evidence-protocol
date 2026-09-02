#!/usr/bin/env python3
"""Regression: the cryptographic_result projection must follow the stage-4 prerequisite.

Contract section 4 and ruling R-6 state stage 4's prerequisite as "binding accepted AND
not definitively revoked". When it is not met the producer-signature stage does not
execute and no signature is verified under any key, so the only honest projection is
NOT_EVALUATED.

The projection previously branched on case identity ("FAIL if PS1 else NOT_EVALUATED if
PB2 else PASS"). A definitively revoked binding is neither of those source cases, so it
fell through to PASS -- reporting that a cryptographic check succeeded when none ran.
That was reproduced independently against the release-pinned handoff corpus on CLS-XT1;
see EXTERNAL_EVIDENCE.md.

These cases carry no case identifier on purpose: they assert the semantic condition, so
a case-ID patch cannot satisfy them.

Run:
    python3 tools/interop_pkg/test_crypto_projection.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("AIREP_INTEROP_REVISION", "v0.2")

from build_expected import crypto_projection  # noqa: E402

CASES = [
    # label, frozen channels, expected projection
    ("definitively revoked producer binding (the XT1 shape)",
     {"authenticated_failures": ["producer-binding-revoked"], "authenticated_withheld": []},
     "NOT_EVALUATED"),
    ("revoked binding alongside a clean witness",
     {"authenticated_failures": ["producer-binding-revoked"], "authenticated_withheld": [],
      "witnessed_failures": [], "witnessed_withheld": []},
     "NOT_EVALUATED"),
    ("producer binding missing (the PB2 shape)",
     {"authenticated_failures": [], "authenticated_withheld": ["producer-binding-missing"]},
     "NOT_EVALUATED"),
    ("producer binding malformed",
     {"authenticated_failures": [], "authenticated_withheld": ["producer-binding-malformed"]},
     "NOT_EVALUATED"),
    ("producer binding not trusted",
     {"authenticated_failures": ["producer-binding-not-trusted"], "authenticated_withheld": []},
     "NOT_EVALUATED"),
    ("producer suite unsupported",
     {"authenticated_failures": [], "authenticated_withheld": ["producer-suite-unsupported"]},
     "NOT_EVALUATED"),
    ("signature verified under the bound key and failed (the PS1 shape)",
     {"authenticated_failures": ["producer-signature-invalid"], "authenticated_withheld": []},
     "FAIL"),
    # R-6 is explicit: an unresolvable revocation STATE is not "revoked". The gate still
    # runs diagnostically, so these must not be suppressed into NOT_EVALUATED.
    ("revocation state missing -- gate still runs (R-6)",
     {"authenticated_failures": [], "authenticated_withheld": ["producer-revocation-state-missing"]},
     "PASS"),
    ("revocation state malformed -- gate still runs (R-6)",
     {"authenticated_failures": [], "authenticated_withheld": ["producer-revocation-state-malformed"]},
     "PASS"),
    ("clean authenticated path",
     {"authenticated_failures": [], "authenticated_withheld": [], "authenticated_caveats": []},
     "PASS"),
    ("clean path carrying only a caveat",
     {"authenticated_failures": [], "authenticated_withheld": [],
      "authenticated_caveats": ["wire-alg-mismatch"]},
     "PASS"),
    ("clean producer path with a witnessed-tier failure only",
     {"authenticated_failures": [], "authenticated_withheld": [],
      "witnessed_failures": ["witness-freshness-outside-window"], "witnessed_withheld": []},
     "PASS"),
]

def main():
    failures = []
    for label, channels, want in CASES:
        got = crypto_projection(channels)
        ok = got == want
        print("  %-58s %-14s %s" % (label, got, "OK" if ok else "FAIL (want %s)" % want))
        if not ok:
            failures.append(label)
    print()
    if failures:
        print("RESULT: %d projection case(s) FAILED" % len(failures))
        for f in failures:
            print("  FAILED: %s" % f)
        return 1
    print("RESULT: all %d cryptographic_result projection cases PASSED" % len(CASES))
    return 0

if __name__ == "__main__":
    sys.exit(main())
