#!/usr/bin/env python3
"""Emit the eight-dimension expected-result model. INTERNAL TOOLING."""
import json, os, subprocess, hashlib
from pathlib import Path

PIN = "b5ae87f74b386b11b8882865e50c3ad38120ff97"
from revision import REPO, OUT, REVISION  # noqa: E402
SRC = "spec/airep/v0.2"

# Stage 4 -- producer-signature verification -- has a prerequisite. Contract section 4
# and ruling R-6 state it as "binding accepted AND not definitively revoked". When the
# prerequisite is not met the stage does not execute, no signature is verified under any
# key, and the honest projection is NOT_EVALUATED. Reporting PASS there would state that
# a cryptographic check succeeded when none ran.
#
# R-6 is explicit that a missing or malformed REVOCATION STATE is not "revoked": the
# signature gate still runs diagnostically, so those two reasons must not suppress.
BINDING_NOT_ACCEPTED = frozenset({
    "producer-binding-missing",
    "producer-binding-malformed",
    "producer-binding-not-trusted",
    "producer-suite-unsupported",
})
DEFINITIVELY_REVOKED = frozenset({"producer-binding-revoked"})
SIGNATURE_VERIFIED_AND_FAILED = frozenset({"producer-signature-invalid"})


def crypto_projection(expected):
    """Project the frozen reason channels onto cryptographic_result.

    Driven by the contract's stage-4 prerequisite, not by case identity: any case
    whose frozen channels say the binding was never accepted, or was definitively
    revoked, projects NOT_EVALUATED regardless of which case it is.
    """
    reasons = (set(expected.get("authenticated_failures", []))
               | set(expected.get("authenticated_withheld", [])))
    if reasons & (BINDING_NOT_ACCEPTED | DEFINITIVELY_REVOKED):
        return "NOT_EVALUATED"
    if reasons & SIGNATURE_VERIFIED_AND_FAILED:
        return "FAIL"
    return "PASS"

def git_show(p):
    r = subprocess.run(["git","show",f"{PIN}:{p}"],cwd=REPO,capture_output=True)
    return r.stdout if r.returncode==0 else None

def main():
    """Emit the expected-result rows for the configured corpus revision."""
    idx = json.loads((OUT/"CASE_INDEX.json").read_text())
    probes = json.loads(git_show(f"{SRC}/class-verification/corpus/probes/probe_index.json"))
    probe_by_id = {p.get("probe_id") or p.get("id"): p for p in
                   (probes if isinstance(probes,list) else probes.get("probes",[]))}

    rows = []
    for c in idx["cases"]:
        pid, sid, kind = c["package_case_id"], c["source_case_id"], c["source_kind"]
        row = {
            "package_case_id": pid,
            "source_case_id": sid,
            "source_path": c["source_path"],
            "category": c["category"],
            "artifact_family": c["artifact_family"],
        }
        if kind == "class":
            e = json.loads(git_show(f"{SRC}/class-verification/corpus/cases/{sid}/expected.json"))
            cls = e["class"]
            # dimension 1-3 are derived from the frozen expected result, and the derivation
            # is stated so a reader can dispute it rather than take it on trust.
            row.update({
                "run_validity": "VALID",
                # The signing input reconstructs for every class case, PS1 included: the
                # preimage is well-formed and the signature is well-formed 128-hex. What fails
                # in PS1 is verification under the BOUND key. Reporting MISMATCH here would
                # conflate "could not rebuild the input" with "rebuilt it and the signature
                # did not verify" - the exact distinction a three-valued checker exists to make.
                "signing_input_reconstruction": "RECONSTRUCTED",
                "cryptographic_result": crypto_projection(e),
                "airep_class": cls,
                "reason_channels": {
                    "authenticated_failures": e.get("authenticated_failures", []),
                    "authenticated_withheld": e.get("authenticated_withheld", []),
                    "authenticated_caveats": e.get("authenticated_caveats", []),
                    "witnessed_failures": e.get("witnessed_failures", []),
                    "witnessed_withheld": e.get("witnessed_withheld", []),
                },
                "observer_assessment": e.get("observer_assessment"),
                "process_exit": 0,
                "expected_provenance": {
                    "provenance_kind": "frozen_release_expected_result",
                    "source_file": f"{SRC}/class-verification/corpus/cases/{sid}/expected.json",
                    "sha256": hashlib.sha256(
                        git_show(f"{SRC}/class-verification/corpus/cases/{sid}/expected.json")).hexdigest(),
                    "class_and_five_channels_and_observer": "verbatim, unmodified, order preserved",
                    "run_validity_reconstruction_crypto": (
                        "package_derived projection of the frozen expected result onto the three "
                        "dimensions the recipient's checker reports separately; the frozen release "
                        "does not carry these three fields. Derivation, driven by the contract's "
                        "stage-4 prerequisite rather than by case identity: stage 4 runs only if the "
                        "producer binding is accepted and not definitively revoked (contract s4, "
                        "ruling R-6), so a frozen channel reporting the binding missing, malformed, "
                        "not trusted, suite-unsupported, or revoked means no signature was verified "
                        "under any key and cryptographic_result is NOT_EVALUATED; a populated "
                        "authenticated_failures channel naming a signature reason implies FAIL while "
                        "signing_input_reconstruction stays RECONSTRUCTED, because the preimage "
                        "rebuilds and only verification under the bound key fails; otherwise "
                        "RECONSTRUCTED/PASS. Per R-6 a missing or malformed revocation state is not "
                        "'revoked' and does not suppress the gate. Dispute this projection rather "
                        "than the frozen fields if you disagree."),
                },
            })
        else:
            p = probe_by_id[sid]
            row.update({
                "run_validity": "INVALID_ARTIFACT" if p.get("expected_exit") == 1 else "INVALID_CONFIGURATION",
                "signing_input_reconstruction": "INDETERMINATE",
                "cryptographic_result": "NOT_EVALUATED",
                "airep_class": None,
                "reason_channels": None,
                "observer_assessment": "not_applicable",
                "process_exit": p.get("expected_exit"),
                "expected_provenance": {
                    "provenance_kind": "frozen_release_expected_result",
                    "source_file": f"{SRC}/class-verification/corpus/probes/probe_index.json",
                    "note": "the release declares a process exit for this probe and NO verdict; "
                            "airep_class and reason_channels are null because none is emitted.",
                },
            })
        row["does_not_establish"] = (
            "Reproducing this row establishes only that a separately implemented verifier reached the "
            "same stated result for this one release-pinned case. It does not establish AIREP "
            "correctness, stability, standardisation, third-party producer interoperability, or the "
            "truth of any real-world evidence.")
        rows.append(row)

    (OUT/"expected").mkdir(parents=True, exist_ok=True)
    with (OUT/"expected/expected_results.jsonl").open("w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")

    from collections import Counter
    print("expected rows:", len(rows))
    print("by category:", dict(Counter(r["category"] for r in rows)))
    print("by family:", dict(Counter(r["artifact_family"] for r in rows)))
    print("by class:", dict(Counter(str(r["airep_class"]) for r in rows)))
    print("by exit:", dict(Counter(str(r["process_exit"]) for r in rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
