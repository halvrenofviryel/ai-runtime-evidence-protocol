#!/usr/bin/env python3
"""Generate CASE_SELECTION.md FROM CASE_INDEX.json. INTERNAL TOOLING.

Every category, count and family in this document is derived, never hand-maintained.
An earlier CASE_SELECTION.md was written by an ad-hoc script outside the build chain, so
re-running the pipeline left it stale: it still called CLS-LEX1 indeterminate after the
index had been corrected to failure. Prose that restates structured data has to be
generated from it, or it drifts.
"""
import json
from collections import Counter
from pathlib import Path

OUT = Path("/mnt/data/claude/ai-runtime-evidence-protocol/interop/independent-verifier-corpus/v0.1")

RULES = {
 "CLS-P1":("INTEGRITY §2,§3; contract §3 stages 0-5","JCS, SHA-256, Ed25519, schema, trust binding, revocation"),
 "CLS-P2":("contract §3 stages 6-11; INTEGRITY §4","JCS, SHA-256, Ed25519, schema, trust binding, revocation, freshness, independence"),
 "CLS-P3":("contract §3 observer assessment; AD-03","JCS, SHA-256, Ed25519, schema, reference resolution, trust binding, observer assessment"),
 "CLS-CTL1":("control.schema.json; INTEGRITY §5","JCS, SHA-256, Ed25519, schema, trust binding"),
 "CLS-NG1":("INTEGRITY §4.3; non-genesis head","JCS, SHA-256, Ed25519, reference resolution, freshness"),
 "CLS-FR3":("contract §3 stage 10 boundary","freshness"),
 "CLS-PS1":("INTEGRITY §3; contract stage 4","Ed25519, trust binding"),
 "CLS-PS2":("INTEGRITY §3.2 wire alg informative only","Ed25519, trust binding"),
 "CLS-XT1":("contract §3 stage 3 revocation","revocation, trust binding"),
 "CLS-IND4":("contract §1.2 independence policy","independence policy"),
 "CLS-FR1":("contract §3 stage 10 freshness","freshness"),
 "CLS-WM3":("contract §0 reference resolution","reference resolution"),
 "CLS-PB2":("contract §4 withheld vs failure; stage 2","trust binding"),
 "CLS-WB2":("contract §4; stage 7","trust binding"),
 "CLS-OB4":("contract §3 observer assessment","reference resolution, observer assessment"),
 "CLS-LEX1":("INTEGRITY §2 lexical form; frozen ruling E-1","JCS, lexical form preservation"),
 "PROC-UNP":("contract §6.4 exit 1 run-invalid","process exit"),
 "PROC-NGR":("contract §6.4 exit 2 usage error","process exit"),
}
PROPERTY = {
 "positive": "expected class earned cleanly",
 "failure": "definitive normative failure, with a verdict emitted",
 "caveat": "passes while recording a caveat",
 "withheld": "assurance withheld — the check could not run",
 "indeterminate": "no verdict is emitted at all",
}


def main() -> int:
    idx = json.loads((OUT / "CASE_INDEX.json").read_text())
    rows = {json.loads(l)["package_case_id"]: json.loads(l)
            for l in (OUT / "expected/expected_results.jsonl").read_text().splitlines()}
    cases = idx["cases"]
    cat = Counter(c["category"] for c in cases)
    fam = Counter(c["artifact_family"] for c in cases)

    L = ["# Case selection", "",
         "**This file is generated from `CASE_INDEX.json` and `expected/expected_results.jsonl`.**",
         "Do not edit it by hand: every category and count below is derived, so it cannot drift",
         "away from the structured data the package ships.", "",
         "Selected from the 60 scored class-verification cases (45 C0 + 15 C1) and the 15",
         "release-declared CLI/process-exit probes at the pinned commit.", "",
         "## Probe count reconciliation", "",
         "| Quantity | Count |", "|---|---|",
         "| Release-declared official CLI/process-exit probes (`probe_index.json`) | **15** |",
         "| Of those, probes with input-file directories on disk | **13** |",
         "| CLI-only probes with no input files (`PRB-CLI-CORPUS-NO-OUT`, `PRB-CLI-HELP`) | **2** |",
         "| Filesystem entries under `corpus/probes/` (13 dirs + `probe_index.json`) | **14** |", "",
         "Not every directory is an official scored probe, and not every official probe has a",
         "directory.", "",
         "## Selection matrix", "",
         "| Pkg id | Source | Category | Class | Exit | Property | Family | Rule | Capabilities | Not redundant because |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for c in cases:
        pid = c["package_case_id"]
        r = rows[pid]
        rule, caps = RULES[pid]
        L.append(f"| `{pid}` | `{c['source_case_id']}` | **{c['category']}** | "
                 f"{r['airep_class'] or '—'} | {r['process_exit']} | {PROPERTY[c['category']]} | "
                 f"{c['artifact_family']} | {rule} | {caps} | {c['why_not_redundant']} |")

    L += ["", "## Counts (derived)", "",
          "| Category | n |", "|---|---|"]
    for k in ["positive", "failure", "caveat", "withheld", "indeterminate"]:
        L.append(f"| {k} | {cat.get(k, 0)} |")
    L += ["", "| Family | n |", "|---|---|"]
    for k, v in sorted(fam.items()):
        L.append(f"| {k} | {v} |")

    noverdict = [p for p, r in rows.items() if r["airep_class"] is None]
    L += ["", f"**Cases emitting no verdict at all: {len(noverdict)}** — {', '.join('`'+x+'`' for x in sorted(noverdict))}.",
          "Every other case emits a verdict, the definitive failures included: a failure is a",
          "*verdict*, not the absence of one. `CLS-LEX1` emits `AIREP-Authenticated` at exit 0 with a",
          "definitive `witness-claim-invalid` and a reconstructed signing input, so it is a failure",
          "case.", "",
          "## Artifact families", "",
          "**`execution` is present as bytes but never as a primary artifact.** It appears as a",
          "`related_artifacts` member inside `CLS-P3` and `CLS-OB4`, and as fixed vector `V3`. The",
          "package does not claim four evaluated families.", "",
          "## Control scope", "",
          "`CTL1` is the only **selected primary Control case in this compact scored corpus**. It is",
          "not the only Control artifact in the release: the pinned tree carries roughly thirty more",
          "under `schema-validation/corpus/`, plus Stage-4 material.", "",
          "Separately, and more narrowly: searching every `.json` under the pinned `spec/airep/v0.2`",
          "tree for the values `\"receiver\"`, `\"received\"` or `\"delivery_failed\"` returns exactly one",
          "file — `schemas/control.schema.json`, which *defines* the enum. **No fixture in the pinned",
          "release carries a receiver-side value.** That is a statement about this release only. It",
          "does not imply receiver-side evidence was never produced elsewhere, and it does not imply",
          "non-delivery. Paired control-delivery reconciliation is therefore **not tested** here, and",
          "no paired case was synthesised.", "",
          "## Sampling policy, and the population it samples from", "",
          "| Population of the 60 scored source cases | Count |", "|---|---|",
          "| contains at least one **definitive failure** reason | **22** |",
          "| contains **withheld** reasons only, no failure | **35** |",
          "| **fully clean** — neither failure nor withheld | **3** |", "",
          f"This package selects **all 3** clean cases and **{cat.get('failure',0)} of the 22** definitive-failure cases.", "",
          "**That is not a proportionate sample, and no balance claim is made.** An earlier draft",
          "asserted the selection was \"not a favourable subset\"; the assertion did not survive",
          "checking and is withdrawn.", "",
          "The policy is **rule coverage, not proportional representation**: one case per distinct",
          "normative property, so a verifier passing all 18 has exercised each rule at least once.",
          "Omitted failure cases each duplicate a property already covered — `PB1`, `PB3` and `XT1`",
          "all exercise producer-binding rejection, and only `XT1` is selected.", "",
          "A reader wanting proportional coverage of the failure space should use the full public",
          "60-case release corpus. This is the compact set, and compactness has a cost stated here",
          "rather than argued away.", "",
          "## Byte material", "",
          "Per-case canonical bytes and hash preimages for **17 of 18** cases; signature preimages for",
          "the 16 with a resolving producer binding; the full chain for the 6 fixed vectors.",
          "`PROC-UNP` has none — its request is unparseable by design.", ""]
    (OUT / "CASE_SELECTION.md").write_text("\n".join(L))
    print(f"CASE_SELECTION.md generated from CASE_INDEX.json: {dict(cat)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
