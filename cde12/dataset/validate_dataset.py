#!/usr/bin/env python3
"""Check a CDE-12 dataset against the instrument's own rules.

Run before submitting rows. The rules are in ../CDE-12.md; this enforces the ones a
machine can. It found two violations in the authors' own first dataset, which is the
reason it exists.

    python3 reality_check/dataset/validate_dataset.py [csv]
"""
from __future__ import annotations
import csv, sys
from pathlib import Path

VERDICTS = {"supported", "partial", "not demonstrated", "out of scope", "not tested"}
TIERS = {"", "T0", "T1", "T2", "T3", "T4"}
COLS = ["system", "revision", "criterion", "verdict", "tier", "evidence_ref",
        "quote", "rater", "date", "note"]


def check(path: Path) -> int:
    rows = list(csv.DictReader(path.open()))
    errs: list[str] = []

    def bad(i, msg):
        errs.append(f"  row {i}  {rows[i-1]['system']}/{rows[i-1]['criterion']}: {msg}")

    for i, r in enumerate(rows, 1):
        if r["verdict"] not in VERDICTS:
            bad(i, f"unknown verdict {r['verdict']!r}")
        if r["tier"] not in TIERS:
            bad(i, f"unknown tier {r['tier']!r}")
        # §4 rule 3 — documentation alone can never be `supported`
        if r["tier"] == "T0" and r["verdict"] == "supported":
            bad(i, "T0 evidence cannot yield `supported` (§4 rule 3)")
        # §4 rule 2 — an out-of-scope call needs the project's own words
        if r["verdict"] == "out of scope" and not r["quote"].strip():
            bad(i, "`out of scope` requires a quotable exclusion (§4 rule 2)")
        # `not tested` is a claim about the rater, so it carries no tier or evidence
        if r["verdict"] == "not tested" and (r["tier"] or r["evidence_ref"].strip()):
            bad(i, "`not tested` must carry no tier and no evidence — it is a claim "
                   "about the rater, not the system (§3)")
        # a named gap is what makes `partial` different from a shrug
        if r["verdict"] == "partial" and not r["note"].strip():
            bad(i, "`partial` requires the gap to be named (§3)")
        # a positive finding needs somewhere to look
        if r["verdict"] in {"supported", "partial", "not demonstrated"} and not r["evidence_ref"].strip():
            bad(i, f"`{r['verdict']}` requires an evidence_ref")
        for c in ("system", "criterion", "rater", "date"):
            if not r[c].strip():
                bad(i, f"missing {c}")

    print(f"{path}: {len(rows)} rows, "
          f"{len({r['system'] for r in rows})} systems, "
          f"{len({r['criterion'] for r in rows})} criteria")
    if errs:
        print(f"\nFAIL — {len(errs)} rule violation(s):")
        print("\n".join(errs))
        return 1
    print("PASS — all machine-checkable CDE-12 rules hold")
    print("\nNot checked here, and not checkable: whether a quote supports its verdict, "
          "whether a\nreading was deep enough for its tier, and whether the rater was "
          "honest. A second rater is\nthe only check for those (CDE-12 §7).")
    return 0


if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "cde12_scores.csv"
    raise SystemExit(check(src))
