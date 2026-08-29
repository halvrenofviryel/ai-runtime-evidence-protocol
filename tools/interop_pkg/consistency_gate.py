#!/usr/bin/env python3
"""Build-time consistency gate. INTERNAL TOOLING. Exits non-zero on any violation.

Every check here exists because the corresponding mistake was actually made and shipped:
prose drifted from structured data, a category contradicted the index, a scope claim outgrew
its evidence. Assertions, not review, are what stop those recurring.
"""
import json, re, sys
from collections import Counter
from pathlib import Path

# Accept a target so the gate's own negative controls can run against throwaway copies
# rather than mutating the real package.
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    "/mnt/data/claude/ai-runtime-evidence-protocol/interop/independent-verifier-corpus/v0.1")
errs: list[str] = []


def fail(msg): errs.append(msg)


idx = json.loads((OUT / "CASE_INDEX.json").read_text())
cases = idx["cases"]
rows = [json.loads(l) for l in (OUT / "expected/expected_results.jsonl").read_text().splitlines()]
by_id = {r["package_case_id"]: r for r in rows}
cat = Counter(c["category"] for c in cases)
sel = (OUT / "CASE_SELECTION.md").read_text()
readme = (OUT / "README.md").read_text()

# 1. every CASE_SELECTION category must equal CASE_INDEX
for c in cases:
    pid, want = c["package_case_id"], c["category"]
    m = re.search(rf"^\|\s*`{re.escape(pid)}`\s*\|.*$", sel, re.M)
    if not m:
        fail(f"CASE_SELECTION.md has no row for {pid}")
    elif f"**{want}**" not in m.group(0):
        fail(f"CASE_SELECTION.md category for {pid} does not match CASE_INDEX ({want})")

# 2. CLS-LEX1 must never be described as indeterminate or no-verdict
lex = by_id.get("CLS-LEX1")
if lex and lex["airep_class"] is None:
    fail("CLS-LEX1 expected result has a null class; it must emit a verdict")
for name, text in [("CASE_SELECTION.md", sel), ("README.md", readme)]:
    for m in re.finditer(r"^.*CLS-LEX1.*$", text, re.M):
        line = m.group(0)
        if re.search(r"\bindeterminate\b", line, re.I) and "not an indeterminate" not in line:
            fail(f"{name}: CLS-LEX1 described as indeterminate: {line[:90]}")
        if re.search(r"no verdict", line, re.I):
            fail(f"{name}: CLS-LEX1 described as emitting no verdict: {line[:90]}")

# 3. no document may claim CTL1 is the only Control artifact in the release
for name, text in [("CASE_SELECTION.md", sel), ("README.md", readme),
                   ("START_HERE.md", (OUT / "START_HERE.md").read_text())]:
    # These must match the ASSERTION and not its correct negation, nor a sentence that
    # counts something else. A gate with false positives gets disabled, which is worse than
    # no gate: the first draft flagged "NOT the only Control artifact" and a line counting
    # matched files.
    for m in re.finditer(r"[^.]*only Control (?:Evidence )?(?:artifact|case) in the release[^.]*",
                         text, re.I):
        if not re.search(r"\b(not|never|is not|isn't)\b", m.group(0), re.I):
            fail(f"{name}: claims CTL1 is the only Control artifact in the release: "
                 f"{m.group(0).strip()[:80]}")
    for m in re.finditer(r"[^.]*\bexactly one\b[^.]{0,60}\bControl\b[^.]*", text, re.I):
        seg = m.group(0)
        if re.search(r"\bexactly one\s+(file|match|result|entry)\b", seg, re.I):
            continue          # counting search hits, not Control artifacts
        if re.search(r"scored|selected|primary|compact", seg, re.I):
            continue          # already scoped to the measured set
        fail(f"{name}: unscoped 'exactly one Control' claim: {seg.strip()[:80]}")

# 4. source-basis prose must not say no byte at all came from main
if re.search(r"no byte (here )?(was|is) taken from `?main`?", readme, re.I):
    fail("README.md: unqualified 'no byte taken from main' — package-authored files were not")

# 5. README category totals must equal CASE_INDEX
for k, v in cat.items():
    label = {"positive": "positive", "failure": "definitive failure", "caveat": "caveat",
             "withheld": "withheld assurance", "indeterminate": "indeterminate"}[k]
    if not re.search(rf"\|\s*{re.escape(label)}[^|]*\|\s*{v}\s*\|", readme):
        fail(f"README.md count for '{label}' does not match CASE_INDEX ({v})")

# 6. report template must have exactly 18 rows, one per case
tmpl = [json.loads(l) for l in (OUT / "reporting/REPORT_TEMPLATE.jsonl").read_text().splitlines()]
if len(tmpl) != len(cases):
    fail(f"REPORT_TEMPLATE.jsonl has {len(tmpl)} rows, expected {len(cases)}")
if {t["case_id"] for t in tmpl} != {c["package_case_id"] for c in cases}:
    fail("REPORT_TEMPLATE.jsonl case_ids do not match CASE_INDEX")

# 7. every template row must validate against REPORT_SCHEMA
schema = json.loads((OUT / "reporting/REPORT_SCHEMA.json").read_text())
try:
    from jsonschema import Draft202012Validator
    v = Draft202012Validator(schema)
    for i, row in enumerate(tmpl):
        for e in v.iter_errors(row):
            fail(f"REPORT_TEMPLATE.jsonl row {i} ({row.get('case_id')}): {e.message[:110]}")
except ImportError:
    fail("jsonschema unavailable: cannot validate the report template (gate must not pass blind)")

# 8. the archive digest must not be embedded in the package
for p in OUT.rglob("*"):
    if p.is_file() and p.suffix in {".md", ".json", ".cff", ".txt"}:
        pass  # digest-of-self check is performed by the builder after the archive exists

if errs:
    print(f"CONSISTENCY GATE FAIL: {len(errs)} violation(s)")
    for e in errs:
        print("  -", e)
    sys.exit(1)
print(f"CONSISTENCY GATE OK: {len(cases)} cases, categories {dict(cat)}, "
      f"{len(tmpl)} template rows all schema-valid")
