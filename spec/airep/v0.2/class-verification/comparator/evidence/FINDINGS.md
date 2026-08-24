# Comparator findings — official run

Measurement context: third integration context, comparator v1.0.0, offline.
Contract `sha256:2d028de62e9ceca223931da5abd28aaa93658aeec801ba17e68d74c97406687e`.
Verifiers `verifier_py sha256:5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc`,
`verifier_node_r2 sha256:7e1a0ec9ba3a00aa8bbbcbb9f7909855a45097619c7703ad66075eff542cabfc`.
Corpus aggregate `55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4`
(265 files, all recomputed and matching).

**Overall comparator outcome: FAILURE** (2 hard-gate findings, both on the
run-validity / CLI surface, neither on the 45-case semantic surface).

**Neither verifier was changed and no output was altered. Both output files are
preserved verbatim under `official_run/`.**

---

## FINDING 1 — exit-code divergence on `--request … --out …` (gate G2)

| | |
|---|---|
| Probe | `--request corpus/cases/P1/request.json --out <file>` plus clean operator inputs |
| Python | exit **2**, `usage error: --out is only valid with --corpus` |
| Node | exit **0**, verdict written to stdout, `--out` silently ignored, no file created |
| Contract | **not pinned.** §6.4 pins `0` / `1` / `2` / `--help`→`0` for named conditions; it does not say whether `--out` alongside `--request` is a usage error. |

The two implementations answer an unpinned CLI question differently. On the
contract-pinned rows the two agree completely: **19 of 19 pinned probes agree
with each other and each matches the contract's own expected code** (exit 0 for
`--help` and a valid single case; exit 1 for unparseable request, unreadable
request, stage-0 schema invalidity, stage-1 hash mismatch, request-envelope
unknown member, `head_witness` null, and unknown members inside `head_witness`
/ `head_ref` / `signature` per R-4 and R-7; exit 2 for malformed `--now`,
non-Gregorian `--now`, negative window, non-integer window, no arguments,
unknown option, `--corpus` with `--request`, `--corpus` without `--out`). Both
corpus runs exit 0.

Maintainer decision needed: pin the behaviour in §6, or record it as
out-of-scope CLI latitude.

## FINDING 2 — duplicate `(chain_id, record_id)` rejection divergence (gate G12)

| | |
|---|---|
| Probe | comparator-authored two-case corpus referencing the frozen `P1` fixture twice |
| Python | exit **1**, `invalid: duplicate (chain_id, record_id) tuple: (b'cv-chain-p1', b'cv-rec-p1')`, no output file |
| Node | exit **0**, results file written containing **two verdicts with the same tuple** |
| Contract | **not pinned as a verifier obligation.** §2 says "a duplicate `(chain_id, record_id)` tuple makes the run invalid (**comparator gate**)"; §6.4 does not list it as an exit-1 condition. |

Read strictly, Node is conformant — §2 assigns the check to the comparator — and
Python implements a stricter local rule. The behaviours nonetheless diverge on a
surface the parity contract names. The frozen corpus contains no duplicate
tuple, so **this finding does not affect any of the 45 pinned verdicts**; both
official outputs are duplicate-free and correctly ordered (G12's output-side
checks PASS).

Maintainer decision needed: state in §2/§6 whether a verifier MUST, MAY, or MUST
NOT reject a duplicate tuple itself.

---

## Limitations of this run (stated, not rounded up)

- **Ordering is exercised on ASCII identifiers only.** All 45 corpus
  `chain_id`/`record_id` values are ASCII, where UTF-8 byte order and UTF-16
  code-unit order coincide. The contract explicitly admits non-ASCII free-form
  core strings and names the Python-vs-JavaScript order divergence as the reason
  for the byte-order rule. **That divergence is therefore not exercised by the
  frozen corpus** — G12 measures that both outputs are correctly ordered and
  identically ordered, not that the two runtimes would agree on non-ASCII input.
  A future corpus case with a non-BMP or ≥U+FF00 identifier would close this.
- Semantic gates are measured on the batch (`--corpus`) path; the single-case
  (`--request`) path is measured for exit semantics only.
- The comparator performs no cryptography, no artifact hash recomputation and no
  schema validation. It measures agreement, conformance to the pinned expected
  values, and envelope legality.
- Agreement between the two implementations is consistent with independent
  authoring; it is not proof of it.

## Auxiliary observation (not a gate)

The two output files are **byte-identical**
(`sha256:556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735`).
This is recorded as an observation about two serializers that happen to agree on
key order, indentation and encoding. It is **not** the parity result, it is
neither necessary nor sufficient for parity, and no gate depends on it.
