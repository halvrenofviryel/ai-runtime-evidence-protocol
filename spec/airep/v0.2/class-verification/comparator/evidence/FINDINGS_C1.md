# Comparator findings — official parity run C1

**Run C1 is CLEAN: zero findings. All fourteen hard gates PASS. Comparator exit 0.**

Stated explicitly rather than left to be inferred from an absent file: the
comparator produced **no** finding of any kind on the C1 run — no divergence, no
contract mismatch, no envelope defect, no expected-value mismatch, no ordering
violation, no probe mismatch, no determinism failure.

Measurement context: parity measurement authored in a third integration context,
comparator v1.1.0, offline, no network, no `git`. Full basis record:
[`basis.json`](basis.json).

## The two SHAs — named, not conflated

| Role | SHA |
|---|---|
| C1 execution semantic basis — the frozen basis under which the first unmodified dual-verifier execution was measured | `0cc95f5ce5426ca41e7a2c26c0f77a6ba842cd81` |
| Comparator official-run checkout — the tree this comparator ran in and measured | `7c03438382f74ffabc123c08fdb9e1a5182e63d4` |

The commits between them carry **only measurement evidence and a documentation
correction**; the semantic basis is **unchanged** across them.

**Measured here, not taken on trust.** `c1_execution/basis.json` was written at
the execution basis SHA and records the digests that held there; this comparator
recomputes each from the bytes at its own checkout. All six agree:

| Subject | At execution basis | Recomputed at comparator checkout | Identical |
|---|---|---|---|
| `verifier_py/class_verifier.py` | `5d08c327…` | `5d08c327…` | yes |
| `verifier_node_r2/class_verifier.mjs` | `e678ff57…` | `e678ff57…` | yes |
| `CLASS_VERIFIER_CONTRACT.md` | `7ecfce56…` | `7ecfce56…` | yes |
| corpus manifest aggregate | `55f5189e…` | `55f5189e…` | yes |
| combined 60-case index | `365c0a99…` | `365c0a99…` | yes |
| scored case count | 60 | 60 | yes |

A future reader therefore does not need a checkout to confirm that no
implementation moved between the first C1 execution and this run.

**Relayed, not measured (labelled as such).** The *shape* of the difference —
"exactly 12 paths differ, 11 under `c1_execution/` and 1 is `C1_COVERAGE.md`" —
comes from the coordinator. It is not derivable inside a single checkout without
the commit graph, and `git` is not available here, so it is recorded as relayed.
One half of it **is** corroborated in-root: `C1_COVERAGE.md` carries the live
extended aggregate `55f5189e…` and mentions `5b053183…b9b95` only as an
explicitly superseded pre-remediation value.

## Verifier fingerprints

Both are byte-identical to run 2, so **neither verifier was modified for C1**:
`verifier_py 5d08c327…` (also byte-identical to run 1 — Python has received no
code change at any point) and `verifier_node_r2 e678ff57…`.

## What the C1 run measured

| Gate | C1 surface added | Outcome |
|---|---|---|
| G1 | 416 manifest digests + aggregate recomputed; declared counts (416 files / 60 cases / 45 C0 / 15 C1 / 15 probes); combined 60-case index rebuilt from the two root arrays and its digest checked against the pinned `365c0a99…`; the 265-path C0 subset re-aggregated to the pre-C1 `55d43c51…2950a4`; execution-basis cross-SHA identity | PASS |
| G2 | the run-2 matrix (19 pinned rows) and the R-9 sentinel probe (4 rows) **retained unchanged**, plus all 15 C1 probes × 2 implementations = 30 rows, each asserting `expected_exit`, `expected_results_file` and `must_not_create` | PASS |
| G3–G9 | class, all five channels, `observer_assessment` across 60 cases (420 cross-impl field comparisons) | PASS |
| G10 | evidence-block equality plus 360 comparator-recomputed digest comparisons from the exact operator input bytes | PASS |
| G11 | envelope / registry / invariants across 60 verdicts | PASS |
| G12 | the exact order of all 60 verdicts recomputed with the comparator's own UTF-8 byte comparator (120 positions checked), explicit **ORD2-precedes-ORD1** discrimination, the pinned corpus ordering fixture cross-checked, plus the unchanged duplicate-tuple rejection and sentinel gates | PASS |
| G13 | each implementation separately at **60/60** against frozen `expected.json` (840 comparisons) | PASS |
| G14 | per-implementation repeat-run byte determinism | PASS |

## A run-1/run-2 limitation is now CLOSED

Runs 1 and 2 recorded that ordering was exercised on ASCII identifiers only,
where UTF-8 byte order and UTF-16 code-unit order coincide, so cross-runtime
ordering agreement on non-ASCII identifiers was **not** established. C1's ORD1 /
ORD2 pair closes exactly that: the two `record_id`s share the prefix
`cv-rec-ord-` and differ first at UTF-8 `ef` vs `f0` (ORD2 first), while in
UTF-16 code units the comparison is `ff00` against the high surrogate `d800`
(ORD1 first). The two orders **disagree**, so the pair is a naive-JavaScript-sort
detector, and both implementations placed ORD2 at index 26 and ORD1 at index 27.

## Non-vacuity — because a clean result was the expected outcome

The prior unmodified execution already came back clean, which is exactly when a
comparator most easily passes for the wrong reason. Every new C1 surface was
shown able to fail:

| Surface | Injected defect | Detected as |
|---|---|---|
| G12 ordering (committed proof 4) | ORD1/ORD2 transposed on one side | `ordering-discriminator-violated` + `order-not-utf8-expected`; G11 and G3–G9/G13 stayed clean |
| G2 C1 probes (committed proof 5a) | one pinned probe returns the wrong exit | `c1-probe-exit-mismatch` + `c1-probe-exit-divergence`, no leakage to other probes |
| G2 C1 probes (committed proof 5b) | probe exits correctly but writes `${OUT}` | `c1-probe-results-file-mismatch` + `c1-probe-must-not-create-violated` + `c1-probe-out-path-created` |
| G1 C0 preservation (ad hoc) | one C0 file digest perturbed | C0 aggregate diverges from the pinned pre-C1 value |
| G1 C0 preservation scope (ad hoc) | a C1-only file digest perturbed | C0 aggregate correctly **unaffected** — the check is scoped to the C0 subset, as "strictly additive" requires |
| G1 combined index (ad hoc) | one C1 entry dropped (59 entries) | digest diverges from the pinned `365c0a99…` |
| G1 execution basis (ad hoc) | a moved verifier digest | `execution-basis-drift` |
| G13 on a C1 case (ad hoc) | `MC4 authenticated_withheld` changed | `G5 reason-set-mismatch` + `G13 expected-mismatch` naming case MC4 |

Proofs 1–3 (class flip, reason mutation, envelope/invariant) were re-run against
the C1 known-good pair and still fire for their original causes.

## Limitations of run C1 (stated, not rounded up)

- **Ordering is now exercised, but only on one discriminating pair.** ORD1/ORD2
  cover the UTF-16-vs-UTF-8 divergence class. They do not cover every non-ASCII
  ordering hazard (for example combining sequences, or normalization-sensitive
  identifiers — §2 forbids normalization, and no fixture tests that a verifier
  refrains from applying it).
- Semantic gates are measured on the batch (`--corpus`) path; the single-case
  (`--request`) path is measured for exit and side-effect semantics only.
- The comparator performs no cryptography, no artifact hash recomputation and no
  schema validation. It measures agreement, conformance to the pinned expected
  values, envelope legality, ordering and process behaviour.
- The C1 `expected.json` values are, per the manifest, manually derived from
  cited normative clauses. G13 measures conformance *to* them; it cannot tell you
  the derivations are right.
- Agreement between the two implementations is consistent with independent
  authoring; it is not proof of it.
- The shape-of-diff claim between the two SHAs is relayed, not measured (above).
- **This is implementer/measurement evidence, not acceptance.** No `ACCEPTED`
  verdict is assigned here.

## Auxiliary observation (not a gate)

The two C1 output files are **byte-identical**
(`sha256:b078a3abeaf0555a9f369e3ffb244f8df6a472282e4c5f4f6191eb7aace363b1`). This is an observation about two
serializers that happen to agree on key order, indentation and encoding — it is
**not** the parity result, it is neither necessary nor sufficient for parity, and
no gate depends on it. Notably it now also holds across non-ASCII `record_id`
values, where the two runtimes escape and order strings by different native
rules; that is a slightly stronger observation than in runs 1 and 2, but it is
still an observation, not a gate.
