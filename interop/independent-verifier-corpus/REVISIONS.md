# Independent-verifier corpus — revisions

A published revision and its digest are never rewritten. A corrected expectation is emitted as the
next revision, and the provenance between revisions is recorded here.

| Revision | Expected-results digest | Status |
|---|---|---|
| `v0.1` | `b942137c3a825906614845176614b92504e514447a490a295f42c737ab9b8211` | **published and frozen** — handed off and externally run |
| `v0.2` | `0dad9fa5190523d9713b77690831762b022a43ea22782a2168318acd44b7bfb9` | corrected projection; not yet packaged or handed off |

## v0.1 — published, frozen

Packaged as `airep-v0.2-independent-verifier-corpus-v0.1-full.zip`,
`sha256:b47f01c81577c9dc95b7d1f1fd1119c839866e182d24c251c386ad2a08b17923`, and run externally by
Joel Hillier (Certisyn, Inc.). That run recorded **17 AGREE / 1 DISAGREE** and remains the
historical result. It is not regenerated, not re-scored, and not restated as 18/18.

## v0.1 → v0.2 — what changed and why

**Exactly one field on one row.**

| Row | Field | v0.1 | v0.2 |
|---|---|---|---|
| `CLS-XT1` | `cryptographic_result` | `PASS` | `NOT_EVALUATED` |

Every other value on every other row is byte-identical. The `expected_provenance` derivation text
also changes on all class rows, because it states the rule and the rule was corrected.

**Why.** `CLS-XT1` is a definitively revoked producer binding. Contract §4 and ruling **R-6** make
stage 4's prerequisite "binding accepted **and** not definitively revoked", so on that row the
producer-signature stage does not execute and no signature is verified under any key. The v0.1
projection rule branched on case identity — `FAIL` for `PS1`, `NOT_EVALUATED` for `PB2`,
`PASS` otherwise — and a revoked binding is neither, so it fell through to `PASS`. Reporting
`PASS` there states that a cryptographic check succeeded when none ran.

**This is a defect in the package-derived projection, not in the contract.** R-6 already states the
correct prerequisite and was not changed. The frozen class, all five reason channels, observer
assessment, process exit, run validity and signing-input reconstruction were correct on that row
and are unchanged.

**How it was found.** Independently, by the external run, and reproduced maintainer-side before any
correction was made. See [`../../EXTERNAL_EVIDENCE.md`](../../EXTERNAL_EVIDENCE.md).

**The fix is semantic, not a case-ID patch.** `tools/interop_pkg/build_expected.py` now derives
`cryptographic_result` from the frozen reason channels against the stage-4 prerequisite, so any
case whose binding was never accepted or was definitively revoked projects `NOT_EVALUATED`
regardless of its identity. `PB1` in the 60-case corpus carries the same
`producer-binding-revoked` channel and would have inherited the same defect had it been selected;
it is now covered by construction. Per R-6, a missing or malformed revocation **state** is not
"revoked" and does not suppress the gate. `tools/interop_pkg/test_crypto_projection.py` asserts
all of this on channel shapes carrying no case identifier, so a case-ID patch cannot satisfy it.

## Re-runs

Any future external re-run must reference the revision explicitly. A result against `v0.1` and a
result against `v0.2` are not interchangeable on the `CLS-XT1` row.
