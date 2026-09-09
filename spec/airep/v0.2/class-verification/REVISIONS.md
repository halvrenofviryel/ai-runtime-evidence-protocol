# Class-verification — measurement-contract revisions

A published revision and its digest are never rewritten. A changed measurement basis is emitted as
the next revision, and the provenance between revisions is recorded here.

**The revision axis is not the protocol version.** The AIREP **wire version remains `0.2`**.
`r1` / `r2` / `r3` identify measurement-contract revisions only; no artifact ever carries one.

| Revision | Path | Contract SHA-256 | Status |
|---|---|---|---|
| **r1** | [`CLASS_VERIFIER_CONTRACT.md`](./CLASS_VERIFIER_CONTRACT.md) | `7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885` | **historical — frozen.** Basis of the C1 parity run, the 60-case corpus, and every external run recorded to date. Byte-identical copies ship in both interop handoff packages' `normative_basis/` and are recorded in their `SOURCE_BASIS.json` and `manifests/FILES.json`. Never edited, never replaced. |
| **r2** | [`contract-r2/CLASS_VERIFIER_CONTRACT_R2.md`](./contract-r2/CLASS_VERIFIER_CONTRACT_R2.md) | `630676b1a199a5453e96b5e18890b17a4d0e5c290c2156aa15f1a3f899aad8a0` | **superseded before implementation/measurement.** No implementation, corpus, parity or external result exists against it; it was superseded on a read-only closure audit, not because a measurement failed. Added the deterministic profile-validation basis input, the additive `profile_evaluations` verdict channel, and the extended parity surface. Preserves r1's process-exit semantics unchanged. |
| **r3** | [`contract-r3/CLASS_VERIFIER_CONTRACT_R3.md`](./contract-r3/CLASS_VERIFIER_CONTRACT_R3.md) | `d68b6b75c1a6729ba712cc7ec202abe271ff846f01e1e2a83be388c9f3e69de2` | **current — COMPLETE STANDALONE contract.** Corrects two validation-basis closure defects r2 left undefined (duplicate member names inside the basis document; transitive `$ref` closure) and pins the JSON Schema dialect. Not a delta: it does not depend normatively on r2. |

## r2 → r3 — what changed and why

r2 left the **validation basis** itself unclosed in two ways, both found by read-only audit before any
implementation existed:

| Defect | Problem | r3 correction |
|---|---|---|
| **R2-D1** | r2's duplicate-key rule was scoped to the *registry* only; a basis document with duplicate member names has parser-dependent semantics while `basis_digest` stays identical | duplicate member names rejected at every depth, detected during parse, before semantic validation |
| **R2-D2** | `basis_digest` hashed only the root document; `$ref`, self-containment and transitive resources were never mentioned, so two runs could share a digest while resolving different bytes | Model 1 adopted — the basis MUST be self-contained; external file/network/relative/absolute refs prohibited; intra-document fragment refs permitted |
| *(also)* | dialect was unpinned — same bytes could be read under a different draft | Draft 2020-12 pinned by contract; `format` annotation-only; no custom vocabularies, plugins or network loading |

r3 is **standalone**: every r2 normative requirement is carried into it (machine-verified: 0 absent),
so no composition of `r2 + patch` is required to determine the effective contract.

## r1 → r2 — what changed and why

r1 has no representation for profile evaluation at all: no channel, no vocabulary, no basis input.
An artifact carrying a namespaced profile could not be reported on without either inventing a result
or overstating one. r2 adds exactly that representation and nothing else.

| Change | Basis |
|---|---|
| Deterministic profile-validation basis input; exact identifier, exact bytes, exact digest; no network resolution, no fallback | N-01 |
| Additive `profile_evaluations` channel — `PASS` / `FAIL` / `NOT_EVALUATED` with `basis_digest` | N-01b |
| Basis-unusable kept distinct from payload-invalid | N-01 / N-01b |
| Process exit **unchanged** — run validity only; a profile `FAIL` keeps exit `0` | N-01c |
| Parity surface extended to the full `profile_evaluations` surface | AD-14 |

Every r1 surface not listed above is carried unchanged by reference and is not restated in r2.

## Evidence basis, by layer

```text
r1  ->  historical 60-case corpus  ->  C1 parity evidence + external independent verifier run
r2  ->  (nothing)                  ->  superseded before any corpus, parity or external run existed
r3  ->  beta regression fixtures   ->  first-party adapter parity (see ../BETA_READINESS.md)
```

**No historical external run covers r2 or r3.** The recorded independent consumer/verifier evidence
was measured against r1 and establishes nothing about `profile_evaluations` or any other revised
surface. A future external rerun must identify the **current** revised basis exactly, by the digests
in [`contract-r3/CLASS_VERIFIER_CONTRACT_R3.md`](./contract-r3/CLASS_VERIFIER_CONTRACT_R3.md) §R3.0
and [`contract-r3/SOURCE_BASIS.json`](./contract-r3/SOURCE_BASIS.json) — **never** the superseded r2
digests.

Where a revised-corpus case repeats a historical semantic scenario, it is a **new regression
measurement under the revised basis** — not a restatement, correction, or update of the historical
result, which remains frozen as measured.

## Beta implementation measurement

The Python/Node beta adapters implement the AD-17 and r3 surfaces and re-run
the historical 60-case scenarios as new regression measurements. They were
developed together and do not claim independent authorship. See
[beta verification](../VERIFICATION.md) and [readiness](../BETA_READINESS.md).
The frozen r3 contract and SOURCE_BASIS digests are unchanged. No external
implementation is claimed to have evaluated r3 or the beta lifecycle.
