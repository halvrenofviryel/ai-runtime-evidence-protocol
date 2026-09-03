# Class-verification — measurement-contract revisions

A published revision and its digest are never rewritten. A changed measurement basis is emitted as
the next revision, and the provenance between revisions is recorded here.

**The revision axis is not the protocol version.** The AIREP **wire version remains `0.2`**.
`r1` / `r2` identify measurement-contract revisions only; no artifact ever carries one.

| Revision | Path | Contract SHA-256 | Status |
|---|---|---|---|
| **r1** | [`CLASS_VERIFIER_CONTRACT.md`](./CLASS_VERIFIER_CONTRACT.md) | `7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885` | **historical — frozen.** Basis of the C1 parity run, the 60-case corpus, and every external run recorded to date. Byte-identical copies ship in both interop handoff packages' `normative_basis/` and are recorded in their `SOURCE_BASIS.json` and `manifests/FILES.json`. Never edited, never replaced. |
| **r2** | [`contract-r2/CLASS_VERIFIER_CONTRACT_R2.md`](./contract-r2/CLASS_VERIFIER_CONTRACT_R2.md) | `630676b1a199a5453e96b5e18890b17a4d0e5c290c2156aa15f1a3f899aad8a0` | **current.** Adds the deterministic profile-validation basis input, the additive `profile_evaluations` verdict channel, and the extended parity surface. Preserves r1's process-exit semantics unchanged. |

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
r2  ->  revised corpus             ->  new parity evidence
```

**No historical external run covers r2.** The recorded independent consumer/verifier evidence was
measured against r1 and establishes nothing about `profile_evaluations` or any other r2 surface. A
future external rerun must identify the revised basis exactly, by the digests in
[`contract-r2/CLASS_VERIFIER_CONTRACT_R2.md`](./contract-r2/CLASS_VERIFIER_CONTRACT_R2.md) §R2.0.

Where a revised-corpus case repeats a historical semantic scenario, it is a **new regression
measurement under the revised basis** — not a restatement, correction, or update of the historical
result, which remains frozen as measured.
