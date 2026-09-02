# Class verification — current status

The status text embedded in [`CLASS_VERIFIER_CONTRACT.md`](./CLASS_VERIFIER_CONTRACT.md)
reflects the contract's freeze-time authoring state and is intentionally preserved because the
complete file is evidence-pinned. Current implementation and release status is maintained here.

That separation is deliberate. The contract's full-byte digest is compared as the semantic-basis
identity of every recorded measurement, so a single byte changed anywhere in it — including in
prose — correctly registers as basis drift. Status is mutable project metadata and changes at
every lifecycle step; normative text pinned as evidence does not. Keeping them in one file would
tie the status lifecycle to the evidence lifecycle, which is why they are now apart.

## Where the phase stands

| | |
|---|---|
| Class-verifier corpus/parity phase | **COMPLETE** |
| Verifiers | **two**, authored separately against the frozen contract |
| Corpus | **60 scored cases** (45 C0 + 15 C1) and **15 CLI/process-exit probes** |
| Official C1 parity run | **PASS**, all hard gates, 0 findings |
| Producer implementation | **not started** |
| v0.2 | **`v0.2.0-alpha.1` — released prerelease.** Experimental and not stable. Producer implementation remains unstarted and the AD-15 stable-release criteria remain unmet. There is no stable `v0.2.0`. |
| Stable-release criteria (AD-15) | **not met** |

## What the phase result does and does not establish

**Establishes:** two separately authored verifiers agree across the measured surface — class,
all five reason channels, observer assessment, evidence block, envelope invariants, exit
semantics, UTF-8 verdict ordering including a pair that separates UTF-8 byte order from UTF-16
code-unit order — and each independently matches the frozen expected values on all 60 cases,
deterministically across repeat runs.

**Does not establish:** correctness of the underlying semantics; coverage of all Unicode ordering
edge cases; or the truth or completeness of any real-world AIREP artifact. Agreement between the
two implementations is consistent with separate authoring but is not proof of it.

**External evaluation, recorded separately.** One external independently implemented
consumer/verifier has been measured against a release-pinned handoff corpus, subject to the
recorded exposure qualifications. This is not expected-blind validation and does not establish
semantic correctness, v0.2 stability, deployment interoperability, or third-party producer
interoperability. That external run is **not** a third official verifier: the two official
verifiers and the official parity result above are unchanged by it. Identities and boundaries are
in [`EXTERNAL_EVIDENCE.md`](../../../../EXTERNAL_EVIDENCE.md).

## External evaluation and the handoff-corpus projection defect

Kept separate from the official internal parity result above, which is unchanged by any of this.

| | |
|---|---|
| Official internal parity | **unchanged** — 60 scored cases, two separately authored verifiers, parity PASS |
| External evaluation | one independently implemented consumer/verifier, run against the release-pinned handoff corpus |
| Original external result | **17 AGREE / 1 DISAGREE** — frozen, not regenerated, not restated as 18/18 |
| The single disagreement | `CLS-XT1`, `cryptographic_result` only: expected `PASS`, observed `NOT_EVALUATED` |
| Classification | **package-derived projection defect**, independently reproduced maintainer-side |
| Contract | **not changed.** Ruling R-6 already states stage 4's prerequisite correctly |
| Correction | emitted as corpus revision `v0.2`; revision `v0.1` and its digest are preserved |

The external run is **not** a third official verifier. It is a separate evaluation with recorded
exposure qualifications — it is not expected-blind, and it does not establish semantic correctness,
v0.2 stability, deployment interoperability, or third-party producer interoperability.

On `CLS-XT1` the external implementation reproduced every frozen field — class, all five reason
channels, observer assessment, process exit, run validity and signing-input reconstruction. Only
the package-derived projection disagreed, and the projection was the thing that was wrong: a
definitively revoked producer binding suppresses stage 4, so no signature is verified under any
key, and `PASS` asserted a cryptographic check that never ran.

Provenance between corpus revisions is recorded in
[`../../../../interop/independent-verifier-corpus/REVISIONS.md`](../../../../interop/independent-verifier-corpus/REVISIONS.md).

## Reproduction

The v0.2 validation and class-verification toolchain can be reproduced in an offline/no-index
configuration using the repository's vendored, hash-verified dependency bundle — the Node
tarballs under `offline-node-deps/` and the Python wheels under `offline-python-deps/`. The
schema-validation phase reuses the same bundle; its pinned versions are a subset of this one.

`preflight_offline_basis.py` states the limits of that claim in its own header: it establishes
that the configured tools ran in no-index mode against vendored, hash-verified inputs, not that
the network was unavailable at the kernel level.

CI runs this chain as **reproduction and regression evidence**. It does not produce new official
acceptance evidence — the official runs are the ones recorded under `comparator/evidence/`.
