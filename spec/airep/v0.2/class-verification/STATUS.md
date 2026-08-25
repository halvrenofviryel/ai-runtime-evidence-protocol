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

**Does not establish:** correctness of the underlying semantics; independent external validation
of the manually derived expected values; third-party implementation or third-party audit;
coverage of all Unicode ordering edge cases; or the truth or completeness of any real-world
AIREP artifact. Agreement between the two implementations is consistent with separate authoring
but is not proof of it.

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
