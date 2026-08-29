# Method

## Provenance kinds

Every expected byte and every expected result carries a `provenance_kind`:

| kind | Meaning |
|---|---|
| `frozen_release_vector` | byte material read verbatim from the pinned release |
| `frozen_release_expected_result` | expected class, reason channels, observer assessment or process exit, read verbatim |
| `package_derived` | produced by this packaging step, with its source bytes and derivation named |

Two derivations exist, and both are stated so they can be disputed rather than trusted:

1. **Raw `.bin` byte files.** The release stores byte material as lowercase hex. The package adds
   `.bin` alongside `.hex` by `bytes.fromhex()` of the frozen field. Nothing is recomputed.
2. **The three reporting dimensions the release does not carry** — run validity, signing-input
   reconstruction and cryptographic result. The frozen `expected.json` carries class, five reason
   channels and observer assessment; it does not split the outcome the way a three-valued checker
   reports it. The projection rule is recorded per row. **Dispute the projection, not the frozen
   fields, if you disagree** — the frozen fields are verbatim and order-preserving.

## Dual-implementation agreement

The Stage-3 vectors exist in two released forms, `vectors/out/python_vectors.json` and
`vectors/out/node_vectors.json`. At the pin they are **byte-identical**
(`sha256:3153ef09…` on both). The builder compares them per vector and **stops with a preserved
finding** if they ever differ. No value in this package was taken from a single implementation
where two exist.

## Reason codes

Reason arrays are verbatim from the frozen release: exact vocabulary, exact order. They are not
paraphrased, re-sorted or normalised.

## Why there is no inputs/oracle split

An earlier build produced `inputs.zip` and `oracle.zip` alongside `full.zip`. **Both were
withdrawn**, for two independent reasons found in review:

1. **The split did not do what its name implied.** `inputs.zip` omitted only the aggregate
   `expected_results.jsonl` while retaining all sixteen per-case `expected.json` files and the
   category labels in `CASE_INDEX.json`. A recipient holding it still held the oracle.
2. **It broke the integrity checker.** `inputs.zip` shipped `verify_package.py` together with the
   full manifest, which declares a file that archive does not contain, so the checker could only
   fail.

A split could not have established expected-blind authoring in any case: the AIREP corpus and its
expected outcomes are already public in the source repository. Since it supported no
methodological claim and actively misled, the package ships **one archive**.

## Implementation independence

The permitted claim is exactly:

> The external verifier implementation was developed separately from the AIREP reference verifier
> code, subject to the exposure disclosures recorded by its author.

Not proof of independent authoring, not expected-blind, not clean-room, not third-party producer
interoperability. AIREP's reference code is public, so the external implementer records whether
they inspected it. Nobody else can record that for them.
