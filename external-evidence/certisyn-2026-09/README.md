# External evidence deposit — Certisyn, Inc., September 2026

Immutable deposit of the four artefacts supplied by Joel Hillier (Certisyn, Inc.) from an
independently implemented AIREP v0.2 consumer/verifier run against a release-pinned handoff corpus.

**These bytes are frozen.** They are not edited, regenerated, reformatted, line-ending-normalised,
re-scored or annotated. No licence header was added to any of them — see *Licence* below for why
that matters.

## Artefacts

| File | Bytes | SHA-256 |
|---|---|---|
| `AIREP-RUN-RECORD.txt` | 6199 | `58557bef06610763b61875864689940ff44a27c2944d7710a9a859710445f88c` |
| `AIREP-report-18-rows.txt` | 72573 | `37d68fbf1293f6f2006338d974f5451ba3a1e3b9304fe7218950533576e2c4cf` |
| `AIREP-observed-verdicts.txt` | 13085 | `f4a2b23ab1b996ac3daa4b5985fd90f96467bbe84b6ad878832cf09f73d36f92` |
| `AIREP-verifier-source.txt` | 43016 | `2aef1212adeaab5a1dc7f07c3f240183db97478b247c008c5fcc0e177fbfeca8` |

Verify with `sha256sum -c SHA256SUMS`.

`AIREP-verifier-source.txt` is the concatenated source of the seven implementation modules in load
order. Its digest **is** the implementation identity recorded on all 18 report rows, so any change
to those bytes — including adding a licence header — would break the identity that ties the report
to the code that produced it. That is why the licence is carried here and in `LICENSE`, separately,
and never inside the source.

## Subject of the run

| | |
|---|---|
| Package run against | `sha256:b47f01c81577c9dc95b7d1f1fd1119c839866e182d24c251c386ad2a08b17923` |
| Implementation digest | `sha256:2aef1212adeaab5a1dc7f07c3f240183db97478b247c008c5fcc0e177fbfeca8` |
| Recorded outcome | **17 AGREE / 1 DISAGREE** |
| The one disagreement | `CLS-XT1`, `cryptographic_result` only — a package-derived projection, classified by the report as an expected-result defect |

The disagreement was independently reproduced and the projection was corrected in corpus revision
`v0.2`. **This deposit is not updated to match.** The run stands as recorded.

## Licence

**BSD-3-Clause as published by OSI, copyright 2026 Certisyn, Inc.** Full text in `LICENSE`.

Stated explicitly, at the licensor's instruction:

- it is a **copyright licence only**;
- it grants **no patent rights, expressly or by implication**;
- it does **not anticipate or alter Certisyn's BCP 79 disclosures**;
- it permits redistribution, modification and archiving under BSD-3-Clause terms;
- it requires retaining the copyright notice and the disclaimer;
- the **Certisyn name may not be used to endorse** a derived work.

## What this deposit does and does not establish

It establishes that these exact bytes are the ones that were supplied and run, and makes them
independently checkable.

It does **not** establish a third-party AIREP v0.2 producer, deployment interoperability, semantic
correctness of the protocol, AIREP v0.2 stability, IETF endorsement, or SCITT endorsement. It is
**not** expected-blind validation: the expected outcomes shipped inside the same archive, and the
run record says so. The runner's work-order sequence is his own recorded account and is not an
independently checkable property.

Scope, boundaries and the maintainer-side reproduction are recorded in
[`../../EXTERNAL_EVIDENCE.md`](../../EXTERNAL_EVIDENCE.md).
