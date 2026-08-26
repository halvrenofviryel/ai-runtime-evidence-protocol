# W2 standards-alignment preflight — `scitt-ccf-ledger`

Required by `SCITT_POC_CONTRACT.md` §7 before any implementation work. This document records
steps 1–3 of that mandate and hands step 4 — the materiality decision — to the maintainer.

**Measured 2026-08-26. No implementation was built, deployed or executed.** Every row below is a
*documentary* comparison between what the pinned build states about itself and the current state
of the referenced standards. Nothing here is a behavioural measurement of the running service.

---

## 1. The pinned build

| | |
|---|---|
| Repository | `microsoft/scitt-ccf-ledger` (public, active — last push 2026-08-26) |
| Pinned release | **`0.19.0`**, published 2026-07-29 |
| **Pinned commit** | **`c641e0d2cd4bb17e1085c0594a7dd23c55f640dd`** |
| Release assets | `pyscitt-0.14.1` wheel + sdist, `LICENSE.txt` — **no container image** |
| Container | built locally by `./docker/build.sh`; no registry digest is published by the project |

**Consequence for reproducibility.** The pin is the git commit. Because the image is built
locally from a moving base (`azurelinux/base/core`, bumped twice in the week before this
preflight), the container digest is only determined at build time. A reproducible run must record
the base-image digest *observed at build* alongside the commit; the commit alone does not pin the
image.

## 2. What that exact build states it implements

Read from `docs/scitt.md` at tag `0.19.0` — the project's own SCITT Standard alignment document.
The file on `main` is identical: it was last modified **2026-05-06** (`09b5c99b`, "align API with
SCRAPI v09").

| Surface | Target named by the build |
|---|---|
| Signed Statement inputs | Architecture **Draft 11** §4.2 |
| Registration policy | Architecture **Draft 11** §4.1.1 |
| Transparent Statement output | Architecture **Draft 11** §4.4 |
| Receipts | **COSE Receipt Draft 8** §4, with **CCF Tree algorithm profile Draft 3** proofs |
| API | **SCRAPI Draft 09** |
| Hashed Envelope Format | **explicitly not supported** — the build states the draft "is not currently implementable because the Header Parameters it introduces have undefined value" |

## 3. Current state of those standards

Retrieved from the IETF Datatracker on 2026-08-26.

| Standard | Build targets | Current | Delta |
|---|---|---|---|
| SCITT Architecture | Draft **11** | **RFC 9943** — *An Architecture for Trustworthy and Transparent Digital Supply Chains*, Proposed Standard, 2026-06-30 (from `draft-ietf-scitt-architecture-22`) | **11 revisions + RFC publication** |
| COSE Receipts | Draft **8** | **RFC 9942** — *COSE Receipts*, Proposed Standard, 2026-06-30 (from `draft-ietf-cose-merkle-tree-proofs-18`) | **10 revisions + RFC publication** |
| SCRAPI | Draft **09** | `draft-ietf-scitt-scrapi-11`, still a draft (updated 2026-08-13) | 2 revisions |
| CCF tree profile | Draft **03** | **`draft-ietf-scitt-receipts-ccf-profile-04`** (WG document, updated 2026-08-24). The individual draft named by the build is state **Replaced** / **Adopted by a WG**, last touched 2026-01-16 | **individual draft replaced by a WG line** |

**The alignment document predates both RFCs.** It was last touched 2026-05-06; RFC 9943 and
RFC 9942 published 2026-06-30; release `0.19.0` shipped 2026-07-29 without updating it. So the
build's own statement of alignment has not been re-examined against the published RFCs by its
authors.

**One confirmed concrete divergence.** Upstream issue **#414** (open, filed 2026-07-17, labelled
`documentation`/`enhancement`/`formats`) asks the project to adopt SCRAPI-11 and replace the
**`302`** return on registration with **`202`**. That is a wire-visible difference on the
registration call, which is exactly stage **S3**.

## 4. S1–S6 compliance matrix

Status vocabulary is the project's own. **`NOT_MEASURED` means the measurement did not execute** —
here, because no service was deployed. It is not a soft pass.

| # | Stage | SCITT dependency | Affected by the drift? | Status |
|---|---|---|---|---|
| S1 | Seal an AIREP artifact or chain head | **none** — AIREP-internal, before any registration call | No | `PASS`-eligible; no SCITT surface involved |
| S2 | Project to a signed statement | Signed Statement input format — Architecture Draft 11 §4.2 vs **RFC 9943** | **Yes** | `NOT_MEASURED` — format delta between Draft 11 and RFC 9943 not characterised |
| S3 | Register with the transparency service | SCRAPI **Draft 09** vs **Draft 11** | **Yes — confirmed** | `NOT_MEASURED`, with a **known** divergence: registration returns `302` where SCRAPI-11 specifies `202` (upstream #414) |
| S4 | Receive the receipt | COSE Receipt **Draft 8** vs **RFC 9942** | **Yes** | `NOT_MEASURED` — receipt-format delta not characterised |
| S5 | Verify the receipt against published verification material | COSE Receipt Draft 8 + CCF profile Draft 3 vs RFC 9942 + profile Draft 5 | **Yes — load-bearing** | `NOT_MEASURED` — this is the stage whose credibility the drift most directly threatens |
| S6 | Anchor the receipt in a subsequent Decision Receipt | **none** — AIREP-internal, per `SCITT-IR-2` | No | `PASS`-eligible; unaffected by SCITT version |

**Shape of the result.** The two stages the contract calls load-bearing split cleanly. **S6 — the
one §2 says carries the load — is untouched by this drift**, because it is an AIREP-side property:
the sealed object's bytes are unchanged and the anchor rides a genuine subsequent Decision Receipt.
**S2–S5, the entire SCITT-facing span, sit on pre-RFC surfaces.**

## 5. Assessment — for the maintainer's step-4 decision

I am not making the step-4 call. What the measurement supports:

**The drift is real, current, and acknowledged upstream.** It is not a documentation lag we can
read past: the architecture and receipt formats both became RFCs after this build's alignment
document was last written, and the one divergence that has been characterised by a third party is
wire-visible on the S3 call.

**But "material incompatibility" is not yet established.** An RFC publication is not automatically
a wire break from the last draft — many drafts publish with editorial changes only. What is
established is that **nobody has checked**, including upstream. Declaring incompatibility now
would be as unfounded as declaring compatibility.

**Where the claim would actually break.** The risk is not that the PoC fails to run — it very
likely runs. The risk is that it runs and gets described as *"an AIREP artifact anchored in a
SCITT transparency service per RFC 9943"*, when what was measured is a draft-era implementation
of a pre-RFC architecture. That sentence would be exactly the over-claim the contract's §6 claim
boundary exists to prevent.

**Three options, in the order I would rank them:**

1. **Proceed, scoped.** Run the PoC against `0.19.0` and describe the result *only* as SCITT
   draft-era (Architecture Draft 11 / COSE Receipt Draft 8 / SCRAPI Draft 09), never as RFC 9943
   or RFC 9942. Cheapest, and S6 — the load-bearing measurement — is unaffected either way.
   Requires §6's claim boundary to name the draft versions explicitly.
2. **Characterise first, then proceed.** Diff Architecture Draft 11 §4.2/§4.4 against RFC 9943,
   and COSE Receipt Draft 8 §4 against RFC 9942, before deploying. Converts four `NOT_MEASURED`
   rows into real findings and would let a clean run be described against the RFCs where the
   surfaces genuinely match. Costs a bounded reading task; no code.
3. **Choose another implementation.** Only warranted if (2) surfaces a real wire break. I found no
   evidence of one, and no alternative with a comparable local reproducible deployment.

My recommendation is **(2) then (1)**: characterise the two format deltas, then run scoped to
whatever that characterisation supports. It keeps the PoC's description inside its evidence, which
is the whole point of the exercise.

**Implementation remains on HOLD pending that decision.**

## 6. Verification record

| Check | Method | Result |
|---|---|---|
| Repo state | `gh repo view` | public, not archived, last push 2026-08-26 |
| Release + commit pin | `gh release list`, `gh api .../git/ref/tags/0.19.0` | `0.19.0` → `c641e0d2cd4bb17e1085c0594a7dd23c55f640dd` |
| Build's alignment statement | `gh api contents/docs/scitt.md?ref=0.19.0` | read in full; quoted above |
| Same file on `main` | `gh api contents/docs/scitt.md?ref=main` + commit history | identical; last modified 2026-05-06 |
| RFC 9943 / RFC 9942 identity | IETF Datatracker API | titles, Proposed Standard, both dated 2026-06-30 |
| Draft revisions | IETF Datatracker API | architecture rev 22, merkle-tree-proofs rev 18, scrapi rev 11 |
| CCF profile lineage | IETF Datatracker API (states resolved by ID) | individual `draft-birkholz-…-05` = **Replaced** + **Adopted by a WG**; successor `draft-ietf-scitt-receipts-ccf-profile-04` |

**Correction (2026-08-26, maintainer-flagged).** The first version of this preflight reported the
CCF profile as "still an individual draft" at rev 05. That was incomplete: it searched only the
document name the build cites and did not look for a successor. The individual draft has been
replaced and adopted by the SCITT WG, and the current line is
`draft-ietf-scitt-receipts-ccf-profile-04`. The delta on this axis is larger than first reported —
a changed document lineage, not a two-revision lag.
| Upstream divergence | `gh issue view 414` | open; SCRAPI-11, `302` → `202` on registration |
