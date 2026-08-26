# AIREP v0.2 — SCITT proof-of-concept contract (W2)

> **Status: DRAFT for maintainer review. No implementation, no evidence.** This contract fixes
> what the PoC must demonstrate, what it must not claim, and what artifacts constitute its
> evidence — before any code is written.
>
> Basis: `v0.2.0-alpha.1` / `b5ae87f74b386b11b8882865e50c3ad38120ff97`. This workstream is
> branched from the release basis, **not** from W1, so it takes no dependency on interop corpus
> semantics that are not yet accepted.

## 1. What AD-10 requires

[AD-10](../../v0.2-design/ARCHITECTURE_DECISIONS.md) adopts a SCITT binding profile rather than
growing AIREP's own transparency stack, and pins one normative ordering:

> **seal → register → receive SCITT receipt → subsequent anchor evidence.**

with an explicit prohibition: a receipt returned by the transparency service is **never written
back into the already-sealed object it attests**, because that would either break the seal or
demand a second signing pass over mutated bytes. The receipt is carried in a **subsequent**
artifact — a checkpoint/anchoring record, or the next chain record — referencing the sealed head
it anchors by `record_id`/hash.

AD-10 also fixes what SCITT does **not** provide: a receipt proves a statement was registered at
a time. It does not prove the control was delivered, executed, or had effect. Registration
composes with AD-03's evidence family; it does not replace it.

## 2. What the PoC must demonstrate

| # | Step | Observable |
|---|---|---|
| S1 | **Seal** an AIREP artifact or chain head | the sealed bytes and their digest, recorded before any registration call |
| S2 | **Project** it to a signed statement for registration | the mapping applied, and its inputs and outputs by digest |
| S3 | **Register** with a SCITT transparency service | the request as sent, and the service identity |
| S4 | **Receive** the receipt | the receipt bytes as returned, unmodified |
| S5 | **Verify** the receipt against the service's published verification material | a machine-observable pass/fail, not an assertion |
| S6 | **Anchor** the receipt in a *subsequent* artifact referencing the sealed head | the anchoring record, and proof the sealed object's bytes are unchanged |

**S6 carries the load.** The measurement that matters is not that a receipt was obtained but
that the sealed object is byte-identical before registration and after anchoring. The PoC must
record that digest at both points and compare them; a PoC that cannot show this has not
demonstrated AD-10's ordering, only that a registration API exists.

At least one real SCITT implementation must be used. AD-10 notes that adjacent work
(`draft-noa-scitt-ai-agent-receipt`) suggests AIREP artifacts should be registrable with at most
a thin mapping — the PoC **tests** that claim rather than assuming it, and the mapping's actual
size is a finding either way.

## 3. Three separate predicates

The previous draft conflated cryptographic receipt verification with AIREP↔SCITT binding, which
would have produced negative cases that cannot fail for the reason claimed. They are distinct:

| Predicate | Question |
|---|---|
| **P1 — receipt cryptographic validity** | is the receipt well-formed and valid against the service's verification material, for the statement it attests? |
| **P2 — statement ↔ AIREP projection binding** | do the AIREP bytes in hand project to the statement that was actually registered? |
| **P3 — subsequent-anchor ↔ sealed-head binding** | does the anchoring artifact reference the sealed head it claims to anchor? |

A receipt can be **cryptographically valid while the binding is wrong**. That is exactly the case
the PoC must be able to detect, and it is a P2/P3 question, not a P1 one.

## 4. Negative cases — required

A PoC that only shows success has demonstrated an integration, not a verification.

- **N1 — tampered AIREP sealed object.** The original signed statement and its receipt may still
  verify **P1 perfectly**, because they attest bytes that were correct when registered. What must
  fail is **P2**: the current AIREP bytes no longer project to the registered statement. A
  negative case asserting "receipt verification fails" here would be testing the wrong predicate
  and could pass or fail for reasons unrelated to the tamper.
- **N2 — receipt anchored to the wrong sealed head.** Again **P1 may pass**: the receipt is valid
  for its own statement. What must fail is **P3**, the anchor-to-head binding.
- **N3 — malformed or truncated receipt.** This one *is* a direct **P1** failure, and must be
  rejected rather than silently treated as an absent receipt.

Each must be shown failing for its own cause **and for the right predicate**, as the
class-verifier negative proofs were.

## 5. Evidence

- the sealed object digest at S1 and again after S6, with their comparison;
- the projection mapping, and its input/output digests;
- the registration request and the service identity;
- the receipt bytes as returned;
- the P1, P2 and P3 results separately, each machine-observable;
- the anchoring artifact;
- the three negative-case results with the cause each triggered;
- the SCITT implementation identity and version, and whether it is a public service or a local
  instance.

## 6. Claim boundary

A clean PoC would establish that an AIREP artifact can be sealed, registered with a SCITT
implementation, and have its receipt anchored in a subsequent artifact without mutating the
sealed bytes, and that the end-to-end binding detects tampered AIREP input **even when the original SCITT
receipt remains cryptographically valid for the originally registered statement**.

It would **not** establish that AIREP is SCITT-conformant in general, that any particular
transparency service is trustworthy, that registration implies the recorded decision was correct,
or that the control was delivered, executed or had effect. It satisfies AD-15 clause (3) only in
part — AuthZEN (W3) is separate — and satisfies clause (1) not at all, since it is maintainer-side
work and produces no external producer.

## 7. Decided (maintainer, 2026-08-26)

**SCITT implementation — a local, pinned `microsoft/scitt-ccf-ledger`** as the primary PoC
target: it exposes a real registration and receipt flow and supports a local virtual-mode
deployment, so the measurement is reproducible.

**Standards-alignment preflight is mandatory before any implementation work.** The project's own
alignment documentation still refers to Architecture Draft 11, COSE Receipt Draft 8 and SCRAPI
Draft 09, while the SCITT architecture is now RFC 9943. That gap must be characterised, not
assumed away:

1. pin the exact `scitt-ccf-ledger` commit or container digest;
2. document which RFC/draft versions **that exact build** implements;
3. compare the S1–S6 path against RFC 9943 / RFC 9942 and the applicable API profile;
4. on **material incompatibility, STOP** and choose another implementation rather than
   proceeding and describing the result as a SCITT PoC.

A second run against a public SCITT service would be valuable but is **not required** for the
AD-15 gate. The reproducible local run against a real implementation is the primary measurement.

**The projection mapping stays PoC/informative — it is NOT frozen as a normative profile.**
Freezing a mapping against a single SCITT implementation would bake that implementation's
choices into the specification. The freeze decision waits for a second SCITT implementation or
external interop.

### Ruling SCITT-IR-2 — decision-chain carrier

**No new checkpoint artifact type.** Introducing one after `v0.2.0-alpha.1` would mean a new wire
family. Leaving the carrier as "an existing, valid subsequent chain record" was also insufficient:
it left a wire-visible packaging choice to be made while writing code. It is pinned here.

- the **sealed head is a Decision Receipt**;
- the receipt is carried on the **next genuine, valid Decision Receipt in the same Decision
  chain**, via a **namespaced experimental SCITT anchor profile**;
- that second Decision Receipt **must be a semantically valid test decision in its own right**.
  No empty or fabricated decision may be minted merely to carry an anchor — an artifact that
  exists only as a envelope would make the PoC demonstrate a shape the protocol does not
  actually produce;
- normal chain linkage continues through `integrity.previous` as usual.

The anchor profile carries at least:

| Field | Content |
|---|---|
| anchored `record_id` | the sealed head being anchored |
| anchored `integrity.current` | its digest at seal time |
| SCITT statement digest/reference | what was registered |
| SCITT receipt digest/reference | what came back |

This is PoC packaging. It is **not** a new artifact family and **not** a normative profile.
