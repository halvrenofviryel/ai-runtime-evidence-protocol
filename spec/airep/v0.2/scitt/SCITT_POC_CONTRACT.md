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

## 3. Negative cases — required

A PoC that only shows success has demonstrated an integration, not a verification. At minimum:

- **N1** a tampered sealed object whose receipt verification must fail;
- **N2** a receipt presented against the wrong sealed head, which must not verify as anchoring it;
- **N3** a malformed or truncated receipt, which must be rejected rather than treated as absent.

Each must be shown failing for its own cause, as the class-verifier negative proofs were.

## 4. Evidence

- the sealed object digest at S1 and again after S6, with their comparison;
- the projection mapping, and its input/output digests;
- the registration request and the service identity;
- the receipt bytes as returned;
- the verification result, machine-observable;
- the anchoring artifact;
- the three negative-case results with the cause each triggered;
- the SCITT implementation identity and version, and whether it is a public service or a local
  instance.

## 5. Claim boundary

A clean PoC would establish that an AIREP artifact can be sealed, registered with a SCITT
implementation, and have its receipt anchored in a subsequent artifact without mutating the
sealed bytes, and that receipt verification fails on tampered input.

It would **not** establish that AIREP is SCITT-conformant in general, that any particular
transparency service is trustworthy, that registration implies the recorded decision was correct,
or that the control was delivered, executed or had effect. It satisfies AD-15 clause (3) only in
part — AuthZEN (W3) is separate — and satisfies clause (1) not at all, since it is maintainer-side
work and produces no external producer.

## 6. Open for maintainer decision

1. Which SCITT implementation — a public transparency service, a local instance, or both. A
   local instance is reproducible in CI; a public one is more meaningful and less reproducible.
2. Whether the projection mapping becomes a normative profile in this release or stays a PoC
   artifact until a second implementation exercises it.
3. Whether the anchoring artifact is a new checkpoint record type or the next chain record, given
   AD-10 permits either and the choice is wire-visible.
