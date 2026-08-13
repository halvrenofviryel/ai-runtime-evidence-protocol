# `control_delivery` ↔ OWASP APTS-HO-008 — a mapping backed by a working construct

**Anchor status: VERIFIED against the primary source.** The verification anchor is the
merge itself, not a mutable fetch: `OWASP/APTS` PR 67 ("APTS-HO-008: require and verify
control-channel delivery") is **MERGED** into `OWASP:main` — confirmed via
`gh pr view 67 --repo OWASP/APTS`: `state=MERGED`, `mergedAt=2026-07-30T20:18:28Z`,
`mergeCommit=2b210945361bac207f37a21440d0f34c05c07ad9`. The quoted text is the
"Control Channel Delivery Requirements" block and verification items 9–10 under the
`APTS-HO-008` section of `standard/3_Human_Oversight/README.md` (that section, not the
domain-summary table near the top of the file). Quotes are transcribed from that
section, not paraphrased from memory.

> The AIREP profiles README asks that any standard a profile names be treated as
> **INDICATIVE** until checked against the primary source. This mapping is the check.

## The requirement (APTS-HO-008)

APTS-HO-008 — *Immediate Kill Switch with State Dump* (MUST, Tier 1) — now carries:

- **Normative line:** *"An unacknowledged kill instruction MUST NOT be treated as delivered."*
- **Verification item 9 (end-to-end delivery test):** exercise each configured
  operator-initiated kill channel from the operator interface through to the
  enforcement point, **traversing any applicable network, mount, namespace,
  container, privilege-separation, or IPC boundaries**; verify the instruction is
  received and enforced within the Phase 1 / Phase 2 windows (APTS-SC-009).
- **Verification item 10 (delivery acknowledgement and failure test):** verify an
  issued kill instruction produces an **independently observable acknowledgement,
  enforcement result, or explicit delivery failure**, and that the **absence of all
  three triggers operator notification and default-safe handling**.

## The construct (AIREP `control_delivery`)

Two artefacts in this repository (paths are repository-root-relative):

- **`spec/airep/v0.1/profiles/control_delivery.schema.json`** — validates one phase
  record of a control instruction, observed from one side of a boundary.
- **`spec/airep/v0.1/conformance/control_delivery_reconciler.py`** — the cross-record
  RELATION the schema cannot carry: it compares issuer-side and enforcement-side
  records and decides whether an instruction may be treated as delivered. Exercised by
  `spec/airep/v0.1/conformance/fixtures/control_delivery_cases.json` (12 bundles) and
  `spec/airep/v0.1/conformance/test_control_delivery_reconciler.py` (8 tests).

## Requirement → construct

| APTS-HO-008 requirement | Where it is expressed | How |
|---|---|---|
| "unacknowledged ... MUST NOT be treated as delivered" | reconciler | `DELIVERED` requires a record with `phase ∈ {acknowledged, enforced, observed}` **and** `observed_by ∈ {enforcement_point, witness}`. Issuer-only records resolve to `UNCONFIRMED`, never `DELIVERED` — enforced by construction, exercised by `test_issuer_only_is_never_delivered`. |
| item 9 — boundaries: network / mount / namespace / container / privilege-separation / IPC | schema `boundary` enum | The enum is exactly `{none, mount, namespace, container, network, ipc, privilege_separation, other}`; `resolved_path` and `mount_identity` capture the per-side resolution whose mismatch is the diagnostic. |
| item 9 — "operator interface through to enforcement point" | schema `observed_by` | Records are attributed to `issuer` vs `enforcement_point` (vs an independent `witness`); the reconciler compares the two sides rather than trusting one. |
| item 10 — acknowledgement / enforcement result / explicit delivery failure | schema `phase` (+ `result`, `failure`); reconciler | `acknowledged`, `enforced` (with `result ∈ {applied, refused, no_effect}`), and `delivery_failed` are distinct, separately recordable phases in the schema. The schema makes `failure.reason` *optional*; the reconciler adds the rule that a `delivery_failed` record without an observed `failure.reason` is defective (→ `FAIL`), so a failure is not barely-better-than-silence. |
| item 10 — absence of all three → operator notification + default-safe | reconciler | An instruction with no independent enforcement-side confirmation **and** no `delivery_failed` record resolves to `UNCONFIRMED` with `default_safe = true` and `operator_notification_required = true`. (A `delivery_failed` record from any side yields `FAILED`, which is also default-safe; the reconciler does not require the failure itself to be independently observed — see limits.) |
| "enforcement result" distinct from success | schema `result` + reconciler | `no_effect` is a first-class outcome — an instruction can arrive, be accepted, and change nothing; the reconciler reports `DELIVERED` with `enforced_result = "no_effect"`, never as effective enforcement. |

## What this mapping does and does not claim

- **Does:** show that the AIREP `control_delivery` profile plus its reconciler can
  *express and decide* the distinction APTS-HO-008 now requires — the "what would
  this look like in practice?" answer, as a runnable construct with pass/reject
  fixtures.
- **Does not:** claim any deployed system emits these records at a real boundary,
  claim independent reproduction (the fixtures are first-party), or claim the AIREP
  core changed (this is a profile + a conformance tool; the core is untouched and
  the neutrality test still holds).
- **Honest limit carried from the profile:** no single side can prove non-delivery
  on its own — a receiver cannot know what it never received. The construct makes
  the *gap* between an issuer record and a missing enforcement-side record legible;
  it does not decide, from records alone, why an instruction failed to arrive.
- **`delivery_failed` is only as strong as its observer.** The reconciler counts any
  well-formed `delivery_failed` as `FAILED` (a default-safe outcome) regardless of
  which side recorded it; it does not require the failure to be independently
  observed. Item 10's "independently observable ... delivery failure" is best served
  by an `enforcement_point` record ("absent at resolved_path"); an issuer-side
  failure claim is a weaker signal, and the record's `observed_by` field is what
  makes that difference visible to a reader.
- **Not a conformance claim about APTS itself.** APTS is a pentest-platform standard;
  this maps one AIREP profile onto one of its requirements because the delivery-vs-
  decision distinction is general. It is a contribution of a *format and a working
  check*, not an assertion that any product is APTS-conformant.
