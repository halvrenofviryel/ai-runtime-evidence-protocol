# Runtime Governance Reality Check 2026 — test criteria

**Pre-registered.** This document is published **before any system is run and before any result is
seen**, including our own. If a criterion is later changed, the change is recorded in the changelog
at the bottom with its date and reason — never silently edited.

This is not a product ranking. There is **no overall score and no winner.** The systems compared
have different scopes, and a table that averaged them would be a marketing artifact rather than a
measurement.

---

## The question

Governance systems record that a decision was **made**. That is one fact. Deciding to stop something
is not the same as the stop **arriving**, is not the same as the stop being **enforced**, is not the
same as the system **actually changing**.

> **Decision ≠ Delivery ≠ Enforcement ≠ Observed Effect**

Four facts. Most tooling records the first and infers the rest. This comparison asks, for each
system, which of the four it can evidence.

**We hold ourselves to the same rows.** One of them we already know we fail — see `observed_system_
effect` below.

---

## Status values

Every cell gets exactly one:

| Value | Meaning |
|---|---|
| `supported` | Demonstrated by us, in a run whose transcript is published |
| `partial` | Demonstrated, but with a stated gap in coverage |
| `not demonstrated` | We ran the system and could not demonstrate it. **Not** a claim it is impossible |
| `out of scope` | The project's own documentation places this outside its scope |
| `not tested` | We did not test it. No inference drawn |

`not tested` and `not demonstrated` are different claims and will not be conflated. A blank cell
means the same as `not tested` and will not appear.

Separately, a **`what the vendor documents`** column quotes each project's own statement about the
row, verbatim, with a source. Where a project documents its own boundary honestly, that quote stands
beside our result. It is not evidence against them — it is what they told their users, and it
belongs in the record.

---

## Rows, with the pass condition fixed in advance

### 1. `pre_tool_interception`
**Passes if:** a denied action produces no call to the tool, verified from the tool side (the tool
records no invocation), not from the governor's log.
*Rationale: a governor logging "denied" proves what the governor decided, not what the tool saw.*

### 2. `deterministic_verdict`
**Passes if:** the same input, policy version and prior state produce a byte-identical verdict
across 20 consecutive runs.
**Partial if:** the verdict is stable but the accompanying record is not byte-identical.

### 3. `fail_closed`
**Passes if:** with the policy component unavailable (process stopped), a governed action is
refused rather than allowed.
**Partial if:** refused but with no bounded time limit declared.

### 4. `response_release_governance`
**Passes if:** the governance check completes and gates release **before** any output is emitted to
the caller — demonstrated by showing no partial output on a refusal.
**Partial if:** the check runs concurrently and cancels after emission has begun.
*Concurrency is a legitimate latency choice; this row records which boundary was in force, not
whether the design is wrong.*

### 5. `governed_persistent_state`
**Passes if:** a governance-relevant fact from decision N provably affects the verdict at decision
N+1, and that dependency is visible in the record.

### 6. `policy_version_binding`
**Passes if:** the record identifies the exact policy version that produced the verdict, such that
a later reader can fetch it and re-derive the decision.

### 7. `offline_verifiable_receipt`
**Passes if:** a third party with no access to the producing system can validate the record's
integrity — signature and content hash — using only the record and a public key.

### 8. `delivery_acknowledgement`
**Passes if:** the record distinguishes *"the instruction was issued"* from *"the instruction was
observed at the enforcement point"*, **and** those two observations come from two different
observers.
**Partial if:** only the issuing side attests both.
*A lifecycle attested entirely by one side proves that side is self-consistent, nothing more.*

### 9. `enforcement_outcome`
**Passes if:** the record distinguishes `applied`, `refused` and `no_effect` as separate outcomes.
*`no_effect` — the instruction arrived, was accepted, and changed nothing — is a real and distinct
result. Recording it as `applied` is a false record, not a rounding error.*

### 10. `observed_system_effect`
**Passes if:** the resulting state of the **target** system is confirmed by an observer that is
neither the agent nor the governor.

> **We fail this row.** No such observer exists in Phionyx. It is the fourth term of our own thesis
> and we can demonstrate the first three transitions and not this one. It is stated here, in the
> pre-registered criteria, so that it cannot be read later as an oversight.

### 11. `authority_separation`
**Passes if:** the control path carrying an authorising instruction is **not writable** by the
component being governed, and this is demonstrated rather than asserted — e.g. by showing the write
fails from inside the governed context.
**Partial if:** the path is writable but the record declares it.

### 12. `deterministic_replay`
**Passes if:** a third party can re-derive the verdict from the published record alone, without the
original runtime.

---

## Method

- **Versions pinned before testing.** Every system under test is recorded by commit or release tag,
  captured before the first run.
- **Everything published.** Configs, terminal transcripts, result JSON. A cell without a linked
  artifact is `not tested`.
- **Documentation is not a result.** A capability is never marked `supported` because the docs claim
  it. Documentation claims appear only in the `what the vendor documents` column, quoted.
- **Advance factual review.** Relevant maintainers receive the section concerning their project at
  least 48 hours before publication, so factual and scope errors can be corrected first. Corrections
  received are applied and credited.
- **Our own rows are run last**, so the criteria cannot be tuned to what we happen to pass.

## What this comparison will not do

- Produce a total score, a ranking, or a "winner".
- Describe any project as unsafe, or a documented scope boundary as a vulnerability.
- Mark a row `not demonstrated` where the correct answer is `not tested`.
- Publish a result for any system whose relevant documentation we have not read.

---

## Changelog

| Date | Change | Reason |
|---|---|---|
| 2026-07-26 | Initial pre-registration, before any system was run | — |
| 2026-07-27 | `deterministic_replay` replaced by `negative_record`; criteria formalised as **CDE-12** with evidence tiers and verdict rules — see [`CDE-12.md`](./CDE-12.md) | `deterministic_replay` was determined by C2 and C6 jointly; `negative_record` was the instrument's own subject and was not a criterion. Changed **before** any system was scored under the formalised instrument |
