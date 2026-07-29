# CDE-12 — Control-Delivery Evidence, v0.2

An instrument for reporting what a system can and cannot **record** about a control decision and its
fate. Twelve criteria, a five-value scale, and an evidence tier on every cell.

**It measures records, not behaviour.** A system may enforce perfectly and score badly here; that is
not a contradiction. The question throughout is *what can a later reader establish from what the
system wrote down?*

**Design intent.** Two people applying this to the same system, without speaking to each other,
should reach the same cells. Where they cannot, the criterion is defective and the defect is ours.
Disagreements should be reported against this document, not resolved privately.

---

## 1. Scope and definitions

Terms are fixed here because most disagreement between raters is vocabulary, not judgement.

| Term | Definition for CDE-12 |
|---|---|
| **System** | A software artifact or specification that governs or records agent actions, or decision/artifact provenance, at runtime, **and** produces a record intended for later inspection by someone other than the producer. |
| **Record** | Durable output the system is documented as producing for later inspection. Operational logs are records **only if** the system documents them as inspectable evidence. Console output is not a record. |
| **Control instruction** | A directive from an authority to a component that constrains it — stop, suspend, revoke, override, deny. **Not** a business message, a work item, or an update payload. |
| **Enforcement point** | The component that would act on the control instruction. |
| **Observer** | A component that writes a record. Two observers are **distinct** only if one can fail or be compromised without the other's records being affected. Two functions in one process are **one observer**. |
| **Attest** | The record contains a field or structure whose documented purpose is to carry the property. Inferring the property from timestamps, ordering, or absence is **not** attestation. |

**Two observers, expanded**, because this is where raters diverge most: distinctness is about failure
independence, not about naming. A record written by the same process under two different `source`
strings is one observer. A record written by a separate process on the other side of a boundary that
can fail independently is two.

---

## 2. Evidence tiers

Every cell carries the tier of the evidence behind it. **A verdict may not exceed what its tier can
support** (§4).

| Tier | Meaning |
|---|---|
| **T0** | Vendor documentation or marketing |
| **T1** | Normative specification text |
| **T2** | Source code read at a pinned revision |
| **T3** | The project's own tests, read |
| **T4** | Executed by the rater, output retained |

T0 can never yield `supported` (§4). This is the rule that keeps the instrument from measuring
promotional copy.

---

## 3. The scale

| Value | Meaning |
|---|---|
| `supported` | The property is present and evidenced at T2 or above |
| `partial` | Present with a stated gap; the gap must be named in the cell |
| `not demonstrated` | The rater looked and did not find it. **A claim about the system** |
| `out of scope` | The project's own documentation places this outside its purpose. Requires a quote |
| `not tested` | The rater did not look, or looked too shallowly to say. **A claim about the rater** |

**`not tested` and `not demonstrated` are never interchangeable.** Conflating them lets a survey
report its own coverage gaps as findings about its subjects. When in doubt, `not tested`.

---

## 4. Verdict rules

Applied in order; the first that matches decides.

1. If the reading depth for this criterion is below the tier the criterion requires → **`not tested`**.
2. If the project documents the property as outside its purpose, with a quotable sentence → **`out of scope`**.
3. If evidence is T0 only → at most **`partial`**, never `supported`.
4. If the criterion's decision procedure (§5) answers **no** at any required step → **`not demonstrated`**.
5. If it answers **yes** with a named gap → **`partial`**, gap recorded.
6. Otherwise → **`supported`**.

**Tie-break.** Where two readings are defensible, take the one that is *less* favourable to the
system and record why in the cell. A survey that rounds up is not a measurement.

---

## 5. The twelve criteria

Each is a question about the **record**. Answer only from evidence at the stated minimum tier.

### C1 · `pre_tool_interception`
*Can a reader establish, from the record, that a denied action did not reach the tool?*
**Minimum tier T2.** Yes requires the record to carry a tool-side observation — the tool, or its
harness, recording that it was not invoked. A governor's own "denied" entry is **not** sufficient and
scores `partial` at best.

### C2 · `deterministic_verdict`
*Does the record let a reader re-derive the same verdict from the same inputs?*
**T2.** `supported` requires the record to carry inputs, policy identity and verdict such that
re-derivation is possible. If the verdict is produced with a model in the decision path, the answer
is `not demonstrated` unless the record pins the model and its parameters.

### C3 · `fail_closed`
*Does the record distinguish "denied by policy" from "denied because the policy engine was
unavailable"?*
**T2.** Both are refusals and they mean different things. A record that reports only "denied" scores
`partial`.

### C4 · `response_release_governance`
*Does the record state whether the governance check completed before output was released?*
**T2.** Where a system supports both concurrent and blocking modes, `supported` requires the record
to say **which mode was in force for this decision**. Capability is not the question; what the record
says is.

### C5 · `governed_persistent_state`
*Can a reader see, from the record, that state from an earlier decision affected this one?*
**T2.** Requires an explicit reference — a prior decision id, a state version, an accumulated
context digest. A shared session identifier alone is `partial`.

### C6 · `policy_version_binding`
*Does the record identify the exact policy version that produced the verdict?*
**T1.** A rule name is `partial`. A version, digest or content hash that allows the policy to be
fetched and the decision re-derived is `supported`.

### C7 · `offline_verifiable_receipt`
*Can a third party with no access to the producing system check the record's integrity?*
**T1.** Requires a signature or equivalent, plus enough in-record material to verify it without
calling the producer.

### C8 · `delivery_acknowledgement`
*Does the record carry an observation, by the enforcement point, that a specific control instruction
was seen?*
**T2.** Requires (a) an identifier shared between issuer and enforcement point, and (b) two
**distinct observers** as defined in §1. One side attesting both halves is `partial`. Broker-mediated
acknowledgement counts if the record retains it and identifies the acknowledging party.

### C9 · `enforcement_outcome`
*Does the record distinguish applied, refused, and no-effect?*
**T1.** *No-effect* — the instruction arrived, was accepted, and changed nothing — must be
distinguishable from *applied*. A record with only allow/deny is `not demonstrated` for this
criterion regardless of how well it does elsewhere.

### C10 · `observed_system_effect`
*Does the record carry a confirmation of the target system's state by an observer that is neither the
agent nor the governor?*
**T2.** Self-reported success is `not demonstrated`.

### C11 · `authority_separation`
*Does the record state whether the control path could be written by the party being governed?*
**T1.** A declared field is `partial`; `supported` requires the record to carry how the property was
established — a probe result, a mount identity, an attestation reference. A boolean the producer sets
about itself is a claim.

### C12 · `negative_record`
*Can the system positively record an **observation** that a specific expected control instruction was
not seen — and name which observation was made?*

**T1.** This is the criterion the instrument exists for, and it is phrased as an observation rather
than as a fact deliberately. **Non-arrival cannot be established by one party.** A receiver cannot
know what it never received, and an issuer's silence is indistinguishable from a lost
acknowledgement. Any criterion asking a system to record *that an instruction did not arrive* asks
for something no participant can supply, and would be defective.

What a system can record is which of these it observed:

| Observation | What was actually seen |
|---|---|
| deadline passed, no acknowledgement | the issuer waited past a stated deadline |
| counterpart missing at reconciliation | a comparison of both sides found no matching record |
| transport rejected | the channel itself reported a failure |
| verification failed | the artifact was present and failed the authority check |
| undetermined after deadline | the deadline passed and nothing distinguishes the causes |

`supported` requires a record whose documented purpose is to carry, for a **specific** expected
instruction, which of these was observed — as a classified value, so that two implementations
recording the same observation produce comparable records.

`partial` in three cases, each with the gap named:
- generic staleness, expiry or timeout detection not bound to a specific expected instruction;
- the observation is recorded but **unclassified** — a free-text field, however well documented, lets
  two implementations record the same observation incomparably;
- the record asserts non-arrival without naming the observation behind it, reporting a conclusion
  where the evidence supports only an observation.

**Absence of any record is not a negative record.**

---

## 6. Reporting

One row per (system, criterion):

```
system, revision, criterion, verdict, tier, evidence_ref, quote, rater, date, note
```

`revision` is a commit or specification version fixed **before** reading. A release tag is not a
substitute for a commit; a project's `main` may be far ahead of its last release.

**No total score. No ranking.** Systems have different purposes and a sum across these criteria would
assert a comparability the instrument does not establish. Anyone computing one is misusing it.

**Reading depth is reported alongside.** A system read across two of its 182 documentation files and
one read across specification, source and tests are not equally measured, and a table that hides that
is worse than one that shows it.

---

## 7. Rater agreement

For any published application: at least a subset rated independently by a second rater who has not
seen the first rater's cells, with agreement reported. **Disagreements are published with both
readings**, not silently reconciled — a disagreement usually means a criterion is loose, and that is
information about this instrument.

## 8. Self-rating

A rater who authored a system under evaluation must rate it **last** and disclose authorship in the
row. The criteria are fixed before any rating, with a changelog for any change, so the axes cannot be
tuned to a system after seeing how it scores.

## 9. Known limitations of this instrument

- It measures records, not enforcement. A system can enforce perfectly and score poorly.
- Tier T4 is rarely reached in practice; most published applications will be documentation and source
  readings, and should say so.
- C10 is failed by nearly everything, including the authors' own system. It is retained because a
  criterion nobody passes still marks the boundary of what is currently evidenced.
- The five-value scale collapses genuine variety within `partial`. The named-gap requirement is a
  partial mitigation, not a fix.

## 10. Changelog

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-07-27 | Formalised from the twelve pre-registered criteria: added evidence tiers, ordered verdict rules, the observer-distinctness definition, the tie-break rule, and the rater-agreement protocol |
| v0.1 | 2026-07-27 | **Substitution, recorded because pre-registration is worthless without it.** `deterministic_replay` was dropped and `negative_record` (C12) added in its place. Reason: `deterministic_replay` — *can a third party re-derive the verdict from the record alone* — was substantially answered by C2 (`deterministic_verdict`) and C6 (`policy_version_binding`) together, and a criterion whose verdict is determined by two others adds length rather than discrimination. `negative_record` had been implicit throughout and was the property the instrument exists to measure, yet was not a criterion. **This change was made while writing the instrument and before any system was scored under it.** No system had been rated on `deterministic_replay` except in the earlier informal reading, where its cells are superseded rather than carried forward. |

| v0.2 | 2026-07-28 | **C12 rewritten after scoring — an author error, recorded as one.** The v0.1 wording asked whether a system can record *that an expected instruction did not arrive*. That is not observable by any single party: a receiver cannot know what it never received, and an issuer's silence is indistinguishable from a lost acknowledgement. The criterion asked for something no participant can supply. C12 now measures the **non-arrival observation** — deadline passed, counterpart missing at reconciliation, transport rejected, verification failed, or undetermined — and requires it to be classified rather than free-text. **This change was made after scoring and it moved two cells, both the authors' own, both downward:** `airep` and `phionyx-control-plane` fall from `supported` to `partial`, because `failure.reason` is an unconstrained string. No other cell moved; a stricter criterion cannot promote anything, so every `not demonstrated` stands. Raised by an external reviewer of the accompanying paper, whose text had already made the distinction the instrument had not |

**How this changelog is meant to be used.** A change made before scoring is a design decision. A
change made after seeing results is a finding about the author, not the systems. Both are recorded
here in the same table, with dates, so a reader can tell which they are looking at. An instrument
whose criteria move silently measures nothing.

The v0.2 entry is the second kind. **The instrument's central criterion was epistemically wrong for
41 minutes of public exposure — v0.1 was pushed at 2026-07-27 23:33 and v0.2 at 2026-07-28 00:14 —
and the authors' own rows were the only ones flattered by the error.** The short window is luck, not
diligence: the error was caught by an external reviewer of the accompanying paper, and had that review
arrived a week later the wrong criterion would have stood for a week. Left uncorrected it would have let us claim `supported` on the property the whole
instrument exists to measure.
