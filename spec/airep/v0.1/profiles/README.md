# AIREP profiles — the optional extension catalogue

## What a profile is

The AIREP core record (see [`../EXPLAINER.md`](../EXPLAINER.md)) is deliberately small and
generic, so any system can write one. But a real system often needs to record more — a bank
needs the loan reason codes, a game needs the age-rating check, a regulator needs specific
log fields.

A **profile** is a named bundle of those extra fields. It attaches under the record's
`profiles` block — for example `profiles.finance` or `profiles.eu_ai_act_log` — and **never
changes the core**. A reader who does not care about a profile simply ignores it. Delete the
whole `profiles` block and the record is still a valid core record; that is the neutrality
test.

So profiles let AIREP fit many industries without making the shared format bigger or
vendor-specific.

> **Status.** Five profiles ship **published schemas** with worked examples the conformance
> checker validates — `key_trust`, `eu_ai_act_log`, `nist_ai_rmf`, `owasp_threat`, and
> `observability_transport` (see below). The rest of the catalogue is **proposed** — design
> sketches without a schema yet. Maturity and open items are tracked in
> [`../STATUS.md`](../STATUS.md), not repeated here. Where a profile names a specific regulation
> or standard, treat the citation as **indicative** until checked against the primary source.

## Published profiles (with schemas)

Unlike the proposed sketches below, these profiles ship **real, published schemas**, each with a
self-consistent worked example that the conformance checker validates against the schema.

- **`key_trust`** — trust metadata for the key that produced `integrity.signature`: `key_id`,
  `issuer`, `algorithm`, `public_key`, `validity`, `rotation`, `revocation`, and an optional
  `transparency_log` anchor. Schema: [`key_trust.schema.json`](./key_trust.schema.json); worked
  example: [`../examples/key_trust_record.json`](../examples/key_trust_record.json) (signed by the
  very key it declares). It is the dependency [`../THREAT_MODEL.md`](../THREAT_MODEL.md) names for
  turning the format's *partial* signature defenses into enforced ones and for closing the
  replay-as-latest / tail-truncation gaps (via `transparency_log`).
- **`eu_ai_act_log`** — EU AI Act record-keeping fields: the system's risk tier and Annex III point,
  the Article 12 use period / reference database / match, Article 14 human oversight (by pseudonymous
  role, no personal data), Article 19 log retention, and Article 72/73 post-market / serious-incident
  linkage. Schema: [`eu_ai_act_log.schema.json`](./eu_ai_act_log.schema.json); worked example:
  [`../examples/eu_ai_act_record.json`](../examples/eu_ai_act_record.json). **Indicative**: the article
  references are a design aid to be checked against Regulation (EU) 2024/1689 — AIREP produces evidence
  for these obligations, it does not by itself establish conformity.
- **`nist_ai_rmf`** — the NIST AI Risk Management Framework (AI 100-1): `function` (GOVERN/MAP/MEASURE/
  MANAGE), `category`, `trustworthiness` characteristics, and MEASURE/MANAGE fields. Schema:
  [`nist_ai_rmf.schema.json`](./nist_ai_rmf.schema.json). **Indicative.**
- **`owasp_threat`** — a threat identifier from an external catalogue (OWASP Top 10 for LLM Apps, OWASP
  Agentic, MITRE ATLAS, Google SAIF) plus the control that fired and its `status`/`severity`. Schema:
  [`owasp_threat.schema.json`](./owasp_threat.schema.json). **Indicative.** Worked example carrying both
  `nist_ai_rmf` and `owasp_threat`: [`../examples/governance_record.json`](../examples/governance_record.json).
- **`observability_transport`** — correlates a record to the telemetry of the same decision:
  `transport` (OpenTelemetry / OpenInference / OTLP), the `trace_id` / `span_id` it rode on, and how
  the record is carried (`full_record` or just `current_hash`). Schema:
  [`observability_transport.schema.json`](./observability_transport.schema.json); worked example:
  [`../examples/observability_record.json`](../examples/observability_record.json) (an OpenInference
  GUARDRAIL span). **Indicative**: the SDK glue that emits the record as a span attribute is adoption
  work, not part of the core.

## Two kinds of profile

- **Framework profiles** map a record onto an external rulebook (a regulation, a risk
  framework, a threat model).
- **Domain profiles** add the fields a particular industry needs.

---

## Framework profiles (reserved names)

Each binds the core record to one external framework. Reserved names:

- **`eu_ai_act_log`** — EU AI Act record-keeping (Article 12), automatically generated logs
  (Article 19), and post-market monitoring (Article 72). **✓ schema published** — see "Published
  profiles" above.
- **`nist_ai_rmf`** — the NIST AI Risk Management Framework (the MEASURE and MANAGE functions).
  **✓ schema published** — see "Published profiles" above.
- **`iso_records`** — ISO/IEC 42001 and 23894 record-keeping (Clause 7.5 / Clause 9).
- **`owasp_threat`** — OWASP Agentic + MITRE ATLAS + Google SAIF threat identifiers.
  **✓ schema published** — see "Published profiles" above.
- **`provenance_chain`** — supply-chain provenance: an in-toto attestation (a signed
  statement about how an artifact was produced) inside a DSSE envelope (Dead Simple Signing
  Envelope), a C2PA mark (Coalition for Content Provenance and Authenticity) at the asset
  boundary, and a software/AI bill of materials (SPDX or CycloneDX) bound by hash.
- **`observability_transport`** — carry the signed record over OpenTelemetry (the
  vendor-neutral telemetry standard) or OpenInference spans. **✓ schema published** — see
  "Published profiles" above.
- **`incident_reporting`** — the OECD Common Reporting Framework for AI incidents.
- **`maturity_ladder`** — the L1→L5 conformance tiers.

---

## Domain profiles

Each profile below leads with what it is for, then the main fields it adds beyond the core.
All are proposed.

### `finance` — banking and insurance

**For:** regulated money decisions — loan underwriting, adverse-action (a declined
application), insurance pricing, and claims.

It reuses the core verbs (`block` / `defer` / `escalate_to_human` for declines and human
review) and uses `scope.does_not_cover` for the honest caveats a regulator looks for (for
example, "fairness across a protected class was not tested"). The fields it adds record:

- the decision type and, for a decline, the ranked reason codes and their legal basis;
- the model used — its id, version, risk tier, and when it was last validated;
- the fairness test run, the protected classes it covered, and the result;
- whether a human reviewed the decision, and any override.

### `legal` — legal AI

**For:** AI that drafts or advises on legal matters, where a fabricated case citation can get
a lawyer sanctioned.

The key fields record:

- a check, per cited authority, that the case or statute actually exists and says what was
  claimed (the guard against hallucinated citations);
- whether the output was legal *information* or legal *advice*, or was refused as advice;
- the jurisdiction the answer applies to, and the confidentiality posture.

### `education` — generic educational setting

**For:** tutoring, marking, and learner-facing assistants in a school or course — written
generically, with no country-specific regulators.

The key fields record:

- the learner's age band (a band, not a birthdate) and who authorized the processing;
- whether AI was the sole marker, or a human applied judgement;
- the tutoring mode used — scaffold, hint, direct answer, or refused;
- whether a safeguarding concern was raised and a human was notified.

### `safety_critical` — medical, industrial, automotive, defense

**For:** AI whose decisions can hurt people, where a wrong release must fail safely.

It reuses the core `kill` verb (fail-closed) and `escalate_to_human`. The key fields record:

- the assurance level the system is built to (for example an automotive ASIL or an
  industrial SIL rating);
- whether the situation stayed inside the system's approved operating conditions;
- the fail-safe behaviour taken, and whether a human could override in time;
- the hazard being controlled and whether the residual risk was acceptable.

Note: AIREP does not let a record claim "this satisfies assurance level X" by itself — such a
claim stays in `scope.does_not_cover` until an independent review establishes it.

### `game_narrative` — game NPCs and interactive storytelling

**For:** AI characters and branching stories generated live, turn by turn.

It maps a rating-overflow line to `redact` or `block`, and a self-harm signal to
`escalate_to_human`. The key fields record:

- the game's age rating and whether the generated line stayed inside it;
- whether the player was told they are talking to AI;
- whether AI-generated media was marked as synthetic;
- whether the character spoke in-world (a villain may menace) or as the out-of-world safety
  voice (which owes duties of care);
- any harm signal from the player and the protective action taken.
