# AIREP v0.2 — Design line

**Status: Design. Nothing in this directory is normative.**

This directory holds the architecture decisions, breaking-change inventory, and migration model
for AIREP v0.2. It is a working design record, published for review — the same discipline as the
rest of this repository: proposals are labelled proposals, and no document here claims that v0.2
exists, is implemented, or has been independently validated.

## Version policy for this line

- **v0.1 is frozen.** The `spec/airep/v0.1/` tree receives documentation-correctness and security
  fixes only. No wire-format, schema, or conformance-semantics change lands in v0.1.
- **v0.2 proceeds as an isolated design line**: design decisions first (this directory), then a
  `v0.2-alpha` schema + verifier line, then an interoperability gate (a second producer, a
  cross-implementation corpus, external-standard mappings), then an independence gate (genuinely
  third-party production or reproduction). "v0.2 stable" is not claimable before both gates pass.
- Existing v0.1 chains, releases, and DOIs are never rewritten. See `MIGRATION.md`.

## Documents

| Document | Contents |
|---|---|
| [`ARCHITECTURE_DECISIONS.md`](./ARCHITECTURE_DECISIONS.md) | The v0.2 architecture decisions (AD-01 … AD-15), each with context, decision, and status |
| [`BREAKING_CHANGES.md`](./BREAKING_CHANGES.md) | Field- and behaviour-level inventory of what v0.2 changes against v0.1, with wire impact |
| [`MIGRATION.md`](./MIGRATION.md) | The v0.1 → v0.2 migration model: what stays valid, what is projected, what is never re-signed |

## The one-sentence thesis under design

> AIREP v0.2 is a vendor-neutral evidence interchange protocol for cryptographically binding AI
> runtime governance decisions to control delivery, execution, and observed effects, while
> composing with external identity, authorization, telemetry, and transparency standards.

The operative word is **composing**. AIREP does not define identity, authorization, transport,
telemetry, or transparency logging; the 2026 standards landscape supplies those. AIREP supplies the
evidence semantics that bind them across the decision-to-effect gap. See AD-02.
