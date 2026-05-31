# AIREP Core Record — Normative Specification (v0.1)

This document defines what makes a record conform to the AI Runtime Evidence Protocol
(AIREP). It is written for implementers. If you have not met AIREP before, read the
plain-language [`EXPLAINER.md`](./EXPLAINER.md) first; this document assumes you have. The
format's maturity stage and open engineering items are recorded separately in
[`STATUS.md`](./STATUS.md) and are deliberately kept out of this specification.

AIREP is published as an open format. It is not, at this stage, a standards-body
specification; it adopts the requirement discipline below without claiming any standards
track.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in
all capitals, as shown here.

A **record** is one JSON object describing one AI runtime governance decision. A
**producer** is software that writes records. A **verifier** is software that reads a record
(or a chain of records) and checks it. A **profile** is an optional, namespaced block of
extra fields (Section 7).

## 2. Conformance classes

Requirements in this document bind one of two classes. A requirement that names neither
class binds both.

- **Producer.** Software that emits AIREP records.
- **Verifier.** Software that validates and checks AIREP records.

A producer is conformant if every record it emits satisfies the producer requirements. A
verifier is conformant if it enforces the verifier requirements. A verifier MUST NOT report
a record as valid unless all checks in Section 8 pass.

**Assurance tiers (Core / Verified / Trusted).** Independently of the producer/verifier roles
above, a record or chain has an *assurance tier* stating how much a consumer may rely on it.
**AIREP-Core** is a well-formed, untampered record (the Section 8 checks). **AIREP-Verified** adds
re-verified authorship under a key bound by a `key_trust` profile. **AIREP-Trusted** adds an
independent freshness / head witness. The tiers are a strict ladder, defined normatively in
[`conformance/CONFORMANCE_CLASSES.md`](./conformance/CONFORMANCE_CLASSES.md); the reference verifiers
report the highest tier a record satisfies with `--class`. (The witness profile that AIREP-Trusted
requires is a v0.2 item, so no record reaches Trusted yet — see [`STATUS.md`](./STATUS.md).)

## 3. The core record

A record MUST be a JSON object that validates against
[`core.schema.json`](./core.schema.json) (JSON Schema, draft 2020-12). It has nine required
members: `airep_version` and eight structural members. The core's top-level
`additionalProperties` is `false`; the only permitted non-core top-level member is the
reserved `profiles` object (Section 7).

The following table is the normative field registry. "R" = REQUIRED, "O" = OPTIONAL.

| Member | R/O | Type | Meaning |
|---|---|---|---|
| `airep_version` | R | string | The constant `"0.1"`. |
| `subject` | R | object | Who decided and when: `runtime`, `producer`, `decision_index`, `timestamp_utc`; optional `trace_id`. |
| `input` | R | object | What was decided on: `input_ref` (+ optional `input_hash`) and `governance_state`. |
| `claim` | R | object | The assertion about the decision: `assertion` and `basis` (one or more entries). |
| `output` | R | object | The decision result: `result_ref` (+ optional `redacted`). |
| `evidence` | R | array | Typed pointers supporting the claim. Each entry: `type`, `ref`, `resolvable` (+ optional `content_hash`). |
| `directive` | R | object | The decision as a verb: `verb` and `policy_basis`. |
| `scope` | R | object | What the evidence does and does not cover: `covers` and `does_not_cover`. |
| `integrity` | R | object | Tamper-evidence: `previous`, `current`, `canonical_json`, `signature`. |
| `profiles` | O | object | Reserved extension point (Section 7). |

### 3.1 Field value constraints

- `subject.decision_index` MUST be an integer, starting at 0, and increasing by one for
  each successive decision a producer records in the same chain.
- `directive.verb` MUST be exactly one of: `release`, `block`, `defer`, `redact`,
  `escalate_to_human`, `kill`.
- `evidence[].type` MUST be exactly one of: `retrieval`, `tool_call`, `memory`, `policy`,
  `human_approval`, `external_url`, `eval`, `other`.

## 4. Evidence and the resolvable flag

Each entry in `evidence` is a pointer to supporting material, not the material itself. A
producer MUST set `resolvable` to `true` only when a verifier can fetch the referenced
material and check it; otherwise the producer MUST set `resolvable` to `false` (for example,
when the material is redacted but its `content_hash` is still recorded).

A verifier MUST NOT treat an entry with `resolvable: false` as verified evidence. This
prevents an unverifiable pointer from being counted as proof.

## 5. Scope honesty

A producer MUST populate both `scope.covers` and `scope.does_not_cover`. `covers` states
what the evidence in this record attests; `does_not_cover` states what it does not. A record
whose `does_not_cover` is empty asserts that its evidence covers everything material to the
claim, and SHOULD be used only when that is genuinely true.

## 6. Integrity, canonical form, and the chain

The `integrity` block makes a record tamper-evident.

- **Canonical form.** Before hashing, a record MUST be serialized into a single canonical
  form so that the same record always yields the same hash. The canonical form is RFC 8785,
  the JSON Canonicalization Scheme [RFC8785]. A record sets `integrity.canonical_json` to
  `true` to declare that its hash was computed over the canonical form. Because RFC 8785 fixes
  how numbers are serialized, a producer SHOULD avoid placing values whose exact representation
  is significant (for example high-precision decimals) as JSON numbers in a signed record; such
  values SHOULD be carried as strings so that two implementations agree on the bytes.
- **The hash.** `integrity.current` MUST be the SHA-256 digest of the canonical form of the
  record computed with `integrity.current` and `integrity.signature` removed and every other
  member — including `integrity.previous` — retained. Including `previous` in the hash binds a
  record's content to its place in the chain: a validly signed record cannot be replayed or
  spliced into a different position without breaking its hash. The value is written as
  `sha256:` followed by 64 lowercase hexadecimal characters.
- **The signature.** A producer MUST sign `integrity.current` and record the result in
  `integrity.signature` as `{alg, value}`. AIREP does not mandate one signature algorithm;
  `alg` names the algorithm used (for example `Ed25519` or `HMAC-SHA256`) so that any
  conformant signer is interchangeable. A verifier that has the corresponding key SHOULD
  re-check the signature.
- **The chain.** `integrity.previous` MUST be the `current` value of the immediately
  preceding record in the same chain. The first record in a chain MUST set `previous` to the
  genesis value: `sha256:` followed by 64 zero characters. A verifier MUST check that each
  record's `previous` equals the prior record's `current`, and that the first record uses the
  genesis value.

## 7. Extensibility: profiles

A producer MAY attach extra fields under the single reserved `profiles` object, as named
sub-blocks (for example `profiles.phionyx`, `profiles.finance`). Profile names SHOULD be
collision-resistant (a vendor, product, or framework name). Implementation-, vendor-, model-,
or domain-specific content MUST be placed under `profiles`; it MUST NOT appear elsewhere in
the core or inside a core sub-object.

**The neutrality test (normative).** A core-conformant record MUST still validate against
`core.schema.json` after its `profiles` member is removed. This guarantees that no profile
content has leaked into the shared core at the top level. It does not, by itself, prove that
no mechanism was hidden inside a core sub-object such as `input.governance_state`; that
remains a conformance violation, detectable by review.

The available profiles are catalogued in [`profiles/`](./profiles/). The core
`directive.verb` and `evidence[].type` vocabularies are **closed** (Section 3.1): a profile
MUST NOT introduce a new core verb or evidence type. A domain-specific action is recorded in
the profile's own sub-block and mapped onto one of the core verbs (for example, a finance
profile's `freeze_account` maps to the core verb `block`). AIREP v0.1 therefore operates no
central registry: verbs and evidence types are fixed by `core.schema.json`, and profile names
need only be collision-resistant (a vendor, product, or framework name) at this stage.

## 8. Conformance check

A verifier reports a record (or chain) as **valid** only when all of the following hold:

1. each record validates against `core.schema.json` (Section 3);
2. the neutrality test passes — each record still validates with `profiles` removed
   (Section 7);
3. each record's `integrity.current` recomputes from the canonical form (Section 6);
4. the chain links: every `previous` equals the prior `current`, and the first record uses
   the genesis value (Section 6).

A verifier that also possesses signing keys SHOULD additionally verify each
`integrity.signature` over `integrity.current`.

## 9. Security and privacy considerations

AIREP is a record format for after-the-fact checking. Its guarantees and its limits:

- **What the integrity block defends.** Altering any byte of a record changes its hash, so a
  silent change is detectable (the hash check fails). A signature binds the record to its
  writer, so a forged record is detectable by anyone with the public key (the signature check
  fails). The chain binds records in order, so removing or reordering a record in the middle
  is detectable (a `previous` value no longer matches). Replay of an old record into a new
  position is detectable for the same reason — its `previous` will not match.
- **Out of scope.** AIREP does not establish trust in signing keys. Key distribution and
  signer identity are deployment concerns; a profile MAY bind a mechanism (for example, a
  transparency log). AIREP also does not protect record availability — a party that controls
  storage can withhold records, though it cannot alter them undetectably.
- **Privacy.** Records carry pointers and digests, not content. The question, the answer, and
  the evidence are referenced by `*_ref` and `*_hash`, so a record can be retained and shared
  without exposing regulated content. `output.redacted` and `resolvable: false` let a producer
  withhold content while keeping its hash anchor.
- **A record attests the path, not the truth.** A valid record proves what the producer
  recorded and that it was not altered. It does not prove the underlying AI output was
  correct. `scope.does_not_cover` exists to keep that boundary explicit; a verifier MUST NOT
  read a valid record as an assertion of correctness beyond what `scope.covers` states.

## 10. References

**Normative**

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
- [RFC8785] Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)", RFC 8785.

**Informative**

- [`EXPLAINER.md`](./EXPLAINER.md) — plain-language introduction to this format.
- [`STATUS.md`](./STATUS.md) — maturity, open items, and change log.
- [`profiles/`](./profiles/) — the optional binding-profile catalogue.
