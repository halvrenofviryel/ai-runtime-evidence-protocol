# AIREP v0.1 — Status of this specification

**Status: Experimental.**

This document follows the spirit of RFC 7841: the status is a *positive label for the document's
lifecycle stage*, not a disclaimer of worth. AIREP v0.1 is a proposed open interchange format,
published for examination, experimental implementation, and evaluation. It is **not** a ratified
standard, and this label does not assert otherwise — the producing reference implementation is the
Phionyx Reasoned Governance Envelope. An **independent second verifier** now exists: the conformance
kit ships two implementations (Python `verify.py` and Node `verify.mjs`) on different language and
crypto stacks that each, independently, validate a record's structure (the closed top level, the
required members, the closed `directive.verb` / `evidence[].type` enums), run the strip-`profiles`
neutrality test, re-derive every `integrity.current` and agree on it byte-for-byte on the example
vectors, and re-verify the Ed25519 signatures. A **second, independently authored producer** has
since been measured against frozen v0.1.2 and was accepted on first invocation by both pinned
verifiers; that experiment also exposed a v0.1 signature-encoding ambiguity. It is one
compatibility result, not a general interchange property. Broader external review remains open. See
[`EXTERNAL_EVIDENCE.md`](../../../EXTERNAL_EVIDENCE.md).

Maturity is a labelled attribute, not prose hedging in the normative text. The honest maturity
picture — the assurance ladder (AIREP-Core → AIREP-Verified → AIREP-Trusted), what the reference
implementation satisfies today, and the open gaps — is recorded here and in
[`conformance/CONFORMANCE_CLASSES.md`](./conformance/CONFORMANCE_CLASSES.md), kept out of the
normative `SPEC.md` on purpose.

## What "Experimental" commits us to

- The wire format (`core.schema.json`) and the normative rules (`SPEC.md`) MAY change between v0.1 and
  v0.2; changes are tracked below.
- We do **not** describe AIREP as adopted, ratified, or as an industry baseline. It is a proposed
  format with a reference implementation.
- Conformance is defined by the normative text, independently of any one implementation.

## Known open items (tracked, not hidden)

These are normative-adjacent gaps recorded honestly; each is a v0.2 work item:

> **Prepared ENAS profile work.** Eleven standalone ENAS evidence-contract
> schemas and two bounded fixture corpora (40 record cases total) are present
> as working-tree additions. The conformance helper now also reconciles exact
> issuer and receiver graph cardinality, embedded record references and
> digests, typed-edge endpoints, and issuer-to-lifecycle identity. This closes
> a local graph-splice acceptance surface; it does not prove that a named
> producer or deployment boundary ran.
> This advances the named record contracts to schema maturity only. Release,
> runtime emission, receiver acknowledgement, effect observation, complete
> mediation, independent reproduction, and external acceptance are not claimed.

1. **Hash domain & canonicalization** — the spec pins one rule (SPEC §6): the hash covers the canonical
   form with `integrity.current` and `integrity.signature` removed and `integrity.previous` retained, so
   content is bound to chain position (this is what detects a replayed or spliced record). The reference
   implementation **already binds `previous`** into the hash (it hashes the wrapper `{record, previous}`),
   so the anti-splice property holds today. What still differs is (a) the exact serialization — the
   reference wraps `{record, previous}` rather than hashing the record in place — and (b) the
   canonicalizer is sorted-key `json.dumps`, not RFC 8785, and even differs between the shipped reference
   packages (`ensure_ascii` vs `allow_nan`). Aligning the reference serialization to the spec rule **and**
   adopting RFC 8785 is a breaking, version-bumped change (an "item 2 / P1" reference-implementation task),
   because it changes computed hashes for existing chains.
2. **RFC 8785 (JCS)** — the **conformance kit now implements it**: `conformance/jcs.py` (Python, with
   an ES6 Number-to-String serializer) and the Node verifier (`verify.mjs`, ES6-native) produce
   byte-identical canonical bytes, verified across a value battery including the cases sorted-key
   `json.dumps` serialized differently (`1.0`→`1`, `1e-07`→`1e-7`, `-0.0`→`0`). The float-free example
   vectors are unchanged by the switch. What remains open is aligning the **shipped reference RGE
   packages** (which still hash with sorted-key `json.dumps`) to JCS — a breaking, version-bumped change
   across those packages, deliberately deferred from this conformance-tooling work.
3. **Signature re-verification** — the conformance kit now re-verifies Ed25519 signatures in **both**
   verifiers, and the shipped reference chain verifier (`phionyx-mcp-server`) gained **opt-in** signature
   verification (pass a signer; default off → no behaviour change). What remains open is turning signature
   re-verification on **by default** in the shipped verifier, which is a configuration/version decision for
   that package rather than a spec gap.
4. **`profiles` extension model** (single reserved key + top-level `additionalProperties:false`) is
   adopted in `core.schema.json` for v0.1; field-level neutrality (tightening core sub-objects) is a
   v0.2 decision — today the neutrality test proves block-level neutrality only.
5. **`decision_index` ↔ reference `turn_index`** naming + minimum reconciliation is a reference-impl
   alignment item.
6. **Domain + framework profiles** — five profile schemas are now on disk under
   [`profiles/`](./profiles/) (`key_trust`, `eu_ai_act_log`, `nist_ai_rmf`, `owasp_threat`,
   `observability_transport`), each validated by the conformance kit and proven block-neutral. Their
   regulatory/standards anchors remain **INDICATIVE** — flagged in each schema's description as a design
   aid to be checked against the primary source before any compliance claim — not yet verified
   against the primary texts.
7. **Freshness / head witness** — the **`chain_witness` profile now ships** (schema + worked
   independently-witnessed vector). `validate.py` verifies that vector's witness signature under a key
   **distinct from the producer's**, and demonstrates that a dropped tail is detected.
   **AIREP-Trusted is withheld in default mode and reachable only in opt-in strict mode (WP-10).**
   In default mode the general-purpose classifiers (`verify.py --class` / `verify.mjs --class`)
   check witness *presence* only — they do not re-verify the witness signature, cannot prove
   witness-key independence, do not evaluate freshness recency, and consult no revocation source —
   so both verifiers **withhold the top class** and report `TRUSTED_NOT_IMPLEMENTED`, naming each
   unevaluated gate. In **strict mode** (operator supplies `--trust-store` + `--freshness-window` +
   `--revocation-source`), the four gates run for real and a record earns `Trusted` iff every one
   passes; any missing input keeps the tier withheld. Strict-mode v1 scope is deliberately narrow:
   one independent trusted witness (no N-of-M quorum), local JSON inputs (no transparency-log or
   online revocation lookup), timestamp freshness only. Semantics of both modes:
   [`conformance/CONFORMANCE_CLASSES.md`](./conformance/CONFORMANCE_CLASSES.md)
   §TRUSTED_NOT_IMPLEMENTED and §AIREP-Trusted (strict mode); the fail-closed behaviour is held by
   [`conformance/test_trusted_gates.py`](./conformance/test_trusted_gates.py) and
   [`conformance/test_strict_trusted.py`](./conformance/test_strict_trusted.py) over committed
   corpora run against both verifiers. Widening strict-mode v1 scope (quorum, transparency-log
   proofs, online revocation, nonce/challenge freshness) is the remaining **v0.2-proper**
   Trusted-tier work.

### 5. `subject.principal` — added, and deliberately optional

A record could say `producer: acme-governor/1.0` decided to `block`, and could not say **on whose
authority**. `subject.principal` closes that: `human`, `service`, `session`, `scope` — the four
layers an authorisation question actually needs.

It is **optional in v0.1** so that every record already written stays valid; the conformance runner
confirms this. A producer that can determine any layer SHOULD record it.

The field that matters most is `established_by`, and it is the reason this is not just a copy of the
obvious design. It records **how** the identity was established:
`asserted_by_caller` · `verified_credential` · `mutual_tls` · `platform_attested` ·
`out_of_band_signature` · `not_established`.

`asserted_by_caller` means the party being governed told us who it was — a claim, not evidence. This
is the same principle as `authority.writable_by_controlled_system` in the `control_delivery` profile,
applied to identity: **an identity the controlled system asserts about itself is worth exactly as
much as a control path the controlled system can write.** Recording the identity without recording
how it was established would have reproduced, in the identity field, the confusion this format
exists to remove.

`not_established` is an honest and useful answer, and omitting the block entirely is better than
implying a verification that did not happen.

## Known interoperability limitation — signature input and value encoding

**Status: preserved, not fixed. Released v0.1.2 is unchanged.**

**What v0.1 states.** `SPEC.md` §6, the signature bullet, requires that a producer MUST sign
`integrity.current` and record the result in `integrity.signature` as `{alg, value}`, and that
`alg` names the algorithm "so that any conformant signer is interchangeable". `integrity.current`
is defined as the string `sha256:` followed by 64 lowercase hexadecimal characters.

**What remained under-specified.** Two things the frozen text does not state:

1. **The exact bytes signed.** "Sign `integrity.current`" does not say whether the signed bytes
   are the ASCII bytes of that string or the 32 bytes the string denotes.
2. **The exact encoding of `signature.value`.** The frozen text never constrains it. The strings
   `signature.value`, `base64`, `UTF-8`, `signed bytes` and `preimage` each occur **zero** times
   in `SPEC.md`.

**How it was exposed.** Independently, by an external producer experiment against frozen v0.1.2
rather than by internal review. An independently authored producer chose the ASCII bytes of the
string and lowercase hex, and both pinned reference verifiers accepted its records on first
invocation. Re-signing the same records under each of the other two readings — same key, nothing
else changed, `integrity.current` untouched because it is computed with `integrity.signature`
removed — was rejected by both verifiers with a signature-only failure. Identities, commands and
the reproduction are in [`EXTERNAL_EVIDENCE.md`](../../../EXTERNAL_EVIDENCE.md).

**The honest reading.** The two reference verifiers implement one interpretation consistently,
and that interpretation is what an interoperating producer must match. But the normative text did
not pin it, so a conformant-looking producer could reasonably choose either reading. The sentence
that says naming `alg` makes any conformant signer interchangeable therefore rests on two
conventions v0.1 does not state. This is recorded as a limitation of the released text; it is not
a claim that v0.1 intended one reading and failed to write it down.

**Disposition.** v0.1.2 is frozen and is preserved unchanged — see the immutability rule in
**Change control** below. v0.2 pins both points explicitly; see
[`v0.2-design/MIGRATION.md`](../v0.2-design/MIGRATION.md). Whether the v0.1 line should receive an
editorial clarification is deliberately left open, because adding algorithm-specific encoding to a
released line may be more than editorial.

**Not part of this limitation.** Two adjacent observations from the same experiment are
**interface conventions, not normative-core defects**, and are recorded as such: `SPEC.md` does
not state how a chain is serialised as a file (the string `jsonl` occurs zero times in it;
one record per line comes from the usage line in
[`conformance/README.md`](./conformance/README.md)), and the CLI public-key encoding is convention
rather than specification.

## Prior art, and what AIREP does not claim to have invented

Recorded here because a format that overstates its novelty is not one you should trust with an
honesty field.

**Signed, canonical, offline-verifiable per-decision records are established practice, not a
contribution of ours.** Regulatory and industry expectations already point the same way — EU AI Act
Article 12 record-keeping, the NIST AI RMF measure/manage functions, and the OWASP Agentic Top 10 all
assume per-decision accountability. AIREP's use of RFC 8785 JCS canonicalization and Ed25519
signatures follows widely used practice on purpose: interchange formats should not invent crypto.

So AIREP's signature semantics, canonicalization and offline verifiability are **not** presented as
points of distinction.

### What AIREP adds

1. **Mandatory record-level chaining.** `integrity.previous` is required on every record, so content
   is bound to chain position and a spliced or replayed record is detectable without reference to an
   external service.

2. **Control-instruction delivery as evidence.** The `control_delivery` profile records the lifecycle
   of a governance instruction — issued, delivered, acknowledged, enforced, observed, or positively
   recorded as `delivery_failed` — from **both sides of a boundary**, correlated by `instruction_id`
   and `instruction_hash`.

   Scope the claim precisely. Acknowledgement of a *business* action — an order confirmed by a venue,
   a webhook accepted — is long solved and well served by existing formats. The open problem is
   different: proving that a **governance or control instruction reached and bound at the component
   that enforces it**. A record format can say a stop was *decided*; whether it *arrived* is a
   separate fact, and an instruction correctly issued, correctly signed and never delivered is
   indistinguishable from one nobody sent. In the systems we have reviewed we have not found this
   modelled as a first-class, two-sided evidence lifecycle. That is a bounded observation, not a
   proven novelty result.

3. **Honest scope as a required field.** `scope.does_not_cover` is mandatory, and
   `failure.root_cause_isolated: false` is a first-class thing a producer can say. This exists
   because presence of an evidence container is routinely mistaken for sufficiency of evidence; a
   schema that forces a producer to state the limits of a record is addressing that directly.

4. **Authority provenance.** `authority.writable_by_controlled_system` marks whether the control path
   could have been written by the party it constrains — a control path the constrained party can
   author does not establish external authority, however well it is signed.

The open items above remain the accurate picture of maturity; nothing in this section is a claim of
completeness.

## Change control

- **Versioning:** breaking changes (e.g. any future `escalate_to_human` → `escalate` verb rename, or a
  top-level required-field change) increment the version and are logged here as **BREAKING**, never
  presented as additive.
- **Proposing changes:** open an issue against the spec directory; conformance vectors must be updated
  in lockstep with any schema change.

## Change log

- **v0.1 (draft, 2026-05-30):** initial neutral core; reserved `profiles` extension point +
  `additionalProperties:false`; `escalate_to_human` retained (no rename); genesis hash pinned to
  `sha256:` + 64 zero hex; neutrality test made mechanical (strip `profiles`).
- **v0.1 conformance hardening (2026-05-31, no wire-format change):** the Node verifier
  (`verify.mjs`) was brought to parity with the Python reference — it now validates structure
  (closed top level + closed enums) and runs the neutrality test, not only the hash/signature, so the
  two verifiers genuinely agree on conformance, not just on bytes; `conformance/jcs.py` added (RFC 8785
  canonicalization, cross-checked against the Node serializer); the five profile schemas landed under
  `profiles/`; schema `$id`s point at the canonical repository raw URL; Apache-2.0 (code) + CC-BY-4.0
  (spec text) licenses added. `core.schema.json` and the normative rules are unchanged.
- **v0.1 freshness / head witness (2026-05-31, no wire-format change):** the **`chain_witness`
  profile** shipped — `profiles/chain_witness.schema.json` plus a worked 3-record vector
  (`examples/chain_witness.jsonl`) whose tail checkpoint then reached **AIREP-Trusted** under both
  verifiers. The witness is signed by a key **independent of the producer**; `validate.py` re-verifies
  that signature and demonstrates tail-truncation detection. This closes (at the profile level) the
  tail-truncation and replay-as-latest gaps `THREAT_MODEL.md` named as open. The core wire format is
  unchanged; the profile is additive.
  **⚠ Superseded — the `class=Trusted` result described here was withdrawn; see the next entry.**

- **v0.1 Trusted fail-closed (2026-08-07, no wire-format change):** granting `Trusted` on witness
  *presence* was a fail-open bug: the classifiers never re-verified the witness signature, could not
  prove witness-key independence, never evaluated freshness recency, and consulted no revocation
  source — yet reported the top class anyway, including for a record whose own
  `key_trust.revocation.revoked` was `true`. `verify.py` and `verify.mjs` now **withhold** the top
  class and report **`TRUSTED_NOT_IMPLEMENTED`**, naming every unevaluated gate; structurally
  checkable prerequisites that definitively fail stop the ladder at `Verified` with the specific
  failure named. **No input reaches `Trusted` under either verifier**, including
  `examples/chain_witness.jsonl`. New: `conformance/test_trusted_gates.py` — seven adversarial cases
  committed as a shared corpus under `conformance/fixtures/trusted_gates/`, run against **both**
  verifiers, asserting the same class **and** the same withheld-reason set from each, with a
  drift guard binding the corpus to its generator. Class semantics (validity, rank, exit-code
  meaning) are normative in `conformance/CONFORMANCE_CLASSES.md` §TRUSTED_NOT_IMPLEMENTED.
  Also closed: an **empty input** (`[]` or an empty `.jsonl`) previously reported `CLASS: Trusted` at
  exit 0 in both verifiers — the top class awarded to the maximally *unmeasured* input, because the
  chain class was initialised to `Trusted` and no record ever lowered it. An empty input is now
  `INVALID` at exit 1 in both, the chain class starts unset rather than at the ceiling, and the case
  is held by the battery.
  Also closed: a **Python/Node class divergence**. Presence tests on the Trusted path used
  truthiness, and `witness: {}` is falsy in Python but truthy in JavaScript — so for identical bytes
  `verify.py` reported `Verified` (empty withheld set) while `verify.mjs` reported
  `TRUSTED_NOT_IMPLEMENTED` with all four gates named. Every presence predicate is now an explicit
  type + non-emptiness check that both runtimes evaluate identically, and the case is a fixture.
  The shared corpus gained a **multi-record chain** (the single-record fixtures never exercised the
  chain-aggregation path where the empty-input bug lived) and the battery now compares the class and
  reason set of **every** record, not just record 0. Missing `cryptography` now exits non-zero as
  `NOT_RUN` instead of exiting 0 having measured nothing. The exit-code contract is now stated
  accurately (0/1/2, `--help` = 0) and names the fact that the two verifiers' exit codes are **not**
  equivalent while `verify.mjs` runs no profile-schema validation. The core wire format is unchanged
  and the `chain_witness` schema changed only in two `description` strings — this is a verifier and
  documentation correction only.

- **v0.1 strict-Trusted, WP-10 (2026-08-08, no wire-format change):** `Trusted` became reachable in
  an **opt-in strict mode**: with `--trust-store` + `--freshness-window` + `--revocation-source`
  supplied by the operator, both verifiers run the four previously-unevaluated gates (witness
  signature, witness-key independence against resolved public keys, freshness recency against a
  deterministic `--now`, revocation for both producer and witness keys) and grant `Trusted` iff all
  four pass; any gate failure drops the ceiling to `Verified` with the reason named, and any missing
  operator input keeps the tier withheld as `TRUSTED_NOT_IMPLEMENTED`. Default-mode behaviour is
  unchanged. Held by `conformance/test_strict_trusted.py` against both verifiers.

- **v0.1 STATUS correction (2026-08-22, documentation only):** open item 7 previously still said
  "AIREP-Trusted is NOT reportable" with no mention of strict mode — stale since WP-10 (2026-08-08)
  and inconsistent with `conformance/CONFORMANCE_CLASSES.md` and both verifiers' actual behaviour.
  Item 7 now states the single normative truth: withheld in default mode, reachable in strict mode,
  with strict-mode v1 scope named. No schema, verifier, or wire change.
