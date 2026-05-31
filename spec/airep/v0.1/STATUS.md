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
vectors, and re-verify the Ed25519 signatures. What remains open is a second independent **producer**
and broader external review.

Maturity is a labelled attribute, not prose hedging in the normative text. The honest maturity picture
— the L1→L5 ladder, the reference implementation's current rung, and the open gaps — lives in the
companion arXiv papers (per the scope rule), not in `SPEC.md`.

## What "Experimental" commits us to

- The wire format (`core.schema.json`) and the normative rules (`SPEC.md`) MAY change between v0.1 and
  v0.2; changes are tracked below.
- We do **not** describe AIREP as adopted, ratified, or as an industry baseline. It is a proposed
  format with a reference implementation.
- Conformance is defined by the normative text, independently of any one implementation.

## Known open items (tracked, not hidden)

These are normative-adjacent gaps recorded honestly; each is a v0.2 work item:

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
