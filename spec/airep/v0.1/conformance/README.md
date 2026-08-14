# AIREP conformance

This directory lets you check that a record really conforms to AIREP — with **two independent
verifiers** (Python and Node) that agree byte-for-byte on every hash, and reach the same verdict on
the core checks. One documented exception: `verify.mjs` runs **no profile-schema validation**, so a
record whose `profiles` block violates its schema is rejected by `verify.py` and accepted by
`verify.mjs`. `verify.py` is the authority for exhaustive schema validation.

- [`verify.py`](./verify.py) — verify **your own** record or chain (not just the bundled examples):
  `python3 verify.py <record.json | chain.jsonl> [--pubkey <hex|file>]`. For each record it runs
  schema validation (closed top level, required members, closed enums), the strip-`profiles`
  neutrality test, integrity (hash recompute), chain-replay (or the standalone genesis check),
  optional Ed25519 signature verification, and profile conformance — and exits non-zero if any
  record fails.
- [`verify.mjs`](./verify.mjs) — a **second, independent implementation** (Node, zero dependencies):
  `node verify.mjs <record.json | chain.jsonl> [--pubkey <hex|file>]`. It runs the **same checks** on
  a different language and crypto stack — structure (closed top level + closed enums), neutrality,
  hash, chain, signature — and re-derives every `integrity.current` to the **byte-identical** SHA-256
  the Python implementation computes. Two implementations agreeing on *both conformance and the
  hashes* is what makes AIREP an *interchange* format rather than a single-tool artifact. (Hand it a
  record with a stray vendor key and both report `FAIL(extra-top, neutrality, …)`; tamper a field and
  both report `FAIL(hash)`.)

Both verifiers accept `--class`, which reports the highest conformance class satisfied. The classes
they can report are **`Core`, `Verified`, and `TRUSTED_NOT_IMPLEMENTED`** — `Trusted` is **never**
reported, because four of its prerequisites (witness-signature verification, witness-key
distinctness, freshness recency, revocation) are unenforced, and an unenforced prerequisite is never
reported as satisfied. `TRUSTED_NOT_IMPLEMENTED` ranks **equal to `Verified`** and names each
unevaluated gate. The **exit code encodes record validity only, never the class** (0 = every record
passed every check *that verifier ran*, 1 = a record failed or the input was unreadable, 2 = usage
error) — a `TRUSTED_NOT_IMPLEMENTED` record exits 0 because it is a valid record, so exit 0 must not
be read as "Trusted". The two verifiers' exit codes are **not equivalent**: `verify.mjs` runs no
profile-schema validation, so a profile-invalid record exits 1 under Python and 0 under Node. Full
semantics: [`CONFORMANCE_CLASSES.md`](./CONFORMANCE_CLASSES.md).

- [`validate.py`](./validate.py) — the one-command conformance battery over
  [`../examples/`](../examples/). It runs: FULL schema validation; the **neutrality test** (delete
  `profiles`, still valid); **negative tests** (a stray vendor key and a missing `scope` must be
  rejected); **integrity** (recompute `integrity.current` over the canonical form, check the genesis
  `previous`, verify the Ed25519 signature); **chain replay** (walk the 5-record chain); **tamper
  detection** (an edited field, a rewritten `previous`, and a corrupted signature must each break
  exactly the right check); and **profile conformance** (every `profiles.<name>` validates against
  `profiles/<name>.schema.json`). Exit 0 when all pass.
- [`enas_profiles.py`](./enas_profiles.py) — validates thirty-seven experimental,
  standalone ENAS evidence contracts against Draft 2020-12 schemas and bounded
  cross-field and typed-graph rules. Its five corpora contain 164 cases: forty-nine
  expected passes and one hundred fifteen expected rejections. The bundle validators
  (`validate_issuer_bundle`, `validate_lifecycle_bundle`,
  `validate_issuer_lifecycle_pair`) add exact record/link cardinality,
  embedded-reference and digest reconciliation, issuer-to-receiver identity, and
  bounded timestamp ordering. They are **total** over malformed input — a missing
  required field, or a non-object record/link/endpoint, returns a validation-error
  list, never an exception. A pass is schema/semantic and local
  graph-reconciliation evidence only; it is not runtime, effect, independent, or
  external conformance evidence.
- [`test_enas_bundle_validators.py`](./test_enas_bundle_validators.py) — the
  bundle-reconciliation test battery for the three validators above: positive
  baselines from a golden issuer/lifecycle fixture pair, negative cases (missing
  record id, non-object record/link/endpoint, unknown `profile_type`, missing /
  duplicate manifest / use / typed link, missing / duplicate lifecycle relation,
  cross-attempt / cross-trace / cross-decision joins, digest mismatch, unbound
  instruction, broken timestamp, pair disposition mismatch), and totality checks
  that every malformed input returns errors rather than raising.
- [`test_enas_profiles.py`](./test_enas_profiles.py) — pins the five fixture-corpus
  outcomes (164 cases) against their expected pass/reject labels.
- [`enas_obligation_reconciler.py`](./enas_obligation_reconciler.py) — the **bounded
  G3 reference implementation** for the obligation protocol (WP-OP): the cross-record
  layer the single-record checker deliberately does not cover. It takes a *bundle*
  (origin contract + ordered conservation transitions + closure), reuses the G2
  single-record checker per record, then resolves references, chains the §8.4
  conservation transitions (`after` of one equals `before` of the next), verifies A3
  end-to-end conservation (nothing appears or vanishes unaccounted; a transformed
  predecessor is superseded, not closed), and evaluates A7 global closure (the closure
  disposes exactly the accountable obligations, consistently with each obligation's
  in-chain fate, and a global `PASS`/`SUCCEEDED` is unsound if anything failed or was
  left unresolved). It also enforces single-use obligation identity (§P5 — no
  resurrection of a superseded id) and an **opt-in justification layer**: if a bundle
  carries `handoffs` / `transformations` / `fork_joins`, every transition's
  `transition_ref` must resolve to one and the justifying record must be consistent
  with the delta it explains (a handoff cannot discharge what its transition does not
  account; a transformation's predecessor/successors must match). It emits
  `PASS` / `FAIL` / `INCONCLUSIVE` (a malformed embedded record cannot be reconciled →
  `INCONCLUSIVE`) and is TOTAL over malformed bundles. A `PASS` means "this bundle of
  records is a conserved, closed lineage", **not** that the workflow really ran — the
  records remain producer-attested.
- [`test_enas_obligation_reconciler.py`](./test_enas_obligation_reconciler.py) — pins
  the reconciler over a 17-bundle battery (5 conserved-lineage passes incl. a
  not-success honest failure and handoff/transformation-justified lineages; 11
  reconciliation rejects — broken lineage, wrong entry set, closure hiding an
  unresolved obligation, omitted outstanding obligation, disposed superseded
  predecessor, superseded-identity resurrection, unresolved justification ref,
  handoff created/discharge and transformation delta mismatches, and an ambiguous
  justification id; 1 malformed-record inconclusive) plus totality.
- [`enas_reference_orchestrator.py`](./enas_reference_orchestrator.py) — the **reference
  emitter** that closes the other half of the bounded-G3 slice. A small in-process
  `ObligationOrchestrator` executes an obligation lifecycle (`declare` / `discharge` /
  `transform` / `close`) and emits the WP-OP records from its own state transitions, so
  the records are derived from execution rather than hand-authored. `bundle()`
  round-trips through the reconciler. Because the emitter constructs the conservation
  math from real state and the reconciler re-derives and checks it **independently**, a
  round-trip `PASS` is agreement between two code paths, not one trusting itself.
  **Boundary:** this is a reference orchestrator, not a full agent framework, and the run
  is bounded and in-process — a round-trip `PASS` does not establish that any external
  system emits conformant records, nor is it independent reproduction (both remain
  external-review-gated).
- [`test_enas_reference_orchestrator.py`](./test_enas_reference_orchestrator.py) — the
  emit→reconcile round-trip: a success run and an honest-failure run both reconcile to
  `PASS`, a corrupted emitted bundle (one closure disposition dropped) is caught as
  `FAIL` by the independent reconciler, and the orchestrator's step guards raise.
- [`enas_gate_adapter.py`](./enas_gate_adapter.py) — binds the reconciler to a real
  **external** boundary: the Phionyx pipeline governance gate. `phionyx_session_report`
  exposes a per-claim governance lifecycle (claim_created → evidence → gate_decision →
  signed_record → outcome); the adapter maps a real session report onto WP-OP records —
  each governed claim an obligation, the gate directive its disposition (`pass` →
  discharged, `block` → failed, revise directives → unresolved at the snapshot) — and
  reconciles them. **Boundary:** this maps a *captured* report from one real trace; the
  directive→disposition mapping is a modelling choice and "unresolved" is pending-revision.
  A reconciled `PASS` means the mapped bundle is a conserved lineage, not that the gate is
  itself ENAS-conformant; a live feed and gate-native record emission are external-review-gated.
- [`test_enas_gate_adapter.py`](./test_enas_gate_adapter.py) — reconciles a **verbatim
  captured** real `phionyx_session_report` ([`fixtures/enas_profiles/enas_gate_report_capture.json`](./fixtures/enas_profiles/enas_gate_report_capture.json),
  trace-fcf66f8bb7364529: 8 governed claims, 1 passed / 7 sent for revision) into a conserved
  non-success lineage; plus all-pass-with-observed-enforcement→SUCCEEDED (a gate directive is a
  DECISION, not an observed effect, so a directive-only all-pass report is INCONCLUSIVE, never
  PASS), blocked→failed, a tampered closure caught `FAIL`, and malformed-report rejection.
- [`enas_gate_feed.py`](./enas_gate_feed.py) — turns the one-shot adapter into a **live feed**.
  A `GateFeed` holds a dependency-injected `report_source` callable (a running Phionyx process
  wires the live `phionyx_session_report`; tests wire a simulated evolving source) and, on each
  `poll()`, resamples the current report, deduplicates claims to their latest gate directive,
  reconciles, and reports how each obligation's disposition changed since the previous poll
  (`resolved` / `regressed` / `new_pending` / `new_terminal` / `still_pending`). It keeps two
  verdicts separate: `global_verdict` is the **gate outcome** (PASS all-discharged **and**
  enforcement observed / FAIL any-failed / INCONCLUSIVE revision-pending **or** enforcement not
  observed) and `reconciled` is the reconciler's **structural integrity**
  (expected PASS). The temporal view closes the snapshot's gap — a revision-pending `UNRESOLVED`
  claim is watched **resolving** to `DISCHARGED`/`FAILED` across polls. Each poll also anchors to
  the report's tamper-evident `mcp_envelope_chain` via `chain_integrity` (`INTACT` / `BROKEN` /
  `NOT_MEASURED` / `ABSENT`); a `BROKEN` hash chain raises an evidence-not-tamper-evident error, and
  signature state is reported as `VERIFIED`/`NOT_MEASURED` only — the feed never claims the chain is
  "trusted" on hash-chain integrity alone. Boundary: the feed observes whatever the source reports;
  live wiring to a production gate remains external-review-gated.
- [`test_enas_gate_feed.py`](./test_enas_gate_feed.py) — a simulated evolving source: a pending
  claim is watched resolving over three polls (INCONCLUSIVE→PASS→FAIL) with `resolved` deltas;
  revisions dedup to the latest directive; empty/malformed polls stay INCONCLUSIVE without crashing;
  and a single poll of the captured real report reproduces the adapter's verdict.
- [`test_jcs.py`](./test_jcs.py) — the **cross-runtime canonicalization test**. It proves
  [`jcs.py`](./jcs.py) (Python, RFC 8785) and the Node canonicalizer produce byte-identical output
  across a value battery — including the cases naive sorted-key `json.dumps` gets wrong
  (`1.0`→`1`, `1e-07`→`1e-7`, `-0.0`→`0`). If Node is absent it falls back to hand-verified vectors.
- [`test_trusted_gates.py`](./test_trusted_gates.py) — the **Trusted fail-closed battery**. Seven
  adversarial records — a forged witness signature, a "witness" that is the producer, a missing
  freshness anchor, a stale one, a revoked producer key, absent revocation state, and a
  structurally-perfect witness — are committed as a **shared corpus** under
  [`fixtures/trusted_gates/`](./fixtures/trusted_gates/) and run through **both** verifiers. It
  asserts none reaches `Trusted`, that each lands on the expected class, and that Python and Node
  emit the **same class AND the same `trusted_withheld` reason set** (agreeing on the verdict while
  disagreeing on *why* is not parity). A drift guard re-derives every case from its fixed seeds and
  fails if the committed bytes diverged, so the corpus cannot rot away from its generator
  (`--write-fixtures` regenerates it). Node absent is reported as `NOT_RUN`, never as a pass.
- [`test_verifier_parity.py`](./test_verifier_parity.py) — the **verdict-parity test**. It runs both
  `verify.py` and `verify.mjs` over a battery of good and adversarial records (vendor-leak, bad verb,
  missing nested member, wrong type, empty `minItems`, non-`const`, tampered hash) and asserts the two
  verifiers reach the same verdict, matching the expected pass/fail. This is the runnable evidence
  behind the parity claim. (Node half skipped if `node` is absent.)

## Conformance vectors

The records in [`../examples/`](../examples/) are the test vectors — `neutral_record.json` (zero
vendor fields), `phionyx_profile_record.json` (vendor data under `profiles.phionyx`), plus
`eu_ai_act_record.json`, `key_trust_record.json`, `governance_record.json`,
`observability_record.json`, and the 5-record `chain.jsonl`. Their hashes and Ed25519 signatures are
**really computed**, not placeholders, and are reproducible via
[`../examples/regenerate.py`](../examples/regenerate.py) from a fixed, published test key.

## What this does not do

Canonicalization is **byte-exact RFC 8785** ([`jcs.py`](./jcs.py)); the *shipped reference RGE
packages*, however, still hash with sorted-key `json.dumps`, and aligning them to JCS is a separate
breaking change tracked in [`../STATUS.md`](../STATUS.md). `verify.py` validates with the full Draft-2020-12
engine (`jsonschema`) and is the authority for exhaustive schema validation; `verify.mjs` hand-codes
the same fixed core shape (closed top level, nested required members, value types, closed enums) and
is kept in lockstep with it. The two are tested to reach the same verdict on the example vectors and
on adversarial cases (vendor-leak, bad-verb, missing nested member, wrong type, tampered hash); they
agree on `integrity.current` byte-for-byte. `verify.mjs` exists to prove the format is checkable on a
second, dependency-free stack — not to be a general JSON Schema engine.

## Run

```bash
pip install jsonschema cryptography     # cryptography is optional: without it the hash recompute
cd ..                                   # still runs and the signature check is skipped
python3 conformance/validate.py             # full battery over the examples
python3 conformance/test_jcs.py             # Python vs Node canonicalization
python3 conformance/test_verifier_parity.py # verify.py and verify.mjs agree on every case
python3 conformance/enas_profiles.py         # 30 ENAS schemas / 115 expected outcomes
python3 conformance/verify.py  examples/chain.jsonl --pubkey examples/test_public_key.txt
node      conformance/verify.mjs examples/chain.jsonl --pubkey examples/test_public_key.txt
```
