# AIREP v0.2 — Schema Fixture/Validation Contract (Stage 1: contract only)

> **Status: CONTRACT for maintainer review — no corpus and no validator code exists yet.**
> Sequence per the maintainer directive: this contract → review → corpus + harness. Every
> dependency choice and parity rule is pinned HERE, before implementation, so semantics are
> never defined backwards from two already-written programs.
>
> **Evidence boundary:** everything this phase produces is **schema-validation harness
> evidence** — proof that the five accepted schemas genuinely discriminate. It is NOT AIREP
> conformance evidence: no assurance class, no AIREP reason codes, no signature/hash validity,
> no evidence truth. The normalized outputs below are harness vocabulary only.

## 1. Engines (pinned dependency decision)

Two independent JSON Schema 2020-12 engines, on different language stacks:

| Engine | Pinned configuration |
|---|---|
| Python `jsonschema` (already in-repo) | `Draft202012Validator` + a local `referencing` registry holding the five schemas by `$id`; `format` NOT asserted (no format validation — the accepted design gives `format` no semantic weight) |
| Node `ajv` v8 (**new dev-dependency, decided here**) | `Ajv2020` (2020-12 dialect), `allErrors: true`, `validateFormats: false`, **`strict: false` — explicitly pinned** (maintainer: Ajv's compile-time strictness must not become an additional normative gate on schema semantics; the accepted schemas are still consumed byte-unchanged); the five schemas registered locally by `$id` — no network resolution |

The accepted schema files are consumed **byte-unchanged**. If either engine cannot load them
without modification, that is a finding to report, never a silent schema edit.

**Version pinning (maintainer hardening):** the implementation commit MUST record in the
evidence package the **exact resolved versions** of `jsonschema`, `referencing`, `ajv`, the
Python interpreter, and the Node runtime, and MUST make them reproducible via a dependency
lock/pin (e.g. a pinned requirements file + `package.json`/lockfile for the harness). "Latest
at the time" is not an evidence baseline.

## 2. Fixture envelope (harness object — never an AIREP wire schema)

One JSON file per fixture under `corpus/`, deterministic serialization (sorted keys, trailing
newline, no timestamps):

```jsonc
{
  "fixture_id": "control-neg-empty-instruction-id",
  "target_schema": "decision" | "control" | "execution" | "effect",
  "expected": "VALID" | "INVALID",
  "expected_error_scope": "/instruction_id",     // REQUIRED for INVALID: a JSON-Pointer prefix ("" = root)
  "expected_error_keywords": ["minLength"],      // REQUIRED for INVALID: acceptable JSON Schema keywords (may hold several where engines legitimately differ, e.g. propertyNames-related reporting)
  "description": "...",
  "instance": { ... }                             // the artifact instance under test
}
```

Fixture ids: `<family|core|cross>-<pos|neg>-<slug>`, lowercase, hyphenated, unique.

## 3. Normalized result contract

Per fixture, per engine, one normalized record:

```
fixture_id | schema | expected VALID|INVALID | actual VALID|INVALID | normalized violations [{instance_path, keyword}...]
```

- The normalized error unit is a **violation tuple** `{instance_path, keyword}` (maintainer
  hardening: a bare instance path is unreliable for `required` and closure keywords — engines
  typically report a deleted top-level member or an unknown member at the **root**, so a
  path-only rule cannot separate "failed for the right reason" from any other root failure).
  `normalized violations` = the sorted, deduplicated list of the engine's violation tuples
  (`[]` for VALID). Harness vocabulary only — never AIREP reason codes.
- Results files: `results_python_schema.json` / `results_node_schema.json`, shape
  `{"results": {"<fixture_id>": {"schema","expected","actual","violations":[{"instance_path","keyword"},...]}}}`,
  keys sorted, trailing newline, no metadata; byte-deterministic across runs.

## 4. Parity + correct-failure contract (pinned before implementation)

1. **Verdict parity (hard):** for every fixture, both engines MUST produce the same
   `actual` verdict, and it MUST equal `expected`. Any deviation ⇒ gate failure.
2. **Correct-failure matching (hard):** for every INVALID fixture, **each engine** MUST report
   at least one violation tuple satisfying **both** conditions simultaneously:
   `instance_path` starts with `expected_error_scope` **AND** `keyword` ∈
   `expected_error_keywords`. A fixture failing with the right verdict but the wrong
   scope/keyword is a gate failure. Canonical examples (maintainer-decided): top-level
   required deletion → scope `""` + keyword `required`; nested evidence `content_hash`
   deletion → `/evidence/0` + `required`; unknown top-level member → `""` +
   `unevaluatedProperties`; unknown `subject` member → `/subject` + `additionalProperties`;
   wrong artifact type → `/artifact_type` + `const`; empty `instruction_id` →
   `/instruction_id` + `minLength`; malformed digest → `pattern`; `sequence` bounds →
   `minimum`/`maximum`. Where engines legitimately report through different keywords (e.g.
   `propertyNames`-related paths), `expected_error_keywords` carries every acceptable keyword.
3. **Violation-set equality across engines is deliberately NOT required.** 2020-12 engines
   legitimately differ in error localization and keyword granularity (notably around
   `unevaluatedProperties` and composition); demanding exact cross-engine equality would
   define parity backwards from engine internals. Each engine's own violation output MUST be
   deterministic run-to-run, and both violation sets are recorded side-by-side in the parity
   manifest as evidence. Only rules 1–2 are hard gates.
4. A third comparator program (independent of both runner scripts' engine code) checks 1–3,
   fixture-set equality against the corpus, result-file shape (root exactly `{"results"}`,
   sorted keys, trailing newline, no extra fields), and the corpus manifest (per-file SHA-256
   + the same pinned aggregate rule as Stage 4: sorted `"<sha256>  <relative-path>\n"` lines).
   Exit 0 only when everything holds; committed negative proofs MUST show it failing on
   (a) a flipped `expected`, (b) an injected extra result field, and (c) **a correct-failure
   corruption**: a fixture whose verdict remains INVALID in both engines but whose declared
   scope/keyword is corrupted so no violation matches — proving the new correct-failure gate
   itself can fail, not only the verdict and shape gates.

## 5. Corpus matrix (minimum, per maintainer directive)

Positives: 1 canonical positive fixture per family (4) — every required member present,
optional members exercised at least once across the set (incl. `profiles` with a valid
namespaced key, `principal` with `established_by`, `digest_projection`, `redacted`,
`state_digest`, `issuer_id`, `chain_id` on a reference).

Negatives (each with `expected_error_scope`):

| Group | Cases |
|---|---|
| Required-member deletion | For EVERY required top-level member of every family (core 8 + family-specific), one deletion fixture — enumerated deterministically by the corpus builder |
| Type/const gates | wrong `artifact_type` (registered-but-other value); `airep_version` ≠ "0.2" |
| Closure (adversarial, per maintainer: composition metaschema-validity is not proof — **complete AD-07 coverage, measured not sampled**) | unknown top-level member per family (×4); AND at least one unknown-member negative for **every distinct closed surface**: `subject`, `principal`, `scope`, `integrity`, `integrity.signature`, `evidence_item`, `artifact_ref`, Decision `input`/`claim`/`directive`/`output`, Control `authority`, Effect `observed_state` |
| Lexical/pattern | invalid digest syntax (uppercase hex; wrong prefix; short hex); signature value wrong length and uppercase; invalid `sequence` bounds (−1; 2^53); invalid timestamp structural forms (offset instead of `Z`; month 13; missing seconds; 10-digit fraction); invalid namespaced ids (single segment; uppercase; leading digit segment) |
| Sub-object gates | `principal` present without `established_by`; `evidence[]` item missing `content_hash`; reference missing `record_id`; reference with an illegal extra member |
| Decision | empty `claim.basis` (`[]`); invalid `directive.verb`; malformed `digest_projection` |
| Control | empty `instruction_id` (`""`); invalid `control_event`; invalid `boundary_side`; `authority` missing `writable_by_controlled_system`; `authority` with unknown member |
| Execution | empty `instruction_id`; invalid `execution_event` (incl. the retired `completed`) |
| Effect | invalid `observer_relationship`; `execution_ref` malformed; `observed_state` missing `description` / with unknown member |
| Cross-family rejection | each family's canonical positive instance presented to each OTHER family's schema — all 12 pairs, all INVALID (scope: `/artifact_type`) |

The corpus builder is deterministic (two runs byte-identical), enumerates the
deletion-negatives programmatically from the schemas' own `required` lists (no hand-kept
duplicate list to drift), and emits the corpus manifest. Valid instances are constructed by
the builder; where sealed-looking values are needed (digests, signatures) they are
**syntactically valid placeholder values** — this harness measures schema discrimination, not
cryptography, and its fixtures are never presented as cryptographically valid artifacts.

## 6. Determinism and evidence package

- Builder, both runners, and the comparator: no timestamps, no randomness, no network; two
  consecutive full runs MUST be byte-identical (hash-compared in the reproduction script).
- Evidence package: corpus manifest (+ aggregate), both results files (+ SHA-256s), the parity
  manifest (per-fixture table incl. both engines' violation sets), the **three** committed
  negative proofs (§4.4a–c), the **exact resolved versions** of `jsonschema`, `referencing`,
  `ajv`, Python, and Node with their lock/pin files (§1), and one reproduction script running
  builder → both engines → comparator from a clean checkout.
- Language ceiling: "the five schemas discriminate the measured corpus as expected under two
  independent engines" — nothing stronger; no "schemas verified/complete" claims.

## 7. Out of scope (this phase)

Producers; conformance classes and AIREP reason codes; migration tooling; integrity/witness
cryptography (already covered by the WP-α01 harness); any schema edit (a schema defect found
by the corpus is a finding for the maintainer, not a silent fix).
