# Stage-4 test contract

> Binding for all Stage-4 work. The key words MUST, MUST NOT, SHOULD, MAY are per BCP 14.
> Frozen normative input: [`../INTEGRITY.md`](../INTEGRITY.md) — read-only for this stage.

## 1. Normalized result contract

Each integrity verifier emits, per fixture, exactly this JSON object — the **normalized
result**:

```json
{"fixture_id": "...", "verdict": "PASS|PASS_WITH_CAVEAT|REJECT", "reasons": ["..."]}
```

- `verdict` semantics:
  - `PASS` — every check the fixture requires succeeded, with no caveat. `reasons` MUST be
    exactly `["OK"]`.
  - `PASS_WITH_CAVEAT` — cryptographic verification succeeded; one or more caveat codes apply
    (e.g. `WIRE_ALG_IGNORED`). Caveats MUST NOT be conflated with rejection in either
    direction.
  - `REJECT` — a required check failed. Fail-closed: the verifier performed no alternate-tag,
    alternate-version, alternate-suite, or v0.1-fallback attempt.
- `reasons` is a non-empty array of codes from the closed registry
  ([`REASON_CODES.md`](./REASON_CODES.md)), **deduplicated and sorted ascending by ASCII** —
  that is the deterministic ordering the comparator relies on.
- **A `REJECT` carries exactly ONE reason: the first decisive failure** under the pinned
  evaluation precedence of §2a. Two independent implementations finding the same cryptographic
  outcome MUST emit the same single code; "legitimate alternative reason sets" are exactly the
  parity leak this rule removes. (Multiple caveat codes on a `PASS_WITH_CAVEAT` remain
  possible and are sorted per the rule above.)
- No other fields. Debug, timing, environment, and library information MUST NOT appear in the
  result object (verifiers may log them elsewhere).

Each verifier writes one results file (`results_python.json` / `results_node.json`):
`{"results": {"<fixture_id>": {…normalized result…}, …}}`, keys sorted, trailing newline, no
metadata — byte-deterministic across runs.

## 2. Verifier obligations

Both integrity verifiers MUST, per the frozen INTEGRITY text:

1. derive tags purely from the artifact's declared (`airep_version`, `artifact_type`) and the
   witness tag version purely from the referenced head's `airep_version` — no search of any
   kind on failure (INTEGRITY §5, §4.3);
2. derive cryptographic suite behaviour **only** from the fixture-supplied verifier-accepted
   key bindings (producer binding, witness trust store); wire algorithm labels are informative
   only and MUST NOT select behaviour (INTEGRITY §3.2, §4.3);
3. for wire-label substitution with a cryptographically valid signature (A11a, A13a), apply
   the **deterministic reference behaviour**: verdict `PASS_WITH_CAVEAT` with reason
   `WIRE_ALG_IGNORED`. This is a reference-verifier *reporting contract* for parity
   measurement; it does not strengthen INTEGRITY §3.2's SHOULD/MAY into new normative wire
   semantics;
4. evaluate witness freshness **only** against the signed `witnessed_at`, against the
   fixture-supplied `now` and `freshness_window_seconds` (deterministic — no system clock);
   validate `witnessed_at` per INTEGRITY §4.2 time semantics;
5. reconcile the witness claim's `chain_id`, `sequence`, `current` against the resolved head
   artifact and fail on unresolved or mismatching heads (INTEGRITY §4.3);
6. treat mechanical subtraction per INTEGRITY §2 — the same canonical body MUST result whether
   the input carried `integrity.current`/`integrity.signature` or not (fixture S1 measures
   this; this is a test clarification, not an edit to frozen text);
7. never call, import, or shell out to the other verifier, and never read the other verifier's
   source or output.

## 2a. Evaluation precedence (reference diagnostic pipeline)

To make exact verdict/reason parity measurable, both integrity verifiers follow one pinned
diagnostic order. A step is evaluated only if every earlier step succeeded; **when a step
fails, its code is the single `REJECT` reason and no downstream step contributes a reason.**

- **Artifact path:**
  `version → tag registry → hash → producer binding → suite → signature → (optional wire-alg caveat)`
  i.e. `UNSUPPORTED_VERSION` → `UNREGISTERED_TAG` → `HASH_MISMATCH` →
  `KEY_BINDING_UNAVAILABLE` → `SUITE_UNSUPPORTED` → `SIGNATURE_INVALID` →
  `WIRE_ALG_IGNORED` (caveat, only on an otherwise-passing result).
- **Witness path** (fidelity-gate revision, 2026-08-22):
  `head resolve → head version → claim structure → head reconcile → witnessed_at validity → witness binding → suite → witness signature → freshness → (optional wire-alg caveat)`
  i.e. `WITNESS_HEAD_UNRESOLVED` → `UNSUPPORTED_VERSION` → `WITNESS_CLAIM_INVALID` →
  `WITNESS_HEAD_MISMATCH` → `WITNESS_TIME_INVALID` → `KEY_BINDING_UNAVAILABLE` →
  `SUITE_UNSUPPORTED` → `WITNESS_SIGNATURE_INVALID` → `WITNESS_STALE` →
  `WIRE_ALG_IGNORED` (caveat).

  Step semantics: **head version** — the resolved head's `airep_version` MUST be a version
  this integrity verifier implements (v0.2: exactly `"0.2"`); the closed tag registry is
  thereby enforced on the witness path too — a head declaring `0.3` with a witness genuinely
  signed under `0.3` tags is `UNSUPPORTED_VERSION`, never a cryptographic accept (A12 is
  unchanged: head `0.2` + signature under `0.3` tag → `WITNESS_SIGNATURE_INVALID`).
  **claim structure** — the presented claim's member set is exactly the closed five of
  INTEGRITY §4, and the four non-time members satisfy their pinned §4.2 constraints
  (`WITNESS_CLAIM_INVALID` on violation). Extra members are never silently ignored and never
  silently included in a rebuilt claim: structure fails first. After the structure step
  passes, the witness signature is verified over **JCS of the presented claim object** —
  which at that point has exactly the five members. **witness binding** — a trust-store entry
  is verifier-accepted only when it explicitly carries `trusted: true`; a missing or
  non-`true` `trusted` member is `KEY_BINDING_UNAVAILABLE` (fail closed, no default-trust).

This precedence is a **Stage-4 reference-reporting contract only**: it pins how the reference
integrity verifiers report, so parity is exact; it adds no guarantee, ordering, or semantics to
the AIREP wire format or to the frozen INTEGRITY text.

## 3. Independence mandate (authoring)

The two verifiers are independently authored, in separate fresh contexts. Each author may read
ONLY: the frozen `../INTEGRITY.md`, this `stage4/` contract directory (including the committed
fixture corpus), the Stage-3 public fixed vectors under `../vectors/` (inputs, plan, committed
outputs — NOT the other Stage-4 verifier), and its own language's pre-existing v0.1 JCS
implementation. Each authoring mandate MUST explicitly prohibit reading the other Stage-4
verifier's source or output. Evidence claims about this discipline use the bounded form of §6
— never "independence proved".

## 4. Parity comparator contract

A third program, independent of both verifiers (it shares no code with either beyond stdlib),
compares the two normalized results files **against each other and against the fixtures'
expected outcomes**. It MUST exit non-zero on any of:

- a fixture missing from either results file, or an extra fixture present in either;
- a verdict mismatch between the verifiers, a reason mismatch (missing reason, extra reason,
  or order violation after normalization), or any mismatch between the agreed result and the
  fixture's `expected` outcome;
- **any normalized-result shape violation**, in either file: an enclosing map key that does
  not equal the result's own `fixture_id`; a result object with any field beyond the three
  contract fields, or with a missing field; a `verdict` outside the three allowed values; a
  `reasons` array that is empty, contains duplicates, is not ASCII-ascending, or contains a
  code not in the closed registry; a `PASS` whose reasons are not exactly `["OK"]`; a `REJECT`
  with more than one reason (§1).

Its output is the parity manifest: per fixture, both verdicts, both reason lists, the expected
outcome, and the per-field agreement. The parity manifest additionally records the harness
assertions of [`FIXTURES.md`](./FIXTURES.md) §2a (A1 tag-divergence, S1 subtraction-path
equality) with their measured values.

The Stage-3 vector comparator (`../vectors/compare_vectors.py`) is additionally hardened in
this stage: an unexpected/extra field is a **failure** (non-zero exit), proven by a committed
deterministic negative invocation.

## 5. Gate rules

- **Implementation defect:** if the two verifiers disagree and the cause is a defect in one
  implementation, fix only that implementation; the frozen text is untouched.
- **Specification ambiguity:** if a fixture cannot be produced from the frozen INTEGRITY text,
  or a disagreement traces to a genuine byte ambiguity in that text, Stage 4 STOPS and reports
  **`STAGE1_REREVIEW_REQUIRED`** with the exact reading conflict. It is never silently
  resolved, never "fixed" as a test bug, and never patched into the frozen text from here.
- A rejection fixture MUST fail closed under both verifiers — any fallback observed is a
  failed fixture regardless of final verdict.

## 6. Evidence package

Stage-4 completion evidence comprises: the corpus manifest (fixture list + SHA-256 per fixture
file + corpus aggregate SHA-256); both results files and their SHA-256s; the parity manifest;
and an exact command transcript or a deterministic reproduction script that regenerates
results and parity from a clean checkout.

**Corpus aggregate SHA-256 — pinned rule:** for every fixture file, form the UTF-8 line
`"<lowercase-hex-sha256>  <relative-path>\n"` (two spaces; `<relative-path>` is the path
relative to `stage4/corpus/`, `/`-separated); sort the lines ascending by ASCII over the
relative path; the aggregate is the SHA-256 of the concatenation of the sorted lines. Any
other aggregate construction is non-conformant. The independence statement is bounded:
**separate-authoring process claim + repository-verifiable code separation + result parity** —
the phrase "independence proved" MUST NOT appear.

## 7. Commit sequence

1. **Contract commit** (this directory; no verifier code) — maintainer reviews the contract.
2. Corpus commit: fixture files generated per [`FIXTURES.md`](./FIXTURES.md) + corpus
   manifest; Stage-3 comparator hardening with its negative proof.
3. Two verifier commits (or one commit per independently authored verifier), then the parity
   comparator and evidence package.
4. Maintainer gate on the full evidence package.
