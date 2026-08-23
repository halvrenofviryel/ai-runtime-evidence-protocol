# WP-α01 Stage-4 — Evidence package

> Final Stage-4 evidence per STAGE4_CONTRACT §6. Terminology: the two programs are **AIREP
> v0.2 WP-α01 integrity verifiers** (integrity-construction verifiers) — not full v0.2
> conformance verifiers; the fixtures are construction/adversarial fixtures, not
> "v0.2-conformant artifacts". Every claim below states its evidence; the documentation
> ceiling is "observed / measured", never "verified/trusted" beyond what ran.

## 1. Artifacts and digests (measured 2026-08-23)

| Artifact | Value |
|---|---|
| Corpus | 39 fixtures under `corpus/`; per-file SHA-256 in `corpus_manifest.json` |
| Corpus aggregate SHA-256 (pinned rule) | `52cc00a752df169029e00db5363cc62e1527ab12c6905f0e7ba5a6d8feb2c2c0` — recomputed independently by `parity_compare.py` |
| `results/results_python.json` | sha256 `1a53720e4cc2ae8caf29c114dd8d9b0ca9f2608749fa5428499a143bd8b8e9c0` |
| `results/results_node.json` | sha256 `0065a2127e09dce327242a96e700d24b2787ae033f5488d844b187ddf5e633aa` |
| Parity manifest | [`PARITY_MANIFEST.md`](./PARITY_MANIFEST.md) — per-fixture table of both verdicts, both reason lists, expected outcome, and status |
| Reproduction | [`reproduce.sh`](./reproduce.sh) — builder(×2) → both verifiers(×2 each) → comparator → A5 auxiliary check; nonzero on any failure |

## 2. Parity result

`parity_compare.py` (independent of both verifiers and **stdlib-only** per STAGE4_CONTRACT §4
— it imports nothing beyond the Python standard library; the A1/S1 re-measurements use its
own minimal, fail-closed canonicalizer for the restricted evidence-body value domain, so the
comparator is a genuinely third implementation surface: verifier A → verifier B → separate
comparator) — **exit 0: FULL PARITY + EXPECTATION EQUALITY across 39 fixtures**:

- Python ↔ Node exact normalized `verdict`/`reasons` equality per fixture;
- agreed results equal each fixture's `expected` outcome (compared here only — the verifiers
  never consult `expected`);
- normalized-result shape enforced (three contract fields; enclosing key = `fixture_id`;
  closed reason registry; dedup + ASCII-ascending; `PASS` = `["OK"]`; `REJECT` = one reason;
  **verdict-class enforcement** per REASON_CODES);
- missing/extra fixture, missing/extra/unsorted/duplicate/unregistered reason, and extra
  result fields are gate failures;
- the **results-file envelope** is gated strictly: root object with exactly the key
  `results`, no metadata, results map keys ASCII-sorted in the serialized file, no duplicate
  keys anywhere, trailing newline;
- **A1 tag divergence** recomputed from primitives (both currents re-derived from the A1-1
  body; distinct; equal to the manifest record);
- **S1 subtraction** re-performed by the comparator on the sealed artifact: canonical bytes
  compared **byte-for-byte** against `S1_probe.canonical_body_hex` (not digest equality
  alone); recomputed `current` equals the probe and the sealed value;
- numeric lexemes (`1.0`, `1e0`, `-0`) confirmed present in the on-disk fixture bytes;
- corpus aggregate recomputed per the pinned rule.

## 3. Negative controls (the gates can fail)

- Stage-3 vector comparator: committed proof `../vectors/prove_extra_field_gate.py` — exit 0
  on committed outputs, exit 1 on an injected extra field (run: PROOF OK).
- Stage-4 parity comparator (verdict tamper): session-run control — flipping one fixture's
  verdict in a copy of `results_python.json` produced exit 1 with the mismatch named;
  restoring the file (byte-identical, sha256 re-checked) returned exit 0.
- Stage-4 parity comparator (envelope): committed proof [`prove_envelope_gate.py`](./prove_envelope_gate.py)
  — exit 0 on the committed envelopes; exit 1 on an injected top-level `metadata` member,
  with the violation named in the emitted manifest (run: PROOF OK).

## 4. A5 auxiliary check (freeze intact)

**The genuine v0.1 record value is embedded** in `corpus/A5-1.json` **and remains accepted by
the v0.1 verifier**: the nested artifact was extracted and `spec/airep/v0.1/conformance/verify.py`
run on it — exit 0 (measured; also part of `reproduce.sh` step 4). No claim of exact original
byte embedding is made: the builder parses and re-serializes the v0.1 JSON value; v0.1
canonical verification is serialization-independent, which is what the measurement shows.

## 5. Bounded independence statement

What is claimed, and its evidence class:

- **Separate-authoring process claim:** the two verifiers were authored by two isolated
  agent contexts under the recorded mandates (`mandates/AUTHORING_MANDATE_{python,node}.md`),
  which forbade reading `build_corpus.py`, the Stage-3 generators/comparators, the other
  verifier's source/output, and every fixture's `expected` member.
- **Repository-verifiable code separation:** the two implementations share no code, use
  different lexeme-capture techniques (Python: `parse_int`/`parse_float` lexeme-carrying
  subclasses; Node: a strict RFC 8259 recursive-descent parser with a symbol-keyed side
  table), and neither imports, calls, or shells out to the other.
- **Result parity:** measured by the separate, independently implemented parity comparator
  (§2). It is not a third *party* — it was written within this project; AD-15 third-party
  independence remains future work, per §6.

**Process disclosure (recorded verbatim):** the Python authoring session had limited direct
expected-field visibility for five fixtures (whole-file reads during input-shape inspection);
the author reports non-use; the runtime verifier deletes `expected` before evaluation. The
Node session inspected fixtures via `jq 'del(.expected)'`. Accordingly, **no
"expected-blind authoring" claim and no "independence proved" claim is made** — the evidence
is the bounded triple above.

## 6. What this evidence does NOT establish

- It does not make the two verifiers full v0.2 conformance verifiers (schemas, profiles, and
  class semantics do not exist yet).
- It does not establish third-party independence in the AD-15 sense (both authoring contexts
  and the harness were operated within this project); the AD-15 independence gate remains
  future work for v0.2 as a whole.
- It does not assert the truth of any fixture's recorded content — the malicious-producer
  boundary of the frozen construction is unchanged.
