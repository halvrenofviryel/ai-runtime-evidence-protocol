# AIREP v0.2 class-verification — C1 adversarial coverage extension

> **Status: fixture/corpus authoring only.** This document and the artefacts it describes add
> coverage to the frozen class-verification corpus. They change no contract clause, no schema,
> no frozen construction, and no existing expected value.
>
> **Provenance of expected values — stated at its exact strength.**
> The 45 C0 cases are a **verbatim transcription** of the `CLASS_VERIFIER_CONTRACT.md` §7
> appendix. The 15 C1 cases and the 15 probes are **manually derived from cited normative
> clauses, without executing evaluation logic**. Every C1 derivation chain is written out below
> in the form *input/tamper → contract clause (cited) → prerequisite/dependency rule → expected
> process exit, or expected class/channel result*, so it can be audited later by someone who was
> not present. No class, reason set, observer value or exit code below was obtained by running a
> class verifier, a comparator, or any ladder-evaluation code.
>
> **Bounded provenance statement.** This extension was authored without reading, listing,
> executing or otherwise inspecting either class verifier's source or output, or any comparator's
> source or output. Neither is present in the authoring snapshot. The only executable inputs used
> were `build_class_corpus.py` (the third-context corpus harness) and
> `../../v0.1/conformance/jcs.py` (the repository's own RFC 8785 canonicalizer, loaded by its
> committed relative path). Cryptographic values — digests, signatures, canonical bytes, UTF-8
> byte sequences — are of course computed; **verdicts are reasoned from the specification and
> written down by hand.**

## 1. What C1 adds

| Artefact | Location | Count | Scored? |
|---|---|---|---|
| C1 verdict cases | `corpus/cases/<CASE_ID>/` | 15 | yes — each carries `expected.json` |
| C1 case index | `corpus/c1_case_index.json` | 1 | index only, no expected values |
| Batch-ordering expectation | `corpus/ordering/expected_verdict_order.json` | 1 | ordering only |
| CLI / process-exit probes | `corpus/probes/<PROBE_ID>/` | 15 | **no** — process behaviour only, no `expected.json` anywhere under `probes/` |
| Probe index | `corpus/probes/probe_index.json` | 1 | index only |

Probes live **outside `corpus/cases/`** and carry **no `expected.json`**, so a scoring harness
that enumerates verdict cases cannot mistake them for scored cases. They assert only *process*
behaviour: exit code, whether a results file was emitted, and which paths must not be created.

### Changed / new files

**Modified (2):**

- `build_class_corpus.py` — extended in the existing style; C0 construction untouched.
- `corpus_manifest.json` — regenerated for the extended corpus (see §3).

**New (1 document + 151 corpus files):**

- `C1_COVERAGE.md` (this file)
- `corpus/c1_case_index.json`, `corpus/ordering/expected_verdict_order.json`,
  `corpus/probes/probe_index.json`
- 89 files under `corpus/cases/{ORD1,ORD2,CTL1,NG1,LEX1,LEX2,LEX3,TI1,TI2,OBX1,OBX2,MC1,MC2,MC3,MC4}/`
- 60 files under `corpus/probes/`

**Unchanged (265):** every pre-C1 corpus file — `corpus/case_index.json` and all
`corpus/cases/<C0 case id>/*` — is byte-for-byte identical. Proof in §2.

## 2. C0 immutability — machine-checked, not asserted

Three independent proofs, all reproducible from the repository:

**(a) Per-file digest identity against the previous manifest.** Every one of the 265 pre-C1
paths appears in the regenerated `corpus_manifest.json` with the *same* SHA-256 it carried in the
pre-C1 manifest, and each still hashes to that value on disk. No pre-C1 path was removed.

**(b) C0 aggregate identity, enforced inside the builder.** `build_class_corpus.py` pins

```
C0_AGGREGATE_SHA256_PRE_C1 = 55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4
C0_FILE_COUNT_PRE_C1       = 265
```

— the pre-C1 manifest's `aggregate_sha256`, which covered exactly the C0 path set
(`case_index.json` + `cases/<C0 case id>/*`). Every build re-aggregates that subset under the
**same** `aggregate_rule` and asserts equality. Assertions
`c0-preservation:file-count` and `c0-preservation:aggregate-unchanged` fail the build with
`MAINTAINER_FINDING` (exit 3) if a single C0 byte moves. The regenerated manifest records the
comparison in its `c0_preservation` block.

**(c) Direct byte comparison.** A snapshot of the pre-C1 `corpus/` tree was diffed file-by-file
against the rebuilt tree across all 265 C0 paths: zero byte differences, zero digest differences,
zero removals.

**Semantics preserved too, not only bytes:** the C0 45 expected values live in
`EXPECTED_APPENDIX`, which is untouched; C1 values live in a **separate** dict `EXPECTED_C1`, and
the builder asserts the two key sets are disjoint (`appendix:c0-c1-disjoint`) — C1 can add a
case but can never redefine one. `corpus/case_index.json` remains the C0 index verbatim; C1 cases
are indexed in `corpus/c1_case_index.json` precisely so that no pre-existing file changes.

> **Harness note.** Because the indexes are split, a batch harness must either enumerate
> `corpus/cases/` directly (recommended — C0 and C1 cases are structurally identical and scored
> identically) or read **both** index files. The alternative — appending C1 rows to
> `case_index.json` — was rejected because it would have changed a pre-C1 file's bytes.

## 3. Manifest and aggregate rule

The regenerated `corpus_manifest.json` covers **416** files (265 C0 + 151 C1) and follows the
existing `aggregate_rule` **unchanged**:

> sha256 of the concatenation, in ASCII-ascending order of corpus-relative path strings, of UTF-8
> lines `<sha256>  <relative-path>\n`, where `<sha256>` is the recorded digest for that path. The
> sort key is the relative path, **NOT** the assembled line and **NOT** the hash prefix; each line
> is built **AFTER** the sort. Paths are relative to `class-verification/corpus/`.

Every C1 path is pure ASCII (the non-ASCII identifiers of the ordering fixture live *inside*
`record_id` values, never in a path), so ASCII-ascending path order is unambiguous.

- extended `aggregate_sha256` = `5b05318396002fee1adcf95aeeedfbe0d6e5f5ebf8759d0737276f7eba7b9b95`
- C0-subset aggregate = `55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4` (unchanged)

**Determinism.** Two consecutive builds produce byte-identical `corpus/` trees and byte-identical
`corpus_manifest.json`. Sources of determinism are unchanged: fixed inputs, published TEST-ONLY
seeds, RFC 8032 Ed25519 (deterministic signatures), `sort_keys=True` JSON with a trailing newline.
The one new emission mechanism — the raw source-token substitution used by LEX1–LEX3 — is a
deterministic regex rewrite of the serialized text.

## 4. Required-item → coverage map

| # | Required surface | Covered by | Kind |
|---|---|---|---|
| 1 | Non-ASCII multi-verdict ordering separating UTF-8 byte order from UTF-16 code-unit order | `ORD1`, `ORD2` + `corpus/ordering/expected_verdict_order.json` | verdict cases + ordering fixture |
| 2 | Duplicate `(chain_id, record_id)` tuple → exit 1, no results file | `PRB-DUP-TUPLE` | probe |
| 3 | Stage-0 schema-invalid; Stage-1 hash-invalid | `PRB-SCHEMA-INVALID`, `PRB-HASH-INVALID` | probes |
| 4 | exit 1 / exit 2 / `--help` | exit 1: `PRB-DUP-TUPLE`, `PRB-SCHEMA-INVALID`, `PRB-HASH-INVALID`, `PRB-REQUEST-UNPARSEABLE`, `PRB-HEADWITNESS-NULL`, `PRB-HEADWITNESS-UNKNOWN-MEMBER`, `PRB-HEADREF-UNKNOWN-MEMBER` · exit 2: `PRB-CLI-REQUEST-WITH-OUT`, `PRB-CLI-CORPUS-NO-OUT`, `PRB-CLI-REQUEST-AND-CORPUS`, `PRB-CLI-NOW-STRUCTURAL`, `PRB-CLI-NOW-NOT-GREGORIAN`, `PRB-CLI-WINDOW-NEGATIVE`, `PRB-CLI-WINDOW-NONINTEGER` · `--help`: `PRB-CLI-HELP` | probes |
| 5 | Witness numeric lexical forms (`1e0`, `1.0`, `-0`) | `LEX1`, `LEX2`, `LEX3` | verdict cases |
| 6 | Invalid `witnessed_at` with no clock supplied | `TI1` (+ paired control `TI2`) | verdict cases |
| 7 | Effect wire `independent` over an Execution that fails authentication ⇒ effective `unknown` | `OBX1`, `OBX2` | verdict cases |
| 8 | Malformed operator-container / closure variants | `MC1`, `MC2`, `MC3`, `MC4` | verdict cases |
| 9 | Control-family Authenticated positive | `CTL1` | verdict case |
| 10 | Witnessed head with `sequence > 0` and `length > 1` | `NG1` | verdict case |

### Registry coverage delta

All 31 reasons in the closed §5 registry are now exercised. Before C1, exactly one was not:
**`witness-time-invalid` had zero coverage across all 45 C0 cases** (see FINDING F-1). `TI1`/`TI2`
close it.

## 5. Derivation chains — C1 verdict cases

Clause references are to `CLASS_VERIFIER_CONTRACT.md` unless prefixed `INTEGRITY` (→
`../INTEGRITY.md`) or `DESIGN` (→ `../conformance-design/CONFORMANCE_CLASS_DESIGN.md`).
Every case applies **one** tamper; all other inputs are clean and supplied.

---

### ORD1 / ORD2 — item 1 (UTF-8 vs UTF-16 batch ordering)

**Input.** Two clean Decision Receipts in one chain (`chain_id = cv-chain-ord`), differing only
in `record_id`; all operator inputs supplied; no `head_witness`.

**Derivation of the verdict.** The artifact is tamper-free, so the shape is the **pinned §7 row
P1**, applied to a differently-identified artifact:

1. tamper-free artifact → §3 stages 2–4 clean → §3 stage 5 → `class = AIREP-Authenticated`
2. no `head_witness` in the request → §3 stage 6 → `no-witness-supplied`; §5 types it
   *witnessed / WITHHELD* → `witnessed_withheld = ["no-witness-supplied"]`
3. §4 dependency table: stages 7–10 all require `head_witness` present or stage 6 clean →
   **no further reason in any channel**
4. non-Effect artifact → §2 → `observer_assessment = "not_applicable"`

**Derivation of the ordering expectation.** §2 (Results file): verdicts are sorted by
`(chain_id, record_id)` under *unsigned lexicographic order over each string's UTF-8 byte
sequence, with no Unicode normalization*. Both `chain_id`s are equal, so the pair is separated by
`record_id` alone. Bytes, written out:

| case | `record_id` | UTF-8 bytes | final scalar | final scalar UTF-8 | final scalar UTF-16BE |
|---|---|---|---|---|---|
| `ORD2` | `cv-rec-ord-` + U+FF00 | `63 76 2d 72 65 63 2d 6f 72 64 2d ef bc 80` | U+FF00 | `ef bc 80` | `ff00` |
| `ORD1` | `cv-rec-ord-` + U+10000 | `63 76 2d 72 65 63 2d 6f 72 64 2d f0 90 80 80` | U+10000 | `f0 90 80 80` | `d800 dc00` |

The strings share the prefix `cv-rec-ord-`; the first differing **byte** is `0xEF` against
`0xF0`, and `0xEF < 0xF0`. **Required order: `ORD2` before `ORD1`.**

In UTF-16 code units the first differing **unit** is `0xFF00` against the high surrogate
`0xD800`, and `0xD800 < 0xFF00` — a native JavaScript string comparison yields **`ORD1` before
`ORD2`**, the opposite order, and a detectable failure.

*Verified empirically before being relied on*: the UTF-8 byte comparison and the UTF-16BE
code-unit comparison of these two exact strings were computed and disagree. Builder assertions
`ordering:discriminating-pair-utf8-order`, `ordering:discriminating-pair-utf16-would-invert`,
`ordering:discriminating-pair-same-chain` and
`ordering:corpus-directory-order-is-the-wrong-order` re-check this on every build.

**Stated at its exact strength.** For *all* valid Unicode scalar values, code-point lexicographic
order and UTF-8 byte lexicographic order agree — UTF-8 is order-preserving by construction. So
this fixture is a **naive-JavaScript-sort detector**, not symmetric cross-runtime coverage: UTF-16
code-unit order is the only one of the three orders that genuinely diverges, and it is exactly the
requirement's real runtime risk. The corpus-directory order (`ORD1`, `ORD2`) deliberately *agrees*
with the wrong (UTF-16) order, so a verifier that emits verdicts in directory order fails the same
gate.

**Unicode validity.** Both `record_id`s end in a valid Unicode **scalar** value. No lone surrogate
appears anywhere in this corpus: a lone surrogate is not UTF-8 encodable and would raise a separate
Unicode-validity question that is not what this fixture tests.

---

### CTL1 — item 9 (Control-family Authenticated positive)

**Input.** A clean Control Evidence artifact (`artifact_type: "control"`, hashed and signed under
the `AIREP/0.2/hash/control` and `AIREP/0.2/sig/control` tags per INTEGRITY §1.2/§5); all operator
inputs supplied; no `head_witness`.

**Chain.** Family membership does not change the ladder — **DESIGN §7**: *"Core and Authenticated
apply to every artifact family identically (per-artifact assurance)."* → §3 stages 0–5 evaluate
exactly as for P1 → `AIREP-Authenticated`; §3 stage 6 with no witness → `no-witness-supplied`
(§5: witnessed / WITHHELD); §4 suppresses stages 7–10; §2 → non-Effect → `not_applicable`.

**Expected** = the pinned §7 **P1** row: `AIREP-Authenticated`, `— / — / —`,
`— / no-witness-supplied`, `not_applicable`.

This is the corpus's first control-family artifact; before C1 the corpus exercised
decision/execution/effect only (see FINDING F-2).

---

### NG1 — item 10 (Witnessed non-genesis head)

**Input.** A two-artifact chain: predecessor at `sequence 0` supplied as a related artifact, and
the primary head at `sequence 1` with `integrity.previous` = the predecessor's `current`. The
signed claim carries `sequence: 1` and `length: 2`. All operator inputs supplied; witness clean,
independent, fresh.

**Chain.**

1. stages 2–4 clean → §3 stage 5 → Authenticated
2. §9 R-2 **6a**: the claim is the closed five-member set with correct member types, and both
   numeric source tokens (`1`, `2`) match `^(0|[1-9][0-9]*)$` (E-1). INTEGRITY §4.2 admits
   `sequence` as any non-negative integer and `length` as any positive integer — *"the total
   artifact count of the chain at witness time, the referenced head included"*, i.e. **2**. ✔
3. §9 R-2 **6b**: `head_ref` resolves uniquely to the **primary** (§0 must-be-primary rule) and
   INTEGRITY §4.3 reconciliation on `chain_id`/`sequence`/`current` holds. ✔
4. §9 R-2 **6c**: `witnessed_at` is a valid Gregorian UTC datetime. ✔ → stage 6 clean
5. §3 stage 7: witness binding resolved, trusted, `active`. ✔
6. §3 stage 8 + DESIGN §3 three-condition gate: distinct binding identities, distinct resolved
   keys, pair listed in `independent_pairs`. ✔
7. §3 stage 9: witness signature valid over the INTEGRITY §4 preimage. ✔
8. §3 stage 10 + DESIGN §5: `abs(now − witnessed_at) = 1800 ≤ 3600`. ✔
9. §3 stage 11: 6–10 clean **and** Authenticated earned → `class = AIREP-Witnessed`
10. §2 invariant: `class == AIREP-Witnessed` ⇒ all four failure/withheld arrays empty. ✔

**Expected** = the pinned §7 **P2** row: `AIREP-Witnessed`, all five channels empty,
`not_applicable`.

*Note:* `length` is deliberately **not** reconciled by any clause — INTEGRITY §4.3 names only
`chain_id`, `sequence` and `current`. NG1 therefore tests that a non-genesis `length > 1` is
*accepted*, not that it is counted.

---

### LEX1 / LEX2 / LEX3 — item 5 (E-1 source-token rule)

**Input.** A clean artifact and an otherwise perfect witness, except that one claim number is
written with a **source spelling** that is semantically correct but lexically illegal:

| case | member | source token in `request.json` | semantic value | correct value |
|---|---|---|---|---|
| `LEX1` | `length` | `1e0` | 1 | 1 |
| `LEX2` | `length` | `1.0` | 1 | 1 |
| `LEX3` | `sequence` | `-0` | 0 | 0 |

The witness signature is **genuine and valid**: RFC 8785 / ES6 number serialization renders `1e0`,
`1.0` and `-0` to exactly the digits `1`, `1` and `0`, so the wire claim and the signed claim
canonicalize to identical bytes. Builder assertions
`<case>:wire-claim-canonicalizes-identically`, `<case>:raw-token-parses-to-semantic-value` and
`<case>:raw-token-violates-E1-grammar` check all three properties. This is precisely the defect a
post-parse integer check **cannot** see.

**Chain.**

1. stages 2–4 clean → §3 stage 5 → Authenticated
2. §9 **retained E-1**: *"the source spelling must match `^(0|[1-9][0-9]*)$`; a post-parse integer
   check is insufficient, and a violation is `witness-claim-invalid`."* `1e0`, `1.0` and `-0` all
   fail that grammar.
3. §9 **R-2 step 6a** places the E-1 source-token rule inside claim structural + lexical validity,
   and pins: *"on failure, `witness-claim-invalid` alone; 6b and 6c do not run."*
4. §5 types `witness-claim-invalid` as *witnessed / FAILURE* → `witnessed_failures`
5. §4 dependency table + its worked consequence — *"a malformed witness claim (stage 6) ⇒ **no**
   stages 7–10 reasons at all"* → every other witnessed channel entry is suppressed, including
   any freshness reason
6. §2 invariant: non-empty `witnessed_failures` ⇒ `class != AIREP-Witnessed`; Authenticated was
   earned at stage 5 → `class = AIREP-Authenticated`
7. §2 → non-Effect → `not_applicable`

**Expected (each):** `AIREP-Authenticated`, `— / — / —`, `witness-claim-invalid / —`,
`not_applicable` — the same shape as the pinned §7 **WM1** row.

---

### TI1 / TI2 — item 6 (Gregorian-invalid `witnessed_at`, clock-independence)

**Input.** Identical in both cases: a clean artifact, a genuinely signed five-member claim that
resolves and reconciles, whose `witnessed_at` is `2026-02-30T12:00:00Z` — conformant to the fixed
`YYYY-MM-DDTHH:MM:SSZ` format, but February 30 is not a Gregorian date. The **only** difference is
the clock: `TI1` supplies **no** clock input; `TI2` supplies `--now` and `--freshness-window` in
full.

**Chain (identical for both).**

1. stages 2–4 clean → §3 stage 5 → Authenticated
2. §9 R-2 **6a** passes: closed five-member set, correct types, both numeric source tokens legal
3. §9 R-2 **6b** passes: unique resolution to the primary; reconciliation holds (INTEGRITY §4.3)
4. §9 R-2 **6c**: *"`witnessed_at` format + Gregorian validity ⇒ on failure,
   `witness-time-invalid`. **Clock inputs play no part in this check.**"* INTEGRITY §4.2:
   *"An invalid calendar date (e.g. February 30) MUST be rejected."* → `witness-time-invalid`
5. §5 types `witness-time-invalid` as *witnessed / FAILURE* → `witnessed_failures`
6. §4 dependency table: stage 7 requires *stage 6 clean* → no reason; stage 8 requires stage 7
   clean → no reason; stage 9 requires stage 7 clean → no reason; stage 10 requires
   **stage 6 clean *and* clock inputs present** → **no reason**
7. **The load-bearing consequence for TI1:** because stage 10's prerequisite includes *stage 6
   clean*, `freshness-inputs-missing` MUST **NOT** appear even though no clock was supplied. §4's
   reason-dependency rule is explicit: *"A gate whose own required prerequisite is absent or
   failed emits no derivative reason at all."*
8. §2 invariant → `class = AIREP-Authenticated`; §2 → non-Effect → `not_applicable`

**Expected (both):** `AIREP-Authenticated`, `— / — / —`, `witness-time-invalid / —`,
`not_applicable`.

TI1 and TI2 are pinned to the **same** expected value; that pairing *is* the machine-checkable
statement of R-2's clock-independence. `PRB-CLI-NOW-NOT-GREGORIAN` carries the **same** bad date
on the **other** surface — as `--now` — where §1.4 makes it exit 2. Same string, two contract
surfaces, two different required behaviours.

---

### OBX1 / OBX2 — item 7 (wire `independent` over a non-Authenticated Execution)

**Input.** An Effect artifact declaring `observer_relationship: "independent"` on the wire, whose
`execution_ref` resolves uniquely to an Execution artifact that is schema-valid, hash-consistent
and correctly signed — but which cannot reach Authenticated in its own right:

- `OBX1`: the executor binding is present and trusted, but the revocation snapshot marks it
  **`revoked`**.
- `OBX2`: `producer_bindings` carries **no entry** for the Execution's wire producer id.

The Effect's own producer binding is clean, trusted and `active` in both cases. (§7 **OB4**
already covers the third route — an invalid Execution signature; these two cover the other two.)

**Chain.**

1. The **primary Effect** artifact: stages 2–4 clean → §3 stage 5 → `AIREP-Authenticated`
2. §0 observer path: the verifier resolves the Execution artifact through `execution_ref`, then
   *"verifies that Execution artifact to Authenticated in its own right (its schema, frozen hash
   recomputation, producer binding, **revocation snapshot** and signature)"*
3. `OBX1`: DESIGN §4 — *"A `revoked` binding cannot earn any class contribution … Producer
   binding revoked ⇒ **Authenticated cannot be earned**; the ceiling is Core"* → the Execution
   does not reach Authenticated.
   `OBX2`: DESIGN §2 — *"No binding available for the required key ⇒ Authenticated is **not
   evaluable** … never silently as passed"* → the Execution does not reach Authenticated.
4. §0: *"one that does not itself reach Authenticated, yields `observer_assessment = "unknown"` —
   never `independent`"*; §3 and DESIGN §7 say the same. §9 **E-3** confirms a wire `independent`
   is never the effective assessment unless the gate is satisfied → `observer_assessment =
   "unknown"`
5. §0: *"The primary Effect artifact's own class is unaffected by this."* DESIGN §7: *"the
   artifact's class does not drop because of it"* → `class` stays `AIREP-Authenticated`, and no
   reason enters any authenticated channel
6. no `head_witness` → §3 stage 6 → `no-witness-supplied` (§5: witnessed / WITHHELD); §4
   suppresses stages 7–10

**Expected (both):** `AIREP-Authenticated`, `— / — / —`, `— / no-witness-supplied`, `unknown` —
the same shape as the pinned §7 **OB4** row.

---

### MC1 — item 8 (unknown member at the top level of the binding store)

**Input.** The §1.1 binding store carries one member foreign to the document
(`"note": …`). Artifact, witness, revocation snapshot, independence policy and clock are all
clean and supplied.

**Chain.**

1. §1 preamble: *"All are local JSON; unknown members are rejected (fail closed)."* §9 **E-4**:
   *"unknown members anywhere in an operator document are fail-closed to `*-binding-malformed` /
   `independence-policy-malformed` / `*-revocation-state-malformed`."* → the binding **store** is
   malformed.
2. §9 **R-3**: structural malformation precedes the semantic trust decision → the reason is
   `*-binding-malformed` (WITHHELD), never `*-binding-not-trusted`.
3. **Producer path.** §3 stage 2 has no prerequisite (§4 dependency table) and, per §9 **R-8**,
   *"The same malformed store may still independently produce `producer-binding-malformed` on the
   producer path — that path resolves its own wire id and **does reach the gate**."* → §5 types it
   *authenticated / WITHHELD* → `authenticated_withheld = ["producer-binding-malformed"]`
4. §4 dependency table: stage 3 and stage 4 both require *producer binding accepted* → no
   revocation reason, no signature reason.
5. **Witness path.** §9 R-2: stage 6 is clean (valid claim, unique primary resolution,
   reconciliation, valid `witnessed_at`). §9 **R-8 7a**: `witness_id` is present and a string →
   clean. §9 **R-8 7b**: *"The store, the `witness_bindings` map and the referenced entry are
   evaluated here, under R-3: a **malformed store** or entry ⇒ `witness-binding-malformed`."* →
   §5 types it *witnessed / WITHHELD* → `witnessed_withheld = ["witness-binding-malformed"]`
6. §4 dependency table: stage 8 requires witness binding accepted → no independence reason;
   stage 9 requires stage 7 clean → no witness-signature reason; stage 10 requires **stage 6 clean
   and clock inputs present** — both hold, so freshness *does* run and passes
   (`1800 ≤ 3600`) → no reason.
7. §2 consistency invariant: *"a non-empty `authenticated_failures` **or**
   `authenticated_withheld` ⇒ `class == AIREP-Core`"* → `class = AIREP-Core`
8. §2 → non-Effect → `not_applicable`

**Expected:** `AIREP-Core`, `— / producer-binding-malformed / —`,
`— / witness-binding-malformed`, `not_applicable`.

Structurally this is the §7 **PI1** pattern (a Core verdict carrying one withheld reason per tier,
with independence and witness-signature suppressed by §4).

---

### MC2 — item 8 (required container absent from an operator document)

**Input.** The §1.2 independence policy document is well-formed except that the required
`non_independent_pairs` container is **missing**. Everything else clean and supplied, witness
clean.

**Chain.**

1. §1.2 defines the document as carrying both `independent_pairs` and `non_independent_pairs`;
   §9 **E-4**: *"operator-document container members are **required**"* → the document is
   malformed → `independence-policy-malformed`.
2. §5 types `independence-policy-malformed` as *witnessed / WITHHELD* → `witnessed_withheld`.
3. §4 dependency table: stage 8 requires producer binding accepted **and** witness binding
   accepted **and** independence policy present. All three hold — the policy *is* supplied, it is
   merely malformed — so the gate is reached and emits its reason (this is exactly the §7
   **IND5** shape, where a both-lists policy yields the same WITHHELD reason).
4. Stage 9 requires stage 7 clean → runs, signature valid → no reason. Stage 10 requires stage 6
   clean and clock present → runs, fresh → no reason.
5. §2 invariant: authenticated channels are all empty → `class = AIREP-Authenticated`; non-empty
   `witnessed_withheld` ⇒ `class != AIREP-Witnessed`. ✔
6. §2 → non-Effect → `not_applicable`

**Expected:** `AIREP-Authenticated`, `— / — / —`, `— / independence-policy-malformed`,
`not_applicable` — identical to the pinned §7 **IND5** row, reached by a different trigger.

---

### MC3 — item 8 (unknown member at the top level of the revocation snapshot)

**Input.** The §1.3 revocation snapshot carries one member foreign to the document. Bindings,
policy, clock and the witness itself are clean.

**Chain.**

1. §9 **E-4** → the document is malformed → `*-revocation-state-malformed`.
2. **Producer path.** §4: stage 3 requires *producer binding accepted* — it is → the gate runs →
   `producer-revocation-state-malformed`; §5 types it *authenticated / WITHHELD*.
3. §9 **R-6**: *"Stage 4's prerequisite is 'binding accepted **and** not definitively revoked'. A
   missing or malformed revocation state is **not** 'revoked': the signature gate still runs
   diagnostically while Authenticated remains withheld."* → stage 4 runs, the signature is valid →
   no signature reason.
4. **Witness path.** Stage 6 clean; R-8 7a clean; R-8 7b accepts the (well-formed) witness
   binding; **7c** — witness revocation — reads the same malformed document →
   `witness-revocation-state-malformed`; §5 types it *witnessed / WITHHELD*.
5. §4: stage 8 requires *witness binding accepted (stage 7 clean)* — stage 7 is **not** clean →
   no independence reason. Stage 9 requires stage 7 clean → no reason. Stage 10 requires stage 6
   clean and clock present → runs, fresh → no reason.
6. §2 invariant: non-empty `authenticated_withheld` → `class = AIREP-Core`; §2 → `not_applicable`.

**Expected:** `AIREP-Core`, `— / producer-revocation-state-malformed / —`,
`— / witness-revocation-state-malformed`, `not_applicable`.

The pinned §7 **PI1** row is the direct precedent: with the revocation snapshot *absent* rather
than malformed, PI1 pins `producer-revocation-state-missing` in `authenticated_withheld` and
`witness-revocation-state-missing` in `witnessed_withheld`, with **no** independence and **no**
witness-signature reason. MC3 is that row with `-missing` replaced by `-malformed` and the clock
supplied.

---

### MC4 — item 8 (R-3 precedence: malformed entry **and** `trusted: false`)

**Input.** The producer's binding **entry** carries an unknown member **and** `trusted: false`.
**No `head_witness` is supplied.**

**Chain.**

1. §9 **R-3**, stated as a worked example: *"unknown member + `trusted: false` ⇒ **malformed
   only**; clean entry + `trusted: false` ⇒ **not-trusted only**."* → `producer-binding-malformed`
   alone; `producer-binding-not-trusted` MUST **NOT** appear.
2. §5 types `producer-binding-malformed` as *authenticated / WITHHELD* → `authenticated_withheld`.
3. §4 dependency table: stages 3 and 4 require *producer binding accepted* → no revocation
   reason, no signature reason.
4. no `head_witness` → §3 stage 6 → `no-witness-supplied` (§5: witnessed / WITHHELD); §4
   suppresses stages 7–10 entirely.
5. §2 invariant: non-empty `authenticated_withheld` → `class = AIREP-Core`; §2 → `not_applicable`.

**Expected:** `AIREP-Core`, `— / producer-binding-malformed / —`, `— / no-witness-supplied`,
`not_applicable` — the same shape as the pinned §7 **PB4** row.

*Why no witness here:* omitting the witness keeps MC4 clear of the open question recorded as
FINDING **F-3** (whether a defect localized inside **one** binding entry also poisons the *other*
tier's binding path). MC4 tests only R-3's precedence, which is stated verbatim.

## 6. Derivation chains — probe fixtures

Probes assert **process** behaviour only. `probe_index.json` gives each probe's `argv` with four
placeholders — `${VERIFIER}` (the invocation under test; the probes assume nothing about it),
`${PROBE}` (that probe's own directory), `${CORPUS}` (the main corpus directory) and `${OUT}` (a
results-file destination that does **not** exist before the run). Pass criteria: the exit code
equals `expected_exit`; a results file exists afterwards **iff** `expected_results_file`; every
path in `must_not_create` is absent after the run.

| Probe | Input | Clause chain | Expected |
|---|---|---|---|
| `PRB-DUP-TUPLE` | batch of two individually clean cases whose primary artifacts carry the **same** `(chain_id, record_id)` with different bytes | §2 (duplicate tuple makes the run invalid) → §9 **R-10** (*"MUST reject … no results file is emitted — uniqueness must be established before any write … not a class FAILURE or WITHHELD reason … not exit 2"*) → §6.4 exit 1 | **exit 1**, no results file, `${OUT}` not created |
| `PRB-SCHEMA-INVALID` | primary Decision omits the schema-required `claim` member; sealed **without** it, so the artifact is hash-consistent and the only defect is schema | §3 **stage 0** (*"Rejection ⇒ no class at all … reported as invalid, never as Core"*) → §6.4 (*"stage-0/1 artifact validity failed … so no results file is emitted"*) | **exit 1**, no verdict |
| `PRB-HASH-INVALID` | schema-valid artifact with a hashed member mutated **after** sealing, so `integrity.current` does not recompute | INTEGRITY §2 (hash preimage) + §5 (tag selection is a function, no fallback) → §3 **stage 1** → §6.4 | **exit 1**, no verdict |
| `PRB-REQUEST-UNPARSEABLE` | `request.json` is not parseable JSON | §6.4 (*"the evaluation request … could not be parsed"*) | **exit 1** |
| `PRB-HEADWITNESS-NULL` | `head_witness` present but `null` | §9 **R-7** input table, row 2: *"`head_witness` present but `null` / non-object ⇒ run-invalid, exit 1"* — deliberately distinct from *entirely absent*, which is the `no-witness-supplied` WITHHELD path | **exit 1** |
| `PRB-HEADWITNESS-UNKNOWN-MEMBER` | otherwise perfect `head_witness` carrying one foreign member | §0 (the envelope is closed) → §9 **R-7** row 3: *"unknown member inside `head_witness` ⇒ run-invalid, exit 1 — envelope closure preserved"* | **exit 1** |
| `PRB-HEADREF-UNKNOWN-MEMBER` | `head_ref` carrying an unknown member | §9 **R-4** (nested closure is limited to `head_ref` and `signature`, and applies to those two) + R-7 final row | **exit 1** |
| `PRB-CLI-REQUEST-WITH-OUT` | `--request FILE --out PATH` | §9 **R-9** invocation table row 2: *"CLI usage error, exit 2 — no verdict is emitted, and `PATH` is neither created nor modified"* | **exit 2**, `${OUT}` not created |
| `PRB-CLI-CORPUS-NO-OUT` | `--corpus DIR` without `--out` | §9 **R-9** row 4 | **exit 2** |
| `PRB-CLI-REQUEST-AND-CORPUS` | `--request` together with `--corpus` | §9 **R-9** row 5 | **exit 2**, `${OUT}` not created |
| `PRB-CLI-NOW-STRUCTURAL` | `--now` = `2026-08-23 12:00:00` (no `T`, no `Z`) | §1.4: *"Present but malformed — `--now` structurally invalid … ⇒ CLI usage/config error: exit 2, no verdict emitted"* | **exit 2** |
| `PRB-CLI-NOW-NOT-GREGORIAN` | `--now` = `2026-02-30T12:00:00Z` (format-conformant, not a Gregorian date) | §1.4: *"… or not a valid Gregorian datetime … ⇒ exit 2"*. Pairs with `TI1`/`TI2`, which carry the **same** date inside the signed claim, where R-2 6c makes it `witness-time-invalid` | **exit 2** |
| `PRB-CLI-WINDOW-NEGATIVE` | `--freshness-window -1` | §1.4: *"`--freshness-window` non-integer or negative ⇒ exit 2"* | **exit 2** |
| `PRB-CLI-WINDOW-NONINTEGER` | `--freshness-window 3600.5` | §1.4, same clause | **exit 2** |
| `PRB-CLI-HELP` | `--help` | §6.4: *"`--help` — 0, with nothing evaluated and no verdict emitted"* | **exit 0**, no verdict |

## 7. FINDINGS

Reported, never silently fixed. None of these was worked around by changing a frozen artefact.

**F-1 — `witness-time-invalid` had zero coverage in the frozen 45-case corpus.**
It is the only one of the 31 closed §5 registry reasons that no C0 expected value names. The
§7 minimum adversarial matrix has no row for it, so the gap is in the pinned matrix itself, not in
the builder. C1 closes it with `TI1`/`TI2`. **This is a coverage finding about C0, not a defect in
any C0 case**, and it is reported rather than treated as licence to touch §7.

**F-2 — the frozen corpus exercises three of the four artifact families.**
C0 contains decision, execution and effect artifacts but **no control artifact**, even though
INTEGRITY §1.2 registers `AIREP/0.2/hash/control` and `AIREP/0.2/sig/control` and DESIGN §7 says
Core and Authenticated apply to every family identically. C1 adds `CTL1`. The `control` tag pair
therefore had no fixture exercising it end-to-end before now.

**F-3 — OPEN SPECIFICATION QUESTION (not resolved here, and no C1 expected value depends on
it): does a structural defect localized inside ONE binding entry poison the other tier's binding
path?**
§9 E-4 says unknown members *"anywhere in an operator document"* are fail-closed; §9 R-8 reasons
about a malformed **store** reaching both paths; §9 R-3's worked example reasons about a malformed
**entry**. Two readings survive: (a) any defect anywhere makes the whole document malformed, so a
bad *producer* entry also yields `witness-binding-malformed`; (b) the defect is reported on the
path that resolves through it, so a bad producer entry leaves a well-formed witness entry
resolvable. The contract does not separate the two.
**Handling:** `MC1` and `MC3` place the defect at the **document top level**, where both readings
agree and R-8 states the two-path outcome explicitly; `MC4` places it inside one entry but
supplies **no witness**, so the question never arises. No C1 expected value rests on the
ambiguity. A maintainer ruling would be needed before any fixture pins the localized-entry
cross-path behaviour.

**F-4 — unpinned harness surface: case discovery and what `--corpus DIR` points at.**
The contract pins `--corpus DIR --out PATH` (§9 R-9) but not whether `DIR` is the corpus root
(containing `cases/` and an index) or the `cases/` directory itself, nor whether a batch harness
discovers cases by scanning `cases/` or by reading `case_index.json`. `PRB-DUP-TUPLE` and
`PRB-CLI-CORPUS-NO-OUT` both depend on the answer. The probe corpus therefore **mirrors the
existing committed layout exactly** (`<probe>/corpus/case_index.json` + `<probe>/corpus/cases/…`)
and its `argv` points `--corpus` at the corpus root, matching how the real corpus is laid out.
Flagged so the assumption is visible rather than buried.

**F-5 — unpinned harness surface: how per-case `clock.json` becomes `--now` / `--freshness-window`.**
§1.4 defines the clock as **CLI flags**, but the committed C0 corpus supplies it as a per-case
`clock.json` file (and §7 case `PI3` uses a `clock.json` carrying only the window). The mapping
from file to flags is harness convention, not contract. This is a pre-existing condition; C1
preserves it unchanged rather than inventing a rule.

**F-6 — `case_index.json` does not reference `expected.json`.**
The C0 index lists only `request`/`bindings`/`independence`/`revocation`/`clock`, by design
(*"case_index.json deliberately carries no expected values"*), so the index alone does not tell a
harness where expected values live. Inherited convention; `c1_case_index.json` follows the same
convention.

> **Corrected at maintainer review.** An earlier draft of this document claimed
> `c1_case_index.json` "matches it exactly rather than diverging". That was **false**:
> `case_index.json` has a **root array**, while `c1_case_index.json` was emitted as an object
> `{"cases": [...], "note": "..."}`. A differing root shape in an index that extends another
> index is a harness defect, not documentation — it forces any runner to special-case the
> extension, which is the opposite of what an additive extension should cost. The builder now
> emits `c1_case_index.json` as a **root array with the same member shape as C0's**, so a runner
> concatenates without interpretation:
>
> ```text
> combined_index = C0 case_index array + C1 case_index array   # 45 + 15 = 60 unique case_id
> ```
>
> The explanatory prose that lived in the removed `note` member is retained here rather than
> inside a machine-read index. `probe_index.json` remains object-rooted; it extends nothing and
> has no C0 counterpart to concatenate with, so no shape constraint applies to it — recorded so
> the difference is a stated choice rather than an oversight.

**No defect was found in `CLASS_VERIFIER_CONTRACT.md`, `INTEGRITY.md`, the accepted schemas or the
C0 corpus construction.** The builder reproduced all 265 C0 files byte-for-byte before any C1 code
was added, and its 976 pre-existing self-checks all pass in the extended build (1327 total, 0
failed).

## 8. What C1 does NOT do

- It does not modify `CLASS_VERIFIER_CONTRACT.md`, `INTEGRITY.md`, the schemas, or any C0 case,
  expected value or index.
- It does not add a reason to the closed §5 registry, or a class value, or an exit code.
- It does not evaluate the ladder: `build_class_corpus.py` still contains no ladder evaluation, no
  reason derivation and no channel computation.
- It does not certify the two class verifiers. A fixture states what the contract requires; only a
  comparator run against both implementations can state what they do.
