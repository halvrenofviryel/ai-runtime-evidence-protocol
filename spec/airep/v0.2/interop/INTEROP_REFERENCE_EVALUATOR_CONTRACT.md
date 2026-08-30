# Reference interop evaluator contract (AD15-IR-2)

**Lifecycle authority:** canonical status is established externally by the maintainer's pinned
commit, Git blob identity and SHA-256 record; **this document does not self-assert whether the
current blob is canonical.**

The sequence in §13 is authoritative. Corpus construction remains on **HOLD** before completion of
§13 step 10 and opens only at step 11. **No header text authorizes a step ahead of §13.**

## 1. Why this exists

`INTEROP_CORPUS_CONTRACT.md` §2 commits all three evaluation surfaces to a machine-observable
Level-1 result on **every one of the twelve** scenarios, the Python and Node reference lanes
included.

The frozen `CLASS_VERIFIER_CONTRACT.md` §8 says the opposite for part of that set:

> reconciliation (TOCTOU equality, reference resolution, lifecycle completeness — outside the
> ladder by design §7) … **out of scope**

Both cannot be true. Had the corpus been built first, three scenarios would have been scored
against a surface the reference lanes do not measure, and the run would have been reported as
"12/12 across three implementations" while three of the twelve were never actually evaluated by
two of the three. That is the failure this contract exists to prevent, and it is the reason the
frozen verifiers are **not** being changed to close it.

## 2. What is already covered, and what is not

Measured against the frozen contract, not assumed. §0 of that contract carries
`related_artifacts` and performs reference resolution for `head_ref`, an Effect's `execution_ref`,
and "any `decision_ref` a stage needs" — so the gap is narrower than "all reconciliation".

| Scenario | Frozen class verifier alone | Needs new bundle-level code |
|---|---|---|
| 4 positive family baselines | **yes** — schema, hash, signature, class | no |
| `IOP-B-DEC` / `IOP-B-CTL` / `IOP-B-EXE` / `IOP-B-EFF` | **yes** — stages 0, 1 and 4 | no |
| `IOP-R-INDEP` | **yes** — §0 resolves the Execution through `execution_ref`, verifies it to Authenticated in its own right, then compares identity and key, yielding `observer_assessment` | **no** — only the Level-1 mapping below |
| `IOP-R-CLEAN` | **no** — no stage asserts that a four-artifact graph resolves completely | **yes** |
| `IOP-R-TOCTOU` | **no** — no stage compares `authorized_action_digest` with `executed_action_digest` | **yes** |
| `IOP-R-XREF` | **no** — an Effect whose `decision_ref` resolves to nothing still classes normally, because no stage needs that reference | **yes** |

**Three scenarios require new code.** `IOP-R-INDEP` is delegable in full: the independence
condition is already a frozen stage-8 / observer-assessment property, and the evaluator only
translates its output into the Level-1 vocabulary.

## 3. Shape — composite, not a replacement

Two programs, one per lane:

- `interop_eval_py/` — Python reference interop evaluator
- `interop_eval_node/` — Node reference interop evaluator

Each:

1. invokes **its own** frozen class verifier **as a subprocess** for every artifact — in the order
   and subject to the fatal-run abort pinned by `AD15-IR-12` — and takes the per-artifact schema /
   hash / signature / class / reason result from that output verbatim;
2. implements bundle-level AD-03 reconciliation in **its own language, as independent code**;
3. emits one Level-1 verdict per scenario.

**The frozen verifiers are not modified, imported, vendored or re-implemented.** Their digests at
the time of this contract, which the evaluator MUST assert before use and record in its output:

| File | sha256 |
|---|---|
| `verifier_py/class_verifier.py` | `5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc` |
| `verifier_node_r2/class_verifier.mjs` | `e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4` |
| `CLASS_VERIFIER_CONTRACT.md` | `7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885` |

A digest mismatch is a hard `ERROR`. The run is not valid and no Level-1 verdict is emitted.

Crossing the lanes is forbidden: the Python evaluator invokes only `verifier_py`, the Node
evaluator only `verifier_node_r2`. An evaluator that shelled out to the other lane's verifier
would collapse the two surfaces into one and destroy the only property the dual lane provides.

## 4. Isolation — the same discipline as the class verifiers

The two evaluators are **separately authored against this contract**, in isolation. They share:

- no AIREP-specific reconciliation code, in any language;
- no shared helper module, transpiled artifact, or generated source;
- no line-by-line port of one into the other.

They may each use general-purpose libraries (JSON parsing, JCS, hashing, process invocation) and
they both read this contract. The reconciliation logic itself is written twice, independently.

Agreement between them is then evidence of the contract being unambiguous. If they are ported
from one another, agreement is evidence of nothing at all — which is exactly what the original
dual class-verifier exercise established, and the same reasoning applies here.

## 5. Bundle input

An evaluator consumes a **scenario bundle**: a directory containing the scenario's artifacts, the
operator inputs the frozen verifier requires (`--bindings`, `--independence-policy`,
`--revocation`, clock inputs), and a manifest.

#### Manifest encoding (normative, pinned)

An earlier draft fixed only what the manifest must *carry*, not how. Two isolated authoring
contexts independently assumed incompatible encodings from that text, and measurement confirmed
**no manifest either would both accept**. The encoding is therefore exact:

```jsonc
{
  "manifest_version": "1",           // string, exactly "1"
  "scenario_id": "IOP-R-CLEAN",      // one of the twelve
  "files": [                         // closed entries, sorted ascending by `path` (UTF-8 bytes)
    { "path": "artifacts/decision.json", "role": "artifact",     "sha256": "<64 lowercase hex>" },
    { "path": "operator/bindings.json",  "role": "bindings",     "sha256": "<64 lowercase hex>" }
  ]
}
```

**The manifest file is `manifest.json`, in the bundle root.** `--bundle DIR` names the directory;
the evaluator does not search for or accept any other name or location.

**No manifest discovery is performed (Erratum 3).** If the bundle root has no `manifest.json`, the
evaluator does **not** look for a manifest under some other name or in some other directory. Bundle
identity is not established, so the result is **exit 1 with empty stdout** — never
`manifest-invalid`, which would require an identity the evaluator does not have. An earlier draft
listed "a manifest with the wrong name or location" under `manifest-invalid`; that was
unimplementable, because §8.5 already routes exactly that condition to exit 1.

**The identity boundary is a direct read (Erratum 4).** The evaluator establishes bundle identity by
reading the bytes of `DIR/manifest.json` **directly** — not by enumerating the bundle first. Every
one of the following is *identity not established* → **exit 1, stdout empty, no result object**:

- the bundle root itself cannot be accessed;
- `DIR/manifest.json` is not found;
- it is found but cannot be opened or read;
- its bytes do not parse as strict JSON;
- no registered `scenario_id` can be obtained from it.

**A root manifest that cannot be read never yields `bundle-file-unreadable`.** That reason names a
file listed in `files[]`, and the root manifest is deliberately excluded from `files[]` — but more
fundamentally, a reason belongs to a result object, and at this point there is no scenario to name
one after. Unreadable and absent are genuinely indistinguishable *to the evaluator* here, because
neither yields an identity.

A wrongly-named or misplaced file sitting *beside* a valid root `manifest.json` needs no special
rule: it is an unlisted regular file, or a listed entry with an invalid `role`, and the ordinary
layout rules make it `manifest-invalid`.

- The manifest object is **closed**: exactly `manifest_version`, `scenario_id`, `files`. Any other
  member is a hard `ERROR`.
- `files` lists **every regular file under the bundle directory, recursively, except
  `manifest.json` itself.** Excluding it resolves the self-hash problem an earlier "every file the
  bundle ships" reading created. A file present on disk but absent from `files` is a hard `ERROR`;
  so is a `files[]` entry with no file on disk.
- **Symbolic links are forbidden** anywhere under the bundle. A symlink — including one whose
  target resolves inside the bundle — is a hard `ERROR`. A digest over a link's target is not a
  digest over the bundle's own bytes.
- `sha256` is **exactly 64 lowercase hexadecimal characters with no prefix** — not the
  `"sha256:…"` form used for wire digests elsewhere in v0.2. The two encodings live at different
  layers and are deliberately not interchangeable here.
- Each `files[]` entry is **closed**: exactly `path`, `role`, `sha256`.
- `role` is drawn from the closed set `artifact` · `bindings` · `independence_policy` ·
  `revocation` · `clock`.
- `files` MUST be sorted ascending by `path` in UTF-8 byte order, and MUST list every regular file
  under the bundle directory **except the root `manifest.json`**, exactly as defined above.
- `path` is bundle-relative and satisfies the canonical grammar of `AD15-IR-19` **as written**. A
  **duplicate** `path` is a hard `ERROR`.

**Ruling `AD15-IR-19` — the path grammar is lexical and closed.** "Bundle-relative and normalized"
named a property without saying how to test it, and "normalized" invites an evaluator to normalize a
path *into* acceptance. The grammar is exact:

```abnf
path    = segment *("/" segment)
segment = 1*(ALPHA / DIGIT / "." / "_" / "-")
```

with all of the following also required:

```
segment must not equal "." or ".."
no leading slash
no trailing slash
no empty segment
no doubled slash
no backslash
no colon or drive prefix
no NUL or control character
no non-ASCII character
no normalization or repair
```

> **A path is accepted only when its original JSON string already satisfies the canonical grammar.
> An evaluator never normalizes a path into acceptance.**

A violation is `manifest-invalid` at stage 4 — it is a property of the manifest document, testable
before the filesystem is consulted.

**Duplicate members in the manifest itself are pinned (`AD15-IR-17`).** RFC 8259 permits an object
to repeat a member name, both runtimes decode such an object last-wins by default, and a lane
recorded this as unpinned and relied on that default. Relying on a runtime default is the same
defect as relying on traversal order: it is not a rule, it is a coincidence that two implementations
currently agree.

> The evaluator **detects duplicate member names while parsing the manifest**, before taking any
> value from the decoded object. It MUST NOT take first-wins, last-wins, or whatever its parser
> happens to do.
>
> - Only a duplicate **top-level** manifest member named `scenario_id` enters the exit-`1` band: no
>   registered `scenario_id` is *deterministically* obtainable, which is already the fifth condition
>   of §5's direct-read identity boundary. This adds no new condition to that band.
> - A member named `scenario_id` duplicated or illegally present **inside `files[]` or any other
>   nested manifest object does not erase a valid top-level identity**. It is `manifest-invalid` at
>   **stage 4**, exit `3`.
> - **Any other** duplicated member in the manifest is likewise `manifest-invalid` at **stage 4**,
>   exit `3`. Identity was established, so a result object is owed (`AD15-IR-8`).

The nesting distinction is the point: reading a nested `scenario_id` as identity-destroying would let
a member buried in `files[]` suppress a result object the evaluator can perfectly well produce, which
is exactly the exit-1/exit-3 confusion `AD15-IR-8` exists to prevent.

This is the same rule E7-22 pins for listed artifact and operator-input files at stage 8, applied to
the manifest, which is read earlier and therefore could not be covered by that stage.

The evaluator verifies every file against its manifest digest **before** parsing anything; a
mismatch is a hard `ERROR` and no verdict is emitted. This is the layer that protects artifact
provenance (§5.1), and it is what makes "the bundle's own operator-input bytes" an auditable
statement rather than an assumption.

#### Bundle shape (normative, pinned)

| Scenario group | Artifacts | Composition |
|---|---|---|
| `IOP-P-*`, `IOP-B-*` | **exactly 1** | the single artifact of that family |
| `IOP-R-*` | **exactly 4** | exactly one each of Decision, Control, Execution, Effect |

Any other count or composition is a hard `ERROR`. **`head_witness` is absent from every official
W1 bundle** — no scenario in this corpus defines one, and a bundle that supplies one is out of
scope for this run rather than a new case.

**Operator-input composition, official W1 bundles:** exactly one `bindings`, exactly one
`revocation`, exactly one `independence_policy`, and **no `clock`**. Any other operator-input
composition is a hard `ERROR`. `clock` remains a legal `role` value for future runs; it simply
does not occur in this one, because no scenario here evaluates freshness — that is a witness-tier
property and W1 carries no witness.

Reference resolution inside a bundle is by v0.2 reference semantics — `record_id`, additionally
`chain_id` when the reference carries one. **Zero matches is unresolved; more than one match is
ambiguous and fails closed.** An evaluator MUST NOT pick one. This mirrors the frozen §0 rule
deliberately: the same resolution semantics apply whether the resolution happens inside the class
verifier or in the bundle layer above it.

### 5.1 Frozen-verifier request construction (normative)

The evaluator builds one §0 evaluation-request envelope **per artifact**, and the construction is
fixed so that both lanes send the frozen verifier byte-identical evidence.

For a four-artifact reconciliation bundle, evaluating artifact *A*:

- `artifact` = *A* as a **JSON value**, parsed from the bundle file (see the byte rule below);
- `related_artifacts` = the **other three** artifacts of the same bundle, each as a **JSON value
  parsed from its bundle file** under the same rule as the primary, **and no others**. Original
  bytes live only in Layer 1 (manifest provenance); nothing in the envelope is carried "verbatim";
- `related_artifacts` consists of **every other artifact in that bundle**, ordered by ascending
  UTF-8 byte order of its **manifest-relative `artifact_path`** (`AD15-IR-6`), so the envelope is a
  function of the bundle alone

For a single-artifact scenario (the four positives and the four broken-per-family cases),
`related_artifacts` is the **empty array** — not absent, not populated with unrelated artifacts.

Operator inputs (`--bindings`, `--independence-policy`, `--revocation`, clock inputs) are passed
as the **same bytes** to every artifact in the bundle and to both lanes. An evaluator MUST NOT
synthesize, filter, reorder or re-emit them; it passes through the files the bundle ships.

#### Ruling `AD15-IR-7` — duplicate semantic IDs are not bundle-preflight invalidity

The W1 evaluator applies **no** bundle-wide preflight gate on duplicate `record_id` or duplicate
`(chain_id, record_id)`. `artifact_path` is each artifact's total harness identity
(`AD15-IR-5`, `AD15-IR-6`), so duplicated semantic IDs cannot make a bundle unidentifiable.

Artifacts carrying duplicate semantic IDs are still sent to frozen stage evaluation. If a real
reference lookup then produces more than one match, **R-A and the frozen resolution semantics
treat it as ambiguous** — which is what §5 already requires: *"more than one match is ambiguous and
fails closed. An evaluator MUST NOT pick one."* A preflight gate would make that predicate
unreachable, converting a genuine reconciliation finding into the evaluator's own refusal. The
evaluator never picks one and never synthesizes an ID.

**Frozen `R-10` is a different surface.** It makes a duplicate `(chain_id, record_id)` in the
**batch verifier's own emitted verdict set** run-invalid. The W1 evaluator submits each artifact as
a separate request, so that batch invariant does not generalize into a bundle-wide semantic
preflight, and must not be widened into one.

This ruling **confirms** the removal of a duplicate-`record_id` preflight from an evaluator lane.
No mandatory W1 scenario targets duplicate semantic IDs, so the expected matrix is unchanged.

#### Ruling `AD15-IR-6` — envelope ordering is `artifact_path` too

An earlier draft ordered `related_artifacts` by `record_id`. `AD15-IR-5` had already made
`record_id` optional for result identity, so a bundle containing an artifact with no usable
`record_id` had **no defined envelope at all** — and therefore no defined
`request_envelope_digest`, which is what aggregate duty 2 compares. Two isolated remediation
contexts found this independently and resolved it differently: one sorted such an artifact under an
empty key, the other refused to build the envelope. Both were defensible; neither was
cross-lane safe.

Ordering is now `artifact_path` everywhere a harness needs an identity:

| Surface | Key |
|---|---|
| result identity (`artifacts[]` entry) | `artifact_path` |
| `artifacts[]` ordering | `artifact_path` |
| aggregate cross-lane comparison | `(scenario_id, artifact_path)` |
| **request-envelope `related_artifacts` ordering** | **`artifact_path`** |

`artifact_path` always exists — the manifest lists every file — so the envelope is always defined.

`record_id` remains **only** the AIREP semantic reference-resolution key. **R-A is untouched.**

The consequence this ruling exists to secure: an artifact with a missing `record_id` genuinely
reaches frozen stage 0, rather than being turned into either a fabricated ordering or the
evaluator's own preflight failure. Both prior resolutions are superseded.

#### Byte rule — two distinct byte layers

An earlier draft required the nested artifact to be carried as "exact bytes, never re-serialized"
*and* required both lanes to emit byte-identical envelopes. Those cannot both hold: nesting a
document inside a JSON object is a serialization, and two languages using their own serializers
have no reason to agree. The two layers are separated instead.

**Layer 1 — bundle files are immutable and hashed.** Each artifact file keeps its original bytes
on disk, and the bundle manifest records `sha256` over those bytes. The evaluator verifies each
file against its manifest digest before use; a mismatch is a hard `ERROR`. This is what protects
artifact provenance, and it is the *only* place original bytes matter.

**Layer 2 — the request envelope is canonical.** The evaluator parses each artifact file into a
JSON value, assembles the closed §0 envelope from those values, and serializes it as:

> **Ruling `AD15-IR-20` — the JSON byte domain is closed.** Before any parse, the byte encoding of
> `manifest.json` and of every listed artifact and operator-input JSON file is constrained:
>
> ```
> - UTF-8 only;
> - no UTF-8 BOM;
> - no UTF-16 or UTF-32 acceptance;
> - decoding must be strict and lossless;
> - malformed UTF-8 is rejected;
> - replacement decoding with U+FFFD is forbidden;
> - bytes are never repaired or transcoded into acceptance.
> ```
>
> Failure is assigned by which file it is, because the two sit on opposite sides of the identity
> boundary:
>
> | File | Outcome |
> |---|---|
> | `manifest.json` | identity **not established** — exit `1`, empty stdout |
> | a listed artifact or operator-input file | `bundle-json-invalid` at **stage 8**, exit `3` |
>
> A BOM is called out separately because it is the case a lenient runtime most often accepts
> silently: one lane strips it and parses, the other rejects, and the divergence is invisible until
> a corpus carries one.
>
> **A document can parse cleanly and still have no canonical form**, and that is checked in
> preflight, never at envelope assembly. RFC 8785 constrains its input in three ways beyond strict
> JSON syntax, and each one is assigned here so the domain is closed rather than described:
>
> | RFC 8785 input requirement | Violation | Stage | Reason |
> |---|---|---|---|
> | strings are valid Unicode | an **unpaired surrogate** anywhere | 8 | `bundle-json-invalid` |
> | objects have no duplicate member names | the **same member name twice** in one object | 8 | `bundle-json-invalid` |
> | numbers are IEEE-754 doubles | a value outside §5.1's envelope, e.g. `1e400` | **10** | `numeric-preflight-violation`, with its `json_pointer` |
>
> **That table is the whole of stage 8's canonicalizability question** — the first two rows and
> nothing else. It is not shorthand for "whatever RFC 8785 rejects": the numeric row is *also* a
> canonicalization failure, and folding it into stage 8 would lose the `json_pointer` that
> §5.1 requires and §8.7 makes normative.
>
> **No evaluator may repair any of these.** Not by substituting `U+FFFD`, not by dropping a code
> unit, not by taking the first or the last of two duplicate members. Repair is the failure mode
> being prevented: left to the runtime, one lane raises, another silently canonicalizes `{"k":1}`
> where a third canonicalizes `{"k":2}`, and the two produce **different
> `request_envelope_digest` values over the same file** while both reporting success. The digest
> would then attest to something the file did not say.
>
> The first row draws the same boundary the manifest-`path` rule draws at stage 4, applied to file
> contents rather than to the manifest.


```
request-envelope-bytes = RFC 8785 (JCS) canonicalization of the envelope
request_envelope_digest = "sha256:" || lowercase-hex( SHA-256( request-envelope-bytes ) )
```

JCS is deterministic on the JSON value, so both lanes produce the same bytes from the same bundle
without either sharing code or preserving the other's serializer quirks.

**This does not weaken hash verification.** `integrity.current` is defined over
`JCS(artifact minus current and signature)` (INTEGRITY §2), which is a function of the artifact's
JSON *value*, not of its file bytes. Re-serializing while preserving the value therefore leaves
every hash and signature check intact.

#### Numeric preflight (normative)

An earlier draft justified this by saying the only numeric type in the v0.2 schemas is `sequence`,
a non-negative integer. **That was a statement about the declared schema set mistaken for a
statement about instance documents, and it is not true of AIREP artifacts.** `profiles` is the
extension surface (AD-07) and `common.schema.json` constrains a profile value only as
`{"type": "object"}` — its members are unconstrained, so a conforming artifact may carry a JSON
number of any kind inside a profile. Whether the two runtimes agree on such a number is exactly
what must not be left to the implementer.

Every JSON number reachable in the assembled envelope — artifact core, profiles, operator inputs,
`head_witness`, at any depth — MUST satisfy:

- **finite and IEEE-754 representable** — no `NaN`, no infinity, no value requiring more than
  double precision to round-trip;
- **integer-valued numbers**: absolute value **≤ 2^53 − 1** (`9007199254740991`).

The bound is on the **mathematical value**, not on JSON spelling. `1e20` is integer-valued and is
**rejected** — it exceeds the bound — even though it is written in exponential form and is a
perfectly ordinary double. Conversely `1.5` is not integer-valued and is judged only by the
finiteness rule. Reading the bound as a syntax rule would let `1e20` through in one lane and not
the other, which is precisely the divergence this preflight exists to prevent.

A bundle containing any number outside this envelope is a hard **`ERROR`**, no measurement, and
the offending JSON Pointer is reported. This is checked in preflight, before any envelope is
assembled.

**The pointer is RFC 6901, evaluated against the individual file in which the violation occurs** —
the artifact or operator-input document as parsed, **never** the request envelope. The check happens
before any envelope exists, so an envelope-relative pointer would name a document that has not been
built; and the two bases give different strings for the same violation (`/profiles/x` against the
artifact versus `/artifact/profiles/x` against the envelope), which is a normative divergence under
§8.7. RFC 6901 already fixes the rest: `~` escapes to `~0`, `/` to `~1`, and array indices are
decimal with no leading zeros.

The bound is compatible with the core constraint — `sequence` is a non-negative integer and cannot
exceed it in any realistic chain — and it closes the profile hole without adding a schema
constraint to an intentionally open surface.

#### Ruling `AD15-IR-4` — cross-lane envelope equality is an aggregate gate

An earlier draft made cross-lane digest equality a "required pre-run check" inside the evaluator
and listed a lane disagreement among the evaluator's own `exit 3` conditions. **That is not
implementable.** A single Python invocation has no access to the Node lane's digest — it cannot
observe, let alone enforce, a property of a run it is not part of.

The property is real; it belongs one level up:

- each evaluator computes and emits **only its own** `request_envelope_digest`, per artifact;
- the **official harness** compares the Python and Node digests for the same
  **`(scenario_id, artifact_path)`** pair (key updated by `AD15-IR-5`);
- a mismatch makes the **aggregate run invalid / non-qualifying**. It is not translated into any
  individual evaluator's exit code, because no evaluator is in a position to detect it.

Raw outputs from a run whose digests disagree may be retained as measurement records, but **no
result from such a run counts toward qualification** — the two lanes were not evaluating the same
evidence, so their agreement or disagreement means nothing.

## 6. Reconciliation predicates (normative)

Exactly three, evaluated **only after** every artifact in the bundle has a frozen-verifier result.

**R-A — graph resolution.** Every cross-artifact reference in the bundle resolves uniquely:
Control→Decision, Execution→Decision, Effect→Decision, Effect→Execution. Unresolved or ambiguous
is a failure of this predicate.

**R-A is unique reference resolution and nothing more** (maintainer, confirmed at erratum). It does
**not** check that a `decision_ref` resolves to an artifact of the Decision family. Adding a family
check would be a stricter, unpinned predicate that silently widens the corpus design's scope, and
the bundle-shape rule in §5 already fixes family composition.

**R-B — authorized-vs-executed equality.** The Control's `authorized_action_digest` and the
Execution's `executed_action_digest` are compared as **exact strings**. Both are `sha256_digest`
by schema, so no normalization, case folding or re-hashing is performed. Inequality is a failure
of this predicate.

**R-C — independence.** Taken from the frozen verifier's `observer_assessment` for the Effect. An
Effect whose wire `observer_relationship` is `independent` while the frozen output reports an
effective assessment of `unknown` fails this predicate. The evaluator MUST NOT re-derive
independence itself — that is a frozen stage-8 property and re-implementing it would create a
second, unpinned definition.

### 6.1 Applicability (normative)

Each predicate resolves to exactly one of **`PASS` · `FAIL` · `NOT_APPLICABLE`**. `NOT_APPLICABLE`
is a first-class outcome and is never reported, aggregated or displayed as a pass.

The four positive family baselines and the four broken-per-family scenarios are **single-artifact**
scenarios. They have no bundle graph, no Control/Execution pair and no observer relationship to
reconcile. They are **not run through the reconciliation predicates at all**:

| Scenario | R-A graph | R-B digest equality | R-C independence |
|---|---|---|---|
| `IOP-P-DEC` · `IOP-P-CTL` · `IOP-P-EXE` · `IOP-P-EFF` | `NOT_APPLICABLE` | `NOT_APPLICABLE` | `NOT_APPLICABLE` |
| `IOP-B-DEC` · `IOP-B-CTL` · `IOP-B-EXE` · `IOP-B-EFF` | `NOT_APPLICABLE` | `NOT_APPLICABLE` | `NOT_APPLICABLE` |
| `IOP-R-CLEAN` | `PASS` | `PASS` | `PASS` |
| `IOP-R-TOCTOU` | `PASS` | **`FAIL`** | `PASS` |
| `IOP-R-XREF` | **`FAIL`** | `PASS` | `PASS` |
| `IOP-R-INDEP` | `PASS` | `PASS` | **`FAIL`** |

**These are contract expectations, frozen here before any evaluator exists — not values read back
out of evaluator output.** Each `IOP-R-*` fixture is built to break exactly one predicate (corpus
contract §2.2, single target per fixture), so the expected matrix is fully determined by the
transformation table and is stated in advance. An evaluator whose output disagrees with a cell
above is a finding: either the implementation is wrong or the fixture is, and which one is settled
by reading the transformation, never by amending this table to match a run.

Running a reconciliation predicate against a single-artifact scenario would either fabricate a
vacuous `PASS` — an assertion about a graph that does not exist — or force the evaluator to invent
a bundle. Both corrupt the measurement, which is why applicability is pinned here rather than left
to the implementer.

For the four `IOP-R-*` scenarios all three predicates are evaluated even when one has already
failed. An evaluator does not stop at the first failure: a bundle that fails two predicates must
say so, because **which** predicate fired is the measurement.

## 7. Level-1 mapping (normative)

Level-1 is the vocabulary of `INTEROP_CORPUS_CONTRACT.md` §3, unchanged:
`ACCEPT` · `REJECT` · `RECONCILIATION_MISMATCH` · `INDEPENDENCE_NOT_ESTABLISHED`.

Mapping, in this order:

1. Any artifact in the bundle that the frozen verifier reports as **invalid** (no class at all), or
   for which it reports a **definitive Authenticated-tier failure** → **`REJECT`**.
   Per the §3 pin in the corpus contract, a completed verdict leaving the artifact at
   `AIREP-Core` with a populated `authenticated_failures` channel **is** a `REJECT`. A
   **withheld** channel is never a `REJECT`.
2. Otherwise, **R-C** fails → **`INDEPENDENCE_NOT_ESTABLISHED`**.
3. Otherwise, **R-A** or **R-B** fails → **`RECONCILIATION_MISMATCH`**.
4. Otherwise → **`ACCEPT`**.

Step 1 precedes the rest because a bundle containing a cryptographically broken artifact has no
meaningful reconciliation verdict — the reconciliation-negative fixtures are built to be
individually sound precisely so this branch is not taken. Step 2 precedes step 3 because
`IOP-R-INDEP` is built to satisfy R-A and R-B; if it ever reported
`RECONCILIATION_MISMATCH`, the fixture is wrong, not the ordering.

### 7.1 `authenticated_withheld` is never a qualifying `ACCEPT` (normative)

**Withheld is not a pass.** Per frozen §4, a *withheld* channel means the tier could not be
evaluated — an absent binding, a malformed or missing revocation snapshot, an unsupported suite.
It is the absence of a measurement, not a negative one, and it must never be laundered into a
positive Level-1 result.

In an **official run** every operator input is complete by construction: the binding store
resolves all four producer identities (`INTEROP_CORPUS_CONTRACT.md` §2.3), the revocation snapshot
is present and well-formed, and the suite is registered.

**The rule is scenario-independent (Erratum 5).** An earlier draft said "for any artifact the
scenario expects to reach `AIREP-Authenticated`" — which presumes a per-scenario expected-tier table
**no evaluator has, and none should have**: consulting an expected-outcome oracle is exactly what a
measuring instrument must not do. The rule needs no such table:

> On the mandatory W1 surface, **any emitted frozen-verifier verdict carrying a non-empty
> `authenticated_withheld` channel makes the scenario `MEASUREMENT_INVALID`, regardless of scenario
> id.** The evaluator emits no Level-1 verdict and reports the withheld reasons verbatim.

This is sound because of how the mandatory twelve are built: operator inputs are complete by
construction; no mandatory scenario targets Authenticated-withheld behaviour; stage-0 and stage-1
invalid artifacts emit no verdict at all and are handled by §7.2; and `IOP-B-EXE` targets a
definitive `authenticated_failures`, not a withheld channel. On this surface an
`authenticated_withheld` result therefore means the **measurement infrastructure or the operator
inputs failed** — it is never a scenario's semantic outcome.

**This does not extend to `witnessed_withheld`.** W1 carries no witness, so `no-witness-supplied`
is an ordinary diagnostic surface, not a measurement failure.

This is not `REJECT` — nothing was refused — and it is emphatically not `ACCEPT`. It means the
harness or the operator inputs are wrong, and the correct response is to fix them and re-run, not
to score the scenario. Treating it as `ACCEPT` would let a corpus shipped with a broken binding
store report twelve green results while measuring almost nothing, which is the same class of
failure `AD15-IR-2` was raised to prevent.

A measurement-invalid scenario makes the **whole run** non-qualifying: an interop run is a claim
about all twelve, and eleven-plus-one-unmeasured is not that claim.

#### Ruling `AD15-IR-10` — run validity precedes tier withheld

§7.1 and §7.2 can both be live on the same bundle: one artifact may exit `0` carrying a non-empty
`authenticated_withheld` channel while another produces a non-permitted exit or a malformed result.
Both are pinned to exit `3`, but the contract never said which `measurement_status` wins.

> §7.1 is evaluated **only after** every artifact invocation in the scenario has passed the §7.2
> process- and result-shape guard. Where an `ERROR`-class process or run invalidity and an
> `authenticated_withheld` channel are both present on the same bundle, the **`ERROR` outcome is
> reported**.

This is not precedence for its own sake. A verifier that misbehaved *as a process* cannot be
trusted to have produced a meaningful withheld channel either, so reporting `MEASUREMENT_INVALID`
would attribute the failure to the tier when it belongs to the run.

**Both current lanes already do this** — source review found each applying the §7.2 guard before
scanning for withheld channels. No behavioural change is required; this pins an ordering that was
convergent but unstated.

### 7.2 Frozen-verifier `exit 1` is not automatically `REJECT` (normative)

Frozen `exit 1` means **run-invalid: no verdict was emitted**. Its causes are heterogeneous, and
only some of them are the thing a broken-per-family scenario is testing:

| Cause of frozen `exit 1` | Evaluator treatment |
|---|---|
| **stage-0 accepted-family schema invalidity** | Level-1 `REJECT` — *only* under the conditions below |
| **stage-1 hash recomputation mismatch** | Level-1 `REJECT` — *only* under the conditions below |
| unparseable or unreadable request | **`ERROR`**, no verdict |
| unknown member in the request envelope | **`ERROR`**, no verdict |
| `head_witness` present but `null` / non-object, or carrying an unknown member | **`ERROR`**, no verdict |
| duplicate `(chain_id, record_id)` in a batch | **`ERROR`**, no verdict |
| any other `exit 1` | **`ERROR`**, no verdict |

`exit 1` may be read as Level-1 `REJECT` only when **both** hold:

1. **the request was preflight-clean** — the manifest verified, the numeric preflight passed, the
   evaluator constructed the envelope per §5.1, and the operator inputs are the bundle's own.
   Cross-lane envelope equality is **not** part of this condition and never was implementable
   here: it is an aggregate-harness gate only (`AD15-IR-4`, §8.1); and
2. **the scenario's targeted predicate is stage-0 or stage-1 invalidity** — that is,
   `IOP-B-DEC` (stage 1), `IOP-B-CTL` (stage 0) and `IOP-B-EFF` (stage 0), and no other scenario.

Everything else is the evaluator's own error, not the artifact's. The distinction matters because
a malformed request and a malformed artifact both exit 1: without this pin, an evaluator that
built a bad envelope would score its own bug as a successful detection.

**`IOP-B-EXE` does not reach `REJECT` this way.** Its target is stage 4, record-signature
verification, which is an Authenticated-tier **failure** — a *completed* verdict, `exit 0`, class
`AIREP-Core`, with a populated `authenticated_failures` channel. It qualifies through step 1 of
the §7 mapping, not through an exit code. An `IOP-B-EXE` run that exits 1 is a defect in the
fixture or the harness, never a pass.

## 8. Invocation, output and determinism

### 8.1 One invocation evaluates one bundle

```
interop-eval --bundle DIR [operator-input flags]
```

One invocation evaluates **exactly one** scenario bundle and writes **exactly one** JSON object to
stdout. An evaluator performs **no case discovery**: it does not scan for sibling bundles, does not
iterate a corpus directory, and never emits a partial or streaming result set.

Keeping discovery and aggregation out of the evaluator means two authors cannot invent two
different answers to "what counts as the corpus" or "what does partial output mean" — the failure
mode that `AD15-IR-2` exists to prevent, in miniature.

#### Aggregate harness duties (normative)

The official harness performs **exactly twelve invocations per lane** — one per scenario, from a
fixed list, never discovered — and enforces six run-level properties no evaluator can:

1. **Completeness.** All twelve invocations returned `measurement_status: MEASURED`. A missing
   result object, a crash, a non-zero exit or a timeout is recorded as a **non-qualifying
   `ERROR`** for that scenario. Silence is never read as success.
2. **Cross-lane envelope equality** (`AD15-IR-4`). For every **`(scenario_id, artifact_path)`** (`AD15-IR-5`), the
   Python and Node `request_envelope_digest` values are equal. A mismatch makes the run
   non-qualifying; it is never translated into any evaluator's exit code.
3. **Cross-lane verifier identity.** Each lane asserted its own frozen verifier digest (§8.2.1)
   and both asserted the same frozen contract digest. The harness sees both trees and checks the
   pair; no evaluator does.
4. **Expected predicate matrix** (§6.1). Each `IOP-R-*` result matches the frozen expectation —
   `CLEAN` all `PASS`; `TOCTOU` fails only `R-B`; `XREF` fails only `R-A`; `INDEP` fails only
   `R-C`. A disagreement is a **finding**, resolved by reading the transformation table, never by
   amending the matrix.
5. **Level-1 parity and expectation.** For **every** scenario: the Python and Node `level1` values
   are equal to each other **and** equal to the frozen expectation below.

   | Scenario | Expected Level-1 |
   |---|---|
   | `IOP-P-DEC` · `IOP-P-CTL` · `IOP-P-EXE` · `IOP-P-EFF` | `ACCEPT` |
   | `IOP-B-DEC` · `IOP-B-CTL` · `IOP-B-EXE` · `IOP-B-EFF` | `REJECT` |
   | `IOP-R-CLEAN` | `ACCEPT` |
   | `IOP-R-TOCTOU` | `RECONCILIATION_MISMATCH` |
   | `IOP-R-XREF` | `RECONCILIATION_MISMATCH` |
   | `IOP-R-INDEP` | `INDEPENDENCE_NOT_ESTABLISHED` |

   Duty 4 alone cannot catch a Level-1 disagreement on the eight single-artifact scenarios: their
   predicates are all `NOT_APPLICABLE`, so a run where Python said `ACCEPT` and Node said `REJECT`
   for `IOP-P-DEC` would pass every earlier duty. Level-1 **is** the qualifying semantic result, so
   it is checked directly, both for cross-lane parity and against the corpus contract's frozen
   expectation.

6. **Cross-lane normative projection equality.** For each of the twelve expected scenario IDs,
   construct the closed cross-lane projection defined by §8.7 and compare the **RFC 8785 canonical
   bytes** of the two projections. They MUST be identical.

   Duties 2, 4 and 5 each compare one field. Together they still leave most of the result object
   uncompared: two lanes could agree on every envelope digest, every predicate and every Level-1
   verdict while disagreeing on `nonmeasurement.reason`, on `artifacts[]` membership, on
   `artifact_ref`, or on `scenario_id` itself. Duty 6 compares the whole normative projection at
   once, which is why it is stated as a projection rather than a longer list of field duties.

A run failing any of the **six** is **non-qualifying as a whole**. Eleven measured scenarios plus one
unmeasured is not a claim about twelve.

### 8.2 Result object

- `scenario_id`;
- `measurement_status` — `MEASURED` · `MEASUREMENT_INVALID` (§7.1) · `ERROR` (§7.2);
- `level1` — the Level-1 verdict when `measurement_status` is `MEASURED`; **`null` otherwise**;
- `predicates` — `{ "R_A": …, "R_B": …, "R_C": … }` when `MEASURED`; **`null` otherwise**;
- `nonmeasurement` — `null` when `MEASURED`; **required object otherwise**, shape in §8.2.2;
- `artifacts` — the invocations that produced a concrete process result, per §8.3.1 and rulings
  `AD15-IR-11` and `AD15-IR-12`. The full bundle artifact count is required **only** when
  `measurement_status` is `MEASURED`. Shape pinned in §8.3;
- `withheld_reasons` — **emitted unconditionally**, `[]` when nothing is withheld. Its entry shape
  is pinned by `AD15-IR-16`, because §8.7 makes this member normative;
- `verifier_digests` — this lane's asserted digests only, shape in §8.2.1;
- `evaluator_version`.

#### 8.2.1 `verifier_digests` — own lane only

**Frozen-identity preflight order, pinned (Erratum 5).** §8.2.1 required *exactly two*
self-recomputed entries, and the contract separately requires a frozen-identity assertion. When a
frozen file cannot be read those two demands conflict: a digest that cannot be computed cannot be
emitted, and no implementer may fabricate one. The order is therefore fixed:

1. bundle identity is established by the §5 direct read of the root manifest;
2. **immediately afterwards, before any other post-identity preflight**, the evaluator reads its
   own frozen identity pair and computes SHA-256 over each — its own class verifier, and the frozen
   `CLASS_VERIFIER_CONTRACT.md`;
3. if **either cannot be read** → exit `3`, `nonmeasurement.reason = frozen-identity-unreadable`,
   **`verifier_digests: null`**, `artifacts: []`;
4. if both are read, the exact two-entry `verifier_digests` object is built from the **recomputed**
   values;
5. if a recomputed value does not match its expected pin → `verifier-digest-mismatch`, and the
   **actual recomputed two-entry `verifier_digests` is retained** — a reader needs to see what was
   actually there, not what was expected;
6. only then does bundle traversal and the remaining preflight begin.

Because step 2 precedes all other post-identity work, **every other post-identity result carries a
populated `verifier_digests`**, and no implementation ever emits a placeholder.

> `verifier_digests`: an exact two-entry object after a successful frozen-identity read;
> **`null` only for `frozen-identity-unreadable`**.

This also clarifies why the aggregate cross-lane verifier-identity duty is meaningful only over
qualifying measured runs: a run that could not read its own frozen identity has no digests to
compare.

An earlier draft said "the three asserted digests from §3". That is unsatisfiable: §3 forbids a
lane from touching the other lane's verifier, so no evaluator can assert a digest it is not
permitted to read. Both isolated authors hit this independently.

**When `verifier_digests` is non-null, it contains exactly two entries, both recomputed by that evaluator:**

```jsonc
{ "class_verifier": "sha256:…",          // its own lane's frozen verifier
  "class_verifier_contract": "sha256:…" } // the frozen contract, shared by both lanes
```

**The peer lane's verifier digest does not appear in evaluator output at all** — not as an
unasserted value, not as a carried-forward constant. Cross-lane verifier identity is checked by
the aggregate harness, which legitimately sees both trees.

#### 8.2.2 `nonmeasurement` — machine-readable cause (normative)

A non-`MEASURED` result previously carried no machine-readable reason; the cause lived only on
stderr, which §8.3 forbids anything from parsing. A harness therefore received `ERROR` and could
not say why.

The object is **closed**:

| Member | Required | Notes |
|---|---|---|
| `reason` | **yes** | one value from the registry below, and nothing else |
| `detail` | **yes** | short human string. Never parsed, never influences a verdict |
| `json_pointer` | conditional | **required** for `numeric-preflight-violation`; permitted for no other reason |

Any other member is a hard `ERROR` in its own right.

Closed reason registry — no value outside it, and no new value without an erratum. The third
column is the `measurement_status` that MUST accompany it, so the pairing is not left to the
implementer:

| `reason` | Raised when | `measurement_status` |
|---|---|---|
| `manifest-invalid` | manifest parsed and `scenario_id` usable, but any **bundle-layout or manifest rule** is violated — see the enumeration below | `ERROR` |
| `manifest-digest-mismatch` | a listed file's bytes do not match its `files[]` digest | `ERROR` |
| `bundle-file-missing` | a file listed in `files[]` is not present on disk | `ERROR` |
| `bundle-file-unreadable` | a listed file exists and is a permitted regular file, but its bytes cannot be read | `ERROR` |
| `bundle-directory-unreadable` | after identity is established, bundle traversal cannot complete because a directory cannot be enumerated | `ERROR` |
| `bundle-entry-uninspectable` | a directory entry name was obtained, but its filesystem kind could not be determined | `ERROR` |
| `frozen-identity-unreadable` | the evaluator's own frozen verifier or frozen class contract could not be read, so its digest cannot be recomputed | `ERROR` |
| `bundle-json-invalid` | a listed artifact or operator-input file exists but is not parseable JSON, or parses and then violates one of §5's two stage-8 canonicalization rules — an unpaired surrogate, or a duplicate object member name | `ERROR` |
| `bundle-shape-invalid` | artifact count, family composition or operator-input composition outside §5 | `ERROR` |
| `numeric-preflight-violation` | a number outside §5.1's envelope — **`json_pointer` mandatory** | `ERROR` |
| `verifier-digest-mismatch` | a frozen digest assertion failed | `ERROR` |
| `verifier-not-invocable` | the frozen verifier process could not be spawned or executed **at all** | `ERROR` |
| `verifier-run-invalid` | the frozen verifier ran but did not produce a process/result shape accepted by **both** the frozen contract **and** this contract's own result-shape gate — i.e. rejected by either — see the enumeration below | `ERROR` |
| `internal-error` | an unexpected evaluator fault after bundle identity was established | `ERROR` |
| `operator-input-assertion-mismatch` | `AD15-IR-14` — a supplied operator-input flag contradicts the manifest, detectable only after identity was established | `ERROR` |
| `authenticated-withheld` | §7.1 — on the mandatory W1 surface, any emitted frozen-verifier verdict has a non-empty `authenticated_withheld` channel | **`MEASUREMENT_INVALID`** |

**`manifest-invalid` covers the whole bundle-layout surface (Erratum 2).** Both isolated
remediation contexts independently reached this reading; it is now normative rather than inferred.
The reason covers **all** of:

- a **forbidden symlink** anywhere under the bundle;
- a **regular file on disk that `files[]` does not list**;
- a `files[]` entry whose target is **not a permitted file kind**;
- a **FIFO, socket, device or any other non-regular, non-directory object** under the bundle;
- manifest **closure, sort, `role`, `path` or digest-encoding** violations.

**Directories are containers only.** A directory is normal under a bundle and is never itself a
`files[]` entry. No new reason code is added for any of the above.

**The filesystem taxonomy is complete (Erratum 5).** Erratum 3 separated the listed-file cases and
Erratum 4 separated enumeration; one gap remained between them — an entry whose **name** was
obtained but whose **kind** could not be determined. Calling that `manifest-invalid` asserts the
layout is wrong when that is precisely what could not be established, and
`bundle-directory-unreadable` does not fit either, because enumeration *succeeded*. The full
boundary, in order of what was actually learned:

| What happened | Reason |
|---|---|
| entry name obtained, but no-follow kind inspection could not complete (`AD15-IR-9`) | **`bundle-entry-uninspectable`** — exit `3`, `artifacts: []` |
| kind determined: a symlink or a forbidden non-regular object | `manifest-invalid` |
| kind determined: a directory, but it cannot be enumerated | `bundle-directory-unreadable` |
| kind determined: a regular file, but its bytes cannot be read | `bundle-file-unreadable` |

Each row says only what was actually learned, and stops there. Reporting a layout violation when
the layout could not be inspected is the same error as reporting a missing file when the medium was
merely unreadable.

#### Ruling `AD15-IR-9` — entry kind requires authoritative no-follow metadata

The first row above originally said the inspection was `lstat` **or equivalent**. Two isolated
lanes read "or equivalent" differently and were *measured* emitting different reasons for the same
filesystem state, so the reading is now pinned.

A type hint obtained **during enumeration** — `d_type` from `readdir`, `Dirent.isFile()`,
`os.DirEntry.is_file()` and their equivalents — is **not kind evidence on its own**. Those APIs may
answer from a value the directory read happened to carry, without performing any metadata lookup on
the entry itself, and they can only answer that way on filesystems that populate it.

> For **every** enumerated entry the evaluator MUST perform a separate no-follow metadata lookup —
> `lstat`, `fstatat(..., AT_SYMLINK_NOFOLLOW)`, `statx` with the no-follow flag, or a platform API
> guaranteeing the same semantics. Where that lookup cannot complete, the reason is
> **`bundle-entry-uninspectable`**.

**The measured divergence.** Given a bundle directory that is readable but not searchable (mode
`0o444`) holding one file, the two lanes were measured as follows. The Node lane ignores the
`Dirent` and calls `lstat` per entry; that call fails `EACCES`, giving `bundle-entry-uninspectable`.
The Python lane's kind inspection returned `(is_symlink=False, is_dir=False, is_file=True)` from the
cached `d_type` **without raising**, so `bundle-entry-uninspectable` was not reached at that point.
Those two observations are what the source review establishing this ruling actually had.

A **subsequent development measurement, reported by the maintainer after that pin**, ran the Python
lane's r3 head to completion on the same filesystem state and recorded reason
**`bundle-file-unreadable`**, with a `detail` asserting the entry was "present and a permitted
regular file" — a kind that had never been established. That is consistent with the pinned reading
and strengthens its rationale, but it is later development evidence, not part of the source review
that produced the ruling.

**Why the enumeration-time hint loses.** It asserts a kind that was never established. Worse, it
makes the reason reachable only on filesystems that *omit* `d_type`, so a conforming evaluator's
output would depend on the medium the corpus happens to sit on rather than on the bundle itself. A
determinism rule that holds on `ext4` and fails where the kernel returns `DT_UNKNOWN` is not a
determinism rule.

This is a **cross-platform determinism defect, not a semantic one** — no mandatory scenario's
Level-1 value changes. It blocks official identity freeze all the same: two reference evaluators
measured on the same contract-defined input surface must not emit different reasons for it.

**Enumeration failure is not a layout violation (Erratum 4).** Once a usable manifest and
`scenario_id` exist, the evaluator traverses the bundle. If that traversal cannot complete —
permission denied, an I/O error, or any other failure to enumerate a directory — the reason is
**`bundle-directory-unreadable`**, exit `3`.

It is deliberately **not** `manifest-invalid`. `manifest-invalid` says *the layout is wrong*; this
says *the layout could not be measured*. Both isolated lanes independently reached for
`manifest-invalid` here and both recorded discomfort with it, one observing that it is the same
shape Erratum 3 had just closed one level down: saying "the layout violates a rule" about a faulty
medium is as false as saying "the file is missing" was.

The file-level distinctions are unaffected: enumeration succeeding but a listed file being absent
remains `bundle-file-missing`, and a listed regular file whose bytes cannot be read remains
`bundle-file-unreadable`.

**Listed-file failures are four distinct reasons, not one (Erratum 3).** An earlier registry had no
row for a file that exists and is readable-in-principle but cannot actually be read, so it was
reported as `bundle-file-missing` — which says something false about the bundle. The boundary is
exact:

| Condition | Reason |
|---|---|
| path absent, or a definite `ENOENT` on read | `bundle-file-missing` |
| file present, permitted regular-file kind, but open/read fails or I/O errors | **`bundle-file-unreadable`** |
| bytes read successfully but do not parse as JSON | `bundle-json-invalid` |
| bytes parse as JSON but break a stage-8 canonicalization rule — unpaired surrogate, or duplicate object member name | `bundle-json-invalid` |
| bytes read successfully but the digest does not match | `manifest-digest-mismatch` |

Each says a different true thing about what went wrong. Collapsing them loses the distinction a
reader needs to know whether the bundle is incomplete, the medium is faulty, or the content is
wrong.

**`authenticated-withheld` is the only reason that maps to `MEASUREMENT_INVALID`.** Everything else
is `ERROR`. An `ERROR` covers two distinct situations and does not separate them: a
**pre-invocation** failure, where the run never got far enough to attempt a measurement, and a
**post-start run invalidity**, where the frozen verifier process began and then produced something
**either** contract's result-shape gate refuses. `verifier-run-invalid` is the second kind by
definition, so this row must never be read as saying every non-withheld reason failed before any
attempt.

**`verifier-run-invalid` covers every abnormal frozen run (Erratum 2).** The two remediation
contexts diverged here — one reached for `internal-error`, the other for `verifier-run-invalid` —
so the reading is pinned rather than left to the implementer. It means:

> the frozen verifier process **started successfully**, but the invocation did not produce a
> process/result shape accepted by **both** the frozen contract **and** this contract's own
> result-shape gate. Equivalently: **rejected by either** is enough.

Specifically:

- `exit 1` that is **not** a qualifying stage-0/stage-1 case under §7.2;
- `exit 2`, or any other exit the frozen contract does not permit for that invocation;
- `exit 0` with **empty** stdout;
- `exit 0` whose stdout is **not parseable as strict JSON**;
- `exit 0` carrying a **malformed, multiple, or wrong-shape** result instead of the single expected
  verdict object;
- a process that **did not exit normally at all** — killed by a signal or otherwise abnormally
  terminated (`AD15-IR-15`). It started, so it is not `verifier-not-invocable`; it produced no
  permitted shape, so it belongs here.

**`verifier-not-invocable` is now narrower**: it is only for a process that could not be spawned or
executed at all.

**`internal-error` is now narrower**: it is only for the evaluator's **own** unexpected internal
fault. An external subprocess protocol failure is never `internal-error`. Keeping these apart is
the point — one says the thing we invoked misbehaved, the other says we did.

`internal-error` exists so that an unexpected fault after identity is established still produces a
result object naming the scenario, rather than a crash the harness has to infer. It is not a
licence to swallow faults: `detail` must carry enough to locate the fault, and a run containing one
is non-qualifying like any other non-`MEASURED` result.

#### 8.2.3 `NOT_APPLICABLE` is a measured outcome

`NOT_APPLICABLE` means "this predicate does not apply to this scenario, and we established that by
measuring it". It is therefore only ever emitted inside a `MEASURED` result, for the eight
single-artifact scenarios per §6.1.

When `measurement_status` is not `MEASURED`, `predicates` is **`null`** — not a triple of
`NOT_APPLICABLE`. The earlier shape conflated "does not apply" with "never reached", which is the
same `NOT_MEASURED`-as-pass failure the rest of this contract is built to prevent. An aggregator
MUST NOT count a `null` predicate set as anything.

### 8.3 `artifacts[]` entry (normative)

The earlier draft said "per-artifact frozen-verifier verdicts verbatim". That is unrepresentable
for the cases this contract cares most about: when the frozen verifier exits 1 there **is no
verdict** — §6.4 is explicit that no result is emitted. The entry is therefore pinned as:

| Field | Type | Meaning |
|---|---|---|
| `artifact_path` | string, **required** | the artifact's manifest-relative path. This is the entry's identity |
| `artifact_ref` | object **or `null`** | the closed projection `AD15-IR-18` pins; **`null`** when the source carries no string `record_id` |
| `request_envelope_digest` | string | `sha256:…` over the §5.1 canonical envelope bytes |
| `verifier_exit_code` | integer **or `null`** | the frozen verifier's exit code, verbatim, when the process **exited normally**; **`null`** when it was terminated abnormally (`AD15-IR-15`) |
| `verifier_result` | object **or `null`** | the verdict verbatim when an **accepted** one was emitted; **`null`** whenever no accepted verdict exists — `verifier_exit_code` of `1` or `2`, abnormal termination, or a gate-rejected `exit 0` (`E8-4`) |
| `verifier_stderr_digest` | string | `sha256:…` over the captured stderr, for audit |

#### Ruling `AD15-IR-18` — `artifact_ref` has one closed projection

§8.7 makes `artifact_ref` a cross-lane equality field, and it was described only as "the structured
reference when a usable `record_id` exists". That leaves two lanes to invent the same object from
the same artifact by luck. It is now one function, total over every JSON value:

```
artifact_ref_from_artifact(value):

1. If value is not a JSON object, return null.
2. If value.record_id is not a JSON string, return null.
3. Otherwise return an object containing exactly:
     "record_id": value.record_id
   and, only when value.chain_id is a JSON string:
     "chain_id": value.chain_id
4. A missing or non-string chain_id is OMITTED, never represented as null.
5. Empty strings remain strings; the evaluator does not add a
   minLength rule absent from the frozen schema.
6. No coercion, Unicode normalization, case mapping, repair,
   synthesis, or stringification is permitted.
```

Step 4 matters because an omitted member and a `null` member are different JSON values and therefore
different RFC 8785 canonical bytes. Step 6 restates `AD15-IR-5`'s absolute bar on synthesizing a
`record_id`, extended to every form of quiet repair.

**Where the value comes from is pinned too**, because the same artifact yields it at different
times:

| Situation | Source of `artifact_ref` |
|---|---|
| a valid frozen `exit 0` verdict exists | copied **verbatim** from `verifier_result.artifact_ref`, after the W1 result-shape gate has accepted it under `E8-3` |
| no verdict exists — including a qualifying stage-0 or stage-1 `exit 1` | `artifact_ref_from_artifact` over the **parsed artifact value** |
| abnormal termination (`AD15-IR-15`) | the same pre-invocation projection already computed for that artifact |
| spawn failure (`AD15-IR-11`) | no entry exists, so no `artifact_ref` |

**The non-null object is closed**: exactly `record_id`, plus `chain_id` when and only when the
source carried a string one. No other member, at any time — including on the verbatim-copy path. The
frozen class-verifier contract enumerates `artifact_ref` without declaring that nested object closed,
so without the gate obligation above one evaluator could accept an extra member and copy it while
another rejected the verdict. The closure is enforced **at the gate**, so the copy is verbatim over a
value already known to be closed.

**`E8-3` — the Source-A gate is required, typed and closed.** An earlier draft rejected only an
*extra member*, which left an **absent** or **`null`** `artifact_ref` accepted and silently converted
to `null` on the emitted entry. One lane read it that way and the other did not, on a Class-1 field.
**On what the frozen contract does and does not settle here.** Frozen §2 *depicts* `artifact_ref` in
the object it defines, but frozen §6's enumerated verdict-envelope shape gates are "all five arrays
present, sorted, deduplicated, registry-only reasons, class value legal, §2 consistency invariants"
— `artifact_ref` presence is **not** among them, and `common.schema.json` constrains an
`artifact_ref` *value* rather than making the verdict's top-level member required. Whether an omitted
`artifact_ref` is frozen-conforming is therefore **not settled by the frozen text**, and this ruling
does not claim otherwise. W1 requires it on its own authority: `artifact_ref` is a Class-1 cross-lane
equality field, and a field two implementations must agree on cannot be optional. `verifier-run-invalid`
already covers a shape rejected by **either** contract, so a frozen-conforming verdict that W1
rejects has both a reason and a defined outcome. The gate is:

```
artifact_ref MUST be present.
artifact_ref MUST be a JSON object.
record_id    MUST be present and MUST be a JSON string.
chain_id, when present, MUST be a JSON string.
No member other than record_id and chain_id is permitted.
```

Every one of these is `verifier-run-invalid` when it fails — absent, `null`, missing `record_id`,
non-string `record_id`, non-string `chain_id`, extra member. There is no repair and no coercion; a
verdict that does not satisfy the gate is not an accepted verdict, so Source A does not apply to it
and `AD15-IR-18`'s Source B governs the emitted `artifact_ref`.

This is a gate **this contract adds**, not a re-reading of the frozen one. The frozen contract
permits the extra member; W1 does not, because `artifact_ref` is a Class-1 cross-lane equality field
and an open nested object cannot be one. `verifier-run-invalid` is defined above to cover a shape
rejected by either contract precisely so this case has a reason — narrowing it to the frozen
contract alone would have left a rejection with no registry entry.

**Testing splits in two, because the full cross-product is unbuildable.** The frozen
`common.schema.json` makes `record_id` and `chain_id` **both required strings** in `artifact_core`.
An artifact carrying an absent, null, boolean or numeric `record_id` therefore cannot pass stage-0
schema validation, so it can never produce an `exit 0` verdict and can never reach stage 1. Demanding
those cells would require a correct implementation to build impossible fixtures.

**Projection-function tests** exercise `artifact_ref_from_artifact` **directly**, over the full value
matrix, with no requirement that the value could ever yield a frozen verdict:

```
record_id:  absent, null, boolean, number, empty string, non-empty string
chain_id:   absent, null, boolean, number, empty string, non-empty string
```

**Source-selection tests are organised by *source*, not by process-outcome name.** An outcome list
is not exhaustive and invites exactly the error of declaring one outcome the only carrier of some
value. There are three sources, and together they cover every path:

```
Source A -- the accepted exit-0 verdict.
  Emitted artifact_ref is verifier_result.artifact_ref, copied verbatim.
  Reachable only with a schema-valid artifact, so record_id and chain_id
  are strings by construction.
  MUST also test the E8-3 negative gate in full: an exit-0 verdict whose
  artifact_ref is absent, null, missing record_id, carries a non-string
  record_id, carries a non-string chain_id, or carries any extra member
  is verifier-run-invalid -- not a verbatim copy, and not a repair.

Source B -- every OTHER emitted entry.
  Emitted artifact_ref is artifact_ref_from_artifact(parsed artifact),
  the preliminary projection. This is not a two-item list; it is every
  entry that is not Source A, and it includes at least:
    - qualifying stage-0 or stage-1 exit 1 (7.2);
    - NON-qualifying exit 1 -- 7.2 admits only IOP-B-DEC, IOP-B-CTL and
      IOP-B-EFF, so the same malformed artifact under any other scenario
      lands here as verifier-run-invalid;
    - exit 2, which emits no verdict;
    - exit 0 whose output the result-shape gate rejects;
    - abnormal termination (AD15-IR-15), which can occur BEFORE the frozen
      verifier reaches stage 0 and therefore carries any artifact at all.

Source C -- no entry, therefore no artifact_ref.
  Spawn failure (AD15-IR-11) and every pre-invocation failure.
```

**Schema-invalid `record_id` / `chain_id` values MUST be tested on Source B**, and on more than one
Source-B path — at minimum a qualifying stage-0 `exit 1`, a **non-qualifying** exit 1, and an
**abnormal termination**. These cells are reachable: stage-0 schema validity gates only the *verdict*,
not the *entry*.

**What is dropped, exactly.** Only the cells the frozen schema makes unreachable: a schema-invalid
`record_id` or `chain_id` combined with **Source A**, since a verdict cannot exist for an artifact
that failed stage 0. Every other combination remains required, now through Source B. An earlier
draft of this correction claimed the qualifying stage-0 `exit 1` was the *only* outcome that could
carry an invalid ID; that was false, and it dropped reachable cells — hence the source-based
formulation above, which cannot make that error because Source B is defined by exclusion rather
than by enumeration.

`$defs/artifact_ref` in the frozen schema makes `chain_id` **optional**, which is the frozen basis
for the projection's omit-rather-than-null rule.

#### Ruling `AD15-IR-16` — `withheld_reasons` has a pinned entry shape

A lane recorded that this member's **per-entry** shape was unpinned and chose one for itself. That
was tolerable while the member sat outside the parity surface. §8.7 now makes `withheld_reasons`
normative, so an unpinned entry shape is two lanes emitting different objects for the same withheld
channel and calling it conformance.

> **On every result-bearing path**, `withheld_reasons` is the canonical projection below of every
> accepted frozen-verifier verdict **actually retained in `artifacts[]` before termination**
> (`E8-1`). A fatal stage-11 result does not erase withheld channels already observed. A malformed
> or gate-rejected verifier output contributes none, because it is not an accepted verdict. **`[]`
> means no withheld reason was observed among the accepted verdicts actually obtained** — it says
> nothing about invocations never reached.
>
> `withheld_reasons` is **always present**, an array, and `[]` when nothing is withheld. Each entry
> is exactly:
>
> | Member | Type | Meaning |
> |---|---|---|
> | `artifact_path` | string | the artifact the channel came from — the same identity key `AD15-IR-5` pins |
> | `channel` | string | the frozen channel name, verbatim: `authenticated_withheld` or `witnessed_withheld` |
> | `reason` | string | the withheld reason string, **verbatim** from the frozen verdict, never re-worded |
>
> The array is ordered by `(artifact_path, channel, reason)` in UTF-8 byte order, and carries no
> other member.

Verbatim matters here for the same reason it matters in `verifier_result`: a withheld reason is the
frozen verifier's output, and an evaluator that paraphrases it has substituted its own text for a
measurement.

#### Ruling `AD15-IR-15` — abnormal termination has no portable exit code

A frozen verifier killed by a signal plainly *started*, so it is `verifier-run-invalid`, and
`AD15-IR-12` therefore requires it to contribute an entry. But there is no portable integer to put
in `verifier_exit_code`. Language runtimes disagree: one conventionally reports signal death as a
negative return code, another reports no status at all plus a separate signal name. An entry
demanding an integer "verbatim" forces one lane to fabricate a value, emit a schema violation, or
classify the run differently from its peer — and `AD15-IR-12` made that difference observable
through `artifacts[]`.

> **Three process outcomes, distinguished.** The middle row is the one this ruling exists for:
>
> | What happened | `artifacts[]` entry | `verifier_exit_code` | `verifier_result` | `verifier_stderr_digest` |
> |---|---|---|---|---|
> | the process **never started** — `verifier-not-invocable`, `AD15-IR-11` | **none** | not applicable | not applicable | not applicable |
> | the process **started and did not exit normally** — `verifier-run-invalid` | **present** | **`null`** | **`null`** | **present** |
> | the process **exited normally** | **present** | **integer**, verbatim | the verdict, or **`null` whenever no verdict exists** (§8.3 — exit `1` and exit `2` both emit none) | **present** |
>
> **No signal name, signal number or synthesized exit code appears in any normative field** — not in
> `verifier_exit_code`, not in `verifier_result`, and not in any other `artifacts[]` entry field or
> `nonmeasurement` member except `detail`.

**`E8-4` — a rejected `exit 0` object is not a `verifier_result`.** Stdout that parses is not a
verdict until it has passed **both** the frozen contract's shape rules and this contract's gate. When
the gate rejects it:

```
verifier_exit_code = 0
verifier_result    = null
artifact_ref       = AD15-IR-18 Source-B preliminary projection
reason             = verifier-run-invalid, and the scenario terminates
```

The rejected bytes may be kept as diagnostic evidence; they may not enter the normative
`verifier_result`. Both lanes already behave this way, one by explicit decision and one by
construction — but `verifier_result` is Class-1, so it is pinned rather than left to two
implementations happening to agree.

**Abnormal termination is the absence of an exit code, not the absence of a process attempt**, and
it is emphatically **not** the same shape as `AD15-IR-11`. A spawn failure yields no entry because
nothing was attempted. An abnormally terminated process yields a **full entry** — `artifact_path`,
`artifact_ref`, `request_envelope_digest` and a stderr digest over what the child actually wrote —
in which exactly two measurements are missing. Treating the two as one shape would discard the
evidence of a run that genuinely happened.

The signal is useful to a human, so `detail` **may** carry it, and two lanes may word that
differently without it being a divergence — `detail` is outside the parity surface under §8.7. The
prohibition is on letting a signal reach a field anything compares.

#### 8.3.1 When `artifacts[]` may be populated (normative)

The fields above are produced at three different times, and only the last group depends on a
process actually running:

- **`artifact_path` is known before invocation** — it comes from the manifest.
- **A preliminary `artifact_ref` is known before invocation**, derived from the artifact by
  `AD15-IR-18`'s projection. On the **`exit 0` path it is replaced** by the accepted verdict's
  closed `artifact_ref`; on **every other emitted entry** the preliminary value **is** the emitted
  one — see `AD15-IR-18`'s Source B, which is defined by exclusion and is not a list of outcomes.
- **`request_envelope_digest` is produced by successful request-envelope construction**, after
  preflight and before subprocess execution.
- **Only `verifier_exit_code`, `verifier_result` and `verifier_stderr_digest` are products of a
  frozen-verifier process attempt.**

The operational rule is unchanged; this only states correctly why it holds. A numeric-preflight or
frozen-digest failure occurs **before** any invocation, so those fields do not exist — and an
implementer told to emit them anyway would have to fabricate an exit code or a digest. The ordering
is therefore pinned:

1. **The evaluator completes the whole bundle preflight first**, in the stage order §8.6 pins.
   **No frozen verifier is invoked until every preflight stage has passed.** The stages and their
   barriers are defined there and are not restated here.
2. A failure during preflight is a **pre-invocation `ERROR`**: the result object carries
   **`artifacts: []`** — an empty array, not entries with null or placeholder fields.
3. Once invocation begins, `artifacts[]` contains an entry for **each invocation actually
   attempted**, and only those. Invocation order, and the point at which a failing bundle stops,
   are pinned by `AD15-IR-12`; the sense of "attempted" is pinned by `AD15-IR-11`.
4. In a `MEASURED` result, `artifacts[]` length MUST equal the bundle's artifact count from §5 —
   one for a P/B scenario, four for an `IOP-R-*` scenario. A `MEASURED` result with any other count
   is itself a defect.

The rule exists so no implementer ever invents an exit code or a digest to satisfy a required
field. An absent measurement is represented by absence.

#### Ruling `AD15-IR-11` — a spawn failure produces no `artifacts[]` entry

Step 3 says `artifacts[]` carries an entry for each invocation **actually attempted**, while the
field list above makes `verifier_exit_code`, `verifier_result` and `verifier_stderr_digest` products
of a process attempt. A spawn that fails is an attempt in the ordinary sense of the word yet
produces none of the three, so the two sentences could be read against each other. Both isolated
lanes raised it and both resolved it the same way; that resolution is now the rule.

> **"Attempted" means a process attempt that produced a concrete process result.** Where the frozen
> verifier cannot be spawned at all (`verifier-not-invocable`), the current artifact contributes
> **no** `artifacts[]` entry. Entries for invocations that completed earlier in the same bundle are
> retained.

No implementer fabricates an exit code, a verdict or a stderr digest for a process that never ran.
It is step 2's empty array applied one step later in the sequence.

#### Ruling `AD15-IR-12` — canonical invocation order and fatal-run fail-fast

`AD15-IR-11` pinned what a spawn failure contributes to `artifacts[]`, but not the two things that
make the contribution observable: the order invocations happen in, and whether the scenario
continues after one fails. Adversarial review found that a four-artifact bundle failing at its
second artifact admitted `[A]`, `[C, D]` and `[A, C, D]` — all three conforming. Both are pinned
here.

> **Order.** Artifact invocations proceed in **ascending UTF-8 byte order of `artifact_path`** — the
> same key `AD15-IR-5` and `AD15-IR-6` already use for identity and envelope ordering.
>
> **Fail-fast on a fatal run.**
>
> - `verifier-not-invocable` — the current artifact contributes **no** entry, entries for
>   invocations that already completed are retained, and the scenario **aborts immediately**.
> - `verifier-run-invalid` — a concrete process result exists, so the current artifact **does**
>   contribute its entry, and the scenario **aborts immediately**.
> - A clean exit-`0` verdict never aborts, **even when it carries a non-empty
>   `authenticated_withheld` channel**: under `AD15-IR-10` the remaining artifacts must still be
>   evaluated for run validity before §7.1 is applied at all.

The worked case is now single-valued: a bundle `[A, B, C, D]` whose **B** cannot be spawned yields
`artifacts[] = [A]`. `[C, D]` and `[A, C, D]` are no longer conforming.

§3's "for every artifact" is subject to this abort. It states the invocation obligation, not a
guarantee that every artifact is reached on a failing bundle.

#### Ruling `AD15-IR-5` — the manifest path is the total result identity

An earlier draft made `artifact_ref` required and ordered `artifacts[]` by `record_id`. That binds
**result identity** to a **semantic wire field**, and the two are not the same thing. An artifact
that must be rejected at stage 0 may have no usable `record_id` at all — so an evaluator would have
had to **fabricate a semantic identity** simply to name the thing it rejected. Fabricating identity
to report a rejection is exactly backwards.

- `artifact_path` is **required** and is the entry's identity. It always exists: the manifest lists
  every file.
- `artifact_ref` is the structured reference when a usable `record_id` exists, and **`null`** when
  it does not.
- **An evaluator MUST NOT synthesize a `record_id`.** Ever, for any reason.
- `artifacts[]` ordering is by **UTF-8 byte order of `artifact_path`**.
- The aggregate cross-lane envelope comparison key is **`(scenario_id, artifact_path)`**, not
  `(scenario_id, artifact_ref)`.

**R-A is unchanged.** Actual AIREP cross-reference resolution still uses `record_id`, additionally
`chain_id` where the reference carries one. The manifest path is **harness and result identity
only — it is not wire semantics** and never participates in reference resolution.

The consequence that matters: a missing `record_id` now reaches the frozen stage-0 evaluation it
belongs to, instead of being converted into the evaluator's own preflight failure.

**`stderr` is never a source of semantic classification.** It is hashed for audit and may be
retained alongside the run, but an evaluator MUST NOT parse it, match on it, or let its content
influence any predicate, Level-1 verdict or `measurement_status`. Classification comes from the
exit code, the emitted verdict, and — under `AD15-IR-15` — whether the process exited normally at
all; from nothing else. Reading prose to decide a verdict would make the
measurement depend on a surface neither the frozen contract nor this one pins.

### 8.4 Determinism

**Within one evaluator at one version**, identical bundle plus identical operator inputs gives
byte-identical output across repeat runs. This is a *repeat-determinism* requirement, not a
cross-lane one. Two lanes legitimately differ on `verifier_digests.class_verifier`,
`evaluator_version`, the audit-only evidence and the diagnostic-only data §8.7's classes define —
but **not** on `verifier_digests.class_verifier_contract`, which is Class-1 cross-lane equality data.
What they must agree on is the §8.7 projection, not their bytes.

Ordering of any collection **whose identifiers come from JSON strings** is by UTF-8 byte order of
the relevant identifier — **`artifact_path`** for `artifacts[]` (`AD15-IR-5`; it was `record_id`,
which an artifact rejected at stage 0 may not have) — matching the corpus contract's existing
ordering rule. The same key governs manifest `files[]` sorting, invocation order under
`AD15-IR-12`, and request-envelope ordering under §5.1.

**Filesystem directory entries are the one collection this does not govern.** Their names come from
the operating system, not from JSON, and need not be valid UTF-8 at all; §8.6 orders them by its
platform-neutral **name key**. For a name that *is* valid UTF-8 the two keys coincide, so this is a widening, not a second
rule in conflict with the first.

### 8.5 Process exit and stdout (normative)

§8.1 says one invocation writes exactly one result object. That cannot hold unconditionally: if the
manifest itself will not parse, even `scenario_id` is unknown, so there is nothing to write an
object *about*. Exit code and stdout are therefore pinned together.

| Exit | stdout | Condition |
|---|---|---|
| `0` | **exactly one** result object, `measurement_status: MEASURED`, with a Level-1 verdict | the bundle was measured |
| `1` | **no result object** — stdout empty | **bundle identity could not be established under §5's direct-read identity boundary — and only that** (bundle root inaccessible · root `manifest.json` absent · present but unopenable or unreadable · not parseable as strict JSON · no registered `scenario_id` obtainable) |
| `2` | **no result object** — stdout empty | CLI usage error |
| `3` | **exactly one** result object, `measurement_status: MEASUREMENT_INVALID` or `ERROR`, `level1: null`, `predicates: null`, `nonmeasurement` populated | bundle identity was established, but the scenario could not be measured — **every** §8.2.2 registry reason, including a missing listed file, an unparseable listed file, manifest structural violations, digest mismatch, shape violation, numeric preflight, verifier digest/invocation failure, and `authenticated-withheld` under §7.1 |

#### Ruling `AD15-IR-8` — identity establishment is monotonic

Once the root `manifest.json` bytes have been read successfully, parsed as strict JSON, and yielded
a registered `scenario_id`, **bundle identity is established**. No later filesystem, traversal or
preflight failure can retroactively unestablish it.

This resolves an overlap E4-2 and E4-3 created between them. E4-2 lists "the bundle root itself
cannot be accessed" as an exit-`1` identity condition; E4-3 makes an unenumerable directory after
identity `bundle-directory-unreadable` at exit `3`. On POSIX those meet in exactly one place:

> **Worked case — bundle directory mode `0o111`.** Traverse permission lets
> `open(DIR/manifest.json)` succeed while `readdir(DIR)` fails `EACCES`. The manifest read
> succeeded and yielded a registered `scenario_id`, so identity **was** established. The result is
> **`bundle-directory-unreadable`, exit `3`** — not exit 1.

Both isolated lanes reached this independently and were measured returning identical results on the
same bundle. That is convergence under a rule, which is stronger than convergence from silence —
but it is **development evidence, not official parity.** Official parity does not exist until the
corpus runs.

#### Ruling `AD15-IR-14` — a post-identity operator assertion mismatch is result-bearing

One lane recorded an open ambiguity against this dividing line and declined to resolve it: a
supplied operator-input flag that contradicts the manifest is a usage problem, but it is only
*detectable* after the manifest has been read — that is, after identity is established. Reporting it
as a CLI usage error (exit `2`, empty stdout) contradicts the rule that an established identity is
owed a result object.

> A **CLI syntax error** — unknown option, missing value, malformed argument — remains exit `2` with
> empty stdout, because it is detectable before anything is read.
>
> A **semantic or path mismatch between a supplied operator-input flag and the manifest**, being
> detectable only after identity is established, is reason **`operator-input-assertion-mismatch`**,
> `ERROR`, **exit `3`**, with a result object naming the scenario.

The mandatory twelve are unaffected: the official harness passes no operator-input flags, so this
reason is unreachable in an official run. It is pinned anyway, because "unreachable in the official
run" is precisely the class of gap that produced the `--help` divergence in Erratum 4 and the
entry-kind divergence in Erratum 6.

#### `--help` is a CLI meta-action, not an evaluation (Erratum 3)

The exit table above governs **evaluation invocations**. `--help` is not one, and an earlier draft
made it unsatisfiable: §8.5's exit-0 row demands a `MEASURED` result object, while a help screen
obviously emits none. The frozen class-verifier contract carries the same carve-out for the same
reason.

- `--help` exits **`0`**;
- it may write human-readable help to stdout;
- it produces **no result JSON object**;
- it does **not** require `--bundle`;
- the §8.5 evaluation exit table **does not apply to it**;
- the official aggregate harness never invokes it.

Every other CLI usage error remains exit `2`.

**The carve-out is one exact invocation, not one concept (Erratum 4).** "Exactly one flag wide"
proved ambiguous: two isolated lanes read it differently and measurably diverged — one treated it
as a statement about *spellings* and refused `-h`, the other as a statement about the *exit-0
licence* and accepted `-h`. Both readings were defensible, so the text is now precise:

- the meta-action is the **single-token invocation `--help`, and nothing else**;
- **`-h` is not an alias.** It is a CLI usage error: exit `2`, no result object;
- **`--help` combined with any other argument is not a meta-action** — it is a usage error, exit
  `2`. Only the lone help invocation is carved out;
- **help text content and byte length are not a parity requirement.** The lanes may print
  different help; nothing compares it.

This remains not a general licence for exit 0 without a result object, and the "exit 0 never has
empty stdout" invariant continues to bind every evaluation invocation.

The dividing line is **whether bundle identity was established**, and nothing else. Once it is, the
evaluator owes a result object naming the scenario it failed on; before it, it owes silence on
stdout and diagnostics on stderr.

An earlier draft put "a required artifact absent" on the exit-`1` side. That contradicted this very
rule: if the manifest parsed and yielded a usable `scenario_id`, identity **is** established, and a
missing file is something the evaluator can and must report against that scenario. It now exits `3`
with `bundle-file-missing`. **The exit-`1` band is exactly the identity-not-established condition
defined by §5's direct-read identity boundary and summarized in the table above.**

*(That sentence used to restate the condition count, and drifted when the count changed. It is the
third restated list in this contract to do so. Where a rule already exists, reference it.)*

**Diagnostics always go to stderr, and stderr is never a source of semantics** (§8.3). It is not
parsed by the harness, does not influence any verdict, predicate or status, and is retained only
as an audit digest.

**Missing output is itself a finding.** The aggregate harness knows which twelve invocations it
expected. An expected invocation that produces **no result object** — exit `1`, exit `2`, a crash,
a timeout — is recorded by the harness as a **non-qualifying `ERROR`** for that scenario. Silence
is never absence of a problem, and a run missing any of the twelve is non-qualifying regardless of
what the other eleven said.

A non-zero exit is never itself a Level-1 result, and `0` is unreachable while the bundle is
unmeasured. The twelve-of-twelve requirement lives in the aggregate gate (§8.1), not here.

### 8.6 Canonical evaluation pipeline and total failure precedence (normative)

`AD15-IR-10` ordered one pair of failures against each other. That approach does not scale: every
unordered pair is a latent divergence, and the lanes cannot find them without implementing first.
This section replaces pairwise ordering with a **total** one.

#### Ruling `AD15-IR-13` — total failure precedence

Evaluation is a fixed sequence of stages. **A stage runs to completion over the whole bundle before
the next stage begins**, and the first stage that produces a failure determines the reported reason.
No later stage overrides an earlier stage's failure, and no implementation may interleave stages for
efficiency in a way that changes which failure is reported.

| # | Stage | Reasons it can produce |
|---|---|---|
| 1 | CLI and meta-action handling | exit `2` (syntax); the `--help` carve-out |
| 2 | Direct-read bundle identity (§5) | the exit-`1` band — no result object |
| 3 | Frozen-verifier identity: read, then match (§8.2.1) | `frozen-identity-unreadable`, `verifier-digest-mismatch` |
| 4 | Manifest structure and closure | `manifest-invalid` |
| 5 | Canonical traversal — entry kind (`AD15-IR-9`), layout closure, listed-file presence | `bundle-entry-uninspectable`, `bundle-directory-unreadable`, `manifest-invalid`, `bundle-file-missing` |
| 6 | **All** listed-file reads | `bundle-file-missing`, then `bundle-file-unreadable` (`E8-2`) |
| 7 | **All** digest checks | `manifest-digest-mismatch` |
| 8 | JSON parsing, then §5's **two** stage-8 canonicalization rules — unpaired surrogate, duplicate member name | `bundle-json-invalid` |
| 9 | Bundle and operator-input shape; operator assertions (`AD15-IR-14`) | `bundle-shape-invalid`, `operator-input-assertion-mismatch` |
| 10 | Numeric preflight (§5.1) | `numeric-preflight-violation` |
| 11 | Artifact invocation, in `AD15-IR-12` order and subject to its abort | `verifier-not-invocable`, `verifier-run-invalid` |
| 12 | §7.1 `authenticated_withheld`, after stage 11 completes (`AD15-IR-10`) | `authenticated-withheld` |
| 13 | Predicates and Level-1 verdict | — |

**Stage 6 carries two reasons, in that order (`E8-2`).** §8.2.2's listed-file boundary routes *a
definite `ENOENT` on read* to `bundle-file-missing`, while this table's stage-6 row named only
`bundle-file-unreadable`. The two collide when a file is **present at stage 5 and gone before stage
6** — and the two isolated lanes were measured resolving it differently: one reported
`bundle-file-missing`, the other `bundle-file-unreadable`, for the same filesystem state, on a
Class-1 field.

> A definite `ENOENT` obtained while **reading** a listed file is **`bundle-file-missing`**,
> including when stage 5 established the file's presence and it disappeared before stage 6. Where
> both are live within stage 6, **`bundle-file-missing` outranks `bundle-file-unreadable`**.

This is not a preference between two lanes. §8.2.2 already said *"path absent, **or a definite
`ENOENT` on read**"* is `bundle-file-missing`; the stage-6 row simply failed to restate it, and one
lane followed the row while the other followed the boundary. The row is now correct, and
`bundle-file-missing` keeps the rank its stage-5 mechanism gives it.

**The barriers are the whole point.** Stages 6 and 7 are separate so that a bundle with one
unreadable file and a *different* file's digest mismatch reports `bundle-file-unreadable`: every read
completes before any digest is checked. Stages 5 and 6 are separate for the same reason — one
missing file plus a different file's digest mismatch reports `bundle-file-missing`. An implementation
validating each path end-to-end in manifest order would report the mismatch instead, and both
readings satisfied the old "complete the whole bundle preflight first".

**Within a stage, precedence is by mechanism first, then by path.** A path tie-break alone is not
enough: a stage can produce several different reasons, and not every failure has one offending path
(a composition rule is violated by a *set* of files, not by one). `stage_rank` is already fixed by
the stage barriers, so the remaining components are — the last of them conditional:

1. **Mechanism.** Each stage row above lists its reasons **in precedence order**. A failure of an
   earlier-listed reason is reported over a later-listed one, regardless of paths.
2. **Path.** Where a failure has one or more offending paths, its internal path key is the
   ascending-first path. **A pathless whole-bundle violation uses the empty byte string as its
   internal path key.** The internal key is not emitted.

   The earlier wording claimed every set-level failure has a sorted-first path, which is false for a
   composition rule violated by the bundle as a whole rather than by any file. The empty string is
   what makes the ordering total in that case; no real path is empty, so it never collides.
3. **Location within the file.** Path is not enough where one file can fail the same way twice: two
   numbers in the same artifact both outside §5.1's envelope share a stage, a reason and a path, and
   `numeric-preflight-violation` carries a normative `json_pointer`. Where a reason carries a
   `json_pointer`, the **ascending UTF-8 byte order of the pointer string** decides.

   Byte order, not numeric order: `/a/10` sorts before `/a/9` because `1` precedes `9` as a byte.
   That is deliberate. The requirement is a total, implementation-independent order, and a rule that
   compares array indices numerically has to parse them, which invites the two lanes to disagree
   about what is an index.

**The comparison key is three components, plus a conditional fourth:**

```
(stage_rank,
 reason_rank_within_stage,
 canonical_artifact_path
 [, json_pointer — for numeric-preflight-violation only])
```

The fourth is conditional because a locator is **normative only where it is emitted**, and there is
exactly one reason for which it is.

**Two failures sharing the first three components produce results that are identical on the §8.7
parity surface, except in one case.** `nonmeasurement` carries `reason`, `detail` and `json_pointer`, and §8.2.2 permits
`json_pointer` for **`numeric-preflight-violation` and no other reason**. `detail` is outside the
parity surface (§8.7); `canonical_artifact_path` is not an emitted member; a pre-invocation failure
emits `artifacts: []` whichever offending item was selected. So for every reason but one, which of
two same-stage same-reason failures an evaluator selects **cannot be observed**.

> **The locator is normative exactly where it is emitted.**
>
> | Reason | Locator | Totality |
> |---|---|---|
> | `numeric-preflight-violation` | the emitted `json_pointer`: RFC 6901 against the document the violation is in (§5.1), ascending UTF-8 byte order | **required, and total** — a parsed document has one value per pointer |
> | every other reason | none is emitted | **not required.** An evaluator may select either failure; the result object is the same either way |

An earlier draft of this section assigned a locator kind to every reason in a table. Adversarial
review showed that table was **both wrong and unnecessary**: wrong because several of its
assignments were not total — an RFC 6901 pointer cannot name one of two duplicate members, a bare
entry name collides across directories, and several whole-bundle composition rules all mapped to the
same empty locator — and unnecessary because none of those locators is ever emitted. Manufacturing a
total order over unobservable choices would have forced enumerating and ranking every sub-rule of
`manifest-invalid` and `bundle-shape-invalid`, adding a large normative surface that no output
depends on and that two lanes would then have to agree on for no measurable reason.

**The parity surface is what must agree, not an evaluator's internal selection.** That is the same
principle §8.7 states, applied one level down.

**Discovery order may never decide anything observable.** Filesystem traversal order, parser
reporting order and iteration order over a manifest are implementation surfaces. The stage barriers,
the reason precedence within a stage, the path key, and — for `numeric-preflight-violation` — the
emitted pointer are all fixed independently of them. Where the contract leaves a selection free, it
is because the selection changes no emitted value; that is a stated exemption, not a fallback to
discovery order.

So the worked stage-9 case is single-valued: a manifest with two `independence_policy` files
(`bundle-shape-invalid`) and a `--bindings` flag pointing at the revocation file
(`operator-input-assertion-mismatch`) reports **`bundle-shape-invalid`** — the bundle's own
composition is settled before any assertion an operator makes *about* it.

**Stage 11 is the one exception**, and it is not a tie-break at all: artifact invocation is
sequential in `AD15-IR-12`'s order and stops at the first fatal run, so the reported reason is
whichever fatal run is reached first. No comparison between reasons arises.

**Stage 4 and stage 5 both produce `manifest-invalid`, and the split is deliberate.** Stage 4 is
**manifest-object closure** — rules the JSON document violates on its own terms: unknown members,
sort, `role`, `path` syntax, digest encoding. Stage 5 is **filesystem layout closure** — rules the
bundle on disk violates: a forbidden symlink, a non-regular object, an unlisted entry. A manifest
that is malformed on its own terms is reported before the disk is consulted.

**Traversal order is never the operating system's.** `readdir` order is unspecified and varies by
filesystem, so a lane reporting the first failure in enumeration order is not deterministic. Every
directory's entries are sorted before that directory is inspected or descended into.

**The sort key is the entry name exactly as the operating system supplies it, never a normalized
form.** "Raw bytes" alone is a POSIX-shaped rule and would make this contract Linux-only; other
platforms expose a Unicode-native directory API and never hand back bytes. The key is therefore
defined over what the API actually provides:

- **Lossless raw name bytes** — the key is those bytes, compared as unsigned bytes.
- **A Unicode-native name** — the key is the UTF-8 encoding of the **exact string returned**, with
  **no normalization applied**.
- **A name that cannot be represented losslessly**, or that contains an unpaired surrogate — it
  cannot equal any manifest `path`, which is a JSON string, so it is an unlisted entry and a
  deterministic `manifest-invalid` at stage 5.

**NFC or NFD conversion, case folding, locale-dependent mapping and any platform-specific name
normalization are forbidden** — at this key and anywhere else a name is compared. A normalizing key
makes two byte-distinct entries collide on one platform and not on another, which is the
cross-platform determinism defect `AD15-IR-9` exists to close, reintroduced one layer down.

Where a name is valid UTF-8 and needs no normalization all three bullets yield the same key, so this
widens the ordinary case rather than competing with it.

**A directory entry whose name is not valid UTF-8 is an unlisted entry.** A manifest `path` is a
JSON string, so no such entry can ever be listed in `files[]`. It is reported by stage 5's layout
closure as `manifest-invalid`, exactly as any other unlisted entry is — and its sort position is
already well defined by the byte key above.

**A manifest `path` containing an unpaired surrogate is `manifest-invalid` at stage 4.** Strict JSON
admits an escape such as `\ud800` with no pair, which does not encode to well-formed UTF-8 and so
cannot denote any filesystem name. It fails on the manifest's own terms, before the disk is
consulted.

`internal-error` is not a stage: it is raised wherever an unexpected evaluator fault occurs after
identity is established. It cannot mask a failure an earlier stage had already determined — a stage
that has produced its failure has produced the reported reason, and a later fault does not replace
it.

**The order is total over the failures an evaluator detects by design; `internal-error` is outside
it by nature.** An unexpected fault cannot be enumerated in advance, so a lane that faults partway
through a stage may report `internal-error` where its peer reached a registry failure later in the
same stage. That is **not** a conforming difference to be reconciled: on the mandatory twelve,
`internal-error` is itself a defect in the lane that raised it, and a run producing one is
non-qualifying and must be investigated rather than compared.

### 8.7 The normative surface (normative)

Not every observable difference between two conforming evaluators is a defect, and this contract has
so far left that boundary implicit. Without it, adversarial review over invalid-input space never
terminates.

The earlier binary model was internally contradictory. It called **every** `artifacts[]` field and
**`verifier_digests`** normative, while `verifier_stderr_digest` and each lane's own class-verifier
digest are *expected* to differ — the two frozen verifiers are different programs. It also omitted
`scenario_id` entirely, and no harness duty compared the complete normative projection. A field is
therefore placed in exactly one of **four** classes.

#### Class 1 — cross-lane equality fields

These MUST be equal between the two lanes for a scenario to qualify:

- process **exit code** and stdout / result-object shape;
- `scenario_id`;
- `measurement_status`;
- `level1`;
- `predicates`;
- `nonmeasurement.reason`;
- `nonmeasurement.json_pointer`;
- `artifacts[]` **membership and order**;
- `artifact_path`;
- `artifact_ref`;
- `request_envelope_digest`;
- `verifier_exit_code`;
- `verifier_result`;
- `withheld_reasons`;
- `verifier_digests.class_verifier_contract` — the two lanes assert the **same** frozen contract.

#### Class 2 — lane-local normative assertions

Each MUST hold **within** its lane, and is never compared across lanes:

- `verifier_digests.class_verifier` equals **that lane's own** frozen verifier pin;
- `evaluator_version` satisfies that lane's own pinned version rule and the §8.4 repeat-determinism
  requirement;
- mandatory-block execution is complete against the canonical block registry, in each lane
  independently.

#### Class 3 — audit-only result evidence

- `verifier_stderr_digest` remains **required**, and MUST equal SHA-256 over the exact captured
  stderr bytes. It is **not** compared against the peer lane: the two frozen verifiers legitimately
  emit different diagnostic stderr, so requiring equality would fail a conforming pair.

#### Class 4 — diagnostic-only

Never compared, never a source of any normative value:

- `nonmeasurement.detail`;
- raw stderr content;
- signal names and numbers;
- stack traces;
- operating-system error prose;
- help text;
- timing and resource-use diagnostics.

**No normative reason may be derived from diagnostic prose.** An evaluator that picks a reason by
matching on an OS error message has made its output depend on a surface neither contract pins, and
on a platform's phrasing of it.

#### `scenario_id` is bound at four points

Omitting it from the surface left the scenario label itself uncompared. It is bound exactly:

```
result.scenario_id
  == the expected scenario ID selected by the aggregate harness
  == manifest.scenario_id
  == peer_result.scenario_id
```

#### The cross-lane normative projection

Class 1 is compared as a **closed JSON value**, not field-by-field and never by string comparison of
serializations. The projection is the result object with exactly these removed:

```
nonmeasurement.detail
evaluator_version
verifier_digests.class_verifier
artifacts[*].verifier_stderr_digest
```

Everything else is retained — including `verifier_digests.class_verifier_contract`. Equality is
equality of the closed JSON value, **operationalized through its RFC 8785 canonical bytes**, so that
member order, whitespace and number spelling cannot make two equal values compare unequal, nor two
unequal values compare equal.

**A result object carrying an unknown member at any closed level is invalid** — it is not silently
dropped from the projection. Excluding it would let a lane smuggle an uncompared field into a result
that still passed the projection; the closed member set exists to prevent exactly that.

**This surface is the evaluator's output, not a lane's test runner.** A lane's self-test summary —
total check counts, block names, optional-test counts, summary formatting — is diagnostic and is
**not** compared across lanes. Two lanes running different numbers of checks is expected: they are
separately authored. The one thing the runners must agree on is the item already listed above,
**whether every mandatory block executed**, and that is a per-lane property, not a cross-lane
comparison of totals.

#### What "a mandatory test block actually executed" means

Adversarial review found this phrase carried no criterion, so a lane could simply never register a
required test, report zero skips, and look complete. The criterion:

- **The required block IDs are pinned here, not declared by the implementation.** A registry a lane
  writes for itself is not a control: an implementer can delete the block *and* its own registry
  entry and still report `0 skipped`, which is the exact failure this rule exists to catch. Every
  lane's runner accounts for **exactly** this closed set:

  | Block ID | What it must exercise |
  |---|---|
  | `W1-BLK-IR4` | **lane-local half of `AD15-IR-4`**: construct the request envelope exactly per §5.1; prove **repeat determinism** for identical input; **independently recompute** SHA-256 over the actual RFC 8785 canonical envelope bytes and require `request_envelope_digest` to equal that value. MUST include **controlled envelope mutations** that change the canonical bytes, verifying the evaluator hashes the mutated bytes rather than reusing or carrying forward a prior digest. This block does **not** assert that SHA-256 is injective, nor that every pair of distinct envelopes has distinct digests. Cross-lane equality remains aggregate-harness duty 2 and MUST NOT be attempted here |
  | `W1-BLK-IR5` | `artifact_path` is the total result identity: `artifacts[]` ordered by it, `artifact_ref` `null` where no string `record_id` exists, and **no `record_id` is ever synthesized** |
  | `W1-BLK-IR6` | `related_artifacts` ordered by `artifact_path`, proved on a fixture where **`record_id` order is the reverse of `artifact_path` order** — the two orders must actually disagree, or the test proves nothing |
  | `W1-BLK-IR7` | duplicate semantic IDs are **not** preflight invalidity: a bundle with a duplicated `record_id` still reaches frozen stage evaluation and is not rejected by the evaluator |
  | `W1-BLK-IR8` | identity establishment is monotonic: the worked `0o111` case is `bundle-directory-unreadable` at exit `3`, **never exit 1**. Skips cleanly under euid 0, and a skip is reported as a skip |
  | `W1-BLK-IR9` | entry kind by authoritative no-follow lookup, discriminating against the enumeration-time hint |
  | `W1-BLK-IR10` | run validity evaluated before tier withheld, on a bundle where both are live |
  | `W1-BLK-IR11` | a spawn failure contributes no entry while earlier entries are retained |
  | `W1-BLK-IR12` | invocation order, and the abort at the first fatal run |
  | `W1-BLK-IR13` | stage barriers on a multi-fault bundle, and the comparison key including the conditional `json_pointer` component. **MUST include `E8-2`**: a file present at stage 5 that disappears before stage 6 is `bundle-file-missing`, and it outranks a *different* file that is unreadable at stage 6 |
  | `W1-BLK-IR14` | a post-identity operator assertion mismatch is result-bearing at exit `3` |
  | `W1-BLK-IR15` | the three process outcomes, distinguished |
  | `W1-BLK-IR16` | `withheld_reasons` always present — `[]` **only** when none was observed among the accepted verdicts obtained — plus the pinned entry shape and order, **and `E8-1`**: an accepted earlier verdict carrying a withheld channel, followed by a fatal stage-11 result, retains that channel in the emitted array |
  | `W1-BLK-IR17` | duplicate manifest members: a duplicated **top-level** `scenario_id` in the exit-`1` band, a **nested** `scenario_id` and every other duplicate `manifest-invalid` at stage 4, and none of them resolved by the parser's default |
  | `W1-BLK-JCS` | the stage-8 canonicalization rules, that repair is refused, **and** that a numeric JCS-domain failure such as `1e400` is reported as `numeric-preflight-violation` at stage 10 **with its `json_pointer`** rather than `bundle-json-invalid` at stage 8 |
  | `W1-BLK-LIVE` | the live frozen-verifier path, against the genuine frozen files |
  | `W1-BLK-PARITY` | the §8.7 four-class model and the duty-6 projection — see below |
  | `W1-BLK-ARTIFACT-REF` | `AD15-IR-18`'s complete projection-function value matrix, **plus** its three sources — including **every** `E8-3` Source-A rejection — absent, `null`, missing `record_id`, non-string `record_id`, non-string `chain_id`, extra member — and schema-invalid IDs on at least three distinct Source-B paths. **And `E8-4`**: a gate-rejected `exit 0` emits `verifier_exit_code: 0` **with `verifier_result: null`** — the rejected object never becomes the result. Only `schema-invalid × Source A` is excluded, as the frozen schema makes it unreachable |
  | `W1-BLK-JSON-BYTES` | `AD15-IR-20`: UTF-8 BOM, malformed UTF-8, UTF-16LE, UTF-16BE, UTF-32LE and UTF-32BE, for **both** the root manifest and a listed JSON file |
  | `W1-BLK-PATH` | `AD15-IR-19`, over the case list below |

**`W1-BLK-PARITY` is a per-lane block and MUST be executable without peer material.** The real
cross-lane comparison is **aggregate-harness duty 6**, which sees both trees; §4 forbids a lane's
runner from seeing its peer, so a lane-local block demanding a Python-versus-Node comparison would be
unsatisfiable except by breaking isolation. What each lane proves alone is that **the model
separates the classes** — which is peer-safe, because it is a property of the projection, not of the
peer:

```
projection(result)                        # the lane's own result
  == projection(result with verifier_stderr_digest replaced)
  == projection(result with verifier_digests.class_verifier replaced)

projection(result)
  != projection(result with any Class-1 field altered)
```

**No inequality of the two lanes' stderr digests may be asserted.** Both frozen verifiers write
stderr only in their usage-error and invalid branches, so on a normal verdict path both streams are
empty and both digests are SHA-256 of the empty byte string. Requiring them to differ would make a
conforming pair fail. The class-verifier digests do differ by construction (§3), but that too is
aggregate-harness evidence, not something a lane can check alone.

The block MUST then mutate **each top-level and nested result field individually**
and record, for each, whether the mutation:

```
- causes cross-lane projection failure;
- causes lane-local pin failure;
- causes audit-evidence failure; or
- is legitimately diagnostic-only.
```

A mutation of `scenario_id` MUST be detected — that is the field the earlier surface omitted
entirely. A mutation of a Class-3 or Class-4 field MUST be shown **not** to move the projection; that
is the half of the model a passing comparison never exercises.

**`W1-BLK-PATH` case list**, each asserted against `AD15-IR-19` as written:

```
empty path        "."               ".."
"./a.json"        "a/./b.json"      "a/../b.json"
"a//b.json"       "/a.json"         "a.json/"
"C:artifact.json" "a\b.json"
control-character path               non-ASCII path
valid canonical controls
```

- **A block executed** when its assertions ran and their outcomes are counted in the summary, proved
  machine-readably by at least one assertion-counter increment **and** a block-completion record
  carrying the ID. A block that "ran" without incrementing any counter asserted nothing.
- **Any pinned ID with no execution record is reported as skipped.** That is what makes an *omitted*
  block visible rather than invisible.
- **An unknown or duplicate block ID makes the run non-qualifying** — unknown because the set above
  is closed, duplicate because two records under one ID make "did it run" unanswerable.
- The summary distinguishes three states — passed, failed, and not measured — and the default mode
  exits non-zero if any pinned block is in the third.
- This pins **what must be exercised**, not how. The two lanes derive their test code independently
  from the same contract, exactly as they derive their evaluators; sharing an ID vocabulary is not
  shared state and does not touch §4 isolation.

Two lanes may differ on a non-normative surface without an erratum. This is not a licence for
carelessness there; it states what a divergence report must establish before it blocks a freeze.

## 9. Provenance — extends the participation contract

The `PARTICIPATION_CONTRACT.md` D3 rule on the reference verifiers applies **identically** to
these two evaluators. A participant may:

- **read** the evaluator sources, and this contract;
- **run** them as an external process or diagnostic oracle against their own artifacts.

A participant may **not** import, vendor, port or adapt evaluator source into their own qualifying
evaluation path. The reason is unchanged from D3: an implementation that reuses ours measures our
reconciliation logic twice, not two implementations once.

## 10. What a clean run would and would not establish

**Would establish:** that two separately authored bundle-level reconciliation implementations,
each composed over its own frozen class verifier, agree on the Level-1 verdict for all twelve
scenarios — and, with the participant lane, that a third independent implementation agrees.

**Would not establish:** that the reconciliation semantics are correct; that the frozen class
verifiers are correct; that the corpus covers the reconciliation failure space; or that any
real-world AIREP bundle is truthful. As with the class-verifier phase, agreement between the two
reference evaluators is consistent with separate authoring but is not proof of it.

## 11. Out of scope

Producers; any change to the frozen class verifiers, their contract, or the accepted schemas;
SCITT anchoring; the AuthZEN case; lifecycle completeness beyond the four artifacts of a bundle;
and any new artifact family.

## 12. Erratum 1 — record

Applied 2026-08-28 after isolated dual authoring against contract basis
`a792d4eb1150664b95e3ee10eb09ed12396466c2`. **That basis is not rewritten.** Both pre-erratum
evaluator branches are frozen as provenance:

| Lane | Frozen head |
|---|---|
| Python | `8c5f444d572765a0d4a6ff966783b67ba4620d97` |
| Node | `da22e066a6aceaa72b9bda2fb8813205120fe0ff` |

**What those branches are.** They are **not** the official evaluators. They are the preserved
record of how two isolated authoring contexts responded to the same specification defects. Four
ambiguities were surfaced **independently by both** — the §7.2 cross-lane condition, the
`verifier_digests` contradiction, the missing manifest encoding, and the non-`MEASURED` predicate
gap. That is recorded as *two isolated authoring contexts independently surfaced the same
specification ambiguities*. **It is not evidence that the implementations are independent**, and
must not be reported as such.

The manifest gap was not merely flagged, it was measured: no manifest encoding existed that both
lanes would accept. Had the corpus been built first, the official run would have failed at bundle
load and the fixtures would have taken the blame.

Eight corrections, closed together:

| # | Correction |
|---|---|
| 1 | §7.2's cross-lane envelope condition removed entirely — aggregate gate only |
| 2 | §8.2.1 — each lane asserts its own verifier digest plus the frozen contract digest; the peer digest does not appear in evaluator output |
| 3 | §8.2.2 — machine-readable `nonmeasurement` object, closed reason registry, `json_pointer` mandatory on a numeric violation |
| 4 | §5 — manifest encoding pinned exactly |
| 5 | §5 — bundle shape pinned; `head_witness` absent from every official W1 bundle |
| 6 | §8.2.3 — `predicates` and `level1` are `null` when not `MEASURED`; `NOT_APPLICABLE` only inside a measured single-artifact result |
| 7 | §5.1 — the numeric bound is on integral **value**, so `1e20` is rejected |
| 8 | §8.1 — aggregate harness duties pinned: twelve fixed invocations, cross-lane envelope equality, cross-lane verifier identity, expected predicate matrix |

**R-A is unchanged** and deliberately narrow: unique reference resolution, no artifact-family check.

### `NODE-IMP-1` — implementation defect, not a contract defect

The Node lane's adversarial review found that `new URL(import.meta.url).pathname` is
percent-encoded, so on a repository path containing a literal space the direct-invocation guard was
false and the program exited **`0` with empty stdout** — the one output §8.5 cannot defend against,
since exit `0` asserts a measured result while stdout carries none.

The pre-erratum source is **not** touched. Remediation belongs to the post-erratum Node context:
use `fileURLToPath` or an equivalent safe conversion, and add a regression case whose path contains
a literal space. **`exit 0` with empty stdout is unacceptable under every condition.**

### Erratum 1 — final closure (2026-08-29)

Five residual seams closed on top of `7a3d278`, which is preserved rather than rewritten. Each was
a place two remediation authors could still have decided differently.

| # | Seam | Closure |
|---|---|---|
| 1 | The manifest file itself was unnamed, and "every file the bundle ships" implied self-hashing | `manifest.json` at bundle root; `files[]` covers every regular file **except** it; symlinks forbidden; `sha256` is bare 64 lowercase hex; official W1 operator-input composition pinned with **no `clock`** |
| 2 | Three real failures had no reason | `bundle-file-missing`, `bundle-json-invalid`, `internal-error` added; `nonmeasurement` closed; status pairing pinned — `authenticated-withheld` alone is `MEASUREMENT_INVALID` |
| 3 | §8.5 put "required artifact absent" on the exit-`1` side, contradicting its own identity rule | exit `1` is exactly the three no-identity conditions; everything after identity is exit `3` with a named reason |
| 4 | `artifacts[]` was mandatory but unproducible before invocation | full preflight precedes any invocation; pre-invocation `ERROR` → `artifacts: []`; afterwards only attempted invocations; `MEASURED` count must match bundle shape |
| 5 | The aggregate gate never checked Level-1 itself | fifth duty: cross-lane Level-1 parity **and** equality with the frozen per-scenario expectation |

Seam 5 is the one with teeth. The four earlier duties would have passed a run in which the two
lanes returned opposite Level-1 verdicts for a single-artifact scenario, because its predicates are
all `NOT_APPLICABLE` and nothing else compared the verdicts. Level-1 is the qualifying result, so
it is now compared directly.

Erratum 1 also moved a self-asserted status line from `DRAFT — awaiting maintainer acceptance` to
`ACCEPTED FOR POST-ERRATUM REMEDIATION`. **That line no longer exists** — `E8-6` removed
self-asserted lifecycle state from this document entirely, because a blob that declares its own
canonical status is either wrong when pinned or unreviewed when corrected. Canonical status is
established externally; §13 governs what may proceed.

### Erratum 2 — record (2026-08-29)

Raised by **two isolated post-erratum remediation contexts**, working from their own pre-erratum
lineages plus the canonical contract, neither able to see the other. Both are frozen as
**pre-Erratum-2 remediation evidence** — they are *not* official evaluator identities:

| Lane | Pre-erratum lineage | Remediation candidate |
|---|---|---|
| Python | `8c5f444d572765a0d4a6ff966783b67ba4620d97` | `57c4a113883098ac7d5b033e16aed7f74f2e876f` |
| Node | `da22e066a6aceaa72b9bda2fb8813205120fe0ff` | `801a1dc1a056ab65e20d735c83cf04a28c1fb45d` |

**What the round established, stated exactly:**

> Two isolated remediation contexts independently surfaced the same two residual specification
> gaps; one gap produced divergent implementation choices before measurement.

That is **not** "implementation independence proven" and **not** parity evidence. Official parity
does not exist until the corpus runs.

| # | Gap | Both lanes? | Outcome |
|---|---|---|---|
| 1 | bundle-layout failures had no registry row | yes — **same** resolution | `manifest-invalid`, now enumerated normatively |
| 2 | abnormal frozen runs had no registry row | yes — **divergent** resolutions (`internal-error` vs `verifier-run-invalid`) | `verifier-run-invalid`, pinned |
| 3 | `artifacts[]` required a semantic `record_id` an unidentifiable artifact may lack | Node only | `AD15-IR-5` |

Gap 2 is the one this round existed to catch. Both lanes were internally consistent and would have
passed their own tests; they would have disagreed on `nonmeasurement.reason` for a frozen `exit 2`
**without changing any Level-1 verdict**, so all five aggregate duties would have passed while the
lanes disagreed underneath.

**`NODE-IMP-1`** remains an implementation defect, not a contract one. The Node context additionally
found a second route to the same failure — an async `process.stdout.write` followed by
`process.exit()` can truncate on a pipe. Both must stay closed in the official Node evaluator, with
the pipe-backed stdout regression retained alongside the literal-space path regression.

### Erratum 3 — record (2026-08-29)

Raised by two isolated **micro-remediation** contexts working from their own Erratum-2 candidates
plus the canonical contract. Both candidates are frozen as **pre-Erratum-3 micro-remediation
evidence** — not official evaluator identities:

| Lane | Erratum-2 candidate | Micro-remediation candidate |
|---|---|---|
| Python | `57c4a113883098ac7d5b033e16aed7f74f2e876f` | `4cc3773e1b27b85f889717afe5f2ba8121fd2a09` |
| Node | `801a1dc1a056ab65e20d735c83cf04a28c1fb45d` | `4b14328d67ea36f7657db8b3b4765bf3e187e639` |

| # | Change | Raised by |
|---|---|---|
| E3-1 | `AD15-IR-6` — `related_artifacts` ordering moves to `artifact_path` | **both lanes, divergent resolutions** |
| E3-2 | `bundle-file-unreadable` added; the four filesystem reasons bounded exactly | Python |
| E3-3 | manifest wrong-name/location removed from `manifest-invalid`; no discovery is performed | Python |
| E3-4 | `--help` pinned as a CLI meta-action outside the evaluation exit table | Python |
| — | `W1-CORPUS-IR-1` in the corpus contract | Python |

**On what E3-1 would have cost.** Both lanes stayed green on their own tests while resolving the
same gap differently — one sorted an unidentifiable artifact under an empty key, the other refused
to build the envelope. That is **not** a green qualification hiding a disagreement: differing
`related_artifacts` order changes `request_envelope_digest`, and aggregate duty 2 compares exactly
that. The real cost would have been a **first official run going non-qualifying on contract
ambiguity** rather than on anything either implementation did wrong. The distinction matters,
because Erratum 2's gap 2 *was* invisible to all five duties — it changed neither envelope bytes
nor Level-1 — and these two failures are not the same shape.

Both lanes also independently found and fixed the same real bug unprompted: a `files[]` entry whose
target exists but is the wrong kind was returning `bundle-file-missing`, when nothing is missing.

**`observer_assessment` needs no erratum and the open item is closed.** The frozen verdict envelope
makes it a required member over a closed enum, so an exit-0 result lacking it is a wrong-shape
frozen result, which Erratum 2 already routes to `verifier-run-invalid`. Adding missing-value
semantics to R-C would mean accepting malformed frozen output as ordinary semantic input.

### Erratum 4 — record (2026-08-29)

Raised by the final micro-remediation round. Both candidates are frozen as evidence, not identities:

| Lane | Erratum-3 candidate | Final candidate (r1) |
|---|---|---|
| Python | `4cc3773e1b27b85f889717afe5f2ba8121fd2a09` | `0d05975caacd4624e201c67b0f7ccd0abf648d26` |
| Node | `4b14328d67ea36f7657db8b3b4765bf3e187e639` | `c801d5058c5538de0fd0fb414a68041538806f0e` |

**The three findings have different evidential strengths, and conflating them would overstate two
of them:**

| Finding | Strength | Reach |
|---|---|---|
| `-h` spelling | **measured cross-lane divergence** — Python exit 2 / Node exit 0, both from the same sentence | **unreachable** by the official harness, which never invokes help |
| directory enumeration failure | **convergent inferred resolution** — both lanes reached `manifest-invalid` and both recorded discomfort | contract was silent; now pinned |
| duplicate-`record_id` preflight | **source-contract boundary ruling** — one lane removed a gate its own reading of §5/§8.2.2 forbade | confirmed by `AD15-IR-7` |

Only the first is a measurement. The second is two implementers inferring the same thing from
silence, which is weaker evidence than agreement under a rule. The third is a reading of existing
text, not a new observation.

| # | Change |
|---|---|
| E4-1 | help carve-out is one exact single-token invocation; `-h` is a usage error; `--help` with other arguments is not a meta-action; help content is not a parity requirement |
| E4-2 | identity boundary is a direct read of `DIR/manifest.json`; five listed conditions all yield exit 1 with no result object; the root manifest never yields `bundle-file-unreadable` |
| E4-3 | `bundle-directory-unreadable` added — the layout could not be *measured*, as distinct from being *wrong* |
| E4-4 | `AD15-IR-7` — duplicate semantic IDs are not preflight invalidity; frozen `R-10` stays a batch-verifier output invariant |

Also worth recording as method: the Node lane found that its **own prior ordering fixture measured
nothing** — with the outlier `record_id` on one artifact, the remaining three ordered identically
under both keys depending on which was primary. Both lanes now make `record_id` rank the exact
reverse of `artifact_path` rank, so the test cannot pass under the wrong key. A test that passes
with and without the fix is not a test.

### Erratum 5 — record (2026-08-29)

Raised by the last remediation round. Both candidates are frozen as evidence, not identities:

| Lane | r1 | **r2** |
|---|---|---|
| Python | `0d05975caacd4624e201c67b0f7ccd0abf648d26` | `8af0227344ee64cb5053454a6661d5f3c4e6453b` |
| Node | `c801d5058c5538de0fd0fb414a68041538806f0e` | `7c873428f54d2707d414492eeb931e565a3f04bc` |

| # | Change | Raised by |
|---|---|---|
| E5-1 | `AD15-IR-8` — identity establishment is monotonic; the `0o111` case is `bundle-directory-unreadable` at exit 3 | **both lanes; measured identical** |
| E5-2 | the stale "three conditions" restatement replaced by a reference to §5 | Python |
| E5-3 | `bundle-entry-uninspectable` — the last gap in the filesystem taxonomy | Python |
| E5-4 | `frozen-identity-unreadable`, nullable `verifier_digests`, and a pinned frozen-identity preflight order | Python |
| E5-5 | §7.1's expected-tier dependency removed; the rule is scenario-independent | Python |

**On E5-1's evidential weight.** Both lanes resolved the `0o111` overlap identically and were
*measured* doing so on the same bundle. That is convergence **under a rule** — §8.5's dividing-line
sentence — which is stronger than the convergence-from-silence recorded in Erratum 4. It remains
**development evidence, not official parity**; official parity does not exist until the corpus runs.

**On E5-5.** The removed wording required the evaluator to know what a scenario *expected*. A
measuring instrument that consults an expected-outcome oracle is not measuring. The replacement
needs no table and is sound on this surface only because the mandatory twelve are built so that an
`authenticated_withheld` result can only mean the infrastructure failed.

**On E5-2, and the pattern behind it.** This is the third restated list in this contract to drift
from the rule it restated — §13's step numbering, the §8.5 exit-1 row, and now the exit-1 band
sentence. Each was written to help a reader and each became a second source of truth. Where a rule
already exists, reference it.

**No corpus-contract change.** The mandatory twelve and the expected matrix are unaffected.

### Erratum 6 — record (2026-08-29)

Raised by the closure remediation round. Both candidates are frozen as evidence, not identities:

| Lane | r2 | **r3 (closure)** |
|---|---|---|
| Python | `8af0227344ee64cb5053454a6661d5f3c4e6453b` | `41516a292bf07b4c7875c2e370dd2fcb1396a20a` |
| Node | `7c873428f54d2707d414492eeb931e565a3f04bc` | `809c610840a841531ade33fb077d29afb49343f0` |

| # | Change | Raised by |
|---|---|---|
| E6-1 | `AD15-IR-9` — an enumeration-time type hint is not kind evidence; a no-follow metadata lookup is mandatory | **measured divergence between the lanes** |
| E6-2 | `AD15-IR-10` — §7.2 run validity is evaluated before §7.1 tier withheld | Node raised; both lanes already conform |
| E6-3 | `AD15-IR-11` — a spawn failure contributes no `artifacts[]` entry; "attempted" means a concrete process result | **both lanes; identical resolution** |

**On E6-1, the only blocker.** Erratum 5's convergences were reached *from the contract text*. This
one is the reverse: the lanes diverged, and the divergence was visible only because it was measured
on a constructed filesystem state rather than argued from source. "`lstat` **or equivalent**" read
as one rule to one lane and a different rule to the other, and neither reading was unreasonable.
The defect is in the contract, not in either implementation.

It is also the first W1 defect that is not about semantics. No Level-1 value moves. What moves is
whether two conforming evaluators produce the same reason for the same input — and on a
cross-platform surface, "the same input" has to include the filesystem underneath it.

**On E6-3, and what it says about the process.** Both lanes reached the same resolution
independently, and both flagged the ambiguity rather than resolving it silently. That is what the
participation contract asks for, and it is why this ruling is a confirmation rather than a choice
between two candidate readings.

**Evidence narrowing — Node selftest counts.** The Node selftest skips its live frozen-verifier
block when `verifier_node_r2/node_modules` is not materialized, and its summary reports only
`X/Y checks passed`, with skipped blocks absent from both numbers. Earlier Node green counts
therefore attest only to the checks that actually executed:

> **`NODE INTEROP SELFTEST COUNTS — PARTIAL WHERE LIVE VERIFIER DEPS WERE NOT MATERIALIZED`**

This invalidates no prior W1 step: no `-official`, `-r1` or `-r2` ref was ever an official evaluator
identity, and `MEASURED END-TO-END PATH` has never been claimed. It narrows what those counts prove.
The gap surfaced when the r3 Node candidate materialized the dependencies before measuring, and the
`AD15-IR-6` fixture was among the checks inside the previously skipped block. Exact per-run figures
belong to that run's own provenance record, not to this contract. §13 closes the class.

**No corpus-contract change.** The mandatory twelve and the expected matrix are unaffected.

### Erratum 7 — record (2026-08-29)

Raised by a **pre-pin adversarial review** rather than by a remediation round — the first erratum in
this chain found before the lanes implemented against it. Both Erratum-6 candidates are frozen as
evidence, not identities:

| Lane | r3 (closure) | **Erratum-6 remediation** |
|---|---|---|
| Python | `41516a292bf07b4c7875c2e370dd2fcb1396a20a` | `e6d0bed831bd43b2b4dc9a3276e05562749bf51e` |
| Node | `809c610840a841531ade33fb077d29afb49343f0` | `4babeb4a809f45ed4e2e9bbe1f530ef2d0a82651` |

| # | Change | Raised by |
|---|---|---|
| E7-1 | `AD15-IR-12` — canonical invocation order and fatal-run fail-fast | adversarial review |
| E7-2 | `AD15-IR-13` — total failure precedence: a canonical stage pipeline with barriers, a within-stage tie-break, and deterministic traversal order | adversarial review |
| E7-3 | the top-level `artifacts` field description stopped asserting one entry per bundle artifact | adversarial review |
| E7-4 | the `ERROR` prose stopped claiming every non-withheld reason failed before any attempt | adversarial review |
| E7-5 | the `AD15-IR-9` evidence record narrowed to what its own source review established | adversarial review |
| E7-6 | per-run selftest figures removed from the normative text | adversarial review |
| E7-7 | `AD15-IR-14` — a post-identity operator assertion mismatch is result-bearing | Python lane's declared open ambiguity |
| E7-8 | `AD15-IR-15` — abnormal process termination records a null exit code and null result; no signal name or synthesized code enters a **normative** field (see E7-14) | pre-pin review |
| E7-9 | intra-stage precedence is by **mechanism then path**, every failure carries a key, and stage 11 is carved out as sequential | pre-pin review |
| E7-10 | the canonical traversal key is **raw bytes**, not a decoded string; non-UTF-8 entry names and unpaired surrogates in manifest paths are pinned | pre-pin review |
| E7-11 | §8.7 made exhaustive, with a **fail-closed default** and `evaluator_version` declared lane-specific | pre-pin review |
| E7-12 | "mandatory test block executed" given a criterion: a declared registry, with unexecuted entries reported as skipped | pre-pin review |
| E7-13 | §8.6's totality claim scoped honestly around `internal-error`; §8.4 scoped to repeat determinism, not cross-lane | pre-pin review |
| E7-14 | `AD15-IR-15`'s signal prohibition scoped to **normative fields**; `detail` may carry the signal. It had forbidden what its next sentence required | pre-pin review, **second pass** |
| E7-15 | a **third tie-break level**: where a reason carries a `json_pointer`, ascending byte order of the pointer decides. Two bad numbers in one file shared a stage, a reason and a path | pre-pin review, second pass |
| E7-16 | §8.4's "ordering of **any** collection is by UTF-8 byte order" narrowed to JSON-string identifiers, with filesystem entries explicitly excepted | pre-pin review, second pass |
| E7-17 | §8.7's fail-closed default confined to the **result object**; lane self-test totals declared diagnostic | pre-pin review, second pass |
| E7-18 | an unpaired surrogate anywhere in a parsed **listed artifact or operator-input document** is `bundle-json-invalid` at stage 8; repair by substitution is forbidden. Strict JSON admits it, RFC 8785 cannot canonicalize it | pre-pin review, **third pass** |
| E7-19 | `json_pointer` pinned to RFC 6901 **against the file the violation is in**, never the envelope — the two bases give different normative strings | pre-pin review, third pass |
| E7-20 | the precedence rule called itself "two-level" while listing three; the E7-8 record row still carried the unconditional signal prohibition | pre-pin review, third pass |
| E7-21 | stage 8 narrowed away from "canonicalizability" in general; §5.1 numeric failures stay at stage 10 with their pointer. The broad wording had silently captured `1e400` | pre-pin review, **fourth pass** |
| E7-30 | the five-tuple's locator scoped to **where it is emitted**. Pass 7 required an assignment per `(stage, reason)`; pass 8 showed that table was not total *and* that none of its locators is emitted. §8.2.2 permits `json_pointer` for `numeric-preflight-violation` alone, so every other intra-reason selection is unobservable and is now an explicit exemption | pre-pin review, **seventh and eighth passes** |
| E7-34 | the "byte-identical result objects" claim corrected to "identical on the §8.7 parity surface" — `detail` and `evaluator_version` legitimately differ — and the key described as three components plus a conditional fourth rather than a five-tuple whose last two are undefined for almost every reason | pre-pin review, **ninth pass** |
| E7-33 | `W1-BLK-JCS` extended to require the stage-8/stage-10 boundary discrimination — that `1e400` is a stage-10 `numeric-preflight-violation` with its pointer, not a stage-8 `bundle-json-invalid` | pre-pin review, eighth pass |
| E7-31 | `W1-BLK-IR16` and `W1-BLK-IR17` added to the closed block set; adding two rulings without extending it had left both untestable | pre-pin review, seventh pass |
| E7-32 | two operative "raw bytes" restatements and the "three-level" framing corrected after the platform-neutral key and the five-tuple replaced them; `AD15-IR-15`'s normal-exit row now covers exit `2` | pre-pin review, seventh pass |
| E7-28 | `AD15-IR-16` — `withheld_reasons` entry shape pinned. A lane had chosen one for itself while the member sat outside the parity surface; §8.7 had just moved it inside | **declared-ambiguity sweep** (lane A5) |
| E7-29 | `AD15-IR-17` — duplicate **manifest** member names pinned. E7-22 closed this for artifact files at stage 8; the manifest is read earlier, and a lane was relying on its runtime's last-wins default | **declared-ambiguity sweep** (lane A8) |
| E7-23 | `AD15-IR-15` restated as a **three-outcome table**; the surviving "same shape as `AD15-IR-11`" sentence removed. Abnormal termination is the absence of an exit code, **not** of a process attempt | maintainer |
| E7-24 | the traversal key made **platform-neutral** — raw bytes where the API gives them, the exact Unicode-native name UTF-8-encoded otherwise, normalization forbidden. "Raw bytes the OS returns" was a POSIX-only rule | maintainer |
| E7-25 | the parity surface bounded by a **closed result member set**; an unknown machine-readable member is schema-invalid, not implicitly normative. Diagnostics, signal names, OS error strings and timing explicitly excluded | maintainer |
| E7-26 | precedence completed with a canonical locator, originally as a five-tuple; "the first one I encountered" forbidden at every key. **Superseded by E7-30**, which reduced the key to three components plus a conditional `json_pointer` | maintainer |
| E7-27 | mandatory-block IDs **pinned by this contract** rather than self-declared, with execution proved by counter increment plus completion record, and unknown/duplicate IDs making a run non-qualifying | maintainer |
| E7-22 | RFC 8785's input domain closed as an explicit three-row table. **Duplicate object member names** had no treatment at all — two lanes could canonicalize `{"k":1}` and `{"k":2}` from the same file and emit different `request_envelope_digest` values while both reporting success | pre-pin review, **fifth pass** |

**On E7-2, and why it is the largest change here.** Every erratum before this one ordered failures
*pairwise*, as divergences surfaced. That method cannot converge: each unordered pair is a latent
divergence, and the lanes cannot find them without implementing first, which costs a full round
each time. §8.6 replaces it with a total order over stages, with the barriers stated explicitly
because the barriers — not the stage list — are what make a multi-fault bundle single-valued.

**On E7-1.** `AD15-IR-11` closed what a spawn failure contributes and, in doing so, made two
previously invisible things observable: invocation order and the continue-or-abort policy. A ruling
that makes something observable inherits the duty to pin it.

**On the pre-pin review, and what it caught.** Erratum 6 was reviewed *after* it was pinned, and two
of its own defects (E7-3, E7-5) were found there. From this erratum onward a full-contract
adversarial pass runs **before** a canonical SHA is requested. It paid for itself on its first run:
E7-8 through E7-13 are all defects **in the Erratum 7 candidate itself**, three of them rated
blocking, found before either lane implemented against them. Every one would otherwise have cost a
remediation round to discover.

The second pass then found that **the closures had introduced three new blocking defects of their
own** (E7-14 through E7-16). That is the more useful lesson: a fix to a normative document is new
normative text and inherits the same review duty as the text it replaces. E7-14 is the sharpest
case — a prohibition whose very next sentence required what it forbade, written while closing a
finding about contradictory requirements. Review therefore runs until a pass returns no blocker, not
once per erratum.

Later passes found more of the same kind — a rule announcing itself as two-level while enumerating
three, a record row still carrying a prohibition the text had already scoped, a narrowing whose
wording silently captured a neighbouring stage — alongside genuine holes no earlier pass had reached
(E7-18, E7-19, E7-22). The pattern held across every round and is worth stating plainly: **roughly
half of what each pass finds was introduced by the previous pass's closures.** That is not an
argument against closing findings. It is the measured cost of editing a normative document, and it
is why the pin waits for a pass that returns nothing rather than for a fixed number of passes.

The deepest defect in this erratum was found last. **Duplicate object member names** (E7-22) had no
treatment anywhere: RFC 8785 excludes them from its input domain, strict JSON parsers disagree about
them, and two lanes could have canonicalized `{"k":1}` and `{"k":2}` from the same bytes and emitted
different `request_envelope_digest` values **while both reported success**. That is the worst class
of defect this contract can carry — not a divergent error, but divergent evidence over identical
input with no error raised. Four passes read past it. It is the reason §5 now closes RFC 8785's
input domain as an explicit table rather than describing it in prose. The pass reads the whole document rather than the diff — restatement sweep, declared-open-ambiguity sweep, total precedence,
filesystem and process fault matrix, result-shape contradictions, and test vacuity. That is a
working process, deliberately **not** written into this contract as methodology: a contract that
carries its own development history becomes a second source of truth, which is the defect this
chain keeps paying for.

**On §8.7.** The normative surface is stated so a divergence report has to establish that it moves
something observable before it blocks a freeze. Without that boundary, review over invalid-input
space does not terminate. It is an addition beyond the six review findings and the lane's ambiguity,
made because `AD15-IR-13` is otherwise unbounded in scope.

**Numbering note.** §8.6 and §8.7 are appended rather than inserted so that no existing
cross-reference to §8.4 or §8.5 is renumbered.

**No corpus-contract change.** The mandatory twelve and the expected matrix are unaffected.

### Erratum 7 round three — record (2026-08-30)

Raised by **maintainer canonical source review** of the round-two candidate
`f546d2bc3fff0335a9d245e78cd6de7ac1091651`, which is preserved unchanged as round-two provenance.

| # | Change | Raised by |
|---|---|---|
| E7-SR-1 | §8.7's binary model replaced by **four classes** — cross-lane equality, lane-local assertion, audit-only, diagnostic-only — plus the `scenario_id` four-point binding, the closed projection, and harness **duty 6** comparing its RFC 8785 canonical bytes | maintainer source review |
| E7-SR-2 | `AD15-IR-18` — one closed `artifact_ref` projection, total over every JSON value, with its source pinned per process outcome | maintainer source review |
| E7-SR-3 | `AD15-IR-19` lexical path grammar; `AD15-IR-20` closed JSON byte domain; `AD15-IR-17` restricted to a **top-level** duplicate `scenario_id` | maintainer source review |
| E7-SR-N1 | the empty-set path-key claim corrected — a pathless whole-bundle violation uses the empty byte string | maintainer source review |

**On E7-SR-1, which is the substantive one.** The binary model was not merely incomplete, it was
**contradictory**: it declared every `artifacts[]` field and all of `verifier_digests` normative,
while `verifier_stderr_digest` and each lane's own class-verifier digest are *expected* to differ —
the two frozen verifiers are different programs. A lane obeying it literally would have failed a
conforming peer. It also omitted `scenario_id`, so the scenario label itself was never compared, and
no duty compared the complete projection: duties 2, 4 and 5 each check one field, leaving
`nonmeasurement.reason`, `artifacts[]` membership and `artifact_ref` uncompared across lanes.

**On comparing a projection rather than listing fields.** Field-by-field duties grow by one entry per
erratum and silently omit whatever nobody thought of. A closed projection compared as RFC 8785
canonical bytes inverts that: anything inside it is compared by construction, and anything a lane
adds is an unknown member and therefore invalid rather than quietly uncompared.

| E7-SR-4 | `W1-BLK-PARITY` made **peer-safe and satisfiable**: the cross-lane comparison is harness duty 6, the per-lane block proves the projection is invariant under Class-3/Class-4 substitution and moves under any Class-1 change. The mandatory stderr-digest inequality was **unsatisfiable** — both frozen verifiers write stderr only in usage/invalid branches, so on a normal verdict both digests are SHA-256 of the empty string | pre-pin review |
| E7-SR-9 | the E7-SR-8 correction had **over-narrowed**: it claimed the qualifying stage-0 `exit 1` was the only outcome that could carry a schema-invalid ID, which §7.2 (qualifying only for `IOP-B-DEC`/`CTL`/`EFF`) and `AD15-IR-15` (death can precede stage 0) both falsify. Source-selection testing is now organised by **source, defined by exclusion**, not by an outcome list; the Source-A negative gate is named explicitly | pre-pin review |
| E7-SR-8 | `W1-BLK-ARTIFACT-REF`'s full `record_id` × `chain_id` × process-outcome cross-product was **unsatisfiable**: the frozen schema requires both to be strings, so schema-invalid values can never reach an `exit 0` verdict or stage 1. Projection-function totality testing is now separate from reachable process / source-selection testing | maintainer source review |
| E7-SR-7 | the widened definition's Boolean fixed. "Not accepted by A **or** B" parses as rejected by *both*; the rule is rejected by **either**, so it now reads "accepted by both … and …". A stale "the frozen contract does not permit" restatement, which independently excluded the new case, corrected with it | pre-pin review |
| E7-SR-6 | `verifier-run-invalid` widened to cover a shape rejected by **this** contract's result-shape gate, not only the frozen one — the `artifact_ref` closure is a gate W1 adds, and the narrower definition left it with no registry entry; and §8.3.1's field-timing passage corrected, since `artifact_ref` on the `exit 0` path comes from the verdict, not from the artifact | pre-pin review |
| E7-SR-5 | `W1-BLK-IR17` regained "top-level"; §8.4's determinism restatement rewritten to the four-class model — it still said the lanes may differ on `verifier_digests` wholesale, which is now false for `class_verifier_contract`; the exit-0 `artifact_ref` closure pinned **at the result-shape gate** | pre-pin review |

**On E7-SR-4 and E7-SR-8, and what they say about writing tests into a contract.** Both are the same
defect, and E7-SR-8 was written into round three *while closing* E7-SR-4. A test obligation is
normative text and can be wrong in a way prose cannot: prose that overreaches is merely unclear,
whereas a mandatory check that cannot be satisfied makes a **correct** implementation non-qualifying.
Three such rules have now been written and removed — a lane-local block demanding peer material, an
inequality the frozen sources make impossible, and a Cartesian product the frozen schema forbids.
Each was added in the act of demanding more verification.

**On E7-SR-4 specifically.** `W1-BLK-PARITY` as first
written demanded a lane-local runner compare its result against its peer's, in a document whose §4
forbids a lane from seeing its peer. It also demanded an inequality that the frozen sources make
impossible. Both were written while closing a finding about a surface that was not being compared —
the reflex was to demand more comparison, and the check is where that reflex does the most damage,
because an unsatisfiable mandatory block makes a conforming implementation non-qualifying.

**No corpus-contract change.** The mandatory twelve and the expected matrix are unaffected.

## Erratum 8 — record (2026-08-30)

Raised by **maintainer source review of the two Erratum-7 remediation candidates**, both of which are
preserved as historical evidence and are **not** official identities:

| Lane | Erratum-7 candidate |
|---|---|
| Python | `a90e6279a2351953518ae94431ad4af6bb86abea` |
| Node | `1d7b664405d68da0b0d600481be0592d46456e71` |

| # | Change | Raised by |
|---|---|---|
| E8-8 | §13 made **invariant** too. Fixing the header left §13 asserting "Official freeze is held by Erratum 8", "Remaining sequence", and an erratum-named step 2 — the same defect one section down, in the same round. Round-specific expectations moved into this record, which is dated and historical by construction | maintainer source review |
| E8-6 | the header made **invariant**: it no longer self-asserts a lifecycle position at all. `E8-5`'s rewrite still said "not yet canonical" and admitted it "goes stale by design" — which created a self-reference loop, since pinning those bytes would canonicalize a blob claiming not to be canonical, and rewriting the line after review would pin bytes that were never reviewed. Canonical status is now established externally, by the maintainer's pinned commit, blob and digest | maintainer source review |
| E8-7 | `W1-BLK-IR4` stripped of "any envelope change moves it" — an **unprovable universal** over an infinite input domain, and false as a contract invariant because SHA-256 is not injective. It now requires repeat determinism, an independent recomputation of the digest over the actual canonical bytes, and controlled mutations proving the evaluator re-hashes rather than carries a digest forward | maintainer source review |
| E8-5 | the header status line rewritten to defer to §13. It read "post-erratum dual remediation may proceed against this document" — an unconditional authorization that contradicted §13's requirement to canonicalize first, and had survived an earlier sweep because it was checked for erratum-count staleness rather than lifecycle staleness | pre-pin review |
| E8-1 | `withheld_reasons` on a fatal path is the projection of the accepted verdicts **actually retained**; `[]` means none was observed among them, not that none exists | both lanes converged; pinned rather than left to agreement |
| E8-2 | stage 6 carries **two** reasons — a definite `ENOENT` on read is `bundle-file-missing` and outranks `bundle-file-unreadable` | **measured cross-lane divergence** |
| E8-3 | the Source-A `artifact_ref` gate is **required, typed and closed**, not merely closed. W1 requires presence on its own authority — the frozen shape gates do not enumerate it | **measured cross-lane divergence** |
| E8-4 | a gate-rejected `exit 0` object is not a `verifier_result`: null result, Source-B `artifact_ref`, `verifier-run-invalid` | both lanes agree; pinned because the field is Class-1 |

**On E8-2, which is why this erratum exists.** Both lanes' self-tests were entirely green — 347 and
1683 checks, zero failures, zero skips, fifteen mandatory blocks each — and they still emitted
**different Class-1 `nonmeasurement.reason` values for the same filesystem state**: a listed file
present at stage 5 and gone before stage 6. One lane followed §8.2.2's boundary (*"a definite
`ENOENT` on read"* is missing); the other followed §8.6's stage-6 row, which named only
`bundle-file-unreadable`. Both readings were defensible against the text, which is what made it a
contract defect rather than an implementation bug.

**On how it was found, and how it was nearly missed.** The Python lane *declared* this as an open
question. It was reported onward as a declared position and not cross-checked against the peer —
even though a declared open question on a Class-1 field is exactly where a cross-lane comparison
should be run. Green self-tests and a convergence on one field were treated as the headline while a
divergence neither lane had flagged sat unmeasured. The lesson is narrow and worth keeping: **a
lane's declared ambiguity is a divergence candidate, not a footnote.**

**On where lifecycle state is allowed to live.** `E8-6` removed self-asserted state from the header;
the very next pass found §13 doing the same thing — "official freeze is held by", "remaining
sequence", a step naming its own erratum. Two fixes, one section apart, in one round. The rule that
falls out is worth more than either fix: **a pinned artifact may state a fixed order, never a present
position.** Position is external state, carried by the maintainer's pinned commit, blob and digest. A
document that names where it currently stands is wrong the moment the sequence advances — and if it
is corrected afterwards, the bytes that were reviewed are not the bytes that were pinned. Anything
round-specific belongs in that round's erratum record, which is dated and cannot go stale.

**On `E8-7`, and a fourth flavour of unsatisfiable rule.** Three mandatory rules in Erratum 7 were
unsatisfiable because the fixture could not be built — peer material, an impossible inequality, a
forbidden Cartesian cell. `W1-BLK-IR4` was unsatisfiable for a different reason: the fixture is
trivial, but the *proposition* is not provable. "Any envelope change moves the digest" quantifies
over an infinite domain, and is not even true as a contract invariant, since SHA-256 is not
injective. A test obligation can therefore fail in two distinct ways — an impossible fixture, or an
impossible proof — and only the first was being checked for.

**On block coverage, which turned out to be systemic.** Closing the `E8-1` gap prompted a sweep of
every ruling against the registry, and it found the registry began at `W1-BLK-IR9`: **`AD15-IR-4`
through `AD15-IR-8` had no block at all.** Five normative rulings — including `AD15-IR-8`'s `0o111`
worked case, which was a *measured convergence* in Erratum 5 — could each be violated by a lane
while every mandatory block reported green. `E8-4` was uncovered for the same reason. The registry
was built during Erratum 7 and only ever covered the rulings that erratum touched; nothing swept
backwards. It now runs `W1-BLK-IR4` … `W1-BLK-IR8`, `IR9` … `IR17`, `JCS`, `LIVE`, `PARITY`,
`ARTIFACT-REF`, `JSON-BYTES`, `PATH` — **twenty blocks**, and §13 step 1 now makes the sweep part of
every pre-pin pass rather than something remembered.

**On the mandatory blocks, again.** The first draft of this erratum added `E8-1` as a rule and did
not extend `W1-BLK-IR16` to test it — so two lanes could have diverged on a Class-1 field while both
reported every mandatory block green. That is the same defect this record names one paragraph above,
committed in the act of writing it down. Pre-pin review caught it before the candidate was
committed. **A ruling and its block obligation are one change, not two.**

**On E8-1 and E8-4.** Both record agreements, not divergences. They are pinned anyway because both
fields are Class-1: two implementations happening to agree is not a rule, and the next remediation
round has no reason to preserve an agreement the contract never stated.

**Expected remediation surface for this erratum.** Python: `E8-1` through `E8-4`, and the five newly
pinned blocks `W1-BLK-IR4` … `W1-BLK-IR8`; its `E8-2` behaviour is already correct and needs a
discrimination test rather than a change. Node: the same rulings, with `E8-2` and `E8-3` requiring
**behavioural** change. Both lanes carry discrimination tests for all twenty blocks.

**Erratum-7 candidates preserved as evidence, not identities**: Python
`a90e6279a2351953518ae94431ad4af6bb86abea`, Node `1d7b664405d68da0b0d600481be0592d46456e71`, against
the Erratum-7 canonical pin `51c14fe11ae7a94e9c55e30490a754bbe4ccf505`.

**No corpus-contract change.** The mandatory twelve and the expected matrix are unaffected.

## 13. Sequencing (invariant)

**This section states a fixed order, not a present position.** Which step the work currently stands
at is external state, recorded by the maintainer's pinned commit, Git blob identity and SHA-256
record — never by this document. Round-specific expectations belong in that round's erratum record,
which is dated and historical by construction.

**Ref discipline, always true.** No ref in this chain is ever rewritten or deleted, a round's
candidates always take new refs rather than moving an existing one, and every `-official`, `-final`,
`-r1`, `-r2`, `-r3`, `-freeze` and per-erratum candidate ref is preserved. A remediation candidate is
**evidence, not an identity**, until step 10.

The order:

1. **A full-contract adversarial pass runs before a canonical SHA is requested.** It reads the whole
   document, not the diff, and includes a **block-coverage sweep** — every normative ruling must have
   a mandatory block obligation that fails if the ruling is implemented wrongly — and an
   **obligation-satisfiability sweep**, classifying each obligation as buildable-with-finite-proof,
   impossible fixture, or unprovable proposition.
2. **The current erratum is source-reviewed and canonicalized** — the maintainer pins a head and the
   evaluator-contract digest. The corpus contract keeps its own pin unless an erratum changes it.
3. **Python remediation** in a fresh isolated context, on a new ref.
4. **Node remediation** in a fresh isolated context, on a new ref.
5. **Both lanes carry explicit discrimination tests for every pinned block.** A rule that holds by
   accident is not tested.
6. **The Node selftest reports `passed / failed / skipped` and exits non-zero on any skip** in its
   default mode. The official evidence command does not use the developer-only skip opt-in.
7. **Peer material remains invisible** throughout.
8. **The canonical lineage is merged into each branch**, no squash or rewrite.
9. Tests, adversarial review, and **cross-source review of the two candidates against each other**.
   Two lanes have reported fully green self-tests while diverging on a Class-1 field; this step is
   what caught it, and self-test totals cannot replace it.
10. **Official Python and Node evaluator identities are frozen.**
11. **Only then is corpus construction opened.**

A difference blocks step 10 only if it moves something on the Class-1 surface defined in §8.7.

**Corpus bytes remain on HOLD through step 10; step 11 is the only point at which corpus
construction opens.**
