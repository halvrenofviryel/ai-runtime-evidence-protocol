# Reference interop evaluator contract (AD15-IR-2)

Status: **DRAFT — awaiting maintainer acceptance.** No evaluator code and no corpus bytes may be
produced until this contract is accepted.

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

1. invokes **its own** frozen class verifier **as a subprocess** for every artifact, and takes the
   per-artifact schema / hash / signature / class / reason result from that output verbatim;
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

- The manifest object is **closed**: exactly `manifest_version`, `scenario_id`, `files`. Any other
  member is a hard `ERROR`.
- Each `files[]` entry is **closed**: exactly `path`, `role`, `sha256`.
- `role` is drawn from the closed set `artifact` · `bindings` · `independence_policy` ·
  `revocation` · `clock`.
- `files` MUST be sorted ascending by `path` in UTF-8 byte order, and MUST list **every** file the
  bundle ships. A file present on disk but absent from `files` is a hard `ERROR`.
- `path` is bundle-relative and normalized. An absolute path, a path containing a `..` segment, a
  backslash, or a **duplicate** `path` is a hard `ERROR`.

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
- ordering of `related_artifacts` is **ascending UTF-8 byte order of `record_id`**, so the
  envelope is a function of the bundle alone;
- `head_witness` is present only where the scenario defines one, exactly as the bundle carries it.

For a single-artifact scenario (the four positives and the four broken-per-family cases),
`related_artifacts` is the **empty array** — not absent, not populated with unrelated artifacts.

Operator inputs (`--bindings`, `--independence-policy`, `--revocation`, clock inputs) are passed
as the **same bytes** to every artifact in the bundle and to both lanes. An evaluator MUST NOT
synthesize, filter, reorder or re-emit them; it passes through the files the bundle ships.

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
  `(scenario_id, artifact_ref)` pair;
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
is present and well-formed, and the suite is registered. So for any artifact the scenario expects
to reach `AIREP-Authenticated`:

> a **non-empty `authenticated_withheld`** channel ⇒ **measurement-invalid**. The evaluator emits
> **no Level-1 verdict** for that scenario and reports the withheld reasons verbatim.

This is not `REJECT` — nothing was refused — and it is emphatically not `ACCEPT`. It means the
harness or the operator inputs are wrong, and the correct response is to fix them and re-run, not
to score the scenario. Treating it as `ACCEPT` would let a corpus shipped with a broken binding
store report twelve green results while measuring almost nothing, which is the same class of
failure `AD15-IR-2` was raised to prevent.

A measurement-invalid scenario makes the **whole run** non-qualifying: an interop run is a claim
about all twelve, and eleven-plus-one-unmeasured is not that claim.

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
fixed list, never discovered — and enforces four run-level properties no evaluator can:

1. **Completeness.** All twelve invocations returned `measurement_status: MEASURED`. A missing
   result object, a crash, a non-zero exit or a timeout is recorded as a **non-qualifying
   `ERROR`** for that scenario. Silence is never read as success.
2. **Cross-lane envelope equality** (`AD15-IR-4`). For every `(scenario_id, artifact_ref)`, the
   Python and Node `request_envelope_digest` values are equal. A mismatch makes the run
   non-qualifying; it is never translated into any evaluator's exit code.
3. **Cross-lane verifier identity.** Each lane asserted its own frozen verifier digest (§8.2.1)
   and both asserted the same frozen contract digest. The harness sees both trees and checks the
   pair; no evaluator does.
4. **Expected predicate matrix** (§6.1). Each `IOP-R-*` result matches the frozen expectation —
   `CLEAN` all `PASS`; `TOCTOU` fails only `R-B`; `XREF` fails only `R-A`; `INDEP` fails only
   `R-C`. A disagreement is a **finding**, resolved by reading the transformation table, never by
   amending the matrix.

A run failing any of the four is **non-qualifying as a whole**. Eleven measured scenarios plus one
unmeasured is not a claim about twelve.

### 8.2 Result object

- `scenario_id`;
- `measurement_status` — `MEASURED` · `MEASUREMENT_INVALID` (§7.1) · `ERROR` (§7.2);
- `level1` — the Level-1 verdict when `measurement_status` is `MEASURED`; **`null` otherwise**;
- `predicates` — `{ "R_A": …, "R_B": …, "R_C": … }` when `MEASURED`; **`null` otherwise**;
- `nonmeasurement` — `null` when `MEASURED`; **required object otherwise**, shape in §8.2.2;
- `artifacts` — one entry per artifact in the bundle, shape pinned in §8.3;
- `withheld_reasons` — verbatim, whenever any `*_withheld` channel is non-empty;
- `verifier_digests` — this lane's asserted digests only, shape in §8.2.1;
- `evaluator_version`.

#### 8.2.1 `verifier_digests` — own lane only

An earlier draft said "the three asserted digests from §3". That is unsatisfiable: §3 forbids a
lane from touching the other lane's verifier, so no evaluator can assert a digest it is not
permitted to read. Both isolated authors hit this independently.

Each evaluator emits **exactly two** entries, both of which it recomputed itself:

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
not say why. Required shape:

```jsonc
{ "reason": "<closed registry value>",
  "detail": "<short human string, never parsed>",
  "json_pointer": "<RFC 6901>" }        // REQUIRED for numeric-preflight violations
```

Closed reason registry — no value outside it, and no new value without an erratum:

| `reason` | Raised when |
|---|---|
| `manifest-invalid` | manifest absent, unparseable, closure/sort/role violation, bad path |
| `manifest-digest-mismatch` | a shipped file does not match its `files[]` digest |
| `bundle-shape-invalid` | artifact count or family composition outside §5's pinned shape |
| `numeric-preflight-violation` | a number outside §5.1's envelope — **`json_pointer` mandatory** |
| `verifier-digest-mismatch` | a frozen digest assertion failed |
| `verifier-not-invocable` | the frozen verifier could not be executed |
| `verifier-run-invalid` | frozen `exit 1` outside §7.2's two qualifying conditions |
| `authenticated-withheld` | §7.1 — an artifact expected to reach Authenticated was withheld |

`detail` is for a human reading a log. Like stderr, it is never parsed and never influences a
verdict.

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
| `artifact_ref` | object | `record_id`, and `chain_id` where the bundle carries one |
| `request_envelope_digest` | string | `sha256:…` over the §5.1 canonical envelope bytes |
| `verifier_exit_code` | integer | the frozen verifier's exit code, verbatim |
| `verifier_result` | object **or `null`** | the verdict verbatim when one was emitted; **`null` whenever `verifier_exit_code` is 1**, because no verdict exists |
| `verifier_stderr_digest` | string | `sha256:…` over the captured stderr, for audit |

**`stderr` is never a source of semantic classification.** It is hashed for audit and may be
retained alongside the run, but an evaluator MUST NOT parse it, match on it, or let its content
influence any predicate, Level-1 verdict or `measurement_status`. Classification comes from the
exit code and the emitted verdict only. Reading prose to decide a verdict would make the
measurement depend on a surface neither the frozen contract nor this one pins.

### 8.4 Determinism

Identical bundle plus identical operator inputs gives byte-identical output. Ordering of any
collection is by UTF-8 byte order of the relevant identifier — `record_id` for `artifacts[]` —
matching the corpus contract's existing ordering rule.

### 8.5 Process exit and stdout (normative)

§8.1 says one invocation writes exactly one result object. That cannot hold unconditionally: if the
manifest itself will not parse, even `scenario_id` is unknown, so there is nothing to write an
object *about*. Exit code and stdout are therefore pinned together.

| Exit | stdout | Condition |
|---|---|---|
| `0` | **exactly one** result object, `measurement_status: MEASURED`, with a Level-1 verdict | the bundle was measured |
| `1` | **no result object** — stdout empty | bundle/manifest preflight could not be performed: manifest missing or unparseable, bundle identity unknown, a required artifact absent |
| `2` | **no result object** — stdout empty | CLI usage error |
| `3` | **exactly one** result object, `measurement_status: MEASUREMENT_INVALID` or `ERROR`, `level1: null` | bundle identity was parsed, but the scenario could not be measured — verifier digest assertion, frozen verifier not invocable, numeric preflight rejection, a file failing its manifest digest, withheld-when-Authenticated-expected |

The dividing line is **whether bundle identity was established**. Once it is, the evaluator owes a
result object naming the scenario it failed on; before it, it owes silence on stdout and
diagnostics on stderr.

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

## 13. Sequencing

1. This contract is accepted.
2. Both evaluators are authored in isolation and their sources frozen with recorded digests.
3. Only then is corpus construction opened.

**Corpus bytes remain on HOLD until step 3.**
