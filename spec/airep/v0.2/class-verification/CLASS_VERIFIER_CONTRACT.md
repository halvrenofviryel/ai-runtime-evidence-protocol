# AIREP v0.2 — Class-Verifier Implementation Contract (contract only)

> **Status: CONTRACT for maintainer review — no class-verifier code exists yet.**
> Spec-before-code, as with every prior stage: the machine output surface and reason vocabulary
> are frozen here, *then* two verifiers are authored independently. Producer implementation
> remains unstarted.
>
> **Frozen inputs (expressed, never re-decided):** the accepted
> [`../conformance-design/CONFORMANCE_CLASS_DESIGN.md`](../conformance-design/CONFORMANCE_CLASS_DESIGN.md)
> (ladder, snapshot revocation, three-condition independence, three-class withheld model,
> sorted reason sets, Stage-4 freshness predicate, trust-policy digest evidence), the frozen
> [`../INTEGRITY.md`](../INTEGRITY.md), and the accepted artifact schemas. A defect found in
> any of those during implementation is a **maintainer finding**, never a silent fix.
>
> **Evidence boundary:** class verification produces provenance/integrity/freshness assurance
> statements only. No class makes a producer honest or any recorded content true.

## 0. Evaluation request envelope (the verifier's evidence input)

The three §1 inputs are **operator policy**; this is the **evidence** the verifier evaluates.
It is a harness/invocation object, **never an AIREP wire artifact**, and it is closed
(unknown members rejected):

```jsonc
{
  "artifact": { … },                     // the primary AIREP artifact under evaluation
  "related_artifacts": [ { … }, … ],     // zero or more AIREP artifacts, for reference resolution
  "head_witness": {                      // optional; absent ⇒ no-witness-supplied (§5)
    "head_ref":   { "record_id": "…", "chain_id": "…" },       // v0.2 artifact-reference semantics; chain_id optional
    "witness_id": "…",                                          // binding lookup key ONLY
    "claim":      { "chain_id": "…", "sequence": N, "current": "sha256:…",
                    "length": N, "witnessed_at": "…" },         // the frozen exact five-member claim
    "signature":  { "alg": "…", "value": "<128 lowhex>" }
  }
}
```

Resolution rules (identical in both implementations):

- **Reference resolution** (`head_ref`, an Effect's `execution_ref`, any `decision_ref` a stage
  needs) searches `artifact` + `related_artifacts` by v0.2 reference semantics: match on
  `record_id`, additionally on `chain_id` when the reference carries one.
- **Zero matches ⇒ unresolved** (`witness-head-unresolved`, or the observer path treats the
  Execution artifact as unavailable ⇒ `unknown`). **More than one match ⇒ ambiguous, fail
  closed** — the same reason as unresolved; a verifier MUST NOT pick one.
- `head_witness.claim` is the frozen five-member claim verbatim (INTEGRITY §4); its structural
  validation is the frozen rule, not a new one.
- `witness_id` is **only** a `witness_bindings` lookup key. It is never evidence of
  independence (design §3) and never a substitute for a resolved key.
- **The witness must witness THIS artifact** (maintainer, 2026-08-23): to earn
  `AIREP-Witnessed`, `head_witness.head_ref` MUST resolve **uniquely to the primary
  `artifact`** itself. Resolving to any `related_artifacts` member is `witness-head-mismatch`
  — a valid witness over some *other* artifact never confers Witnessed on the primary.
  `related_artifacts` exists for context and reference resolution only; it never transports
  another artifact's class.
- The Effect observer path (§3) resolves the Execution artifact through `execution_ref`, then
  **verifies that Execution artifact to Authenticated in its own right** (its schema, frozen
  hash recomputation, producer binding, revocation snapshot and signature), and only then
  compares identities/keys. An unresolved or ambiguous Execution artifact, or one that does not
  itself reach Authenticated, yields `observer_assessment = "unknown"` — never `independent`;
  an attacker-supplied unauthenticated Execution artifact therefore cannot manufacture the
  appearance of independence. The primary Effect artifact's own class is unaffected by this.

## 1. Operator-input JSON formats (network-free, v1)

Three operator inputs. All are local JSON; unknown members are rejected (fail closed).

**Two identifier classes, deliberately different** (maintainer, 2026-08-23): *verifier-side*
identifiers — `binding_id`, `subject_identity`, `snapshot_id`, and the independence-pair
endpoints — MUST match the accepted namespaced grammar
`^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$`. *Wire-carried* ids — `subject.producer` and
`head_witness.witness_id` — are **opaque, exact JSON strings**, compared byte-for-byte and
never constrained: the accepted artifact schema types `subject.producer` as a plain `string`
(verified), and a wire id carries no identity assurance in the first place.

### 1.1 Binding store (`--bindings`)

```jsonc
{
  "bindings": {
    "<binding_id>": {                      // verifier-side binding id (namespaced)
      "subject_identity": "<namespaced id>",  // the identity this binding attests (NOT a wire-carried id)
      "role": "producer" | "witness",
      "public_key_hex": "<64 lowercase hex>", // Ed25519 raw public key
      "suite": "ed25519",                     // from the closed suite registry
      "trusted": true                          // MUST be literally true
    }
  },
  "producer_bindings": { "<opaque wire producer id>": "<binding_id>" },
  "witness_bindings":  { "<opaque wire witness id>":  "<binding_id>" }
}
```

- **Two separate maps, exact lookup** (maintainer, 2026-08-23): the artifact's producer is
  looked up in `producer_bindings` by the exact string `artifact.subject.producer`; the witness
  is looked up in `witness_bindings` by the exact string `head_witness.witness_id`. A binding
  referenced from `producer_bindings` MUST have `role: "producer"` and one referenced from
  `witness_bindings` MUST have `role: "witness"`; otherwise `*-binding-malformed`. A single map
  is forbidden precisely so that the same wire token appearing in both roles is never coerced
  by verifier policy into one identity.
- Binding acceptance outcomes **defer to the registry (§5)**, not to a blanket "withheld":
  absent entry ⇒ `*-binding-missing` (WITHHELD); `trusted` present but not literally `true` ⇒
  `*-binding-not-trusted` (**FAILURE** — the operator policy's definitive negative); `trusted`
  absent, malformed key, wrong `role`, or otherwise ill-formed entry ⇒ `*-binding-malformed`
  (WITHHELD); unregistered `suite` ⇒ `*-suite-unsupported` (WITHHELD).
- `subject_identity` is the verifier's own statement of *who* the binding attests; two
  bindings with different `binding_id` but the same `subject_identity` are **the same
  identity** for independence purposes (§1.2, §3).

### 1.2 Independence policy (`--independence-policy`)

```jsonc
{
  "independent_pairs": [
    { "a": "<binding_id>", "b": "<binding_id>" }   // unordered; explicitly accepted as independent
  ],
  "non_independent_pairs": [
    { "a": "<binding_id>", "b": "<binding_id>" }   // explicitly declared NOT independent
  ]
}
```

- A pair is independent **only** when listed in `independent_pairs`. Absence is *unproven*,
  never independent. Presence in `non_independent_pairs` is a definitive failure, and a pair
  listed in both is a **malformed policy** (fail closed).

### 1.3 Revocation snapshot (`--revocation`)

```jsonc
{
  "snapshot_id": "<namespaced id>",        // names this policy snapshot
  "bindings": { "<binding_id>": { "state": "active" | "revoked" } }
}
```

- State is per **binding_id**, never per wire-carried key id, and carries **no timestamps**:
  the snapshot model deliberately admits no time comparison (design §4).
- A binding required by an evaluation with no entry, or an entry whose `state` is neither
  value, is **missing/malformed** ⇒ that tier is withheld (§4), never passed.

### 1.4 Clock inputs

`--now` (`YYYY-MM-DDTHH:MM:SS(.1-9)?Z`) and `--freshness-window` (integer seconds ≥ 0) are
required for Witnessed evaluation. `--now` makes verdicts deterministic and is echoed in the
evidence (§2). Two distinct outcomes, pinned so the runtimes cannot diverge on parsing
(maintainer, 2026-08-23):

- **Absent** ⇒ Witnessed withheld with `freshness-inputs-missing` (a normal verdict is still
  produced).
- **Present but malformed** — `--now` structurally invalid or not a valid Gregorian datetime,
  or `--freshness-window` non-integer or negative ⇒ **CLI usage/config error: exit 2, no
  verdict emitted**. No new reason code is introduced, and no engine's lenient date parsing
  can leak into a class result.

## 2. Normalized verdict envelope

One object per evaluated artifact:

```jsonc
{
  "artifact_ref": { "chain_id": "…", "record_id": "…" },   // structured, never a concatenated string
  "class": "AIREP-Core" | "AIREP-Authenticated" | "AIREP-Witnessed",
  "authenticated_failures":  ["<reason>", ...],
  "authenticated_withheld":  ["<reason>", ...],
  "authenticated_caveats":   ["<reason>", ...],
  "witnessed_failures":      ["<reason>", ...],
  "witnessed_withheld":      ["<reason>", ...],
  "observer_assessment": "same_executor" | "independent" | "unknown" | "not_applicable",
  "evidence": {
    "now": "<timestamp or null>",
    "freshness_window_seconds": <integer or null>,
    "bindings_digest":    "sha256:<64 lowhex> | null",
    "independence_policy_digest": "sha256:<64 lowhex> | null",
    "revocation_digest":  "sha256:<64 lowhex> | null"
  }
}
```

Rules:

- All five reason arrays are **present always** (empty when nothing applies), each
  deduplicated and ASCII-ascending — sorted sets, not first-decisive (design §6).
- `class` carries exactly one of the three values; no pseudo-class, ever.
- Consistency invariants (verifier MUST satisfy; comparator MUST check): a non-empty
  `authenticated_failures` or `authenticated_withheld` ⇒ `class == AIREP-Core`; a non-empty
  `witnessed_failures` or `witnessed_withheld` ⇒ `class != AIREP-Witnessed`;
  `authenticated_caveats` non-empty ⇒ `class != AIREP-Core`; `class == AIREP-Witnessed` ⇒ all
  four failure/withheld arrays empty.
- `observer_assessment` is `not_applicable` for non-Effect artifacts; for Effect artifacts it
  is the *effective* assessment after §3 (never the raw wire value when that value is
  `independent` and independence is not verified).
- Input digests are the SHA-256 of the exact input file bytes (`null` when that input was not
  supplied), so a verdict names the trust-policy snapshot it came from.
- **Identity is structured, not concatenated:** `chain_id`/`record_id` are free-form core
  strings that may contain `/`, so a `"<chain_id>/<record_id>"` key would be ambiguous. The
  verdict carries the pair as an object.
- Results file: `{"verdicts": [ {…}, … ]}` — a **deterministically ordered array** sorted by
  `(chain_id, record_id)` under **unsigned lexicographic order over each string's UTF-8 byte
  sequence, with no Unicode normalization** (maintainer, 2026-08-23: these are free-form core
  strings that may be non-ASCII, and Python code-point order vs JavaScript UTF-16 order
  diverge on some characters — byte order is the one both runtimes can implement identically).
  A **duplicate `(chain_id, record_id)` tuple makes the run invalid** (comparator gate).
  Trailing newline, no metadata, byte-deterministic across runs. Reason arrays remain
  ASCII-ascending: the registry is ASCII by construction, so the two rules never conflict.

## 3. Evaluation order and dependencies

The **frozen constructions are used, never redesigned**: the class layer invokes the frozen
hash/domain-tag recomputation, the frozen record-signature preimage, and the frozen
head-witness claim/preimage/reconciliation/freshness rules — each **at the tier where the
accepted class design places it**. It does NOT call the Stage-4 artifact verifier program as
one indivisible Core prerequisite: that program's artifact path includes producer binding and
signature verification, and folding it into Core would deny Core to a hash-consistent artifact
that merely lacks a binding, contradicting the accepted design (Core = schema + internal hash
consistency; Authenticated = the signature/binding layer).

**Class-earning path vs diagnostic path (maintainer clarification):** Authenticated not
earned ⇒ **Witnessed can never be earned**. But when the witness-side inputs are locally
present, stages 6–10 still run **diagnostically** and populate `witnessed_failures` /
`witnessed_withheld` — the cross-tier case (revoked producer + a perfect witness) reports
`class = AIREP-Core` **with the witness channels evaluated and reported**, never silently
skipped.

| # | Stage | Outcome |
|---|---|---|
| 0 | Artifact validity: accepted family **schema** validation | Rejection ⇒ **no class at all** (not a well-formed v0.2 artifact); reported as invalid, never as Core |
| 1 | **Core** — frozen hash/domain-tag recomputation over the declared `(airep_version, artifact_type)` pair | Mismatch ⇒ **no class at all** (invalid); success ⇒ `class = AIREP-Core` |
| 2 | Producer binding resolution (§1.1) | not accepted / missing ⇒ `authenticated_withheld` |
| 3 | Producer revocation snapshot (§1.3) | `revoked` ⇒ `authenticated_failures`; missing/malformed ⇒ `authenticated_withheld` |
| 4 | Signature verification over the **frozen record-signature preimage** under the binding-derived suite | invalid ⇒ `authenticated_failures` |
| 5 | **Authenticated** iff 2–4 all clean | `class = AIREP-Authenticated`; self-declared revocation and wire-`alg` mismatch land in `authenticated_caveats` |
| 6 | Witness head resolution + claim reconciliation (frozen §4.3) | unresolved/mismatch ⇒ `witnessed_failures`; no witness present ⇒ `witnessed_withheld` (`no-witness-supplied`) |
| 7 | Witness binding resolution + revocation snapshot | as 2–3, into the `witnessed_*` channels |
| 8 | Independence (§1.2 + design §3, three conditions) | explicit non-independent / same identity / same key ⇒ `witnessed_failures`; policy relation absent ⇒ `witnessed_withheld` |
| 9 | Witness signature verification | invalid ⇒ `witnessed_failures` |
| 10 | Freshness: `abs(now − witnessed_at) <= window` | outside ⇒ `witnessed_failures`; `now`/window absent ⇒ `witnessed_withheld` |
| 11 | **Witnessed** iff 6–10 all clean **and** Authenticated was earned | `class = AIREP-Witnessed` |

Observer assessment (Effect artifacts, evaluated at stage 5 and above): `independent` on the
wire is accepted only when the Effect and Execution producer bindings satisfy the same three
conditions as §1.2/§3; otherwise the effective assessment is `unknown` — and the artifact's
class does not drop for it.

## 4. Withheld vs failure (binding distinction)

- **FAILURE** = a gate ran and produced a definitive negative.
- **WITHHELD** = a gate could not run (missing/malformed operator input, absent witness).
- **CAVEAT** = a gate ran, the tier is earned, and something must nevertheless be surfaced.

A withheld tier never reads as failed and never as passed. Partial operator input never
silently falls back; each unrunnable gate is named.

**Reason dependency rule (maintainer, 2026-08-23 — binding on both implementations).** A gate
whose own required prerequisite is absent or failed **emits no derivative reason at all**
(neither FAILURE nor WITHHELD): the prerequisite's own reason is the complete account. Gates
that do *not* depend on that prerequisite continue to run diagnostically. The dependency graph
is closed and exhaustive:

| Gate (stage) | Required prerequisites |
|---|---|
| producer binding (2) | — |
| producer revocation (3) | producer binding accepted |
| producer signature (4) | producer binding accepted **and** not revoked |
| witness head resolution + reconciliation (6) | `head_witness` present |
| witness binding + revocation (7) | stage 6 clean |
| independence (8) | producer binding accepted **and** witness binding accepted (stage 7 clean) **and** independence policy present |
| witness signature (9) | stage 7 clean |
| freshness (10) | stage 6 clean **and** clock inputs present |

Worked consequences (the exact questions two authors would otherwise answer differently):
producer binding missing ⇒ **no** revocation or signature reason; producer binding revoked ⇒
**no** signature reason; witness binding missing ⇒ **no** independence or witness-signature
reason, while freshness still runs if the claim is valid and the clock is supplied; a
malformed witness claim (stage 6) ⇒ **no** stages 7–10 reasons at all.

## 5. Closed reason registry

Every reason is exactly one `(tier, channel)` pair. No aliases, no free-form strings, no
reason finer than the verifier can actually distinguish (Stage-4 coarseness rule).

| Reason | Tier | Kind |
|---|---|---|
| `producer-binding-missing` | authenticated | WITHHELD |
| `producer-binding-not-trusted` | authenticated | FAILURE |
| `producer-binding-malformed` | authenticated | WITHHELD |
| `producer-suite-unsupported` | authenticated | WITHHELD |
| `producer-revocation-state-missing` | authenticated | WITHHELD |
| `producer-revocation-state-malformed` | authenticated | WITHHELD |
| `producer-binding-revoked` | authenticated | FAILURE |
| `producer-signature-invalid` | authenticated | FAILURE |
| `producer-key-self-revoked` | authenticated | CAVEAT |
| `wire-alg-mismatch` | authenticated | CAVEAT |
| `no-witness-supplied` | witnessed | WITHHELD |
| `witness-binding-missing` | witnessed | WITHHELD |
| `witness-binding-not-trusted` | witnessed | FAILURE |
| `witness-binding-malformed` | witnessed | WITHHELD |
| `witness-suite-unsupported` | witnessed | WITHHELD |
| `witness-revocation-state-missing` | witnessed | WITHHELD |
| `witness-revocation-state-malformed` | witnessed | WITHHELD |
| `independence-policy-missing` | witnessed | WITHHELD |
| `independence-policy-malformed` | witnessed | WITHHELD |
| `independence-relation-absent` | witnessed | WITHHELD |
| `freshness-inputs-missing` | witnessed | WITHHELD |
| `witness-binding-revoked` | witnessed | FAILURE |
| `witness-head-unresolved` | witnessed | FAILURE |
| `witness-head-mismatch` | witnessed | FAILURE |
| `witness-claim-invalid` | witnessed | FAILURE |
| `witness-identity-not-distinct` | witnessed | FAILURE |
| `witness-key-not-distinct` | witnessed | FAILURE |
| `independence-explicitly-denied` | witnessed | FAILURE |
| `witness-signature-invalid` | witnessed | FAILURE |
| `witness-time-invalid` | witnessed | FAILURE |
| `witness-freshness-outside-window` | witnessed | FAILURE |

Adding a reason is a contract change (this table + the adversarial matrix updated together).

Notes fixing three things implementers would otherwise decide:

- **`*-binding-not-trusted` is a FAILURE, not WITHHELD** (maintainer): an entry present with
  `trusted` not literally `true` is the operator policy's explicit, definitive negative — the
  gate ran. A *missing* `trusted` member, or a malformed/absent entry, remains
  `*-binding-malformed` / `*-binding-missing` (WITHHELD): the gate could not run.
- **`witness-freshness-outside-window`** replaces the earlier `witness-stale` name: the pinned
  predicate is symmetric (`abs(now − witnessed_at) <= window`), so past-stale and
  future-beyond-window are one coarse reason — correct under the Stage-4 coarseness rule, and
  the old name mis-described the future case.
- **Caveat sources are pinned, not inferred.** `producer-key-self-revoked` is emitted iff
  `profiles["airep.key-trust"].revocation.revoked === true` on the artifact — profile
  semantics only, which **never** substitute for the external operator revocation snapshot and
  never change the class. `wire-alg-mismatch` is emitted iff the wire
  `integrity.signature.alg`, compared **ASCII case-insensitively**, differs from the
  binding-derived suite id (so wire `"Ed25519"` against binding suite `ed25519` is **not** a
  mismatch); the wire field never selects cryptographic behaviour.

## 6. Parity contract (two independent implementations)

Python and Node class verifiers, authored in **separate fresh contexts** under mandates that
forbid reading each other's source/output, the corpus builder, and any fixture's expected
values. Hard gates, checked by a third comparator independent of both:

1. identical `class` per artifact;
2. identical **sorted reason sets** in all five channels;
3. identical `observer_assessment`;
4. identical exit-code semantics, **pinned exactly** (exit encodes run validity only — never a
   class):
   - `0` — evaluation completed; the presence of FAILURE / WITHHELD / CAVEAT reasons does
     **not** change the exit code;
   - `1` — the evaluation request, an artifact, or an operator file could not be parsed, or
     stage-0/1 artifact validity failed, so no class verdict could be produced;
   - `2` — CLI usage error;
   - `--help` — `0`, with nothing evaluated and no verdict emitted.
   A parseable-but-malformed **tier-relevant** binding / policy / revocation entry becomes a
   registry WITHHELD or FAILURE reason (§5) — never a process failure;
5. identical evidence block (`now`, window, three input digests);
6. verdict-envelope shape gates (all five arrays present, sorted, deduplicated, registry-only
   reasons, class value legal, §2 consistency invariants);
7. each verdict equals the fixture's expected verdict (expected read by the comparator only).

Committed negative proofs MUST show the comparator failing on: a flipped expected class; a
mutated reason set; a §2 invariant violation (e.g. `class=AIREP-Witnessed` with a non-empty
withheld array).

## 7. Minimum adversarial matrix

**Expected outcomes are pinned per case, before implementation.** Every fixture in the corpus
carries an explicit expected `class`, expected contents of **all five** reason channels, and
the expected `observer_assessment`. Case names alone are not a specification.

**Authoring isolation (maintainer rule):** the expected sets are produced in a **third
context** directly from this contract; the two verifier authors never see them. Expected
semantics are therefore never derived backwards from verifier output.

**Complete expected-outcome appendix.** Every case below is pinned here — `class`, the
contents of **all five** channels, and `observer_assessment`. The third-context corpus author
**copies** these; it does not interpret them. Channel contents assume the case's own tamper and
nothing else (all other inputs clean and supplied); reason arrays are shown in their required
ASCII-ascending order, and `—` means the empty array `[]`. `observer` is `not_applicable`
except on Effect artifacts, where it is stated.

Positives are part of the minimum, not an afterthought — an all-negative corpus is
insufficient: **P1–P3** are the clean Authenticated, clean Witnessed, and
verified-independent-observer cases, and **FR3** is the boundary-equal pass.

Legend for the channel columns: `A-fail / A-withheld / A-caveats` and `W-fail / W-withheld`.

| # | Case | class | A-fail / A-withheld / A-caveats | W-fail / W-withheld | observer |
|---|---|---|---|---|---|
| P1 | Clean artifact, no witness supplied | `AIREP-Authenticated` | — / — / — | — / `no-witness-supplied` | `not_applicable` |
| P2 | Clean artifact + clean witness over this artifact | `AIREP-Witnessed` | — / — / — | — / — | `not_applicable` |
| P3 | Clean Effect, verified-independent observer, no witness | `AIREP-Authenticated` | — / — / — | — / `no-witness-supplied` | `independent` |
| PB1 | Producer binding revoked | `AIREP-Core` | `producer-binding-revoked` / — / — | — / `no-witness-supplied` | — |
| PB2 | Producer binding missing | `AIREP-Core` | — / `producer-binding-missing` / — | — / `no-witness-supplied` | — |
| PB3 | Producer binding `trusted` not literally `true` | `AIREP-Core` | `producer-binding-not-trusted` / — / — | — / `no-witness-supplied` | — |
| PB4 | Producer binding malformed (bad key / wrong `role` / no `trusted`) | `AIREP-Core` | — / `producer-binding-malformed` / — | — / `no-witness-supplied` | — |
| PB5 | Producer binding names an unregistered suite | `AIREP-Core` | — / `producer-suite-unsupported` / — | — / `no-witness-supplied` | — |
| PB6 | Producer revocation state absent from the snapshot | `AIREP-Core` | — / `producer-revocation-state-missing` / — | — / `no-witness-supplied` | — |
| PB7 | Producer revocation state malformed | `AIREP-Core` | — / `producer-revocation-state-malformed` / — | — / `no-witness-supplied` | — |
| PS1 | Producer signature invalid | `AIREP-Core` | `producer-signature-invalid` / — / — | — / `no-witness-supplied` | — |
| PS2 | Valid signature, wire `alg` names another suite | `AIREP-Authenticated` | — / — / `wire-alg-mismatch` | — / `no-witness-supplied` | — |
| PS3 | Valid signature, `airep.key-trust` self-declared revocation | `AIREP-Authenticated` | — / — / `producer-key-self-revoked` | — / `no-witness-supplied` | — |
| WB1 | Witness binding revoked | `AIREP-Authenticated` | — / — / — | `witness-binding-revoked` / — | — |
| WB2 | Witness binding missing | `AIREP-Authenticated` | — / — / — | — / `witness-binding-missing` | — |
| WB3 | Witness binding `trusted` not literally `true` | `AIREP-Authenticated` | — / — / — | `witness-binding-not-trusted` / — | — |
| WB4 | Witness binding malformed (bad key / wrong `role` / no `trusted`) | `AIREP-Authenticated` | — / — / — | — / `witness-binding-malformed` | — |
| WB5 | Witness binding names an unregistered suite | `AIREP-Authenticated` | — / — / — | — / `witness-suite-unsupported` | — |
| WB6 | Witness revocation state absent | `AIREP-Authenticated` | — / — / — | — / `witness-revocation-state-missing` | — |
| WB7 | Witness revocation state malformed | `AIREP-Authenticated` | — / — / — | — / `witness-revocation-state-malformed` | — |
| IND1 | Witness and producer resolve to the same public key (different `binding_id`s) | `AIREP-Authenticated` | — / — / — | `witness-key-not-distinct` / — | — |
| IND2 | Different keys, same `subject_identity` | `AIREP-Authenticated` | — / — / — | `witness-identity-not-distinct` / — | — |
| IND3 | Distinct keys and identities, pair absent from the policy | `AIREP-Authenticated` | — / — / — | — / `independence-relation-absent` | — |
| IND4 | Pair listed in `non_independent_pairs` | `AIREP-Authenticated` | — / — / — | `independence-explicitly-denied` / — | — |
| IND5 | Pair listed in **both** lists (malformed policy) | `AIREP-Authenticated` | — / — / — | — / `independence-policy-malformed` | — |
| IND6 | No independence-policy input supplied | `AIREP-Authenticated` | — / — / — | — / `independence-policy-missing` | — |
| WM1 | Witness claim structurally invalid | `AIREP-Authenticated` | — / — / — | `witness-claim-invalid` / — | — |
| WM2 | Witness signature forged/invalid | `AIREP-Authenticated` | — / — / — | `witness-signature-invalid` / — | — |
| WM3 | `head_ref` resolves to nothing | `AIREP-Authenticated` | — / — / — | `witness-head-unresolved` / — | — |
| WM4 | `head_ref` resolves, claim does not reconcile with the head | `AIREP-Authenticated` | — / — / — | `witness-head-mismatch` / — | — |
| WM5 | `head_ref` resolves to a **related** artifact, not the primary | `AIREP-Authenticated` | — / — / — | `witness-head-mismatch` / — | — |
| WM6 | `head_ref` matches two artifacts (ambiguous) | `AIREP-Authenticated` | — / — / — | `witness-head-unresolved` / — | — |
| FR1 | Signed `witnessed_at` older than the window | `AIREP-Authenticated` | — / — / — | `witness-freshness-outside-window` / — | — |
| FR2 | Signed `witnessed_at` beyond the window in the future | `AIREP-Authenticated` | — / — / — | `witness-freshness-outside-window` / — | — |
| FR3 | Distance exactly equal to the window | `AIREP-Witnessed` | — / — / — | — / — | `not_applicable` |
| FR4 | Clock inputs absent | `AIREP-Authenticated` | — / — / — | — / `freshness-inputs-missing` | — |
| PI1 | Only the binding store supplied (no revocation, no policy, no clock) | `AIREP-Core` | — / `producer-revocation-state-missing` / — | — / `freshness-inputs-missing`, `witness-revocation-state-missing` | — |
| PI2 | Bindings + revocation, no independence policy | `AIREP-Authenticated` | — / — / — | — / `independence-policy-missing` | — |
| PI3 | Everything except `--now` | `AIREP-Authenticated` | — / — / — | — / `freshness-inputs-missing` | — |
| OB1 | Effect; Execution Authenticated, identities/keys distinct, policy relation present | `AIREP-Authenticated` | — / — / — | — / `no-witness-supplied` | `independent` |
| OB2 | Effect; distinct keys but no policy relation | `AIREP-Authenticated` | — / — / — | — / `no-witness-supplied` | `unknown` |
| OB3 | Effect declaring `same_executor` | `AIREP-Authenticated` | — / — / — | — / `no-witness-supplied` | `same_executor` |
| OB4 | Effect claiming `independent`; referenced Execution does **not** reach Authenticated | `AIREP-Authenticated` | — / — / — | — / `no-witness-supplied` | `unknown` |
| OB5 | Effect claiming `independent`; `execution_ref` unresolved or ambiguous | `AIREP-Authenticated` | — / — / — | — / `no-witness-supplied` | `unknown` |
| XT1 | Producer binding revoked **and** a clean witness over this artifact | `AIREP-Core` | `producer-binding-revoked` / — / — | — / — | — |

PI1 shows the dependency rule at work: the witness binding stage is withheld for its own
missing revocation state, so independence and witness-signature emit nothing, while freshness
still reports its own missing clock. XT1 shows the diagnostic path: the ceiling is Core, and
the witness channels are nevertheless evaluated and reported clean.

## 8. Out of scope

Producers; reconciliation (TOCTOU equality, reference resolution, lifecycle completeness —
outside the ladder by design §7); SCITT anchoring (design ODQ-7); N-of-M witness quorum;
online revocation, transparency-log proofs, nonce/challenge freshness; any change to the
frozen integrity construction or the accepted schemas.
