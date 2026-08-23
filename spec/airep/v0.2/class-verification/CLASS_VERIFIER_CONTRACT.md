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
- `witness_id` is **only** a binding-store lookup key. It is never evidence of independence
  (design §3) and never a substitute for a resolved key.
- The Effect observer path (§3) resolves the Execution artifact through `execution_ref` and
  then its producer binding through the §1.1 map; an unresolved/ambiguous Execution artifact
  yields `observer_assessment = "unknown"`, never `independent`.

## 1. Operator-input JSON formats (network-free, v1)

Three operator inputs. All are local JSON; unknown members are rejected (fail closed); every
identifier is a namespaced id per the accepted grammar `^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$`.

### 1.1 Binding store (`--bindings`)

```jsonc
{
  "bindings": {
    "<binding_id>": {                      // verifier-side binding id (namespaced)
      "subject_identity": "<namespaced id>",  // the identity this binding attests (NOT a wire-carried id)
      "role": "producer" | "witness",
      "public_key_hex": "<64 lowercase hex>", // Ed25519 raw public key
      "suite": "ed25519",                     // from the closed suite registry
      "trusted": true                          // MUST be literally true; anything else = not verifier-accepted
    }
  },
  "artifact_bindings": {                   // which binding signs which producer/witness on the wire
    "<wire_producer_or_witness_id>": "<binding_id>"
  }
}
```

- A binding is **verifier-accepted** iff it exists, `trusted` is literally `true`, `suite` is
  registered, and `public_key_hex` is well-formed. Anything else ⇒ not accepted (§4 withheld).
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
required for Witnessed evaluation; absent ⇒ Witnessed withheld. `--now` makes verdicts
deterministic and is echoed in the evidence (§2).

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
- Results file: `{"verdicts": [ {…}, … ]}` — a **deterministically ordered array**, sorted
  ASCII-ascending by `(chain_id, record_id)`; a **duplicate `(chain_id, record_id)` tuple
  makes the run invalid** (comparator gate). Trailing newline, no metadata, byte-deterministic
  across runs.

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

Worked expectations for the cases the maintainer named explicitly (the rest follow the same
form; the corpus builder derives them from this contract, not from any verifier):

| Case | class | authenticated_failures / _withheld / _caveats | witnessed_failures / _withheld | observer |
|---|---|---|---|---|
| No witness supplied (otherwise clean) | `AIREP-Authenticated` | `[]` / `[]` / `[]` | `[]` / `["no-witness-supplied"]` | per artifact family |
| Producer binding missing | `AIREP-Core` | `[]` / `["producer-binding-missing"]` / `[]` | diagnostic per witness inputs (`["no-witness-supplied"]` when absent) | `unknown` for Effect |
| Partial Witnessed inputs (`--now` absent) | `AIREP-Authenticated` | `[]` / `[]` / `[]` | `[]` / `["freshness-inputs-missing"]` | per family |
| Malformed independence policy | `AIREP-Authenticated` | `[]` / `[]` / `[]` | `[]` / `["independence-policy-malformed"]` | `unknown` for Effect |
| Revoked producer + perfect witness | `AIREP-Core` | `["producer-binding-revoked"]` / `[]` / `[]` | `[]` / `[]` — witness stages evaluated, clean, reported | per family |
| Different keys, no independence relation | `AIREP-Authenticated` | `[]` / `[]` / `[]` | `[]` / `["independence-relation-absent"]` | `unknown` for Effect |
| Explicit non-independent relation | `AIREP-Authenticated` | `[]` / `[]` / `[]` | `["independence-explicitly-denied"]` / `[]` | `unknown` for Effect |

Positives first (an all-negative corpus is insufficient): a clean Authenticated; a clean
Witnessed; a clean Effect with verified-independent observer.

| Group | Cases |
|---|---|
| Producer binding | revoked; missing; not-`trusted`; malformed key/suite; unsupported suite |
| Producer signature | invalid signature; valid signature with wire-`alg` mismatch (CAVEAT, class kept); self-declared revocation (CAVEAT, class kept) |
| Witness binding | revoked; missing; not-`trusted`; malformed; unsupported suite |
| Independence | same resolved key, different binding ids; different keys, **same** `subject_identity`; different keys + identities but **no** policy relation (WITHHELD); explicit `non_independent_pairs` entry (FAILURE); pair listed in both lists (malformed policy) |
| Witness material | malformed claim; forged witness signature; head unresolved; head/claim mismatch |
| Freshness | stale; future beyond window; **boundary-equal (passes)**; `now`/window absent (WITHHELD) |
| Partial operator input | bindings only; bindings+revocation but no independence policy; everything but `--now` |
| Observer | verified independent (pass); different keys without policy relation (→ `unknown`, class unaffected); same-executor declared (accepted as declared) |
| Cross-tier | revoked producer binding on an artifact that also has a perfect witness (ceiling Core; witness channels still evaluated and reported, never silently skipped) |

## 8. Out of scope

Producers; reconciliation (TOCTOU equality, reference resolution, lifecycle completeness —
outside the ladder by design §7); SCITT anchoring (design ODQ-7); N-of-M witness quorum;
online revocation, transparency-log proofs, nonce/challenge freshness; any change to the
frozen integrity construction or the accepted schemas.
