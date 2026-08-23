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
  "artifact_id": "<chain_id>/<record_id>",
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
- Results file: `{"verdicts": {"<artifact_id>": {…}}}`, keys sorted, trailing newline, no
  metadata, byte-deterministic across runs.

## 3. Evaluation order and dependencies

Strictly ordered; a stage runs only if its predecessor produced a class contribution. The
**integrity verifier's frozen first-decisive behaviour is unchanged** and sits beneath this
layer — the class layer consumes its verdict, it does not restate or override it.

| # | Stage | Outcome |
|---|---|---|
| 0 | Schema validation + integrity verification (existing frozen layers) | Any rejection ⇒ **no class at all** (the artifact is not a well-formed AIREP artifact); such inputs are reported as invalid, not as Core. |
| 1 | **Core** — schema-valid + integrity-consistent | `class = AIREP-Core` |
| 2 | Producer binding resolution (§1.1) | not accepted / missing ⇒ `authenticated_withheld` |
| 3 | Producer revocation snapshot (§1.3) | `revoked` ⇒ `authenticated_failures`; missing/malformed ⇒ `authenticated_withheld` |
| 4 | Signature verification under the binding-derived suite | invalid ⇒ `authenticated_failures` |
| 5 | **Authenticated** iff 2–4 all clean | `class = AIREP-Authenticated`; self-declared revocation and wire-`alg` mismatch land in `authenticated_caveats` |
| 6 | Witness head resolution + claim reconciliation (frozen §4.3) | unresolved/mismatch ⇒ `witnessed_failures`; no witness present ⇒ `witnessed_withheld` (`no-witness-supplied`) |
| 7 | Witness binding resolution + revocation snapshot | as 2–3, into the `witnessed_*` channels |
| 8 | Independence (§1.2 + design §3, three conditions) | explicit non-independent / same identity / same key ⇒ `witnessed_failures`; policy relation absent ⇒ `witnessed_withheld` |
| 9 | Witness signature verification | invalid ⇒ `witnessed_failures` |
| 10 | Freshness: `abs(now − witnessed_at) <= window` | outside ⇒ `witnessed_failures`; `now`/window absent ⇒ `witnessed_withheld` |
| 11 | **Witnessed** iff 6–10 all clean | `class = AIREP-Witnessed` |

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
| `producer-binding-not-trusted` | authenticated | WITHHELD |
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
| `witness-binding-not-trusted` | witnessed | WITHHELD |
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
| `witness-stale` | witnessed | FAILURE |

Adding a reason is a contract change (this table + the adversarial matrix updated together).

## 6. Parity contract (two independent implementations)

Python and Node class verifiers, authored in **separate fresh contexts** under mandates that
forbid reading each other's source/output, the corpus builder, and any fixture's expected
values. Hard gates, checked by a third comparator independent of both:

1. identical `class` per artifact;
2. identical **sorted reason sets** in all five channels;
3. identical `observer_assessment`;
4. identical exit-code semantics (exit encodes run validity only — never a class);
5. identical evidence block (`now`, window, three input digests);
6. verdict-envelope shape gates (all five arrays present, sorted, deduplicated, registry-only
   reasons, class value legal, §2 consistency invariants);
7. each verdict equals the fixture's expected verdict (expected read by the comparator only).

Committed negative proofs MUST show the comparator failing on: a flipped expected class; a
mutated reason set; a §2 invariant violation (e.g. `class=AIREP-Witnessed` with a non-empty
withheld array).

## 7. Minimum adversarial matrix

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
