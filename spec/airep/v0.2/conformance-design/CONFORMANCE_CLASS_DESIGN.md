# AIREP v0.2 — Conformance-Class Design Contract (Stage 1: contract only)

> **Status: DESIGN CONTRACT for maintainer review — no class-verifier code exists yet.**
> Spec-before-code: this contract fixes the v0.2 assurance-class semantics before any
> implementation. Every formerly open choice is now an **explicit maintainer decision** (§8,
> decided 2026-08-23) — none was made by implementation default. Producer implementation
> remains unstarted.
>
> **Authoritative inputs:** adopted AD-09 (round-2 scoped wording), the frozen
> [`../INTEGRITY.md`](../INTEGRITY.md) (esp. §3.2, §4.1–4.3, §5), the accepted Stage-4 trust
> semantics **stated precisely** (a *supplied* producer binding; explicit `trusted: true` on
> the *witness trust-store* entry; suites derived from bindings; inert wire labels — see §2
> for what this contract newly decides on top), the v0.1 `CONFORMANCE_CLASSES.md` + WP-10
> strict mode as **lineage** (its fail-closed machinery carries forward in substance), and
> AD-03's class-scoped `observer_relationship` rule. This contract closes the standing carry-forward: **witness-key
> independence + revocation assurance semantics**.

## 1. The ladder (adopted names, adopted scoping)

| Class | Establishes — and nothing more |
|---|---|
| **AIREP-Core** | The artifact is structurally valid (accepted schema) and internally hash-consistent under its declared domain tag (frozen §2/§5 recomputation). Core provides **neither provenance nor freshness** — it must never be read as a weaker form of either; an adversary can fabricate a fully self-consistent chain. |
| **AIREP-Authenticated** | Core, plus authorship cryptographically established **under a key binding / trust policy the verifier accepts** (§2). A self-declared in-record key is never sufficient. |
| **AIREP-Witnessed** | Authenticated, plus **head freshness and non-truncation relative to the independent witness or transparency anchor** that vouched for the head (§3–§5) — never evidence-graph or action-history completeness. |

The normative boundary sentence binds the ladder as a whole: *the assurance ladder concerns
provenance, integrity, and freshness properties only; each class establishes only the
properties explicitly assigned to that class; no class provides truth assurance.*

## 2. Verifier-accepted binding (Authenticated's gate)

- The verification suite and key come **only** from the verifier's accepted binding (operator-
  supplied trust material); the wire `integrity.signature.alg` label is informative and MUST
  NOT drive any decision (frozen §3.2).
- A producer binding is verifier-accepted only when supplied to the verifier as trusted key
  material for that producer, carrying explicit `trusted: true`. Attribution stated
  precisely: Stage-4's explicit-`trusted:true` gate applied to the **witness trust-store
  entry**; the Stage-4 producer binding was a supplied binding without that flag. Requiring
  explicit `trusted: true` on the **producer** binding is therefore a **new
  conformance-design decision** made here (maintainer, 2026-08-23), not a Stage-4 carry.
- No binding available for the required key ⇒ Authenticated is **not evaluable** for that
  artifact: reported as withheld (§6), never silently as Core-only-failed and never as passed.

## 3. Witness-key independence (carry-forward, closed here)

Key inequality alone proves only that **two keys** exist — the same actor can control both.
Per AD-09 ("independent witness") and AD-03 ("genuinely distinct under the verifier's accepted
trust policy"), v1 independence is a **three-condition joint gate** (maintainer decision):

1. the verifier-accepted bindings represent **distinct identities** (verifier-side binding
   identity, not wire-carried id strings);
2. the **resolved public keys differ** (necessary, never sufficient; a `witness_id` string
   differing from a producer id establishes nothing — v0.1 strict-mode lesson retained);
3. the verifier's trust policy **explicitly accepts the witness/observer binding as
   independent of** the relevant producer/executor binding (an explicit policy relation).

All three must hold. Absent the policy relation, independence is **unproven** — never a pass.
A producer-signed "witness" provides no truncation defense: independence failing or unproven ⇒
Witnessed is refused/withheld with the reason named; it never silently degrades into a clean
lower class. v1 scope stays one independent trusted witness — **no N-of-M quorum** (future
work, named).

## 4. Revocation semantics (carry-forward, closed here — SNAPSHOT model, maintainer decision)

The v0.1 "signed at/after `revoked_at`" rule is **deliberately NOT carried forward**. The v0.2
record-signature preimage carries no independent trusted signing time: the signature covers
domain tag + suite + `integrity.current`; `subject.timestamp_utc` is producer-declared, and
`witnessed_at` is by frozen definition only *the witness's own signed statement of when it
witnessed*. An actor holding a compromised/revoked key can backdate either value, so a
time-comparison rule would let a revoked key testify about its own past validity.

v0.2 v1 uses **current verifier-policy snapshot semantics**:

- The operator revocation source explicitly evaluates each verifier-side **binding** as
  `active` or `revoked`.
- A `revoked` binding cannot earn any class contribution, and no artifact- or witness-carried
  timestamp can be used to present a revoked binding as historically valid.
- Producer binding revoked ⇒ **Authenticated cannot be earned; the ceiling is Core**
  (`producer-binding-revoked`). Witness binding revoked ⇒ **Witnessed cannot be earned; the
  ceiling is Authenticated** (`witness-binding-revoked`).
- Missing or malformed revocation state for a required binding is **never a pass**: the
  affected class is withheld with the gap named (§6).
- Historical validation ("this signature predates revocation") requires an **independent
  authenticated timestamp/anchor** and is named future work; the SCITT path (AD-10) is a
  candidate route.
- **Self-declared revocation** (a `key_trust`-style profile carrying `revoked: true`) never
  raises or lowers a class by itself but MUST surface as a named caveat on an earned
  Authenticated result (`authenticated_caveats` channel, §6) — never a clean pass.

## 5. Freshness (Witnessed's second gate)

- Recency is evaluated **only** against the signed `witnessed_at` inside the witness claim
  (frozen §4.1), against operator-supplied `now` + freshness window; deterministic — the
  evaluated `now` is recorded in the verdict evidence.
- **Exact predicate (aligned with the Stage-4 verifiers):** fresh iff
  `abs(now − witnessed_at) <= freshness_window`; boundary-equal passes.
- `witnessed_at` structural/Gregorian validity precedes recency (frozen §4.2); head
  resolution and claim reconciliation precede everything (frozen §4.3).

## 6. Fail-closed machinery (v0.1 lineage in substance; withheld model per maintainer decision)

- **The `class` field takes exactly three values** — `AIREP-Core`, `AIREP-Authenticated`,
  `AIREP-Witnessed`. No pseudo-class is ever emitted (`WITNESSED_NOT_EVALUATED` is REJECTED
  as a class name).
- **Withheld is a channel, not a class.** Authenticated not evaluable (missing producer
  binding, missing/malformed revocation state) ⇒ `class = AIREP-Core` +
  `authenticated_withheld = [...]` naming every unevaluated gate. Witnessed not evaluable
  (missing witness trust store / freshness window / revocation state) ⇒
  `class = AIREP-Authenticated` + `witnessed_withheld = [...]`. An unevaluated prerequisite
  is never a satisfied one; partial operator input never silently falls back — the missing
  gates are named.
- `authenticated_caveats = [...]` is the third, distinct channel: warnings on an **earned**
  Authenticated that do not lower it (e.g. self-declared revocation, wire-`alg` label
  mismatch). Definitive class-gate **failures** are a deterministic failure reason set —
  never mixed into a withheld channel: **failed ≠ not measured**, and neither is ever the
  higher class.
- Consumer rule: a class accompanied by a non-empty withheld channel for the next tier ranks
  exactly at its stated class; a consumer requiring the next tier MUST NOT accept it.
- **Class-verifier reason model (maintainer decision, ODQ-3):** class gates can fail
  independently, so class evaluation reports **deterministic, deduplicated, ASCII-sorted
  reason sets** (per channel). The single-first-decisive-reason model remains the
  **integrity verifier's** contract only — it is not carried to class evaluation.
- Exit codes encode record validity only, never a class; the class and its channels are
  separate output a consumer must parse.
- A verifier implementing a gate MUST remove its withheld reason and add the real check in
  the same change.
- **Verdict evidence (reproducibility):** every class verdict records the evaluated `now`,
  the freshness window, and the **digests of the operator trust-store and revocation-source
  inputs**, so the exact external trust-policy snapshot behind a class result is
  demonstrable later.

## 7. Class scope across the four artifact families

- Core and Authenticated apply to **every** artifact family identically (per-artifact
  assurance).
- Witnessed applies to a **chain head** (any family may be the head artifact).
- **`observer_relationship` class scoping (AD-03, closed here):** at Core the field is
  producer-declared information; at Authenticated and above, a verifier accepts `independent`
  only under the same three-condition gate as §3 — the Effect and Execution producers'
  verifier-side **binding identities** are distinct, their resolved keys differ, AND the trust
  policy explicitly accepts them as independent. Where that cannot be verified, the artifact
  MAY still earn Authenticated, but the effective `observer_relationship` remains
  **`unknown`** — the artifact's class does not drop because of it, and `independent` is never
  silently accepted.
- **Cross-artifact reconciliation is NOT a class** (proposal — ODQ-2): TOCTOU digest equality,
  `decision_ref` resolution, and lifecycle completeness are *reconciliation checks* with their
  own named results; folding them into per-record assurance classes would blur what a class
  certifies. Classes stay per-record/per-head provenance-integrity-freshness.

## 8. DESIGN DECISIONS (ODQ-1..7 — decided by maintainer review, 2026-08-23)

| # | Decision |
|---|---|
| ODQ-1 | **ADOPT WITH MODIFICATION.** v0.1's fail-closed two-stage idea is kept, but "strict" concerns **Witnessed evaluation only**. Authenticated is evaluated independently as soon as a producer binding is available. Missing producer binding / revocation input ⇒ `authenticated_withheld`; missing Witnessed operator input ⇒ `witnessed_withheld`. Partial input never silently falls back; missing gates are named. |
| ODQ-2 | **ADOPT.** Reconciliation stays outside the ladder. TOCTOU equality, reference resolution, and lifecycle completeness are separate named results — never a fourth class. |
| ODQ-3 | **MODIFIED.** The closed reason registry is pinned in the next implementation contract, keeping the Stage-4 coarseness discipline — but class evaluation uses **sorted reason sets**; first-decisive stays integrity-path-only (class gates can fail independently, as the v0.1 strict battery already measured). |
| ODQ-4 | **REJECTED as a class.** No pseudo-class outside the three. `class = AIREP-Authenticated` + `witnessed_withheld=[...]`; the equivalent `authenticated_withheld` channel is mandatory for the Authenticated tier. |
| ODQ-5 | **MODIFIED.** Three distinct semantic channels: `authenticated_caveats`, `authenticated_withheld`, `witnessed_withheld`. Definitive class-gate failures are a deterministic failure reason set, never mixed into withheld. |
| ODQ-6 | **REJECTED ("v0.1 unchanged").** AD-09 now requires out-of-record producer binding, which the v0.1 format does not model. The v0.2 local/network-free input format MUST carry: producer + witness bindings; verifier-side binding/subject identity; key; suite; explicit `trusted: true`; and the explicit independence policy relation. The revocation source gives explicit `active`/`revoked` state per verifier-side **binding id**; missing state fails closed. Exact JSON serialization may be pinned in the next implementation contract; these semantics may not change there. |
| ODQ-7 | **ADOPT.** In this implementation stage the only working Witnessed path is the local head-witness. SCITT becomes an alternative anchor later per AD-10; a SCITT receipt cannot earn Witnessed before its profile/verification contract is accepted. |

## 9. What the classes do NOT establish (unchanged boundary)

No class — including Witnessed — makes the producer honest or any recorded content true. A
key-holding producer can write a valid, signed, witnessed artifact with false content; the
classes raise the bar on provenance, integrity, and freshness, never on truth. That boundary
is `scope.does_not_cover`, and it stays deliberately outside every class. Schema validation
(the completed phase) confers no class; class verification is a semantic-verifier concern
building on the WP-α01 integrity construction.
