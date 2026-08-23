# AIREP v0.2 — Conformance-Class Design Contract (Stage 1: contract only)

> **Status: DESIGN CONTRACT for maintainer review — no class-verifier code exists yet.**
> Spec-before-code: this contract fixes the v0.2 assurance-class semantics before any
> implementation; every open choice is an explicit OPEN DESIGN QUESTION (§8) with a proposal,
> never an implementation default. Producer implementation remains unstarted.
>
> **Authoritative inputs:** adopted AD-09 (round-2 scoped wording), the frozen
> [`../INTEGRITY.md`](../INTEGRITY.md) (esp. §3.2, §4.1–4.3, §5), the accepted Stage-4 trust
> semantics (verifier-accepted binding; explicit `trusted: true`; suites from bindings; inert
> wire labels), the v0.1 `CONFORMANCE_CLASSES.md` + WP-10 strict mode as **lineage** (its
> fail-closed machinery carries forward in substance), and AD-03's class-scoped
> `observer_relationship` rule. This contract closes the standing carry-forward: **witness-key
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
  material for that producer; a trust-store entry is accepted only with explicit
  `trusted: true` (no default-trust — Stage-4 semantics carried into class semantics).
- No binding available for the required key ⇒ Authenticated is **not evaluable** for that
  artifact: reported as withheld (§6), never silently as Core-only-failed and never as passed.

## 3. Witness-key independence (carry-forward, closed here)

`independent` witnessing is a **resolved-key comparison, never an identifier comparison**:

- The witness key is resolved from the verifier's witness trust store (explicit
  `trusted: true`); the producer key from the producer binding.
- **Independence holds iff the resolved witness public key ≠ the resolved producer public
  key.** A `witness_id` string differing from a producer id establishes nothing (v0.1
  strict-mode lesson, retained).
- A producer-signed "witness" provides no truncation defense: independence failing ⇒ the
  Witnessed class is refused with the failure named; it never silently degrades into a
  passing lower class without the named reason.
- v1 scope stays one independent trusted witness — **no N-of-M quorum** (future work, named).

## 4. Revocation semantics (carry-forward, closed here)

- The verifier consults an operator-supplied **revocation source** covering **both** the
  producer key and the witness key.
- A key is revoked for an artifact when the artifact/claim was signed **at or after** the
  key's `revoked_at`. Conservative fail-closed carries forward: a listed key with no usable
  `revoked_at`, or an artifact whose signing time cannot be established, is treated as
  revoked — never as a silent pass.
- Producer key revoked ⇒ Witnessed refused (`producer-key-revoked`); witness key revoked ⇒
  Witnessed refused (`witness-key-revoked`).
- **Self-declared revocation** (a `key_trust`-style profile carrying `revoked: true`) never
  raises or lowers a class by itself but MUST surface as a named caveat on an Authenticated
  result — an Authenticated artifact signed by a self-declared-revoked key must not read as a
  clean pass (v0.1 `verified_withheld` mechanism, renamed for the v0.2 ladder — ODQ-5).

## 5. Freshness (Witnessed's second gate)

- Recency is evaluated **only** against the signed `witnessed_at` inside the witness claim
  (frozen §4.1), against operator-supplied `now` + freshness window; deterministic — the
  evaluated `now` is recorded in the verdict evidence.
- Boundary-equal is fresh (Stage-4 pinned semantics); `witnessed_at` structural/Gregorian
  validity precedes recency (frozen §4.2); head resolution and claim reconciliation precede
  everything (frozen §4.3).

## 6. Fail-closed machinery (v0.1 lineage, carried in substance)

- **Default mode withholds the top class**: without the operator inputs (witness trust store,
  freshness window, revocation source) the Witnessed gates cannot run, and the verifier
  reports a **withheld** result naming every unevaluated gate (v0.1 `TRUSTED_NOT_IMPLEMENTED`
  lineage; v0.2 name — ODQ-4). An unevaluated prerequisite is never a satisfied one.
- **Failed ≠ not measured**, reported differently, and neither is ever the higher class.
- A withheld-top result ranks exactly equal to Authenticated for consumers; a consumer
  requiring Witnessed MUST NOT accept it.
- Exit codes encode record validity only, never a class; the class is a separate output
  channel a consumer must parse.
- A verifier implementing a gate MUST remove its withheld reason and add the real check in
  the same change.

## 7. Class scope across the four artifact families

- Core and Authenticated apply to **every** artifact family identically (per-artifact
  assurance).
- Witnessed applies to a **chain head** (any family may be the head artifact).
- **`observer_relationship` class scoping (AD-03, closed here):** at Core the field is
  producer-declared information; at Authenticated and above, a verifier accepts `independent`
  only when the Effect producer's resolved key is verified distinct from the Execution
  producer's resolved key under the accepted bindings — otherwise the effective assessment is
  `unknown` (or a named withheld reason), never a silently accepted `independent`.
- **Cross-artifact reconciliation is NOT a class** (proposal — ODQ-2): TOCTOU digest equality,
  `decision_ref` resolution, and lifecycle completeness are *reconciliation checks* with their
  own named results; folding them into per-record assurance classes would blur what a class
  certifies. Classes stay per-record/per-head provenance-integrity-freshness.

## 8. OPEN DESIGN QUESTIONS (maintainer decisions — none embedded in code)

| # | Question | Proposal + rationale |
|---|---|---|
| ODQ-1 | Mode structure | Carry the v0.1 WP-10 two-mode model: default (withhold Witnessed, name unevaluated gates) + strict (operator supplies trust store / freshness window / revocation source; gates run for real). It is measured, fail-closed, and already survived adversarial review. |
| ODQ-2 | Reconciliation placement | Keep reconciliation OUTSIDE the ladder as named checks (§7); a future "reconciled" designation, if ever wanted, is a separate labeled result — not a fourth class in this phase. |
| ODQ-3 | Verdict/reason vocabulary | Define a closed class-verifier reason registry in the implementation contract (next stage), reusing the Stage-4 coarseness rule (no finer than cryptographically distinguishable) and the single-first-decisive-reason model for refusals. |
| ODQ-4 | Withheld-class name | Propose `WITNESSED_NOT_EVALUATED` (accurate: the gates did not run) replacing the v0.1 `TRUSTED_NOT_IMPLEMENTED` naming, which is now wrong on both words. |
| ODQ-5 | Caveat channel names | Propose `authenticated_caveats=` (e.g. `producer-key-self-revoked`, `wire-alg-mismatch`) and `witnessed_withheld=` as the two distinct channels (v0.1 `verified_withheld`/`trusted_withheld` lineage, renamed to the v0.2 ladder). |
| ODQ-6 | Revocation-source / trust-store wire format | Propose carrying the v0.1 strict-mode local-JSON formats forward unchanged in v1 (network-free); online revocation, transparency-log proofs, and nonce/challenge freshness stay named future work. |
| ODQ-7 | SCITT anchor as a Witnessed path | Propose: in this phase Witnessed is definable via the local head-witness only; the SCITT registration path (AD-10) becomes an *alternative anchor* in a later stage once the binding profile exists — the class text names it as such without specifying it. |

## 9. What the classes do NOT establish (unchanged boundary)

No class — including Witnessed — makes the producer honest or any recorded content true. A
key-holding producer can write a valid, signed, witnessed artifact with false content; the
classes raise the bar on provenance, integrity, and freshness, never on truth. That boundary
is `scope.does_not_cover`, and it stays deliberately outside every class. Schema validation
(the completed phase) confers no class; class verification is a semantic-verifier concern
building on the WP-α01 integrity construction.
