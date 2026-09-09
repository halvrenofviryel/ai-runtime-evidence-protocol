# AIREP v0.2 — Conformance classes (normative)

> **Normative.** The key words MUST, MUST NOT, SHOULD, MAY are per BCP 14 (RFC 2119, RFC 8174).

This document answers one question: **what do the AIREP v0.2 assurance classes mean?**

It is **protocol semantics**, not a measurement contract. It does not describe how any particular
verifier is invoked, what it prints, how results are compared, how corpora are authored, or how
external evidence is admitted. Those belong to verifier measurement contracts and evidence records,
which are separately versioned. A class-verifier contract states *how a given verifier revision
measures these semantics*; this document states *what there is to measure*.

**Derived only from already-adopted sources.** AD-03, AD-08, AD-09, AD-14, the accepted
[`conformance-design/CONFORMANCE_CLASS_DESIGN.md`](./conformance-design/CONFORMANCE_CLASS_DESIGN.md)
(with ODQ-1..7 decided 2026-08-23), and the frozen [`INTEGRITY.md`](./INTEGRITY.md). The historical
class-verifier contract is cited **only** as evidence of mechanics already pinned there, never as
licence to introduce protocol semantics. **No semantics beyond those sources are introduced here.**
Where a rule is pinned in a frozen or accepted document it is **quoted**, and any explanation
follows the quote without replacing or relaxing it.

Companion-profile semantics (AD-10 SCITT, AD-11 authorization reference, AD-12 MCP/A2A/OTel) are
**out of scope** and impose no requirement on any class (AD-16).

---

## 1. The ladder

| Class | Establishes — and nothing more |
|---|---|
| **AIREP-Core** | The artifact is structurally valid under its accepted schema and internally hash-consistent under its declared domain tag. |
| **AIREP-Authenticated** | Core, plus authorship cryptographically established **under a key binding / trust policy the verifier accepts**. |
| **AIREP-Witnessed** | Authenticated, plus **head freshness and non-truncation relative to** the independent witness or transparency anchor that vouched for the head. |

The ladder has **exactly these three classes**. There is no fourth class, and no partial or
intermediate class exists.

### 1.1 The normative boundary sentence

Stated once and bound to the ladder as a whole (AD-09):

> *The assurance ladder concerns provenance, integrity, and freshness properties only; each class
> establishes only the properties explicitly assigned to that class. No class provides truth
> assurance.*

---

## 2. AIREP-Core

Core establishes structural validity and internal hash consistency. It establishes **nothing else**.

> *Core provides **neither provenance nor freshness** — it must never be read as a weaker form of
> either; an adversary can fabricate a fully self-consistent chain.*

AD-09 states the reason precisely, and it MUST NOT be softened:

> *Core deliberately does **not** claim "untampered": without signature verification, an adversary
> can fabricate an entirely new, self-consistent hash chain — internal hash consistency detects
> in-place edits of a given byte sequence, not substitution of the whole sequence. Tamper-evidence
> against a substituting adversary begins at Authenticated.*

Core is therefore **not** authorship assurance, **not** freshness assurance, and **not** truth
assurance.

---

## 3. AIREP-Authenticated

Authenticated requires Core plus a **verifier-accepted producer binding** and the adopted
cryptographic and revocation prerequisites.

### 3.1 Verifier-accepted binding

> *A self-declared public key carried inside the record is not, by itself, sufficient: the signature
> must verify under a key binding / trust policy the **verifier** accepts (a supplied key, a trust
> store, or an equivalent out-of-record binding). Otherwise "Authenticated" would be a claim the
> producer can mint about itself.*

The verification suite and key come **only** from the verifier's accepted binding. The wire
`integrity.signature.alg` label is informative and MUST NOT drive any decision.

A producer binding is verifier-accepted only when supplied to the verifier as trusted key material
for that producer, carrying explicit `trusted: true`.

Where no binding is available for the required key, Authenticated is **not evaluable** for that
artifact and MUST be reported as withheld (§6) — never silently as a Core-only failure, and never as
passed.

### 3.2 Signature baseline

Per AD-08, the interchange baseline is an **asymmetric** signature; **Ed25519 is mandatory to
implement**. A symmetric MAC cannot establish authorship to a third party — any holder of the key,
including the verifier, can forge it — so MAC-based integrity can **never earn the portable
authenticated class**.

### 3.3 Revocation — current verifier-policy snapshot

v0.2 does **not** carry forward v0.1's "signed at/after `revoked_at`" rule. The record-signature
preimage carries no independent trusted signing time, and a holder of a compromised key can backdate
producer-declared timestamps, so a time-comparison rule would let a revoked key testify about its own
past validity.

- The operator revocation source explicitly evaluates each verifier-side **binding** as `active` or
  `revoked`.
- A `revoked` binding cannot earn any class contribution, and **no artifact- or witness-carried
  timestamp may be used to present a revoked binding as historically valid**.
- Producer binding revoked ⇒ **Authenticated cannot be earned; the ceiling is Core**.
- Witness binding revoked ⇒ **Witnessed cannot be earned; the ceiling is Authenticated**.
- Missing or malformed revocation state for a required binding is **never a pass**: the affected
  class is withheld with the gap named.

Historical validation ("this signature predates revocation") requires an independent authenticated
timestamp/anchor and is **not** established by any class in v0.2.

---

## 4. AIREP-Witnessed

Witnessed requires Authenticated plus the adopted witness prerequisites. Its claim is **scoped to
the anchor**:

> *The class does not establish that the evidence graph is complete or that any real-world action
> history is complete; it establishes head freshness and non-truncation **relative to** the
> independent witness or transparency anchor that vouched for the head — nothing beyond what that
> anchor saw.*

Witnessed applies to a **chain head**; any artifact family may be the head artifact.

### 4.1 Witness independence — a three-condition joint gate

Key inequality alone proves only that two keys exist; the same actor can control both. All three
conditions MUST hold:

1. the verifier-accepted bindings represent **distinct identities** (verifier-side binding identity,
   not wire-carried id strings);
2. the **resolved public keys differ** (necessary, never sufficient);
3. the verifier's trust policy **explicitly accepts** the witness/observer binding as independent of
   the relevant producer/executor binding.

> *Absent the policy relation, independence is **unproven** — never a pass.*

A producer-signed "witness" provides no truncation defence. Independence failing or unproven ⇒
Witnessed is refused or withheld with the reason named; it **never** silently degrades into a clean
lower class.

v1 scope is one independent trusted witness. **No N-of-M quorum** is established.

### 4.2 Freshness

Recency is evaluated **only** against the signed `witnessed_at` inside the witness claim, against an
operator-supplied `now` and freshness window. The predicate is:

> *fresh iff `abs(now − witnessed_at) <= freshness_window`; boundary-equal passes.*

`witnessed_at` structural and Gregorian validity precedes recency; head resolution and claim
reconciliation precede everything.

---

## 5. Class scope across the four artifact families

- Core and Authenticated apply to **every** artifact family identically (per-artifact assurance).
- Witnessed applies to a **chain head**.
- **Cross-artifact reconciliation is not a class.** TOCTOU digest equality, `decision_ref`
  resolution, and lifecycle completeness are reconciliation checks with their own named results.
  Folding them into per-record assurance classes would blur what a class certifies. Classes stay
  per-record / per-head provenance-integrity-freshness.

### 5.1 `observer_relationship`

At Core the field is **producer-declared information**. At Authenticated and above a verifier accepts
`independent` only under the same three-condition gate as §4.1 — the Effect and Execution producers'
verifier-side binding identities are distinct, their resolved keys differ, **and** the trust policy
explicitly accepts them as independent.

Where that cannot be verified the artifact MAY still earn Authenticated, but the effective
`observer_relationship` remains **`unknown`**. The artifact's class does not drop because of it, and
`independent` is **never** silently accepted.

---

## 6. Failure, withheld, and caveat — three distinct meanings

These are **not** interchangeable, and an unevaluated prerequisite is **never** a satisfied one.

| Semantics | Meaning |
|---|---|
| **FAILURE** | A class gate was evaluated and did not hold. Definitive. |
| **WITHHELD** | A class gate could **not be evaluated** — required operator input or binding was missing or malformed. The unevaluated gates are **named**. |
| **CAVEAT** | A warning on an **earned** class that does not lower it. |

Adopted consequences, stated as semantics:

- **Withheld is not a class.** Where Authenticated cannot be evaluated the artifact remains at
  **Core**, and the unevaluated gates MUST be named. Where Witnessed cannot be evaluated the artifact
  remains at **Authenticated**, and the unevaluated gates MUST be named.
- Partial operator input **never** silently falls back; missing gates are named.
- **failed ≠ not measured**, and neither is ever the higher class.
- An artifact whose next tier is withheld ranks **exactly at its stated class**; a consumer requiring
  the next tier **MUST NOT** accept it.
- Class gates can fail independently, so more than one reason may apply to a class at once.

*How a verifier serialises, names, orders or compares these reasons is a measurement concern and is
specified in the applicable class-verifier contract revision, not here.*

### 6.1 The one Core-owned profile semantic

`profiles` is Core's only extension surface (AD-07), and Core does **not** interpret profile domain
semantics — with exactly one adopted exception, which affects class *interpretation* and is therefore
stated here.

**The adopted protocol semantic**, quoted from the accepted design contract, is authoritative:

> *Self-declared revocation (a `key_trust`-style profile carrying `revoked: true`) never raises or
> lowers a class by itself but MUST surface as a named caveat on an earned Authenticated result
> (`authenticated_caveats` channel, §6) — never a clean pass.*

That quote fixes all of the following, and none of it is relaxed here: the caveat **MUST** surface;
it surfaces on an **earned Authenticated** result; it surfaces on the **`authenticated_caveats`**
channel; and the outcome is **never a clean pass**. It is **profile semantics only**, and **never**
substitutes for the external operator revocation snapshot of §3.3.

Class effects, from the same quote: it **never raises or lowers a class by itself**. It cannot create
Authenticated, cannot raise a class, and cannot erase a failure or withheld reason.

**What this document does not fix.** The accepted design contract states the semantic at the level of
*"a `key_trust`-style profile carrying `revoked: true`"*. It does **not** specify the exact member
path, nor state the rule as an *iff*. Those are pinned by the applicable **class-verifier measurement
contract**, which is cited here only as evidence of mechanics already pinned there — not as protocol
semantics, and not restated as a normative requirement of this document. The exact path and strength are specified by the
applicable contract revision; this section does not create them.

**Consuming this narrowly adopted semantic does not constitute validation of the
`airep.key-trust` profile as a whole.** Generic profile validation is a measurement concern and is
specified in the applicable class-verifier contract revision, not here.

---

## 7. Lifecycle stages are never promoted into one another

AD-03 separates the artifact family precisely because *"an enforcement point acknowledging receipt is
not a governance decision, and an observer reporting a state change is not a governance decision."*
Assurance classes describe **provenance, integrity and freshness of a record**. They MUST NOT be read
as converting one lifecycle stage into another.

The following are **normative non-implications**. No class — including Witnessed — establishes any
arrow below:

```text
Decision established     ≠  Control delivered
Control delivered        ≠  Execution occurred
Execution occurred       ≠  Intended effect observed
Effect observed          ≠  Underlying decision correct
```

**A class is a property of the record, never of the reported fact.** Authenticated establishes that
a record was authored under a verifier-accepted binding; Witnessed adds head freshness and
non-truncation relative to the anchor. Neither establishes that what the record *reports* actually
happened. A key-holding producer can author a valid, signed, witnessed record whose content is false
(§8).

A record **is** evidence — that is what AIREP produces. What a class does **not** do is establish that
the reported event occurred; raising a record's class raises assurance about the *record*, not about
the *event*.

Concretely, and in both directions of misreading:

- An **Authenticated or Witnessed Decision Receipt** establishes authenticated authorship of a record
  *reporting* a decision. It does **not** establish that the reported decision was in fact taken, and
  it does **not** establish that any control instruction was dispatched, received, or enforced.
- An **Authenticated or Witnessed Control Evidence** artifact establishes authenticated authorship of
  a record *reporting* a dispatch or receipt. It does **not** establish that the dispatch or receipt
  in fact occurred, and it does **not** establish that the authorized action executed.
- An **Authenticated or Witnessed Execution Evidence** artifact establishes authenticated authorship
  of a record *reporting* an execution and its parameters. It does **not** establish that the
  execution in fact occurred, and it does **not** establish that the intended material or system
  effect occurred.
- An **Authenticated Effect Evidence** artifact establishes authenticated authorship of a record
  *reporting* an observation, and identifies the observer's relationship to the executor. It
  strengthens **provenance** assurance for that observation record. A **Witnessed** Effect Evidence
  artifact additionally strengthens **freshness and non-truncation relative to the anchor** for that
  record — freshness is added by Witnessed only, never by Authenticated (§4). Neither establishes the
  truth or completeness of the lifecycle, nor the correctness of the underlying decision.

Correlation across the family is by **explicit keys**, not by co-location in one record. Correlation
establishes that records refer to one another; it does not establish that the referenced stage
occurred.

An observation by the executor itself **is** evidence — it is simply **not independent
corroboration**, and the two MUST NOT be confused (§5.1).

---

## 8. What no class establishes

No class, including Witnessed, makes the producer honest or any recorded content true. A key-holding
producer can write a valid, signed, witnessed artifact with false content. The classes raise the bar
on **provenance, integrity, and freshness** — never on truth.

Specifically, no assurance class establishes that:

- the underlying decision was correct;
- the evidence is complete;
- an action occurred merely because it was decided;
- an effect occurred merely because execution was reported;
- a signature's validity implies the signer's **authority**;
- the recorded content corresponds to what happened in the world.

Schema validation confers no class. Class verification builds on the integrity construction of
[`INTEGRITY.md`](./INTEGRITY.md); it does not replace it.

**No class establishes revocation assurance beyond the verifier-policy snapshot of §3.3.**
