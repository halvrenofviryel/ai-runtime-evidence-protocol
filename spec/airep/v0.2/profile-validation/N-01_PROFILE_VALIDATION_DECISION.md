# N-01 / N-01b — generic profile-validation semantics and output model

**Status: Adopted (maintainer decision) — 2026-09-03.** Basis:
[AD-16](../../v0.2-design/ARCHITECTURE_DECISIONS.md#ad-16--core-release-boundary-and-companion-profile-policy)
item 7 (profile-extension parity capability), AD-07 (core closure, `profiles` as the only extension
surface), AD-14 (verifier parity).

Decided **before** implementation, per the repository's spec-before-code discipline. Nothing here is
inferred from SCITT, AuthZEN, or any external standard.

---

## N-01 — unknown namespaced profile semantics

**Normative Core rule.**

> A syntactically valid namespaced profile that the verifier has no accepted validation basis for
> does not invalidate the AIREP Core artifact merely because its profile semantics are unknown. Its
> profile-specific semantics are `NOT_EVALUATED`, not `PASS`, and cannot contribute to or raise Core
> assurance.

Therefore, and each independently:

- `unknown profile` ≠ Core invalid
- `unknown profile` ≠ profile valid
- `unknown profile` ≠ assurance input
- `unknown profile` ≠ failure merely because unknown

**Precondition.** The rule applies **only after** the Core-defined generic profile-container shape
and the namespaced-key grammar (`^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$`, ODQ-12) have passed. A
malformed profile identifier, or a profile value that violates the Core-level container shape,
remains **Core-invalid** — that is Core structure, not profile semantics.

**Rationale (AD-07).** `profiles` is AIREP Core's only extension surface. If every namespaced
extension required prior Core registration, the mechanism would be a central allow-list rather than
an extensibility mechanism. ODQ-12 already states the registered short-name registry **starts
EMPTY**, so "no registered basis" is the ordinary case, not an edge case.

### Adopted sub-rules

| # | Rule |
|---|---|
| N1 | Syntactically valid unknown namespaced profiles are allowed at Core. |
| N2 | Unknown does not mean valid. Never reported as valid, conformant, verified, trusted, authenticated, or semantically correct. |
| N3 | Profile semantics cannot raise Core assurance without an accepted basis — no class uplift, no producer identity, no witness independence, no execution, no effect, no erasure of a withheld reason. |
| N4 | Profile-specific validation is basis-dependent: a verifier MAY validate a profile only with an explicit accepted validation basis for **that exact** profile identifier. |
| N5 | A supplied basis must be deterministic: same artifact + same Core basis + same declared profile-validation basis ⇒ same observable result across both official verifiers. |
| N6 | Core conformance and profile conformance are mechanically distinguishable in the output; no single ambiguous `PASS`. |

**N5 states the AD-14 parity claim precisely.** The claim is *"same artifact + same Core basis + same
declared profile-validation basis → same observable verifier result"*. It is **not** *"every AIREP
verifier must know every external profile."*

---

## CORE-LOAD-BEARING exception — `airep.key-trust`

`airep.key-trust` is **CORE-LOAD-BEARING**, not an ordinary opaque extension. It is preserved
**exactly at its already adopted strength** and is **not** redesigned or moved by this decision.

Its adopted Core semantic read is narrowly:

```
profiles["airep.key-trust"].revocation.revoked === true
```

on an **already-earned** Authenticated result. The strength is **MUST / iff**, not "may": the
contract pins it as *"`producer-key-self-revoked` is emitted **iff**
`profiles[\"airep.key-trust\"].revocation.revoked === true` on the artifact"*, and
`CONFORMANCE_CLASS_DESIGN.md` §4 states it *"never raises or lowers a class by itself but **MUST**
surface as a named caveat on an earned Authenticated result — never a clean pass."* So whenever the
pinned condition is true on an earned Authenticated result the caveat **is emitted**; when it is
false the caveat **is not** emitted. Covered by corpus case **PS3**. This decision does not relax
that to a permission.

It **cannot** create Authenticated, raise class, lower class by itself, or erase a failure/withheld
reason. It can only add a caveat to a result already earned by other means.

### The distinction that must not be read as a contradiction

> **Core may consume an explicitly adopted, narrowly scoped semantic from a Core-owned profile
> without thereby claiming that the entire profile was profile-schema validated.**

These are statements about **different things**: one is a Core-owned caveat semantic, the other is
generic profile-schema validation. So this output is **correct and self-consistent**, not
contradictory:

```json
"profile_evaluations": {
  "airep.key-trust": { "result": "NOT_EVALUATED", "basis_digest": null }
},
"authenticated_caveats": ["producer-key-self-revoked"]
```

The run evaluated the Core-owned caveat semantic (adopted, narrow) and did **not** validate the
`airep.key-trust` payload against a profile schema (none supplied). Both statements are true
simultaneously.

---

## N-01b — output model

A **new additive** top-level channel. All existing channels keep their shape and meaning.

```json
{
  "profile_evaluations": {
    "vendor.example":      { "result": "NOT_EVALUATED", "basis_digest": null },
    "airep.test-profile":  { "result": "PASS", "basis_digest": "sha256:…" }
  }
}
```

One entry for **every syntactically valid profile identifier present in the artifact**.

### Result vocabulary — exactly three states

| State | Meaning |
|---|---|
| `PASS` | An explicit accepted validation basis for **that exact** profile identifier was supplied to the run, and the profile payload passed it. |
| `FAIL` | An explicit accepted validation basis for that exact identifier was supplied, and the payload failed it. |
| `NOT_EVALUATED` | No accepted validation basis for that identifier was supplied or executed. |

No further states unless implementation reveals a genuinely distinct condition these three cannot
express correctly.

**`NOT_EVALUATED` is an observed statement about the evaluation process.** It is not `PASS`, not
`FAIL`, not a statement about Core validity, and not an assurance class. It is never upgraded.

### Basis identity

Every `PASS` or `FAIL` records `basis_digest = sha256:<digest of the exact validation-basis bytes>`.
`NOT_EVALUATED` carries `basis_digest: null`.

Run evidence additionally captures: profile identifier; validator/engine identity; validation
configuration; the exact basis bytes/digest; and the no-network condition.

- **No network resolution. No implicit discovery. No silent fetching.**
- A basis registered for one profile identifier is **never** applied to another.
- **A changed basis digest is a changed evaluation basis** — substitution without an identity change
  is precisely what the digest exists to make detectable.

---

## N-01c — process exit semantics: RESOLVED, exit stays run-validity-only

**Decision: candidate (b). A requested profile validation that completes and returns
`profile_evaluations.<id>.result = FAIL` does NOT change the process exit code from `0`.**

**No exit code `3` is added. Exit `1` is not reinterpreted. No existing exit-code meaning changes.**

### Why

The frozen class-verifier contract already defines process exit as **run validity only — never a
verdict**, and states that *"the presence of FAILURE / WITHHELD / CAVEAT reasons does **not** change
the exit code."* A `profile_evaluations` `FAIL` belongs to exactly that epistemic class: the
evaluation **ran successfully and produced a negative result**. That is not a failed execution of the
verifier.

A new exit code would have conflated process-execution semantics with evaluation outcome — the very
separation the existing contract exists to maintain, and the same distinction AIREP draws everywhere
else between *"did a measurement run?"* and *"what did it find?"*.

Quoted from the frozen contract rather than paraphrased, because this decision claims **no existing
exit-code meaning changes** — so the restatement must be exact:

| Code | Frozen meaning (verbatim) |
|---|---|
| `0` | *"evaluation completed; the presence of FAILURE / WITHHELD / CAVEAT reasons does **not** change the exit code"* |
| `1` | *"the evaluation request, an artifact, or an operator file could not be parsed, stage-0/1 artifact validity failed, or a **batch-level run-identity invariant** failed (a duplicate `(chain_id, record_id)` tuple in the produced verdict set, §9 R-10), so no results file is emitted"* |
| `2` | *"CLI usage error"* |
| `--help` | *"`0`, with nothing evaluated and no verdict emitted"* |

All four are carried into the revised contract **unchanged**. N-01c adds only one clarification, which
follows directly from the `0` row: a `profile_evaluations` `FAIL` is a completed evaluation, so like a
FAILURE / WITHHELD / CAVEAT reason it does not change the exit code.

So this is the correct outcome:

```text
Core valid . profile basis supplied . profile evaluated
profile result = FAIL . results emitted . process exit = 0
```

This deliberately preserves `process completion != conformance success`.

### The machine-readable result is authoritative

For profile-specific conformance, automation **MUST** inspect `profile_evaluations` and **MUST NOT**
infer semantic success from the process exit code.

> **Forbidden interpretation: `exit 0 == all requested profiles passed`.**

Process exit answers only whether the evaluation itself completed validly. `PASS` / `FAIL` /
`NOT_EVALUATED` answer what it found.

### CI / automation consequence

The Core class-verifier exit contract is **not** changed for shell-scripting convenience. If the
project later needs a command whose operational purpose is *"fail the shell step unless all requested
conformance checks PASS"*, that belongs in a higher-level wrapper/aggregator with its own explicitly
documented exit semantics, and it **MUST NOT** retroactively change the Core class-verifier contract.
No such wrapper is implemented in P2; the P2 parity harness inspects `profile_evaluations` directly.

### Coexisting statements that must not be collapsed

These may all hold simultaneously, when the failed profile is **not** itself an adopted Core
assurance prerequisite:

```text
Core artifact valid
AIREP assurance class = Authenticated
profile evaluation = FAIL
```

AD-14 still requires both official verifiers to agree on profile evaluation, class, reason/caveat
sets **and** exit code — under this resolution that agreement includes agreeing on `0`.

## Contract revision strategy — the historical contract is not edited

`CLASS_VERIFIER_CONTRACT.md` (`sha256:7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885`)
is **byte-identical in three locations** — the working spec and the `normative_basis/` of both frozen
handoff corpora — and that digest is recorded in `SOURCE_BASIS.json` and `manifests/FILES.json` of
both. It is the **semantic-basis identity of every recorded measurement**, including the C1 parity
run and the external consumer/verifier evidence.

Therefore:

- The existing contract is **not edited in place**, and its frozen copies are **not replaced**.
- A **new contract revision** is created; it becomes the semantic basis for new P2-B measurements.
- The historical contract remains valid evidence **for exactly the measurements made under it**. The
  new revision does **not** retroactively change those measurements.

```text
historical contract  sha256:7ecfce56...
    |
    | profile evaluation not represented
    v
revised contract
    |
    | adds generic profile-validation basis          (N-01)
    | adds profile_evaluations output channel        (N-01b)
    | preserves process-exit = run-validity-only     (N-01c)
    v
new corpus / parity evidence
```

**No historical external run is claimed to cover the revised contract.**

The existing 60-case corpus and its C1 parity evidence are likewise **preserved as historical** and
**not mutated** into the new result model. A new corpus/parity revision is created for the revised
contract, and old case results are **not restated** under it.

### Claim boundary after the revision

| Evidence | Basis | Covers `profile_evaluations`? |
|---|---|---|
| **Historical** — C1 parity run; external independent consumer/verifier run | original frozen contract `sha256:7ecfce56…` | **No** |
| **Current revised Core evaluation** | new contract revision | Yes, once measured |

**The existing independent consumer/verifier evidence does not cover `profile_evaluations`, and must
never be described as if it does.** No historical external implementation is claimed to have
implemented or passed the revised contract until it actually does.

---

## Test-only profile

`airep.test-profile` — **TEST-ONLY**, AIREP-owned, repository-controlled.

Its sole purpose is to exercise the generic profile-validation machinery and verifier parity. It is
**not** a companion profile, **not** an external integration, and **not** a recommended deployment
profile. It models no external system and is never named after one.

## Profile fixture matrix (new corpus revision)

| # | Case | Expected Core | Expected profile channel |
|---|---|---|---|
| 1 | no `profiles` | valid | channel absent / empty |
| 2 | syntactically valid unknown profile | valid | `NOT_EVALUATED`, `basis_digest: null` |
| 3 | malformed namespaced key | **Core-invalid** | not reached |
| 4 | malformed Core-level profile value | **Core-invalid** | not reached |
| 5 | known test profile, valid payload | valid | `PASS` + `basis_digest` |
| 6 | known test profile, invalid payload | **valid** (Core separately reported) | `FAIL` + `basis_digest` |
| 7 | known-valid + unknown | valid | `PASS` + `NOT_EVALUATED` |
| 8 | known-invalid + unknown | Core valid; requested validation failed | `FAIL` + `NOT_EVALUATED` |
| 9 | `airep.key-trust` self-revoked, no generic basis supplied | valid | `NOT_EVALUATED`; `producer-key-self-revoked` present in `authenticated_caveats` |
| 10 | assurance-uplift attack: unknown profile asserting authenticity | valid | `NOT_EVALUATED`; **class unchanged**, no reason erased |
| 11 | wrong-profile schema substitution (basis registered for id A applied to id B) | valid | basis **not** applied to B; B `NOT_EVALUATED` |
| 12 | changed basis digest for the same identifier | valid | evaluation basis differs; `basis_digest` differs |
| 13 | Python/Node parity over cases 1–12 | identical | identical |

Adversarial intent, stated so it is testable: unknown must never become `PASS`; unknown must never
uplift assurance; a basis for one identifier must never apply to another; substitution without an
identity change must be detectable; no network lookup may change any result; the two official
verifiers must never disagree.
