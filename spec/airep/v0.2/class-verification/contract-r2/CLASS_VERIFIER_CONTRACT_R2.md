# AIREP v0.2 — Class-Verifier Implementation Contract, revision **r2**

> **Measurement contract.** This document states *how a verifier revision measures* the AIREP v0.2
> class semantics. It does **not** define those semantics. The normative protocol semantics are
> [`../../CONFORMANCE_CLASSES.md`](../../CONFORMANCE_CLASSES.md).

**The revision axis is not the protocol version.** The AIREP **wire version remains `0.2`**
(`airep_version` is pinned `"const": "0.2"` in the shared schema). `r1` / `r2` identify
*measurement-contract revisions* only. An artifact never carries a contract revision.

---

## R2.0 Semantic basis identities

A verifier implementing this revision measures exactly this set. A future external implementer can
determine from these digests precisely which semantics were implemented.

| Basis | Identity |
|---|---|
| Normative class semantics (P2-A) | `spec/airep/v0.2/CONFORMANCE_CLASSES.md` `sha256:331f7cabb99cb12aa55f2395f0f073caf58282e0a43756680b9d86bf59e9a9a6` |
| Profile-validation decision (P2-0, N-01/N-01b/N-01c) | `spec/airep/v0.2/profile-validation/N-01_PROFILE_VALIDATION_DECISION.md` `sha256:5b00cb833a8cca126c524ea4a51c98e2e1dce6fc1a65a7b11a93e764a1a7c7aa` |
| Predecessor measurement contract (**r1**, historical) | `spec/airep/v0.2/class-verification/CLASS_VERIFIER_CONTRACT.md` `sha256:7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885` |
| Frozen integrity construction | `spec/airep/v0.2/INTEGRITY.md` `sha256:2fca9a02ebd8b22807f51742278d7ddfc101e25ca6fd4fa844d6c6a537e98c11` |

Artifact schemas are bound **individually**, by full path and full digest — never only by an
aggregate:

| Path | SHA-256 |
|---|---|
| `spec/airep/v0.2/schemas/common.schema.json` | `b46a02988ba3260444cd92153562346ca633e79f64eaf12c684d5069830e714a` |
| `spec/airep/v0.2/schemas/control.schema.json` | `f986225eac62c8df2091fc1f2af917c717025a88b6b0fe9157fdb07732f00b90` |
| `spec/airep/v0.2/schemas/decision.schema.json` | `04b53d4a5a1f1e3c7ba4d5ad32072a09b9e2b58702304a7845d327bc4ef84a6b` |
| `spec/airep/v0.2/schemas/effect.schema.json` | `4bc2cda84ba68be6e57a8b18a7fce733c54c6835e463822e5b9721a586456297` |
| `spec/airep/v0.2/schemas/execution.schema.json` | `eaf476d0dbc43a7abb3eabc55a427a0bfc8dfd8529f18d8e5efe53672f58085b` |

**Schema-set aggregate — exact derivation, reproducible without guessing.** Build one line per schema
as `<lowercase-hex-sha256><SP><SP><repository-relative-path><LF>`, sort the lines by path under
unsigned byte order, concatenate them with no separator and no trailing content beyond each line's
`LF`, and take the SHA-256 of those bytes:

```
sha256:638c7f520b0295aaae650e86ff86582e6ff3f680e426df84c95c296e2c6352ef
```

This is the same construction `sha256sum` emits, so it is reproducible with
`LC_ALL=C sort -k2 | sha256sum` over the five `sha256sum` lines. The aggregate is a convenience over
the individual bindings above; the **individual** digests are authoritative.

All identities in this section are additionally published machine-readably in
[`SOURCE_BASIS.json`](./SOURCE_BASIS.json).

### Provenance

```text
historical contract (r1)  sha256:7ecfce56...
    |
    | profile evaluation not represented
    v
revised contract (r2)
    |
    | adds deterministic profile-validation basis input   (N-01)
    | adds profile_evaluations verdict channel            (N-01b)
    | preserves process-exit = run-validity-only          (N-01c)
    v
new corpus / parity evidence
```

**r2 is not the basis of any historical measurement.** The C1 parity run, the historical 60-case
corpus, and every external run recorded to date were measured against **r1** and remain measured
against r1. Nothing in r2 retroactively changes them, and no historical external implementation is
claimed to implement or pass r2.

---

## R2.1 Surfaces carried unchanged from r1

Everything in r1 not listed in R2.2–R2.7 is carried **unchanged, by reference**, and is not restated
here: the evaluation-request envelope (r1 §0); operator-input formats for bindings, independence
policy, revocation snapshot and clock (r1 §1); evaluation order and dependencies (r1 §3); the
withheld-vs-failure distinction (r1 §4); the closed reason registry (r1 §5); the adversarial matrix
(r1 §7); and the source-review rulings (r1 §9).

r1 is **not edited** and its frozen copies in the interop handoff packages are **not replaced**.

---

## R2.2 Additive verdict channel: `profile_evaluations`

The r1 normalized verdict envelope gains **one additive member**. Every existing member keeps its
name, shape, meaning and ordering rules.

```jsonc
{
  // … all r1 members unchanged …
  "profile_evaluations": {
    "<namespaced-id>": {
      "result": "PASS" | "FAIL" | "NOT_EVALUATED",
      "basis_digest": "sha256:<64 lowhex>" | null
    }
  }
}
```

Rules:

- **One entry for every syntactically valid profile identifier present on the artifact.** Presence
  in the artifact, not in the supplied basis set, determines membership.
- `profile_evaluations` is **present always**, `{}` when the artifact carries no `profiles` member.
- `PASS` / `FAIL` require an accepted basis for **that exact identifier**; both carry
  `basis_digest`. `NOT_EVALUATED` carries `basis_digest: null`.
- **Deterministic ordering.** Serialized key order is unsigned lexicographic over each identifier's
  UTF-8 byte sequence, with no Unicode normalization — the same rule r1 §2 fixes for verdict
  ordering, chosen for the same reason (Python code-point order and JavaScript UTF-16 order diverge;
  byte order is the one both runtimes implement identically).

  **The ordering algorithm is normative and MUST be performed explicitly.** Each implementation
  MUST enumerate the profile identifiers and **sort them into ascending unsigned lexicographic order
  over the UTF-8 bytes of the profile identifier** before constructing or serializing the result.
  Byte determinism MUST NOT be justified by Python preserving insertion order, by JavaScript
  property-order rules, or by the absence of integer-like keys — those facts make the chosen
  representation viable, but they are **not** the ordering algorithm. Under the current ODQ-12
  grammar (lowercase ASCII) unsigned UTF-8 byte order and ASCII lexical order coincide; the
  normative rule is stated in byte form only, so a future identifier-grammar change inherits the
  byte rule rather than any runtime's behaviour. The comparator gates this independently.

  **Why an object is byte-safe here, rather than an ordered array.** JSON object key order is
  normally a hazard for cross-language byte determinism, because JavaScript reorders
  integer-like own properties ahead of string keys while Python preserves insertion order. That
  hazard cannot arise under the adopted namespaced-id grammar
  `^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$` (ODQ-12): every valid identifier begins with a lowercase
  letter and contains at least one `.`, so **no valid identifier is ever integer-like**, and both
  runtimes preserve insertion order for such keys. Emitting entries in sorted byte order therefore
  produces identical bytes in both. An ordered array of `{profile_id, result, basis_digest}` would
  also be safe; the object is retained because it is not less safe **under this grammar**, and the
  comparator gates the ordering rule independently rather than trusting either runtime. An
  identifier grammar change would reopen this choice.

### `profile_evaluations` is evaluation evidence, never assurance evidence

It answers exactly one question: **did this profile payload satisfy this exact declared validation
basis?** Nothing wider.

```text
profile PASS     != higher AIREP class
profile FAIL     != the reported external fact is false
NOT_EVALUATED    != PASS,  != FAIL
```

- A `PASS` **MUST NOT** raise `class`, remove any reason from any channel, or satisfy any class
  prerequisite.
- A `FAIL` states that bytes did not satisfy a declared basis. It makes **no** claim about the world.
  The verifier evaluates bytes against a basis, not reality.
- `NOT_EVALUATED` is an observed statement about the evaluation process and is **never** upgraded.

---

## R2.3 Profile-validation basis input (operator input, network-free)

Supplied as one deterministic input file, consistent with r1 §1's network-free operator-input model.

```jsonc
{
  "profiles": {
    "<namespaced-id>": {
      "schema_path":  "<path to the exact basis bytes>",
      "basis_digest": "sha256:<64 lowhex>"
    }
  }
}
```

Invariants:

- **Exact identifier.** A basis registered for identifier *A* is **never** applied to identifier *B*.
  There is no fallback, wildcard, prefix or default basis.
- **Exact bytes and digest.** `basis_digest` MUST equal the SHA-256 of the exact basis bytes read
  from `schema_path`.
- **No network resolution and no implicit discovery.** A basis that would require either is
  unusable; it is never silently fetched.
- The input file's own SHA-256 is recorded in the verdict evidence block as
  `profile_bases_digest` (`null` when the input was not supplied), so a verdict names the
  profile-validation snapshot it came from — the same discipline r1 §2 applies to bindings,
  independence policy and revocation.

**Two digest levels, never substituted for one another:**

| Identity | Bytes hashed | Answers |
|---|---|---|
| `evidence.profile_bases_digest` | the exact **registry input file** bytes | *Which complete profile-validation configuration did this run receive?* |
| `profile_evaluations[].basis_digest` | the exact **validation-basis bytes used for that one identifier** | *Against exactly which validation artifact was this profile evaluated?* |

Both are load-bearing and they mean different things. A run may carry
`profile_bases_digest = digest(registry file)` while a single entry carries
`basis_digest = digest(that profile's schema bytes)`.

**Registry bytes MUST have exactly one interpretation — duplicate member names are rejected.**
Ordinary JSON parsers resolve duplicate object member names by "last one wins", and two parsers may
differ. Because `profile_bases_digest` identifies the exact registry bytes, bytes with more than one
possible reading would leave that digest stable while the evaluation semantics were not. Therefore a
registry containing a duplicate member name **MUST** be rejected as unusable (R2.4), specifically:

- duplicate profile identifiers under `profiles`;
- duplicate members inside any single profile-basis entry (e.g. two `schema_path` or two
  `basis_digest` members);
- duplicate members anywhere else in the registry object.

Both official implementations MUST reject such a registry, and this MUST be tested in each. **This
requirement is scoped to the r2 profile-basis registry only.** It does not alter historical artifact
parsing semantics, and nothing here is applied retroactively to r1 measurements.

**Path containment MUST survive filesystem resolution, not merely textual inspection.** Rejecting
absolute paths and textual `..` is **not sufficient**: a symlink inside the package can point outside
it while the written path looks contained, and a symlinked *registry* path would otherwise yield a
root that is itself unresolved.

The required procedure, in this order:

1. **Resolve the registry file itself to its canonical real path**, following all links.
2. Define the **allowed basis root** as the **resolved parent directory** of that canonical registry
   path. The root is never derived from an unresolved or symlinked registry pathname.
3. Resolve each declared `schema_path` against that resolved root.
4. Follow all filesystem links to the final target.
5. Require the final resolved target to remain **within** the resolved root.

Reject, as an unusable basis (R2.4): absolute paths; `..` traversal leaving the root; symlink-mediated
escape; and any path whose final resolved target lies outside the allowed basis root.

**Semantic identity is the exact basis bytes and their digest — never the path.** The path is only a
deterministic in-package locator. Machine-local filesystem layout MUST NOT influence any basis
identity, so evidence packages remain reproducible on a machine that does not share the maintainer's
layout.

*Test-environment limitation, recorded rather than assumed away:* where the test environment cannot
portably create a symlink, the symlink-escape negative probe is recorded as not exercised in that
environment, and real-path containment remains enforced in both implementations regardless.

---

## R2.4 Basis unusable vs payload invalid — a mandatory distinction

**These are different conditions and MUST NOT be conflated.**

### Evaluation basis unusable — NOT a profile FAIL

- declared `basis_digest` does not match the exact supplied basis bytes;
- basis bytes cannot be parsed;
- the basis entry's identifier does not match the requested profile identifier;
- required validator configuration is malformed;
- an implicit or network-resolved basis would be required.

In each case **the profile was never validly evaluated**, so reporting `FAIL` would assert a
measurement that did not occur. It **MUST NOT** appear as
`profile_evaluations.<id>.result = "FAIL"`.

**Exact run behaviour.** A required operator input that cannot be used is handled under r1's existing
operator-input validity model: r1 §2 fixes exit `1` for the case where *"an operator file could not
be parsed … so no results file is emitted"*. A supplied profile-basis registry that is unusable for
any reason above is such an input, therefore:

```text
unusable required profile basis -> run-input invalid -> exit 1 -> NO results file emitted
```

**No partially trustworthy batch result is emitted after the evaluation basis itself has been
declared unusable.** r1 defines no partial-result model and r2 does not add one.

This is distinct in every respect from the completed-evaluation case below, which emits results and
exits `0`.

### Valid basis, invalid payload — this is a profile FAIL

The evaluation completed and produced a negative result:
`profile_evaluations.<id>.result = "FAIL"` with the `basis_digest` that was used.

---

## R2.5 Process exit — carried from r1 unchanged

Quoted from r1, not paraphrased, because r2 changes **none** of it:

> - `0` — evaluation completed; the presence of FAILURE / WITHHELD / CAVEAT reasons does **not**
>   change the exit code;
> - `1` — the evaluation request, an artifact, or an operator file could not be parsed, stage-0/1
>   artifact validity failed, or a **batch-level run-identity invariant** failed (a duplicate
>   `(chain_id, record_id)` tuple in the produced verdict set, §9 R-10), so no results file is
>   emitted;
> - `2` — CLI usage error;
> - `--help` — `0`, with nothing evaluated and no verdict emitted.

**No new exit code is added. Exit `1` is not reinterpreted.** Per N-01c, a `profile_evaluations`
`FAIL` is a completed evaluation, so like a FAILURE / WITHHELD / CAVEAT reason it does **not** change
the exit code:

```text
profile FAIL -> evaluation completed -> results emitted -> exit 0
```

**Automation MUST inspect `profile_evaluations`.** The interpretation
`exit 0 == all requested profiles passed` is **forbidden**. Process exit answers only whether the
evaluation completed validly.

---

## R2.6 `airep.key-trust` — mechanics that implement, and never redefine, the P2-A semantic

`CONFORMANCE_CLASSES.md` §6.1 fixes the protocol semantic: a self-declared revocation caveat **MUST**
surface on an **earned Authenticated** result, on the adopted authenticated-caveat channel, **never
as a clean pass**, and it **never raises or lowers a class by itself**.

This revision pins the exact mechanics that **implement** that semantic. **They do not redefine,
extend or narrow it**; where any tension appears, `CONFORMANCE_CLASSES.md` governs.

- The caveat `producer-key-self-revoked` is emitted **iff**
  `profiles["airep.key-trust"].revocation.revoked === true` on the artifact, on an already-earned
  Authenticated result. *(Carried unchanged from r1 — "caveat sources are pinned, not inferred".)*
- It cannot create Authenticated, raise a class, lower a class by itself, or erase a failure or
  withheld reason.
- **It requires no supplied profile-validation basis.** This narrow Core-owned read is independent of
  R2.2/R2.3 entirely.
- Consequently `profile_evaluations["airep.key-trust"].result` **MAY be `NOT_EVALUATED`** in the same
  verdict that carries `producer-key-self-revoked`. These concern different things — full
  profile-basis validation versus one narrowly adopted Core-owned semantic — and are **not**
  contradictory.

---

## R2.7 Parity contract — extended surface (AD-14)

r1 §6's parity discipline is carried unchanged and **extended**. The comparator MUST independently
gate identical values across the **complete** observable result surface:

| # | Surface |
|---|---|
| 0 | `artifact_ref` (`chain_id`, `record_id`) — structured, never concatenated |
| 1 | `class` |
| 2 | all five reason/caveat sets (`authenticated_failures`, `authenticated_withheld`, `authenticated_caveats`, `witnessed_failures`, `witnessed_withheld`) |
| 3 | `observer_assessment` |
| 4 | evidence identities (`now`, `freshness_window_seconds`, `bindings_digest`, `independence_policy_digest`, `revocation_digest`, `profile_bases_digest`) |
| 5 | `profile_evaluations` **identifier set** |
| 6 | `profile_evaluations` **result values** (`PASS` / `FAIL` / `NOT_EVALUATED`) |
| 7 | `profile_evaluations` **`basis_digest` values** |
| 8 | `profile_evaluations` **deterministic ordering** |
| 9 | results-envelope serialization: the verdict **array ordering** by `(chain_id, record_id)` under unsigned UTF-8 byte order with no Unicode normalization, the duplicate-tuple run-invalidity rule, trailing newline, and absence of metadata — all carried unchanged from r1 §2 |
| 10 | process exit |

**Parity is not scoped to checks both implementations happen to implement.** Per AD-14, *"a check
implemented in one verifier and not the other is a release blocker, not a footnote."* A one-sided
implementation of any surface above means r2 does **not** pass.

### Engine identity is run provenance, not a parity value

The two official implementations are expected to use **different** validation engines. Their
engine-identification strings are therefore **not** compared for equality, and are **not** part of
the parity surface above.

Each run separately records, as provenance: the Python validator engine, version and configuration;
the Node validator engine, version and configuration; and the exact shared profile basis. The
semantic claim this supports is:

> Different approved implementations, using different engines, produced the same required result
> surface against the same exact validation basis.

Implementation identity is preserved, never erased to make parity easier.

### Required negative proofs

The comparator MUST independently gate these, not merely observe them:

1. **Assurance non-uplift.** Two artifacts identical except that one carries an unknown profile, or a
   `PASS`ing test profile, and the other carries none. With identical class prerequisites, the
   profile **MUST NOT** produce a higher class or remove any reason.
2. **Unknown never PASS.** A syntactically valid profile with no supplied basis is `NOT_EVALUATED` —
   never `PASS`, never `FAIL`, and never Core-invalid on that ground alone.
3. **Identifier substitution rejected.** A basis registered for one identifier is not applied to
   another.
4. **Basis mismatch is not FAIL.** A digest/bytes mismatch is a run-input condition (R2.4), never
   `profile_evaluations.FAIL`.
5. **Profile FAIL implies nothing about the world.** No output asserts that the external fact
   represented by a failing payload is false.
6. **`airep.key-trust` regression.** The adopted caveat behaviour is unchanged, requires no supplied
   basis, and coexists with `NOT_EVALUATED` for that identifier.

---

## R2.8 Test-only profile

`airep.test-profile` is a **repository-controlled TEST-ONLY fixture** whose sole purpose is to
exercise the generic profile-validation machinery and verifier parity.

It is **not** a companion profile, **not** an external integration, and **not** a deployment
recommendation. It models no external system, and it is never named after one.

---

## R2.9 Out of scope

Unchanged from r1 §8, and additionally: no companion profile (AD-10 SCITT, AD-11 authorization
reference, AD-12 MCP/A2A/OTel) is defined, required, or implemented by this revision. Per AD-16 their
absence is not a Core blocker, and no profile schema for any of them exists.
