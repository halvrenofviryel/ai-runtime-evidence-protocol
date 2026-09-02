# AIREP v0.2 Independent-Verifier Corpus v0.2

> ### ▶ New here? Read [`START_HERE.md`](./START_HERE.md) first.
> It is the one recipient path: verify the archive, run the package checker, read the normative
> text in order, implement the six fixed vectors, then work the cases and file the report.

A compact, release-pinned test target for a verifier written **from AIREP's published text
rather than from AIREP's code**.

This is not a new AIREP version, not a producer implementation, not a SCITT implementation, and
not evidence that interoperability has been achieved. It is a set of frozen inputs, frozen
expected outputs and the byte material needed to check them.

## Revision provenance — what changed since v0.1

This is corpus revision **v0.2**. Revision **v0.1** was published, handed off and externally run;
it and its archive digest are preserved byte-for-byte and are not superseded as a historical
record. That external run stands at **17 AGREE / 1 DISAGREE** and is not restated.

**Exactly one expected value changed, on one row.**

| Row | Field | v0.1 | v0.2 |
|---|---|---|---|
| `CLS-XT1` | `cryptographic_result` | `PASS` | `NOT_EVALUATED` |

`CLS-XT1` is a definitively revoked producer binding. `CLASS_VERIFIER_CONTRACT.md` §4 and ruling
**R-6** make stage 4's prerequisite *"binding accepted **and** not definitively revoked"*, so on
that row the producer-signature stage does not execute and no signature is verified under any key.
The v0.1 projection rule branched on case identity and a revoked binding matched no branch, so it
fell through to `PASS` — asserting that a cryptographic check succeeded when none ran.

This was a defect in the **package-derived projection**, not in the contract and not in any frozen
field. On that row the class, all five reason channels, observer assessment, process exit, run
validity and signing-input reconstruction were correct in v0.1 and are unchanged here. It was
found by the external run against v0.1 and reproduced before correction.

The corrected rule is **semantic, not case-specific**: `cryptographic_result` is derived from the
frozen reason channels against the stage-4 prerequisite, so any case whose producer binding was
never accepted or was definitively revoked projects `NOT_EVALUATED`. Per R-6 a missing or
malformed revocation *state* is not "revoked" and does not suppress the gate.

**A result against v0.1 and a result against v0.2 are not interchangeable on the `CLS-XT1` row.**
Cite the revision you ran.

No external evaluation has been run against this revision.

## Source basis

| | |
|---|---|
| Repository | `halvrenofviryel/ai-runtime-evidence-protocol` |
| Release tag | `v0.2.0-alpha.1` |
| Annotated tag object | `2c20ff2d6cc990cfc4ceb14a5e22ef823821635f` |
| **Target commit** | **`b5ae87f74b386b11b8882865e50c3ad38120ff97`** |
| Version DOI | `10.5281/zenodo.22101986` |
| Wire version | `0.2` |

The source content is pinned by the resolved commit SHA and per-file digests. **The unsigned tag
does not cryptographically authenticate the author or maintainer identity.** `main` may have advanced since.

**No normative source byte or frozen expected outcome was taken from moving `main`.**
Package-authored documentation, manifests and projections were created on the packaging branch
and are identified as such — see `METHOD.md` for the `provenance_kind` labels.

## What AIREP v0.2 signs with

One suite, and only one. `INTEGRITY.md` §3.1 is a **closed** registry with a single entry:

> `ed25519` — Ed25519 (RFC 8032), **pure** (no pre-hash), over the raw preimage bytes.

Not ES256. Not P-256. Adding a suite is a specification change. The construction stack is
**RFC 8785 (JCS) → SHA-256 → RFC 8032 pure Ed25519**.

## Contents

18 cases and 6 fixed vectors.

| Category | Count |
|---|---|
| positive | 6 |
| definitive failure | 6 |
| caveat (passes with a recorded caveat) | 1 |
| withheld assurance | 3 |
| indeterminate / no verdict emitted | 2 |

Artifact families: `decision` 13, `effect` 2, `control` 1, plus 2 process probes that evaluate no
artifact. **`execution` appears as a referenced `related_artifacts` member inside the Effect
cases, never as a primary artifact under evaluation** — that is how the frozen corpus exercises
it, and the package does not claim otherwise.

## The distinction this corpus is built around

A verifier must not collapse these into one boolean:

| Outcome | Meaning |
|---|---|
| **definitive FAILURE** | a normative check ran and failed |
| **WITHHELD** | the check could not run because an input was absent — *not* a failure |
| **INDETERMINATE** | the signing input, head, reference or configuration could not be rebuilt |
| **run-invalid** | no verdict is emitted at all; a process exit is the only result |

**Two cases emit no verdict at all** — both are process probes returning a non-zero exit and
nothing else. Every other case emits a normal verdict, the definitive failures included: a failure
is a *verdict*, not the absence of one. `CLS-LEX1` in particular returns `AIREP-Authenticated`
with a definitive `witness-claim-invalid`, so it is a failure case, not an indeterminate one.

## What a successful run would NOT establish

- AIREP v0.2 stability, standardisation, or IETF/SCITT endorsement;
- third-party **producer** interoperability, or deployment interoperability;
- correctness of AIREP semantics, or soundness of every AIREP case;
- truth or completeness of any real-world evidence;
- security of production key management;
- proof that any implementation was written independently;
- that an AI action was authorised, delivered, executed, or had a real-world effect;
- correctness of a model output.

It would establish only the bounded result actually measured:

> A separately implemented verifier reproduced, or did not reproduce, specified AIREP
> construction and classification results for the selected release-pinned cases.

## Interoperability boundary

> A successful run may populate the report's **author-produced-corpus / independently
> implemented-consumer** category. It does not establish a third-party AIREP producer or
> deployment interoperability.

## Control delivery — a disclosed absence

The scored class-verification corpus contains **one primary Control case**: `CTL1`,
`boundary_side: issuer`, `control_event: dispatched`. Control artifacts appear elsewhere in the
pinned tree — the schema-validation corpus carries about thirty, Stage-4 more — so this is a
statement about the **scored** corpus, not about the release as a whole.

Searching every `.json` under the pinned `spec/airep/v0.2` tree for the values `"receiver"`,
`"received"` or `"delivery_failed"` returns exactly one file: `schemas/control.schema.json`, which
*defines* the enum. **No fixture anywhere carries a receiver-side value.**

So no paired issuer/receiver delivery case exists in this release, this corpus **does not test
end-to-end control-delivery reconciliation**, and none was synthesised to appear to. **Absence of
a receiver-side record does not prove non-delivery.** What the search establishes is narrower, and
is all that should be said: *no such evidence is present in the pinned release.* Whether such
evidence was ever produced elsewhere is not something this package can observe.

## Keys

All keys are **TEST-ONLY**. Only public halves are distributed. Their signatures are real Ed25519
signatures over real frozen preimages so the cryptographic path is genuinely exercised, and they
are **not evidence of real-world authenticity**. The private seeds are published in the source
repository; they are excluded here and the package's leak scanner fails if any appears.

## Byte material — what is provided, for which cases

| Material | Coverage |
|---|---|
| Canonical JCS bytes and hash preimage (`.bin` + `.hex`) | **17 of 18 cases**, under `bytes/cases/<id>/` |
| Signature preimage | the 16 cases where a producer binding resolves |
| Full chain incl. signature, suite id, public key | the **6 fixed vectors**, under `bytes/vectors/` |
| None | `PROC-UNP` — its request is unparseable by design |

Do not read this as "every case carries every byte artefact". It does not, and the table above is
the precise statement.

The two layers are complementary rather than overlapping. The **vectors** are construction-test
bodies — the release states they are deliberately *not* schema-conformant artifacts — and they
exercise the byte-construction stack. The **16 verdict-emitting cases** are conformant artifacts and
exercise classification. The two process probes are not: `PROC-UNP` ships a deliberately invalid
38-byte request, because a verifier's behaviour on unparseable input is the thing it measures.

Every per-case derivation is self-validated against a value this package did not produce: the
derived hash preimage must SHA-256 to the artifact's own recorded `integrity.current`. All 17
match. Where a signature preimage is emitted it is checked against the artifact's own recorded
signature. `CLS-PS1` does not verify — that is the case's expected outcome, not a packaging error.

## Checking the package

`tools/verify_package.py` is stdlib-only and checks **file presence, digests, JSON parseability
and unexpected files**. It does not canonicalize, hash, verify signatures or classify anything.
It is not a reference verifier and must not be mistaken for one.
