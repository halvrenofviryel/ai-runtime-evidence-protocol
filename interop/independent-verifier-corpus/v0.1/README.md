# AIREP v0.2 Independent-Verifier Corpus v0.1

A compact, release-pinned test target for a verifier written **from AIREP's published text
rather than from AIREP's code**.

This is not a new AIREP version, not a producer implementation, not a SCITT implementation, and
not evidence that interoperability has been achieved. It is a set of frozen inputs, frozen
expected outputs and the byte material needed to check them.

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
does not cryptographically authenticate the author or maintainer identity.** `main` may have
advanced since; no byte here was taken from `main`.

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
| definitive failure | 5 |
| caveat (passes with a recorded caveat) | 1 |
| withheld assurance | 3 |
| indeterminate / cannot-reconstruct | 3 |

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

Three cases carry no verdict by design. Two emit a non-zero process exit and nothing else.

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

The frozen release contains **exactly one** Control Evidence artifact: `CTL1`, `boundary_side:
issuer`, `control_event: dispatched`. Searching the whole pinned `spec/airep/v0.2` tree for
`"receiver"`, `"received"` or `"delivery_failed"` outside the schema and documentation files that
*define* those enum values returns nothing.

So there is **no receiver-side Control artifact and no paired delivery case** in this release.
This corpus therefore **does not test end-to-end control-delivery reconciliation**, and no paired
case was synthesised to appear to. **Absence of a receiver-side record does not prove
non-delivery** — it means the evidence was never produced, which is a different thing.

## Keys

All keys are **TEST-ONLY**. Only public halves are distributed. Their signatures are real Ed25519
signatures over real frozen preimages so the cryptographic path is genuinely exercised, and they
are **not evidence of real-world authenticity**. The private seeds are published in the source
repository; they are excluded here and the package's leak scanner fails if any appears.

## Checking the package

`tools/verify_package.py` is stdlib-only and checks **file presence, digests, JSON parseability
and unexpected files**. It does not canonicalize, hash, verify signatures or classify anything.
It is not a reference verifier and must not be mistaken for one.
