# Start here

One path, in order. Nothing here is optional except where it says so.

## A. Check you have the right bytes

Compare the SHA-256 of the archive you downloaded against the digest supplied to you
**out of band** — in the message that pointed you at this package, not from inside it.

```sh
sha256sum airep-v0.2-independent-verifier-corpus-v0.1-full.zip
```

The archive deliberately does **not** contain its own digest. A digest carried inside the thing
it describes authenticates nothing.

## B. Extract

```sh
unzip airep-v0.2-independent-verifier-corpus-v0.1-full.zip
cd airep-v0.2-independent-verifier-corpus-v0.1
```

## C. Check the package is intact

```sh
python3 tools/verify_package.py
```

Standard library only. It checks **file presence, digests, declared-JSON parseability, unexpected
files and source-basis identity**. It is not an AIREP verifier and does not canonicalize, hash,
verify signatures or classify. If it passes you have the right bytes and nothing more.

## D. Read, in this order

1. [`CAPABILITY_REQUIREMENTS.md`](./CAPABILITY_REQUIREMENTS.md) — what your checker must be able to
   do, and the one capability most likely to be missing
2. [`normative_basis/INTEGRITY.md`](./normative_basis/INTEGRITY.md) — canonicalisation, hash
   preimage, signature preimage, domain separation, suite registry
3. [`normative_basis/CLASS_VERIFIER_CONTRACT.md`](./normative_basis/CLASS_VERIFIER_CONTRACT.md) —
   evaluation order, the five reason channels, withheld vs failure
4. [`METHOD.md`](./METHOD.md) — provenance kinds, and what is derived rather than frozen

## E. Implement the six fixed vectors first

`bytes/vectors/V1`–`V4`, `W1`, `W2`. Each carries the whole chain in raw `.bin` and `.hex`:
canonical JCS bytes, hash tag, hash preimage, expected `integrity.current`, signature tag, suite
id, signature preimage, signature, public key.

Do these before any case. They isolate the byte-construction stack from classification, so if
something is wrong you learn *which stage* is wrong. Note the release states these bodies are
construction-test material and deliberately **not** schema-conformant artifacts.

## F. Then these eight cases

```
CLS-P1     clean Decision                       CLS-PS1    signature under the wrong key
CLS-P2     clean witnessed Decision             CLS-PB2    no producer binding — WITHHELD
CLS-P3     Effect + referenced Execution        CLS-LEX1   lexical form matters
CLS-CTL1   Control Evidence                     PROC-UNP   run-invalid, no verdict
```

They are chosen to hit each distinct machinery once and in increasing difficulty.

> **This is an implementation order, not a reduced final run.** Eight cases is where to start, not
> what to report. A run of these eight alone does not qualify and must not be reported as a run of
> the corpus.

## G. Then all 18

`CASE_INDEX.json` lists them; `CASE_SELECTION.md` says what each one is for and what it does not
establish. The full run is the reportable unit.

## H. Fill in the report

Copy [`reporting/REPORT_TEMPLATE.jsonl`](./reporting/REPORT_TEMPLATE.jsonl) — 18 rows, result
fields blank — and complete it. Validate against
[`reporting/REPORT_SCHEMA.json`](./reporting/REPORT_SCHEMA.json). The schema requires all seven
outcome dimensions and the five reason channels on every result: **FAIL, WITHHELD, INDETERMINATE,
INVALID_CONFIGURATION and INVALID_ARTIFACT are distinct and a conforming report cannot collapse
them.**

## I. Record your own provenance

Only you can state these, and nobody else can state them for you:

- your implementation's **commit or package digest**;
- whether you **inspected the first-party AIREP verifier code** (it is public — the honest answer
  is whatever it is);
- whether **expected results were visible to you before you implemented**;
- the **exact normative text** you worked from;
- the **input package digest** you actually ran against.

[`reporting/ROLE_MODEL.md`](./reporting/ROLE_MODEL.md) has the roles. Every one is blank except
originator. You are not pre-assigned to anything.

## J. Report disagreement as it stands

**If your verifier disagrees with an expected result, report the disagreement. Do not alter the
corpus to make it agree.**

A disagreement is a finding about the corpus, the expected result, your implementation, or the
specification — and which one it is gets decided afterwards, by looking. Classify it in
`finding_classification` and leave it. A disagreement reported honestly is worth more than an
agreement produced by adjustment.
