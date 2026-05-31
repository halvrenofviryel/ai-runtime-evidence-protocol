# AI Runtime Evidence Protocol (AIREP)

[![AIREP conformance](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/actions/workflows/conformance.yml/badge.svg)](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/actions/workflows/conformance.yml)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.20475136-blue)](https://doi.org/10.5281/zenodo.20475136)
[![License: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-green)](./LICENSE)
[![License: CC-BY-4.0](https://img.shields.io/badge/spec-CC--BY--4.0-green)](./LICENSE-CC-BY-4.0.txt)

**An AI decision receipt — one signed, checkable record per AI runtime decision, readable by anyone, tied to no vendor.**

When an AI system decides something — answer this, refuse that, hand it to a person — someone
may later need to ask: *what did it decide, why, and on what basis?* Today every system answers
that differently, or not at all. AIREP is a small, fixed record format that answers it the same
way everywhere — **an AI decision receipt** — so an auditor, a regulator, a customer, or a teammate
on another product can read one decision and check it offline, without access to the model that made
it. (AIREP is the format; *AI decision receipt* is the thing it produces — the way SPDX and CycloneDX
are formats and an *SBOM* is the thing.)

> **Status: Experimental.** AIREP is a *proposed* open format with one reference implementation.
> It is **not** a ratified standard. See [`spec/airep/v0.1/STATUS.md`](./spec/airep/v0.1/STATUS.md)
> for the maturity picture, open items, and change control.

**Canonical home:** <https://github.com/halvrenofviryel/ai-runtime-evidence-protocol> — the schema
`$id`s resolve as raw files under its `main` branch.

## What a record is

A record is a receipt for one decision: who decided and when (`subject`), what was decided on
(`input`), the claim and its basis (`claim`), the result (`output`), the supporting pointers
(`evidence`), the decision as one verb (`directive`), an honest statement of what it does and does
**not** cover (`scope`), and a tamper-evident stamp — hash, signature, and a chain link to the
previous record (`integrity`). Content stays out of the record: the question, answer, and evidence
are referenced by pointer and hash, so a record can be kept and shared without exposing regulated
data. Vendor-, model-, or domain-specific detail lives only under an optional `profiles` block, and
a **neutrality test** proves nothing leaked into the shared core.

A record proves the decision *path* was recorded faithfully and not altered. It does **not** prove
the AI's answer was correct — `scope.does_not_cover` keeps that boundary explicit.

## Who is this for — start here

It is an **Experimental** proposed open format with a reference implementation — see
[`STATUS.md`](./spec/airep/v0.1/STATUS.md). Pick your path:

- **Reviewing / evaluating it?** Read [`EXPLAINER.md`](./spec/airep/v0.1/EXPLAINER.md) (plain-language
  tutorial, **start here**) and [`THREAT_MODEL.md`](./spec/airep/v0.1/THREAT_MODEL.md) (every threat
  graded honestly — `partial`/`none`, never "defended"). Then prove it yourself: `cd spec/airep/v0.1
  && pip install jsonschema cryptography` (Node 20+ also required), then `python3
  conformance/validate.py` and `python3 conformance/verify.py examples/chain.jsonl --pubkey
  examples/test_public_key.txt --class` — two independent verifiers re-derive every hash byte-for-byte
  and you'll see `sig=ok`.
- **Adopting it (writing your own records)?** Follow **"Write your own record in 5 minutes"** in
  [`EXPLAINER.md`](./spec/airep/v0.1/EXPLAINER.md): copy
  [`examples/neutral_record.json`](./spec/airep/v0.1/examples/neutral_record.json), edit the fields,
  sign with your **own** key via [`producers/python/`](./producers/python/), and verify it. A custom
  `profiles.<name>` block works with **no upstream registration** — see
  [`profiles/README.md`](./spec/airep/v0.1/profiles/README.md) "Authoring your own profile".
- **Contributing?** Read [`CONTRIBUTING.md`](./CONTRIBUTING.md), browse the
  [`good first issue`](../../labels/good%20first%20issue) and [`help wanted`](../../labels/help%20wanted)
  labels (the open items from [`STATUS.md`](./spec/airep/v0.1/STATUS.md) are filed there), and report
  verifier / crypto flaws privately via [`SECURITY.md`](./SECURITY.md). The most-wanted contribution is
  a **genuinely third-party producer**.

## Repository map

| Path | What it is |
|------|------------|
| [`spec/airep/v0.1/EXPLAINER.md`](./spec/airep/v0.1/EXPLAINER.md) | Plain-language tutorial. **Start here.** |
| [`spec/airep/v0.1/SPEC.md`](./spec/airep/v0.1/SPEC.md) | Normative specification — the binding rules. |
| [`spec/airep/v0.1/core.schema.json`](./spec/airep/v0.1/core.schema.json) | JSON Schema (draft 2020-12) for the core record. |
| [`spec/airep/v0.1/profiles/`](./spec/airep/v0.1/profiles/) | Optional binding profiles (key trust, chain-witness/freshness, EU AI Act, NIST AI RMF, OWASP/threat, observability). |
| [`spec/airep/v0.1/conformance/`](./spec/airep/v0.1/conformance/) | Two independent verifiers (Python + Node) and a runnable validator. |
| [`spec/airep/v0.1/examples/`](./spec/airep/v0.1/examples/) | Worked records with really-computed hashes + Ed25519 signatures, including a 5-record chain. |
| [`spec/airep/v0.1/THREAT_MODEL.md`](./spec/airep/v0.1/THREAT_MODEL.md) | What the format detects, how, and what it does not. |
| [`producers/python/`](./producers/python/) | Copy-paste producer — sign your own record with your own key. |

## Check it yourself

```bash
cd spec/airep/v0.1
pip install jsonschema cryptography      # Python deps (Node 20+ also required for verify.mjs)
python3 conformance/validate.py          # full battery: schema, neutrality, integrity, chain, tamper
python3 conformance/verify.py  examples/chain.jsonl --pubkey examples/test_public_key.txt --class   # Python -> sig=ok
node      conformance/verify.mjs examples/chain.jsonl --pubkey examples/test_public_key.txt --class   # Node -> same bytes
```

Two implementations on different language and crypto stacks each validate structure, run the
neutrality test, re-derive every hash and agree on it byte-for-byte, and re-verify the signatures.
Two independent verifiers agreeing is what makes AIREP an interchange format rather than a
single-tool artifact.

## Reference implementation

The first producer of AIREP records is the **Phionyx Reasoned Governance Envelope**, which matures
by conforming to this format. AIREP itself carries no Phionyx-specific physics, vocabulary, or
dependency — that is the point of the neutrality test. A second, independent producer is an open
item (see `STATUS.md`).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). In short: the normative text and the conformance vectors
change in lockstep; breaking changes bump the version and are logged as **BREAKING** in `STATUS.md`.

## License

- **Specification text and schemas** (`spec/**/*.md`, `spec/**/*.schema.json`): **CC-BY-4.0** — see
  [`LICENSE-CC-BY-4.0.txt`](./LICENSE-CC-BY-4.0.txt).
- **Conformance and example code** (`spec/**/conformance/`, `spec/**/examples/`): **Apache-2.0** —
  see [`LICENSE`](./LICENSE).

## Patent Non-Assertion

AIREP is intended to be freely implementable as a neutral interoperability format. The maintainer
provides a royalty-free patent non-assertion covenant for implementations limited to producing,
transmitting, canonicalizing, hash-chaining, signing, or verifying conformant AIREP records as
defined by the neutral core specification.

This covenant does not license Phionyx runtime mechanisms, governance engines, scoring systems,
model-routing logic, or any implementation-specific technology beyond the acts necessary to implement
the neutral AIREP interchange record itself.

See [`PATENT_NON_ASSERTION.md`](./PATENT_NON_ASSERTION.md).

## Citation

Archived on Zenodo: concept DOI [10.5281/zenodo.20475136](https://doi.org/10.5281/zenodo.20475136) (always resolves to the latest version); v0.1 specifically is [10.5281/zenodo.20475137](https://doi.org/10.5281/zenodo.20475137).
Machine-readable metadata is in [`CITATION.cff`](./CITATION.cff).
