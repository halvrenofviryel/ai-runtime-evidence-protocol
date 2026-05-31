# AIREP v0.1 — spec directory

The **AI Runtime Evidence Protocol (AIREP)** v0.1: a small, fixed format for one signed,
checkable record per AI runtime decision.

**Start here**

- [`EXPLAINER.md`](./EXPLAINER.md) — a plain-language introduction. Read this first; it
  teaches the format with a worked example and no jargon.

**Build against this**

- [`SPEC.md`](./SPEC.md) — the normative specification: the exact, binding rules an
  implementer conforms to.
- [`core.schema.json`](./core.schema.json) — the JSON Schema (draft 2020-12) for the core
  record.
- [`profiles/`](./profiles/) — the optional extension catalogue (framework and domain
  profiles).
- [`conformance/`](./conformance/) — a runnable checker and the test vectors.

**Reference**

- [`STATUS.md`](./STATUS.md) — the format's maturity stage, open items, and change log.
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — which attacks the format detects, *how*, and which it does
  not (replay, splice, tampering, withholding, forged/malicious producer, evidence poisoning, …).
- [`examples/`](./examples/) — worked records with **really computed** hashes and Ed25519
  signatures (reproducible via `examples/regenerate.py`): one with zero vendor fields, one with
  vendor data under `profiles.phionyx`, and `chain.jsonl`, a 5-record governed-agent chain
  (release → redact → escalate → defer → release) the conformance checker replays end to end.

> **Status: Experimental** — a proposed open format with one reference implementation; not a
> ratified standard. See [`STATUS.md`](./STATUS.md).

**License.** The specification text (`SPEC.md`, `EXPLAINER.md`, `STATUS.md`, `THREAT_MODEL.md`,
this README, and the schemas) is licensed **CC-BY-4.0**; the conformance and example code
(`conformance/`, `examples/`) is licensed **Apache-2.0**. Full texts at the repository root:
[`LICENSE`](../../../LICENSE) and [`LICENSE-CC-BY-4.0.txt`](../../../LICENSE-CC-BY-4.0.txt).
