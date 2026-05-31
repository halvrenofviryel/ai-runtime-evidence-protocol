# Contributing to AIREP

AIREP is an **experimental** open format. Contributions, implementations, and critique are
welcome — especially a second independent producer and adversarial review of the threat model.

## Ground rules

1. **The normative text and the conformance vectors change in lockstep.** Any change to
   `core.schema.json` or `SPEC.md` MUST come with updated example vectors in `examples/` and a
   passing `conformance/validate.py`. A schema change with stale vectors will be rejected.

2. **Breaking changes bump the version.** A change to a required field, a closed enum
   (`directive.verb`, `evidence[].type`), the hash domain, or the canonical form is **BREAKING**:
   it increments the spec version (`v0.1` → `v0.2`) and is logged as **BREAKING** in `STATUS.md`.
   Breaking changes are never presented as additive.

3. **Keep the core neutral.** Vendor-, model-, or domain-specific fields belong under a
   `profiles.<name>` block, never in the core or a core sub-object. Every change must keep the
   neutrality test passing (delete `profiles`, the record still validates). If you need new
   structured fields for a domain, propose a **profile**, not a core change.

4. **Honesty over polish.** Claims in the spec must match what the code does. Regulatory or
   standards anchors in profiles are tagged **INDICATIVE** until verified against the primary
   source; don't remove that tag without doing the verification.

## How to propose a change

- Open an issue describing the change and its conformance-class impact (core / profile / tooling).
- For a normative change, include: the schema diff, updated example vectors, and the `STATUS.md`
  open-item or change-log entry.
- For a new profile, add `profiles/<name>.schema.json` (with `additionalProperties:true`, an honest
  `description`, and INDICATIVE tags on any external anchors) plus an example record under
  `examples/`, and confirm it passes the neutrality test.

## Before you open a PR

```bash
cd spec/airep/v0.1
python3 conformance/validate.py          # must print: RESULT: all conformance checks PASSED
python3 conformance/verify.py  examples/chain.jsonl
node      conformance/verify.mjs examples/chain.jsonl   # both verifiers must agree
```

## Conduct

Be precise, be kind, and assume good faith. Disagreements about the format are resolved by what the
conformance vectors and the threat model actually demonstrate, not by authority.

## License of contributions

By contributing you agree your contributions are licensed under the same terms as the
repository: **Apache-2.0** for code (`conformance/`, `examples/`) and **CC-BY-4.0** for
specification text and schemas.
