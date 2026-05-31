# Security policy

AIREP's value rests entirely on its verifiers being correct: a record is only trustworthy if a
record that *should* fail actually fails. If you find a way to break that, please report it
**privately**.

## Report privately

Use GitHub's private vulnerability reporting — the **Report a vulnerability** button under this
repository's **Security** tab — not a public issue.

## In scope

- A **verifier bypass**: a record that passes `verify.py` / `verify.mjs` / `validate.py` but should
  not — tamper, splice/reorder, a forged or stripped signature, or neutrality-test evasion.
- A **canonicalization or hash mismatch** between the two stacks (`jcs.py` vs the Node canonicalizer)
  that lets one record hash to two values, or lets a record evade the chain / truncation defenses.
- A **signature-verification weakness** in the conformance kit.

## Out of scope (by design)

- The **malicious-producer** limit: a key-holder can write a *valid, signed* record with a false
  `claim`, `scope`, or `evidence`. AIREP records the decision **path**, not the **truth** of the
  output — see [`THREAT_MODEL.md`](./spec/airep/v0.1/THREAT_MODEL.md). This is a property of the
  format, not a bug.
- The `partial` / `none` threat grades in `THREAT_MODEL.md` and the open items in `STATUS.md` —
  those are tracked work, disclosed on purpose, not vulnerabilities.

Thank you for helping keep the format honest.
