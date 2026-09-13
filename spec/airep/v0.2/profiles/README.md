# AIREP v0.2 companion profiles

AIREP v0.2 keeps the core closed and uses namespaced `profiles` as its only extension surface.
Companion profiles in this directory are **not new AIREP artifact families** and do not change
Core/Authenticated/Witnessed assurance semantics.

A profile-specific `PASS` means only that the payload passed the exact accepted validation basis
supplied for that profile identifier. Without that basis, the correct result is `NOT_EVALUATED`.

## Published experimental companion profiles

| Profile | Version | Identifier | Purpose |
|---|---:|---|---|
| [Embedded Evaluation](./embedded-evaluation/) | 0.1 | `airep.embedded-evaluation` | Bind evaluator/target/access/run context, explicit measurement state, evidence digests, disclosures and optional verification references to an AIREP v0.2 artifact. |

See [`../profile-validation/N-01_PROFILE_VALIDATION_DECISION.md`](../profile-validation/N-01_PROFILE_VALIDATION_DECISION.md)
for the generic profile-validation semantics.
