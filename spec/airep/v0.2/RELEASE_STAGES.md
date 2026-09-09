# v0.2 release stages — beta sequencing correction

**Current implementation target: `v0.2.0-beta.1`; not yet a published beta tag.**
This release-process clarification implements the beta task's staging requirements.
It changes no v0.1 rules, v0.2 wire bytes, frozen integrity construction, schemas,
class meanings, external evidence thresholds or prior measurements.

## Historical inconsistency, retained explicitly

AD-01 originally described alpha as “schema + verifiers + migration tooling”.
The released alpha had schemas/verifiers but no migration tool. The earlier
sentence remains in [AD-01](../v0.2-design/ARCHITECTURE_DECISIONS.md) as the
historical definition. It is not retrospectively made true by this beta.

The [migration model](../v0.2-design/MIGRATION.md) is retained. Its implementation
is moved out of the beta critical path to subsequent RC/stable work. A migration
projector is not fabricated and v0.1 artifacts continue to use v0.1 verification.
No re-hashing, relabelling or re-signing of old evidence is performed.

## Beta — implementation readiness

The beta gate consists of a usable first-party four-family producer; consolidated
normative specification and class text; complete runnable Decision/dispatch/
receipt/Execution/Effect example; structured reconciliation; committed negative
cases; producer→Python/Node-verifier round trips; profile/admission parity;
implementation documentation and reproducible CI-equivalent checks.

Every criterion needs runnable evidence. Missing third-party interoperability is
reported as missing, not treated as a failing local beta implementation test.
[BETA_READINESS.md](BETA_READINESS.md) links the actual measurements.

## RC — candidate discipline and broader exercises

The planned RC programme requires a broader cross-implementation corpus, including
external producer output when available; a candidate wire/basis freeze and
reproducible release identities; and the intended SCITT registration/receipt and
AuthZEN authorization-reference E2E exercises. No beta is held for those exercises.

**AD-16 boundary preserved:** concrete SCITT/AuthZEN companion work has its own
lifecycle and does not become a Core wire or Core stable requirement by appearing
in this RC programme. A combined release programme may require those exercises
for its own RC milestone; it must not silently rewrite AD-16's Core gate.
The imported W1 evaluators and contracts remain available under
[interop/](interop/). Their old measurements are not measurements of beta
producer output and their independent-corpus lifecycle is not silently advanced.

## Stable — external independence remains mandatory

The applicable AD-15/AD-16 requirements remain in full force:

* At least two v0.2 producers on the same frozen candidate, at least one genuinely
  non-maintainer, with each actually emitting artifacts for evaluation.
* At least one qualifying non-maintainer consumer/verifier measured on that same
  candidate, at the actual strength of its independence and blindness evidence.
* Candidate corpus covering normative/adversarial cases, each qualifying
  producer's outputs, AD-03 reconciliation and partial/multiple-target cases,
  passing under both reference verifiers and the non-maintainer consumer/verifier.
* Full shipped-surface reference parity, profile-extension parity, reproducible
  immutable identities and no unresolved release-blocking disagreement.

An earlier expected-aware r1 consumer result does not satisfy the changed candidate
gate. A v0.1 producer does not count toward v0.2 diversity. First-party Python/Node
work cannot manufacture non-maintainer independence. No threshold is lowered to
ship beta. See [EXTERNAL_EVIDENCE.md](../../../EXTERNAL_EVIDENCE.md).

Also deferred: production HSM/KMS integration, TEE/hardware attestation, broad
MCP/A2A/OTel profile catalogue, regulatory crosswalk refresh and migration
projector. These are explicitly absent, not implicit promises of stable scope.
