# AIREP v0.2 release readiness

**Current implementation target: `v0.2.0-beta.1`, experimental and not stable.**

The current beta criterion/evidence matrix is [BETA_READINESS.md](BETA_READINESS.md).
The [release-stage contract](RELEASE_STAGES.md) separates beta implementation
readiness, RC exercises and final stable independence requirements.

## Completed local work

Normative [SPEC.md](SPEC.md) and [class text](CONFORMANCE_CLASSES.md); a first-party
four-family [producer](../../../tools/airep_v02/); AD-17 input admission and r3
profile evaluation in Python/Node; a runnable [lifecycle](../../../examples/v02/);
structured [reconciliation](RECONCILIATION.md); committed positive/negative cases
and a [CI-equivalent runner](../../../scripts/check_beta.py). Measurement
results and their limits are linked in the beta matrix.

## Stable gates still open

* At least two v0.2 producers on the same frozen candidate, including a genuinely
  non-maintainer producer, with each contributing actual producer output.
* Same-candidate non-maintainer consumer/verifier measurement and the required
  three-role corpus passes, including producer-output and reconciliation cases.
* Final candidate freeze, same-basis parity/reproduction, and complete immutable
  evidence identities without unresolved release-blocking disagreement.

The older external r1 result is not a current-candidate pass. Emek's v0.1.2
producer result contributes zero to v0.2 producer diversity. First-party beta
parity cannot close either non-maintainer role.

## Preserved earlier matrix and corrections

The [pre-beta matrix](release-history/PRE_BETA_READINESS_2026-09-03.md) is retained
byte-for-byte as a dated historical status snapshot. Its assertions that normative
class text and a producer are absent, and N-01 is undecided, are obsolete current
status. Their completed artifacts are linked above; no historical measurement was
revised. The old D-01 missing AuthZEN contract is a companion-work reference gap:
that branch's work is deferred, not falsely represented as an implemented E2E case.

AD-16's Core/companion boundary is preserved. SCITT/AuthZEN are planned RC
programme exercises with independent companion lifecycles, not beta blockers or
new Core wire dependencies. Migration tooling remains absent and deferred, with
AD-01's earlier contradiction recorded explicitly in RELEASE_STAGES.md.
