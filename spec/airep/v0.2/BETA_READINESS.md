# v0.2.0-beta.1 beta readiness

**Current v0.2 implementation target: `v0.2.0-beta.1`.** This matrix measures
implementation readiness separately from [RC/stable independence](RELEASE_STAGES.md).
A criterion becomes PASS only from its linked runnable test or concrete artifact
inspection, never from absence of a known failure. The final measurement run is
recorded in the [work report](../../../reports/beta-2026-09-08/WORK_REPORT_TR.md).

| Beta criterion | Concrete evidence | Status |
|---|---|---|
| Consolidated normative implementation surface | [SPEC.md](SPEC.md), existing frozen subsidiary sources, `check_beta_docs.py` reading-path/preservation audit | PASS — measured final run |
| Normative three-class text | [CONFORMANCE_CLASSES.md](CONFORMANCE_CLASSES.md), preserved SHA-256 and class tests including witnessed heads for every family | PASS — measured final run |
| Usable first-party reference producer and CLI | [producer](../../../tools/airep_v02/producer.py), [CLI](../../../tools/airep_v02/__main__.py), ProducerTests | PASS — measured final run |
| All four families with real integrity | Four emit commands; Ed25519/Core/Authenticated/Witnessed tests, replay/tamper checks | PASS — measured final run |
| Complete runnable lifecycle | [real local example](../../../examples/v02/run_lifecycle.py), emitted files and reports in the measured run | PASS — measured final run |
| Mechanical cross-artifact reconciliation | [contract](RECONCILIATION.md), [implementation](../../../tools/airep_v02/reconcile.py), ReconciliationTests | PASS — measured final run |
| Positive, negative and qualification corpus | [11 committed sets](../../../examples/v02/fixtures/), required omissions, mismatch, observer variants and one broken family each | PASS — measured final run |
| Producer → Python/Node verifier round trips | [beta tests](../../../tests/v02/test_beta.py), all families, historical 60-case regressions | PASS — measured final run |
| AD-17/r3 input/profile parity | Duplicate/Unicode/binary64 tests; known/unknown/invalid profile, basis substitution, closure and containment probes | PASS — measured final run |
| Existing vectors/schema/class evidence preserved | Original reproduction gates plus [preserved-file audit](../../../scripts/check_beta_docs.py) | PASS — measured final run |
| CI and reproduction path | [beta workflow](../../../.github/workflows/v0.2-beta.yml), [complete runner](../../../scripts/check_beta.py); local results distinct from hosted status | PASS — measured final run |
| Developer docs and honest scope | [quickstart](QUICKSTART.md), [verifier](VERIFICATION.md), [example](../../../examples/v02/README.md), README/status correction | PASS — measured final run |
| Release preparation | [notes and publication checklist](RELEASE_NOTES_BETA_1.md), [changelog](../../../CHANGELOG.md), citation version/concept DOI | PASS — measured final run |

## Measurement

Final local command (Python 3.12.3 / Node v20.19.6):

```bash
python3 scripts/check_beta.py --with-v01-typescript --out reports/beta-2026-09-08/release-validation
```

**54/54 commands succeeded.** The [exact command/result ledger](../../../reports/beta-2026-09-08/TEST_COMMANDS.md)
and [machine results](../../../reports/beta-2026-09-08/release-validation/results.json) retain
complete output and output digests. The [source basis](../../../reports/beta-2026-09-08/release-validation/source-basis.json)
identifies the implementation bytes actually tested.

* Frozen vectors: byte agreement; Stage-4 integrity/adversarial reproduction and
  negative controls passed. Schema engines: 117 fixtures each, comparison/gates passed.
* Historical class verifier: 60 cases, process probes, self-checks, comparator and
  negative proofs passed; beta adapters also matched all 60 historical expectations.
* Beta producer/reconciliation/admission/profile suite: **39 tests, all passed**,
  including parameterized four-family and tamper cases, witnessed heads,
  raw-number bounds, portability, multiple instructions/executions and profile closure.
* v0.1: **124 pytest tests passed**, standalone conformance/parity checks and
  regeneration preserved; TypeScript emitted three records accepted by both verifiers.
* Imported W1: Python **423 tests, 0 failures/errors, 1 platform-branch skip**,
  all 20 mandatory blocks measured; Node **2,329 assertions passed**, 0 failed/skipped,
  with its unconstructible complementary directory-name branch explicitly NOT MEASURED.
* Real local lifecycle and every documented emission/verification/reconciliation
  step passed. Reading-path audit: 12 documents; **1,919 historical files unchanged**.

This establishes local CI-equivalent readiness. Hosted CI was **NOT_RUN during
the implementation measurement**. The [release review](../../../reports/release-v0.2.0-beta.1/RELEASE_REPORT_TR.md)
describes the subsequent publication process; hosted run evidence is attached to
the [GitHub release](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/releases/tag/v0.2.0-beta.1).
Earlier sandbox-blocked and initial regression failures remain in the
[work report's evidence directory](../../../reports/beta-2026-09-08/).
No historical external result is promoted to a beta/r3 pass.

**Technical beta assessment: READY TO TAG after normal review/commit/publication
checks. No remaining beta implementation blocker is identified by the completed
suite.** Publication is a separate measured step; the historical implementation
report remains unchanged.

## Known limitations retained

First-party producer only; no same-version independent third-party producer→consumer
result. Earlier external v0.2 consumer evidence remains against r1 and qualified
as recorded (17 AGREE / 1 DISAGREE; not expected-blind). Emek's v0.1.2 result is
separate and not additive. No test establishes truth, complete history, real
authority or independence of the local demo's roles. No independent witness is
supplied by the demo; no class silently substitutes for one.

Missing evidence, WITHHELD, NOT_EVALUATED and INDETERMINATE remain visible. The
reconciler has no intended-target inventory and reports total coverage unevaluated.
Keys/cursors are reference development surfaces, not production HSM/KMS or
concurrent ledger management. Companion E2E integrations, full profile catalogue,
hardware attestation, migration tooling and regulatory crosswalk refresh are
explicitly deferred. Stable independence requirements are not weakened.
