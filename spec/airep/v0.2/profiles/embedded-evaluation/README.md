# AIREP Embedded Evaluation Profile v0.1

- **Status:** Experimental companion profile
- **Profile identifier:** `airep.embedded-evaluation`
- **Profile version:** `0.1`
- **Carrier:** AIREP wire version `0.2`

This profile is an **evaluation-evidence contract**, not a fifth AIREP artifact family. It binds the
context and evidence of one evaluation claim or measurement to an AIREP v0.2 artifact without
changing the closed AIREP core.

The intended use is third-party, internal, government, academic, or embedded evaluation work where
a later reviewer needs to distinguish:

- **who** performed the evaluation and under what declared independence relationship;
- **what** model/system/checkpoint was evaluated;
- **what access** the evaluator actually had;
- **which harness, task, dataset, configuration and environment** were used;
- **whether a measurement actually ran** and what criterion and observation were recorded;
- **which evidence objects** support the claim, including restricted or withheld evidence;
- **what was redacted, retried, deviated from plan, or incidentally observed**; and
- **what later verification exists**, without converting that reference into an AIREP assurance uplift.

The profile is designed for evidence produced alongside evaluation systems such as benchmark harnesses,
agent-evaluation frameworks, red-team systems, internal laboratory tooling, or regulated audit
workflows. Native evaluation logs remain first-class evidence; this profile does not replace them.

## 1. Claim boundary

A schema `PASS` for this profile means only:

> the `profiles["airep.embedded-evaluation"]` payload conforms to the exact accepted
> `embedded-evaluation.schema.json` basis identified by its SHA-256 digest.

It does **not** establish any of the following:

- that the evaluator is competent or independent;
- that the evaluated party disclosed all relevant access, incidents, safeguards, or limitations;
- that the named model/checkpoint/configuration was the one actually executed;
- that evidence bytes existed at the asserted collection time;
- that an observation is true or representative;
- that a result is reproducible;
- that a model is safe, aligned, secure, compliant, or suitable for deployment;
- that an evaluation is complete; or
- that an AIREP assurance class has been earned or raised.

Those boundaries are deliberate. AIREP Core/Authenticated/Witnessed semantics remain owned by the
AIREP v0.2 specification and verifier basis.

## 2. Attachment model

The profile MAY appear on any AIREP v0.2 family under:

```json
{
  "profiles": {
    "airep.embedded-evaluation": {
      "profile_version": "0.1"
    }
  }
}
```

The enclosing artifact family remains authoritative about what stage is being reported:

- a `decision` is still a governance decision;
- a `control` is still a boundary-side control report;
- an `execution` is still an execution attempt report; and
- an `effect` is still an observation of state following a referenced execution.

**Implementations MUST NOT manufacture an AIREP lifecycle merely to package an evaluation.**
If a benchmark or evaluator produces only native result files, those files SHOULD remain the native
source evidence. An AIREP artifact should be emitted only where its family semantics are actually
satisfied.

This profile therefore acts as context and evidence metadata for an AIREP artifact, not as a generic
replacement for every evaluation result format.

## 3. Required sections

| Section | Purpose |
|---|---|
| `profile_version` | Exact profile payload version; `0.1` for this release. |
| `engagement` | Evaluation engagement, evaluator organization/role, evaluated party, and declared independence status. |
| `target` | Provider, system/model/checkpoint/build identity and release state. |
| `access` | Evaluator access tier, capabilities and limitations. |
| `evaluation` | Run identity, objective, risk domain(s), framework revision/configuration, tasks, environment and safeguard state. |
| `measurement` | Explicit run state, criterion, observed result and limitations. |
| `evidence` | Content-addressed supporting objects, including visibility/withholding state. |
| `disclosure` | Redactions, deviations, retries and incidents. |
| `verification` | Optional later verification references; never an automatic assurance uplift. |
| `scope` | What this profile instance covers and explicitly does not cover. |

The schema is closed (`additionalProperties: false`) at every defined object. Additive semantics
therefore require a new profile-basis revision rather than silent field injection.

## 4. Evaluator identity and independence

`engagement.evaluator` names the organization and role participating in the evaluation engagement.
That is an evaluation-context statement. It is not a cryptographic identity binding.

`engagement.independence.status` is deliberately limited to:

- `independent-declared`
- `not-independent`
- `unknown`

`independent-declared` means the profile carries an independence declaration and its stated basis.
It does **not** prove organizational, financial, personnel, technical, or decision-making
independence.

Where authorship needs cryptographic authentication, use AIREP's normal operator-accepted producer
key binding. Where an independent evaluator signs a separate attestation, that evidence can be
referenced here and/or represented through a separately defined evaluator-attestation mechanism.
This profile does not self-certify independence.

## 5. Access tiers

`access.tier` records the strongest access relationship claimed for the evaluation:

| Tier | Intended meaning |
|---|---|
| `public-black-box` | Publicly available interface only. |
| `private-black-box` | Non-public interface, without internal model/system visibility. |
| `grey-box` | Selected internal artifacts, telemetry, configuration, tools, or interfaces are visible. |
| `white-box` | Broad internal technical access sufficient for white-box evaluation activities. |
| `embedded-employee-like` | Evaluator receives employee-like workspace/tool/process access for the engagement. |
| `other` | A different access model, described by `capabilities` and `limitations`. |

The tier is descriptive, not an assurance level. Two evaluations with the same tier can have
materially different capabilities and restrictions; `capabilities` and `limitations` therefore
remain required arrays.

## 6. Measurement-state discipline

The profile records two distinct questions:

1. **Did the planned measurement execute?** — `measurement.execution_status`
2. **What result was observed?** — `measurement.observed.status`

Execution states are:

- `RAN`
- `NOT_RUN`
- `PARTIAL`
- `INVALIDATED`

Observed states are:

- `PASS`
- `FAIL`
- `NOT_MEASURED`
- `INCONCLUSIVE`
- `ERROR`
- `NOT_APPLICABLE`

The schema enforces three negative-semantic guards:

1. `NOT_RUN` can only pair with `NOT_MEASURED` or `NOT_APPLICABLE`.
2. `PASS` or `FAIL` requires execution state `RAN` or `PARTIAL`.
3. `INVALIDATED` cannot yield `PASS` or `FAIL`.

Accordingly, absence of a measurement cannot silently become success. The
`example.not-measured.json` fixture exists specifically to preserve this distinction.

`criterion` is the predeclared test/evaluation condition. `observed` is what the evaluator reports
after execution. Keeping them separate prevents an observed score from being retroactively treated
as the original criterion.

## 7. Evidence and disclosure

Every `evidence[]` entry carries:

- a local `evidence_id`;
- a role;
- a reference;
- whether that reference is resolvable by the producer;
- a SHA-256 digest;
- a visibility state (`public`, `restricted`, or `withheld`); and
- a withholding reason when visibility is `withheld`.

A digest makes later byte changes detectable relative to the recorded digest. It does not prove that
the bytes are truthful, complete, or collected at an asserted time.

`disclosure` makes four normally easy-to-hide classes of information explicit:

- `redactions`
- `deviations`
- `retries`
- `incidents`

A profile with `redactions_present: false` must carry an empty `redactions` array. A profile with
`redactions_present: true` must describe at least one redaction.

## 8. Verification references

`verification[]` can refer to later schema checks, integrity verification, evidence-digest checks,
reproduction attempts, reruns, platform verification, or external review.

These entries are **references to reported verification work**. They do not change AIREP's Core,
Authenticated, or Witnessed result. In particular:

- `verification[].status = PASS` is not an AIREP assurance class;
- `verification[].independence = declared-independent` is not proof of independence; and
- a platform-specific verified-run token can be preserved as evidence without being reinterpreted as
  proof of model safety.

## 9. Profile-basis validation

The directory ships a self-contained Draft 2020-12 JSON Schema and a digest-pinned registry:

```text
registry.json
embedded-evaluation.schema.json
```

The registry is suitable for the AIREP v0.2 `--profile-bases` mechanism. The profile basis contains
no network-loaded references.

Expected result for a conforming carrier artifact with the registry supplied:

```json
{
  "profile_evaluations": {
    "airep.embedded-evaluation": {
      "result": "PASS",
      "basis_digest": "sha256:ce57bd493d1a3166051bc9029972d6be215793edcd3f1b314534959659b3da8b"
    }
  }
}
```

Without an accepted basis for the exact identifier, the correct profile result remains
`NOT_EVALUATED`, never an implicit pass.

## 10. Hugging Face / OpenEvals mapping

This section is **informative**. It is an integration aid, not a claim that Hugging Face implements
or endorses AIREP.

A native evaluation result can remain authoritative in its own format while this profile binds its
provenance and evaluation context. The mapping below is ecosystem-level guidance; it does not mean
that the repository ships a parser for every named format. The current exporter parses LightEval
`results_*.json` only. Native Inspect `.eval` logs and arbitrary OpenEvals result formats are future
integration targets and are not currently parsed.

| Native evaluation concept | Suggested profile mapping |
|---|---|
| model name / model revision | `target.system_name`, `target.model_id`, `target.model_revision` |
| harness version/revision | `evaluation.framework.version`, `evaluation.framework.revision` |
| harness configuration | `evaluation.framework.configuration_digest` |
| task / dataset / split / revision | `evaluation.tasks[]` |
| runtime/container/tool configuration | `evaluation.environment` |
| safeguard state/configuration | `evaluation.safeguards` |
| aggregate result JSON | `evidence[].role = "aggregate-result"` |
| per-sample details | `evidence[].role = "sample-details"` |
| raw outputs/logs | `evidence[].role = "raw-output"` / `"system-log"` |
| result criterion and observation | `measurement.criterion`, `measurement.observed` |
| missing or invalid run | `measurement.execution_status`, `measurement.observed.status` |
| platform verification token/result | `verification[].kind = "platform-verification"` |

For Hugging Face Hub Evaluation Results, a platform `verifyToken` and its verified badge should be
preserved as platform-specific verification evidence. This profile is complementary: it adds broader
engagement/access/configuration/evidence/disclosure context and must not reinterpret the token as a
general safety or assurance certificate.

The following is a conceptual integration pattern across related ecosystems, not a list of
implemented parsers. The current exporter expects LightEval `results_*.json` structure; native
Inspect `.eval` and arbitrary OpenEvals result formats are not currently parsed. Native files
remain source evidence. LightEval's timezone-naive filename timestamp is never silently labelled
UTC: the exporter requires explicit timezone-aware start/end timestamps in the declared context.

A possible integration pattern is:

```text
LightEval / Inspect / OpenEvals native run
        |
        +-- native result JSON / sample details / logs
        |
        +-- content digests
        |
        +-- AIREP Embedded Evaluation Profile v0.1
        |
        +-- optional AIREP carrier artifact(s), only where AIREP family semantics are real
```

## 11. Relationship to Phionyx work

This profile operationalizes the evidence boundary developed across Phionyx runtime-evidence and
measurement work:

- canonical AIREP repository: <https://github.com/halvrenofviryel/ai-runtime-evidence-protocol>
- Phionyx Runtime Evidence and Measurement collection:
  <https://huggingface.co/collections/phionyx/phionyx-runtime-evidence-and-measurement>
- technical note, *Access Is Not Yet Verifiability: Toward a Claim-Preserving Evidence Contract for
  AI Assurance*: <https://huggingface.co/blog/phionyx/access-is-not-yet-verifiability>
- Hugging Face dataset mirror of this profile (schema, registry, fixtures, byte-identical to the
  canonical directory at the merged commit named on its card): <https://huggingface.co/datasets/phionyx/airep-embedded-evaluation-profile>
- exporter Space (LightEval `results_*.json` → AIREP Embedded Evaluation Profile payload + evidence
  manifest, experimental and non-normative; native Inspect `.eval` and arbitrary OpenEvals result
  formats are not currently parsed;
  source in [`integrations/lighteval/`](../../../../../integrations/lighteval/)): <https://huggingface.co/spaces/phionyx/airep-evaluation-evidence>

The Hugging Face collection is related work and a distribution/discovery surface. The canonical
schema and version history remain in the AIREP repository.

## 12. Versioning

`profile_version` versions this companion profile, independently of the AIREP carrier wire version.
This release requires AIREP wire version `0.2` when embedded in an AIREP artifact.

Changing required fields, field meanings, closed enums, or negative-state semantics requires a new
profile version. A changed schema basis also changes its `basis_digest`; consumers must never treat a
new digest as the same validation basis silently.

## 13. Fixtures

- [`example.measured.json`](./example.measured.json) — synthetic measurement that ran and failed its
  declared criterion.
- [`example.not-measured.json`](./example.not-measured.json) — synthetic planned evaluation that did
  not run and therefore reports `NOT_MEASURED`.

Both are synthetic. They make no claim about a real model, laboratory, evaluator, or evaluation
result.
