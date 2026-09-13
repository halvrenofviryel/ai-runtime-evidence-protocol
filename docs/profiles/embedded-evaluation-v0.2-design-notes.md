# Embedded Evaluation Profile — design notes toward a future v0.2

**Status: design note only.** These are candidate changes for a future profile revision.
They do not alter `airep.embedded-evaluation` v0.1, whose basis remains
`sha256:ce57bd493d1a3166051bc9029972d6be215793edcd3f1b314534959659b3da8b`. Nothing here is
published as a schema, and no v0.2 identifier, registry entry or fixture exists.

Two modelling limitations were confirmed while mapping real evaluation records (a
LightEval-shaped run and an Every-Eval-Ever `evaluation_run` record) into v0.1.

## A. Score-only evaluations

v0.1 forces `measurement.observed.status` into
`PASS | FAIL | NOT_MEASURED | INCONCLUSIVE | ERROR | NOT_APPLICABLE`, and the schema guards
tie `PASS`/`FAIL` to a criterion. A benchmark result such as `accuracy = 0.734` with no threshold
has no honest home: `PASS`/`FAIL` invents a criterion, `INCONCLUSIVE` misdescribes a completed
measurement, and `NOT_APPLICABLE` (the v0.1 workaround used in the EEE desk mapping) reads as if
nothing was measured.

The underlying defect is that v0.1 conflates three questions:

1. **Did the measurement execute?** — `execution_status`
2. **What was observed?** — a metric value, a categorical outcome, or nothing
3. **Was a pre-declared criterion met?** — only meaningful when a criterion exists

### Candidate shapes

**Option 1 — split observation from criterion assessment**

```yaml
execution_status: RAN
observation:
  kind: METRIC            # METRIC | CATEGORICAL | NONE
  metric: accuracy
  value: 0.734
criterion_assessment:
  status: NOT_APPLICABLE  # PASS | FAIL | INCONCLUSIVE | NOT_APPLICABLE
  criterion: null
```

Guards: `criterion_assessment.status ∈ {PASS, FAIL}` requires `execution_status ∈ {RAN, PARTIAL}`
**and** a non-null `criterion`; `execution_status = NOT_RUN` requires `observation.kind = NONE`;
`INVALIDATED` forbids `PASS`/`FAIL`. This preserves every v0.1 negative-state invariant.

**Option 2 — add `SCORE_REPORTED` to the existing enum**

Smallest change; keeps one field. It leaves the conflation in place (a `SCORE_REPORTED` status
still has to carry `metric_value` in the same object as a `PASS` would) and adds a fourth "not a
verdict" value to an enum that already has three.

**Option 3 — make `criterion` optional and treat its absence as "no assessment"**

Backward-looking; a consumer cannot distinguish "no criterion existed" from "the producer omitted
it", which is exactly the silent-absence pattern the Measurement Axioms prohibit.

**Assessment.** Option 1 is preferred. It is also the shape the EEE crosswalk needed: EEE records a
score and no criterion, so `observation.kind = METRIC` with `criterion_assessment = NOT_APPLICABLE`
says precisely what the record says. Compatibility: it is a breaking change to `measurement`, so it
requires `profile_version: "0.2"`, a new basis digest, and no in-place edit of v0.1. A v0.1 → v0.2
mapping is mechanical for `PASS`/`FAIL` (criterion present) and for `NOT_RUN`/`INVALIDATED`; the
only judgement call is which v0.1 `NOT_APPLICABLE` payloads were score-only workarounds.

## B. Withheld evidence with an unknown digest

v0.1 `evidence_item` requires `digest` (`^sha256:[0-9a-f]{64}$`) for every item while also
allowing `visibility: withheld`. That works when the publisher holds the bytes and withholds them.
It cannot express the common case met in the EEE mapping: evidence **known to exist** (the native
harness log a converter read), **bytes unavailable to the publisher**, **digest unknown**,
**reason known**. The v0.1 workaround — recording the absence in `disclosure.deviations` — loses
the link between the missing object and its role.

### Candidate shape

```yaml
evidence:
  - evidence_id: ev-native-log
    role: raw-output
    ref: urn:example:native-log
    availability: withheld          # public | restricted | withheld
    digest: null
    digest_status: unavailable      # verified | reported | unavailable
    withholding_reason: "native log is retained by the evaluation operator and was not released"
    custodian: "evaluation operator (declared)"
```

Guards that keep integrity strong where bytes are known:

- `availability = public` ⇒ `digest` required and `digest_status ∈ {verified, reported}`;
- `digest_status = verified` ⇒ the publisher recomputed the digest from the bytes;
- `digest_status = reported` ⇒ the digest was received from another party and not recomputed;
- `digest = null` is permitted **only** with `digest_status = unavailable` and
  `availability ∈ {restricted, withheld}`, and then `withholding_reason` and `custodian` are
  required.

`digest_status` is the important addition: v0.1 cannot say whether a digest was recomputed or
merely copied, which is the difference between "checked" and "declared" that the rest of AIREP
insists on. This is additive for public evidence and breaking for the `digest` requirement, so it
also belongs to a v0.2 basis rather than a v0.1 patch.

## What would not change

The claim boundary (profile PASS ≠ assurance class ≠ safety ≠ completeness ≠ truth), the
prohibition on inferring independence or access tier, the requirement that `NOT_RUN` never yields
`PASS`/`FAIL`, and the digest requirement wherever bytes are actually held.

## Sequencing

1. Collect at least one more real mapping (an Inspect `.eval`-derived record) before fixing shapes.
2. Draft `profile_version: "0.2"` in a separate directory with its own basis digest and fixtures.
3. Publish v0.2 alongside v0.1; never revise the v0.1 basis in place.
