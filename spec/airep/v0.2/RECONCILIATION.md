# v0.2 lifecycle reconciliation — beta contract

Normative for the beta reconciler. Wire version `0.2`; no new wire fields,
assurance classes or integrity constructions. BCP 14 keywords apply.

Reconciliation evaluates a finite **supplied evidence set**, not the world or a
complete event history. An observed fact means that admissible records **report**
it. Assurance about the records remains separately visible. Records alone do not
prove delivery, execution, effect, policy correctness or completeness.

## Inputs and admission

Inputs are Decision, Control, Execution and Effect artifacts and optional trusted
operator inputs in the class-verifier formats. Artifacts MUST pass the v0.2 raw
JSON boundary, accepted family schema and frozen hash check before contributing
lifecycle facts. Failed admissions MUST remain visible. Per-record class results,
including failure, withheld and caveat channels, MUST be retained. An unsigned or
unauthenticated assertion cannot silently become an authenticated fact.

Global `record_id` resolution MUST be exact and unique, optionally constrained by
`chain_id`; a chain qualifier MUST NOT make a duplicated global identity unique.
An unresolved identity is a missing prerequisite; a wrong family or mismatching
chain qualifier is a contradiction. An ambiguous identity is indeterminate;
dependent checks are not evaluated. Input order MUST NOT choose a winner.

For each supplied chain, sequences are unique and monotonically increasing, and
records link by `integrity.previous` to the preceding `integrity.current`.
Genesis uses `sha256:` followed by 64 zeroes (accepted schema-design lineage).
The reference producer starts sequence at zero and increments by one; this is
a producer convention, not an additional wire requirement. A resolved link with
increasing but nonconsecutive sequences is valid under AD-05.
An absent predecessor or prefix is missing evidence, not a bad hash link; a
present, unique adjacent integer predecessor with a different digest is a
contradiction. A resolved link pointing forward, to itself, or over another
supplied record in the same chain is contradictory. An
identical retransmission is still a duplicate identity and MUST be named, not
silently counted twice. No suffix-completeness claim follows from these checks.

## Correlation and lifecycle facts

Each Control, Execution and Effect `decision_ref` MUST resolve to a Decision.
Controls and Executions are grouped by the **resolved Decision identity and
instruction_id**, not merely by instruction_id or by artifact co-location.
Within that group instruction digests MUST agree. Control authorization digests
MUST agree. Multiple conflicting values MUST be reported without choosing one.

* Dispatch is reported by `control_event=dispatched`, `boundary_side=issuer`.
* Receipt is reported by `control_event=received`, `boundary_side=receiver`.
* A receipt on the issuer side or dispatch on the receiver side cannot satisfy
  the corresponding fact; report the side/event contradiction.
* `delivery_failed` is explicit failure evidence and MUST be reported. It is not
  inferred from an absent receiver record. Failed delivery and later receipt
  may both exist (for example a retry); without attempt semantics their combined
  delivery state is indeterminate, never silently successful.
* Execution presence and `execution_event` MUST be reported separately. Only
  `executed` reports execution; `failed` and `suppressed` remain named negative
  outcomes. Multiple incompatible outcomes remain indeterminate (no inferred
  chronology or attempt selection).
* TOCTOU equality compares every applicable Control authorization with every
  applicable Execution action digest in the group. Equality is not proof that
  an action actually ran. Missing Control or Execution is a missing fact and
  leaves the comparison NOT_EVALUATED.
* Each Effect `execution_ref` MUST resolve to an Execution; its Decision MUST
  resolve to the same Decision as that Execution. Effect presence is evaluated
  **per Execution**, so evidence for one cannot hide absence for another.
* Each Effect MUST expose both declared and effective observer relationship.
  `same_executor` is evidence without independent corroboration. `independent`
  requires the existing three-condition verifier gate on authenticated Effect
  and Execution records. Without it the effective value is `unknown`; name
  independence as INDETERMINATE rather than accepting the declaration.

Multi-instruction decisions MUST be evaluated group by group. With no supplied
instruction inventory, total intended target coverage is NOT_EVALUATED. No number
of complete groups supplies a missing inventory or proves all targets covered.

## Structured result and summary

Each check has a stable `check` name, structured subject identity, `state`,
supporting record references and a human-readable detail. States are exactly:

| State | Meaning |
|---|---|
| `SATISFIED` | The named predicate holds over admitted evidence; observation is scoped to reports. |
| `FAILURE` | An evaluated predicate definitively fails, or explicit negative evidence reports failure. |
| `MISSING` | Required evidence is absent from this supplied set. |
| `NOT_EVALUATED` | An unresolved, invalid or ambiguous prerequisite prevents evaluation. |
| `INDETERMINATE` | Available information does not determine one outcome. |

All checks MUST be returned; an early failure MUST NOT erase missing/unevaluated
facts. Empty input MUST report MISSING, never success. Invalid records MUST NOT
resolve references for other records. The summary reports counts of **all** states
and a derived status: FAILURE if any failure exists, otherwise INCOMPLETE if any
missing, unevaluated or indeterminate check exists, otherwise SATISFIED. The
reference reconciler always reports intended-target coverage NOT_EVALUATED when
no inventory is provided, even for a fully correlated worked example. There is
no lifecycle assurance class and no global PASS boolean.

Reconciler CLI exit `0` means a structured evaluation was emitted, including a
negative evaluation; `1` means unreadable/unparseable run input, `2` usage error.
Consumers MUST inspect structured results. Malformed but parseable individual
artifacts yield named admission failures; they do not disappear from the set.
