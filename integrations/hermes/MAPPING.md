# Hermes approval/runtime → AIREP v0.2 mapping

This is a non-normative, first-party AIREP mapping reviewed against Hermes
`main@9796235822b89e08597a402dad045b5b4464e474`. It is not a Hermes contract or a claim of
Nous Research endorsement.

## Architectural boundary

> Hermes owns authorization and enforcement. AIREP records and exports evidence produced by those mechanisms.

Hermes' native control plane is responsible for the approval request, authenticated/final decision,
durable reserve/claim/consume operation, authorization instruction, and executor. AIREP's evidence
plane may report a `Decision`, `Control`, `Execution`, and optional `Effect` only when the
corresponding fact is available.

AIREP records are not authorization tokens. The exporter must not sit on Hermes' enforcement path,
and accepting an AIREP signature does not prove exactly-once consumption, replay prevention,
approver authentication, policy correctness, instruction delivery, execution, effect, or complete
event history.

## Current Hermes surfaces

The reviewed public observer contract describes read-only telemetry hooks. Most hook returns are
ignored and hook failures are fail-open. `pre_tool_call` retains an older behavior-affecting return,
but approval hooks are explicitly observer-only and cannot pre-answer or veto an approval.

Current approval outcomes distinguish `once`, `session`, `always`, `deny`, `timeout`, and
`cancelled`; gateway notify failure and plugin-transport failures are also distinct fail-closed
paths. Timeout, cancellation, prompt withdrawal, delivery failure, or transport failure therefore
must never be rewritten as an explicit human denial.

The built-in gateway `_ApprovalEntry` mints a `request_id`, but its common approval-hook payload does
not expose that identifier. The selected plugin approval transport is stronger for correlation: its
immutable request and decision carry `request_id` and a SHA-256 request digest, and Hermes rejects a
stale/mismatched response. That digest covers the transport's redacted presentation/request fields;
it is not an authorization-instruction or executed-action digest.

Tool lifecycle events expose session, task, turn, provider-attempt, and tool-call identity, plus
observer-grade execution status. Those fields do not by themselves prove which approval authorized
the call. Private gateway queue entries and other private internal fields are not stable integration
APIs and this mapping does not rely on them.

## Mapping matrix

| Hermes/source fact | AIREP projection | Constraint |
|---|---|---|
| Finalized native release decision over a governed intent | `Decision(release)` | Approval alone does not imply instruction dispatch. |
| Explicit human denial | `Decision(block)` | Preserve denial as native decision evidence with type `other`; it is not positive `human_approval` evidence. |
| Timeout/cancellation/withdrawal/transport failure with native fail-closed result | `Decision(block)` | Attribute the block to the runtime path, never to a human denial. |
| Authorization instruction crosses the issuer boundary | `Control(dispatched, issuer)` | Requires an actual dispatch fact. |
| Executor reports receiving the instruction | `Control(received, receiver)` | Issuer send does not establish receiver receipt. |
| Executor reports that the action ran | `Execution(executed)` | Requires executor evidence and the executed-action projection. |
| Executor reports failure or pre-execution suppression | `Execution(failed)` / `Execution(suppressed)` | Negative evidence must remain negative. |
| Execution state is unavailable | no `Execution` artifact | AIREP v0.2 has no `Execution(unknown)` event; reconciliation exposes missing/not-evaluated evidence. |
| Post-execution state observation | `Effect` | Observer relationship must be stated conservatively. |

## Required non-equivalences

### Approval `request_id` ≠ Control `instruction_id`

A Hermes `request_id` identifies an approval request generation. An AIREP `Control.instruction_id`
identifies a control instruction associated with a finalized `Decision`. They may be equal only if a
future public Hermes contract explicitly establishes that identity. Every fixture uses visibly
different values and the validator rejects accidental equality.

### Presentation/request digest ≠ AIREP application digests

A digest over a redacted approval card or plugin transport request is not automatically any of:

- `Decision.input.input_digest`;
- `Control.instruction_digest`;
- `Control.authorized_action_digest`; or
- `Execution.executed_action_digest`.

Each field needs a documented byte/projection contract. The fixtures choose explicit JSON
projections and call the existing AIREP `digest_json()` implementation. Exact source-file or wire
bytes would instead require `digest_bytes()`; the two operations are never substituted implicitly.

### Approval ≠ Control

Human approval may support a `Decision(release)`. It produces no `Control` evidence until an actual
authorization instruction is reported crossing a boundary. Scenario 03 deliberately stops at the
Decision.

### Missing execution ≠ `Execution(unknown)`

AIREP v0.2 permits `executed`, `failed`, and `suppressed`. Unknown execution remains absent. This is
exercised by scenarios 04 and 09.

## Fixture-local canonical projections

The corpus uses versioned JSON objects for a governed intent, authorization action, authorization
instruction, and (in scenario 11) observed state. The action projection contains `tool`, `action`,
`target`, and `parameters`. Its JCS bytes are hashed through the repository's `digest_json()`.

> This projection is local to the integration fixtures. It is not a Hermes-native authorization contract.

The instruction projection includes its own fixture instruction ID, the AIREP Decision record ID,
the separate Hermes approval request ID, and the authorized-action digest. This makes the
non-equivalence inspectable without asserting that Hermes currently emits that instruction shape.

For the suppressed fixture, the schema-required `executed_action_digest` identifies the
executor-reported action whose attempt was suppressed; `execution_event=suppressed` is the
load-bearing statement that it did not run. Digest equality in that fixture is not an execution or
effect claim.

No Hermes profile namespace is created. The `example.hermes.*` identifiers are fixture-only
producer/projection/policy identifiers, not an official `org.nousresearch.*` profile or namespace.

## Scenario coverage

| ID | Evidence emitted | Important expected state |
|---|---|---|
| 01 explicit denial | Decision block | no Control or Execution |
| 02 timeout | runtime Decision block | not human denial |
| 03 release/no dispatch | Decision release | `instruction_evidence=MISSING` |
| 04 dispatch/no execution | Decision + issuer Control | receipt/execution missing; TOCTOU not evaluated |
| 05 executed | Decision + dispatch + receipt + Execution | TOCTOU satisfied; no effect claim |
| 06 suppressed | Decision + Controls + suppressed Execution | `execution_outcome=FAILURE` |
| 07 mismatch | Decision + Controls + executed Execution | `toctou=FAILURE` |
| 08 stale request | runtime Decision block | rejected interaction creates no release |
| 09 consumed/crash | Decision + dispatch + receipt | execution missing; no invented unknown event |
| 10 concurrent replay | one release lifecycle + one runtime block | exactly one Execution report; AIREP does not implement the race protection |
| 11 effect observed | all four families | `same_executor`, never inferred independent |

Reconciliation assertions target named checks. A global `summary.status = SATISFIED` is neither
expected nor required; without an intended-target inventory, total coverage remains
`NOT_EVALUATED` by design.
