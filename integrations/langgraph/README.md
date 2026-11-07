# Local LangGraph runtime evidence

This experimental integration executes **LangGraph Python 1.2.19** locally and
projects captured events into unchanged AIREP wire **v0.2** artifacts and D's
non-normative `explain` view. It is first-party runtime integration evidence,
with deterministic application nodes, not an LLM-agent evaluation, third-party
interoperability measurement, or a new conformance layer. No frozen v0.1 file,
normative schema, reconciler, or explain implementation is changed.

## Reproduce

The hash lock targets the measured CPython 3.12 / Linux x86_64 environment.
Install requires public PyPI access; the experiment itself makes no network
request and needs no credentials. Wheels for other platforms are not in this
lock; do not silently discard hashes to claim an identical reproduction.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r integrations/langgraph/requirements.lock
.venv/bin/python -m unittest discover -s integrations/langgraph/tests -v
.venv/bin/python integrations/langgraph/run.py --out /tmp/airep-langgraph-run
.venv/bin/python -m tools.airep_v02 explain \
  --input /tmp/airep-langgraph-run/stop-during-action/lifecycle.json \
  --bindings /tmp/airep-langgraph-run/stop-during-action/bindings.json \
  --revocation /tmp/airep-langgraph-run/stop-during-action/revocation.json --json
```

Output paths must be new. `--scenario NAME` can select individual runs.
The suite checks every installed dependency version against the lock and records
the installed LangGraph Python source hashes. `dependencies.json` retains exact
public wheel URLs and hashes from `pip --report`. Other sources are the D commit
and the integration source hashes recorded in `run_record.json`.

## What actually runs

A spawned process compiles and invokes `StateGraph` with a real
`InMemorySaver`. One node appends four JSON lines to an isolated output file,
flushes and `fsync`s each write, and checks a multiprocessing Pipe at cooperative
boundaries. The issuer writes the actual command bytes to that pipe. The
receiver logs only bytes it reads. Calling `interrupt()` is a request; execution
evidence requires both the native `GraphOutput.interrupts` result and matching
interrupt data in the actual checkpoint snapshot. We use the supported
`invoke(..., version="v2")` API because this bounded experiment needs final
state and interrupts, not streamed projections.

The start barrier and the barrier after the first file write make command
timing reproducible. This is controlled scheduling, not a latency benchmark or
an uncontrolled race test. `stop-before-start` means the command is sent before
graph invocation and received at the node's first checkpoint, before any
business side effect. It does not mean the node is never entered.

| Scenario | Applied condition | Runtime observation to expect |
|---|---|---|
| `normal` | No stop command | Graph completes; four file steps; no stop artifacts |
| `stop-before-start` | Stop sent before graph invocation | Native pause; zero observed file steps |
| `stop-during-action` | Stop after first file write, before next cooperative check | Native pause; first step remains; later steps absent in local observation |
| `receiver-unreachable` | Receiver closes its real pipe endpoint before command send | Actual `BrokenPipeError`; no dispatch-success/receipt/stop-execution artifact; business action completes |
| `receiver-ignores-stop` | Deliberately disabled cooperative handler | Receipt exists, enforcement unavailable, graph completes; failed Execution and authorization/action mismatch remain visible |
| `effect-unobserved` | Observer intentionally not run after pre-start pause | Native pause Execution exists; no Effect artifact; effect evidence remains MISSING |

For `receiver-unreachable`, closing the IPC receiver is an explicit fault
injection. It is not a simulated network outage or proof about any remote
receiver. A failed send is a command attempt, not an issuer `dispatched` event.
For `receiver-ignores-stop`, the actual no-pause handler path has a different
action digest and produces `execution_event=failed`; receipt is not promoted to
successful stop. Business action execution is recorded separately in raw events
and the output file. An AIREP Execution here refers to the **stop operation**,
not the append operation.

## Evidence boundaries

`events.jsonl` and per-event JSON files contain captured IPC, node, checkpoint,
observer, and cleanup events with actual wall/monotonic timestamps. The adapter
selects evidence from these events, not from a scenario's expected result.
`event-mapping.json` and each artifact's `evidence` pointers identify exact source
bytes and hashes. `run_record.json` hashes all emitted artifacts; its companion
hash covers the record itself. Fresh ephemeral signing keys are generated in
memory; only public test bindings are saved. Their local trust and active
revocation status are **stipulated experiment policy**, not external trust or a
real revocation service. Signatures authenticate these authored reports under
that policy; they do not establish event truth.

Post-run observations read the actual file twice after the worker exits, with
a short recorded observation window. The observer uses the same local author,
code, host, and trust domain, so Effect declares `same_executor`. The window
shows sampled local state, not independent corroboration, causation, absence of
all intermediate activity, or future stability. All runs use bounded waits,
join the worker, and close pipes. Forced termination is only timeout cleanup;
it is recorded and never projected as successful enforcement. LangGraph's
worker threads end with that joined process. The in-memory checkpoint is
discarded on exit; durable restart and resumption are untested.

This is **cooperative pause**, not forced/preemptive cancellation. `interrupt()`
must be reached inside a node, cannot undo the first file write, and does not
preempt arbitrary blocking code. A later resume restarts the node; side effects
before the interrupt could be repeated. The integration deliberately does not
resume, and does not claim terminal cancellation or idempotent replay.

The worker discards inherited environment names outside a small path/locale
allowlist without fetching their values, disables LangSmith/LangChain tracing,
and rejects socket connections before importing LangGraph. No model or provider
is instantiated, and the harness does not read any API key. Installed transitive
clients are dependencies, not invoked services.
This guard is an experiment constraint, not a sandbox against malicious code.

Control authority declares `writable_by_controlled_system=true`: separate local
process roles are not a security boundary. No independent-observer policy is
supplied. D's `explain` output remains derived and non-normative:
`enforcement_observed` and `relying_party_claim_support` remain
`NOT_EVALUATED`; absent evidence remains MISSING. Even observed cooperative
pause does not upgrade these unavailable native predicates. Normal execution
has no stop lifecycle; its empty input honestly yields MISSING evidence.

## Official API/source basis

Checked on 2026-11-02, then confirmed against the installed pinned package:

- [Install LangGraph](https://docs.langchain.com/oss/python/langgraph/install): base runtime installation; provider integrations are separate.
- [Interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts): node-local interrupt, checkpointer and thread ID, resume and node replay semantics.
- [Streaming and v2 invoke output](https://docs.langchain.com/oss/python/langgraph/streaming): `GraphOutput.value` and `.interrupts` for v2 invocation.
- [Interrupt API](https://reference.langchain.com/python/langgraph/types/interrupt): native resumable interrupt and checkpoint requirement.
- [Pinned LangGraph release](https://pypi.org/project/langgraph/1.2.19/): exact measured distribution, additionally fixed by wheel hash.

The mutable online docs are background context; the lock, source hashes,
tests, actual recorded outputs, and [RESULTS.md](../../reports/langgraph/RESULTS.md)
are the measurement basis.
