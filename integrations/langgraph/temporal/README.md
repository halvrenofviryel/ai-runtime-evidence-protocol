# Bounded temporal consumer and captured-runtime replay

This directory contains two explicitly selected source policies. The original
`CONTRACT.json` accepts authored signed fixtures. `RUNTIME_CONTRACT.json` accepts
byte-exact events captured from real local LangGraph runs. Neither is a new AIREP
artifact family or registered profile. The consumer does not infer event truth
from an authenticated report.

`capture.py` runs LangGraph 1.2.19 in spawned processes with InMemorySaver and real
file writes. It captures a native pause, ignored controls with observed file
progress, and a native pause without an effect observer. One run receives two
separate control requests. The starting checkpoint ID is obtained from
`graph.get_state()` after the initial interrupt-before checkpoint. It anchors the
node attempt; the terminal checkpoint ID is recorded separately. Run and process
epoch IDs are captured at emission, not supplied by a query after the event.

`runtime_source.py` derives receipt from exact received command bytes, paused
execution from matching native and checkpoint interrupt payloads, and effect
from two captured file snapshots. An unchanged sample pair means only sampled
quiescence within that exact window. It cannot exclude transient changes between
samples or establish permanent stopping. The observer shares the executor's
host, credentials and trust domain.

`runtime_report.py` then performs **offline delivery replay** of these captured
reports. Reordering does not alter source bytes or timestamps. Arrival ticks are
a separate replay schedule, not measured network latency. This is not an online
transport service or a durable restart/resume experiment. T03 selects run B's
captured active-work window while retaining run A's history; it does not claim a
network observation was delivered live while the process was running.

Each signed Decision records a mapping report. Exact captured source bytes,
projected event bytes and the explicitly accepted mapping-basis digest are bound
and rechecked using the existing Core/Authenticated verifier. The new reports do
not replace the native Control/Execution/Effect lifecycle. The original six-run
K3 adapter and D explain/CLI remain byte-identical to `../SOURCE_IMPORT.json`.

The consumer matches workflow, run, epoch, starting checkpoint, control, attempt,
target, boundary, predicate, clock and effect window. Late observations cannot
settle another identity or another window. History, duplicate arrivals and
conflicting reports remain visible. Receipt, execution and effect are separate;
there is no combined stopped/success badge. Signed relabeling, byte corruption,
missing operator trust and unaccepted mapping bases fail closed.

## Reproduce

From the repository root, use CPython 3.12 and `../requirements.lock`:

```sh
python -B -m unittest discover -s integrations/langgraph/temporal/tests -v
python -B -m integrations.langgraph.temporal.runtime_report --out /tmp/airep-captured-new
python -B -m integrations.langgraph.temporal.runtime_report \
  --replay /tmp/airep-captured-new/inputs.json --out /tmp/airep-replay-new
```

Output directories must not exist. A fresh capture checks installed dependency
versions against the lock. A saved-input replay needs the verifier dependencies
but starts no LangGraph process. Sources and public test-trust inputs are embedded
in `inputs.json`; references are opaque and are never fetched from URLs or paths.
Local ephemeral private keys are not exported. Review public bindings as test
inputs, not production trust anchors.

The report includes 14 expected/observed views, raw capture JSONL and business
files, native verification results, source hashes, dependency versions and a
SHA-256 manifest. `index.html` presents precomputed, verified results. Its buttons
select replay outcomes; they do not start a live runtime or deliver a network
message. Both positive and negative controls are required.

The original fixture path remains available:

```sh
python -B -m integrations.langgraph.temporal.report --out /tmp/airep-fixtures-new
```

## Acceptance and remaining work

The local G2-Core scope covers T01–T03/T09–T11 through captured-runtime mapping,
offline replay and actual browser checks. The identity-only negatives retain the
old observation's window and clock, so a broken identity matcher cannot pass
merely because windows differ. They are deliberately adversarial query probes,
not claims that a new control existed before it was issued.

See `RESULTS.md` for measured checks. Durable restart/resume, node replay effects,
observer privilege separation and multi-target cases remain Extended. A reusable
user-application hook and a wheel that works outside this checkout remain G3;
this controlled capture harness is not a production SDK.
