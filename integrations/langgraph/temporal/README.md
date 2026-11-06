# Local temporal consumer: first Core implementation slice

This directory contains **authored, signed regression fixtures** and a bounded
consumer policy. It is not a new AIREP artifact family or registered profile.
It does not yet instrument delays in a live LangGraph process. Durable restart,
node replay, observer privilege separation and multi-target runtime tests remain open.

The sibling `../run.py` and D explain/CLI are restored from the frozen K3 source,
with exact origin hashes in `../SOURCE_IMPORT.json`. Their original six runtime
scenarios remain separate from these new fixtures. Core producer, verifier and
reconciler semantics are unchanged.

Each fixture is an AIREP Decision to record an authored test report, not a runtime
Control/Execution/Effect artifact. Its signed evidence binds exact event bytes;
its input binds exact source bytes. Source identity/state projection and the
accepted `CONTRACT.json` digest are checked. The existing AIREP Authenticated
verifier uses explicitly configured local test trust. Test keys are ephemeral;
only public bindings are exported. No URL or filesystem reference is fetched.

The policy matches workflow, run, process epoch, checkpoint, control, attempt,
target, boundary, predicate, clock and effect window. Arrival order never selects
the latest source observation. Conflicts retain all reports. A revision requires
an explicit configured authority and same-scope predecessor; history is retained.
Receipt, execution and effect remain separate stages. `QUIESCENT_REPORTED` means
only the supplied report for the exact window, never permanently stopped.

Run from the repository root using the dependencies in `../requirements.lock`:

```sh
python -B -m unittest discover -s integrations/langgraph/temporal/tests -v
python -B -m integrations.langgraph.temporal.report --out /tmp/airep-temporal-new-run
```

The output includes every fixture byte, public trust inputs, expected/observed
views, native verifier results, code hashes and a standalone HTML view. View
`index.html` in a local browser. The controls change precomputed, verified fixture
views; they are not a live event ingestion service or a replacement for the
runtime adapter. `T01` reverses delivery order, `T02` changes control identity,
`T03` switches runs, and `T11` preserves missing observation.

Unit tests cover the initial T01–T03/T09–T11 fixture cases, binding mutations,
positive support, boundary/predicate separation and explicit revision controls.
These tests and a DOM smoke check alone do **not** close G2-Core: a runtime-backed
adapter mapping and end-to-end delivery replay still need to bind real captured
events to the new contract. Synthetic epoch separation is not a T05 restart test.
