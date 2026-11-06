# Local durable-checkpoint experiment

This separate experimental track covers the bounded T04–T08 questions from the November plan. It is not part of the SDK 0.1.0a3 supported runtime contract. Two real subprocesses share a SQLite checkpoint: the first exits after a native interrupt; the second loads that exact paused checkpoint and resumes the same thread/run/control. Their PIDs and runtime epochs differ. The old pause remains historical evidence.

Two variants run the same interrupted node. In `repeat`, the pre-interrupt business insert is repeated after resume. In `idempotent`, a unique operation key suppresses the repeated insert. Both variants invoke the node twice and attempt three inserts; committed rows are respectively 3 and 2. The post-resume insert occurs once in both. This distinguishes node replay, attempted effects and committed effects. It does not promise exactly-once execution in general.

This design follows the official [interrupt semantics](https://docs.langchain.com/oss/python/langgraph/interrupts) and [SQLite checkpointer](https://github.com/langchain-ai/langgraph/blob/main/libs/checkpoint-sqlite/README.md). Resume re-executes the interrupted node; side effects before the interrupt therefore require explicit idempotency. The tested pins are LangGraph 1.2.19, checkpoint 4.3.1 and checkpoint-sqlite 3.1.3. The latter is an additional experimental dependency; existing integration and SDK locks are unchanged.

## Reproduce

From the repository root, with Linux CPython 3.12 x86_64:

```sh
python3 -m venv /tmp/airep-durable-env
/tmp/airep-durable-env/bin/python -m pip install --require-hashes -r integrations/langgraph/durable/requirements.lock
/tmp/airep-durable-env/bin/python -m unittest discover -s integrations/langgraph/durable/tests -v
/tmp/airep-durable-env/bin/python -m integrations.langgraph.durable.report --out /tmp/airep-durable-run
/tmp/airep-durable-env/bin/python -m integrations.langgraph.durable.report --replay /tmp/airep-durable-run/inputs.json --out /tmp/airep-durable-replay
```

Output directories must not exist. `inputs.json` contains exact source bytes, signed mapping reports, explicit local trust inputs, queries and replay schedules. The replay command does not launch LangGraph. It still requires the installed dependency environment. `report.json` preserves native verification separately from local interpretation. `capture/` includes the actual pause/resume SQLite databases, exact worker reports, two-snapshot effect observations and process exit records. `SHA256SUMS.json` hashes the report inventory. No private signing key is exported.

Open `index.html` through a local server to inspect 12 delivery views. These are views over two workflows/four subprocesses, not 12 independent runtime experiments. The T04 identity-only probes and T08 incompatible/clock/overlap cases are clearly labeled authored negative fixtures; no real runtime contradiction is claimed. Effect history and the exact JSON remain visible. No control receipt is inferred from a checkpoint or a successful signature.

## Binding and time semantics

`CONTRACT.json` defines a separate basis. Admission re-projects exact source bytes and checks identity, actor, reference, digest, fixed signed scope, claim and directive. The only shared Core change is an optional policy validation hook, invoked after native authentication and source binding; existing policies are unaffected. The native verifier and frozen AIREP schemas are unchanged.

The seven-field identity includes the process epoch and paused checkpoint. Resume uses the same checkpoint anchor and a new epoch; its terminal checkpoint is retained separately. Reusing `effect-1` across epochs cannot discard either record. The control `attempt_id` stays the same while node invocation IDs change.

One continuously running harness owns the observation clock across both subprocesses. Their separate worker clocks remain inside source bytes and are not compared across epochs. Replay arrival ticks are synthetic transport metadata, not observed network latency. The harness clock and trust domain are explicit; this is not a cross-host clock solution.

Effect results concern two sampled SQLite row inventories and an explicit window. A later quiet window does not cancel observed earlier progress. Different statuses over partly overlapping windows require reconciliation: overlap alone is not declared a logical contradiction, and no arrival-order winner is selected. Non-equivalent windows cannot satisfy a requested exact window.

## Scope and open work

These are author-operated same-host runs with orderly process exits, not crash/power-loss recovery tests. Observation/signing share the author's authority. SQLite UNIQUE keys are a bounded counterexample, not a general transactional side-effect protocol. Signed Decisions are mapping reports, not native Control/Execution/Effect lifecycle completion. Runtime truth, independent enforcement and complete continuous history remain unestablished.

T12 two targets, T13 in-flight control/effect race, T14 observer record/key authority separation, K7 topologies and LightEval remain open. The timeout test only ensures that harness cleanup cannot emit success evidence; it does not close T13. There is no public push, SDK release or IETF submission in this local track.
