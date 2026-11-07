# K7-R1: partial remote evidence, local candidate

`local-multitarget-partial-evidence-v2` is a separate experimental consumer
contract. It does not reinterpret v1 signed controller reports. v1 node reports
remain independently authenticated; a new controller mapping binds the v2 basis
and scope. Frozen native verifier/reconciler and SDK behavior are unchanged.

With C's report, observation and cleanup absent, A/B can retain their admissible
bounded results. C remains in the original three-target inventory with UNKNOWN
receipt/execution/effect and INDETERMINATE assessment. A sender's alleged reply
does not become evidence of C's execution. Available observations are retained
even if execution is unknown. Missing observations never imply quiescence.

Supplied invalid evidence rejects the package; absent evidence is not invalid
evidence. Intermediate report loss creates explicit corroboration gaps for
downstream targets. Counts of supplied transport attempts are labelled reported,
and the attempt inventory is PARTIAL when any node report is absent. Unknown
sender history must not appear as NOT_ATTEMPTED. Native INCOMPLETE and
intended_target_coverage NOT_EVALUATED are preserved.

Reproduce from this checkout on Linux with CPython 3.12.3 and Node.js 20.19.6.
The existing hash-locked experimental dependencies are reused; no new library
is introduced. From the repository root:

```sh
python3 -m venv /tmp/k7-r1-env
/tmp/k7-r1-env/bin/python -m pip install --require-hashes -r integrations/langgraph/durable/requirements.lock
/tmp/k7-r1-env/bin/python spec/airep/v0.2/class-verification/offline-node-deps/materialize_node_modules.py
/tmp/k7-r1-env/bin/python -B -m unittest integrations.langgraph.multitarget.tests.test_partial -v
/tmp/k7-r1-env/bin/python -B -m integrations.langgraph.multitarget.partial_report --out /tmp/k7-r1-new-output
/tmp/k7-r1-env/bin/python -B -m integrations.langgraph.multitarget.partial_report --replay /tmp/k7-r1-new-output/inputs.json --out /tmp/k7-r1-replay
cmp /tmp/k7-r1-new-output/inputs.json /tmp/k7-r1-replay/inputs.json
cmp /tmp/k7-r1-new-output/report.json /tmp/k7-r1-replay/report.json
```

Each output directory must not exist. The command without `--replay` creates twelve authored
transformations of historical captures, signs new controller fixture mappings
with an ephemeral key, and verifies exact replay from saved public trust inputs.
It performs no new runtime capture or model call. This fixture generator is not
a trust-discovery API: real consumers must supply their expected intent and role
trust separately to `partial.evaluate`.
`--replay` reads the saved fixture inputs and public trust; it does not generate
a new signing key. This is an author-fixture replay command, not an external
producer intake endpoint. Negative cases must remain NO_MATCH; a successful
replay of a negative case is not a successful pause. Input trust remains explicit
fixture trust, not a verifier endorsement of the supplied identities.

Regression command (local Unix socket permission required):

```sh
python -m unittest integrations.langgraph.multitarget.tests.test_partial integrations.langgraph.multitarget.tests.test_multitarget -v
```

No cross-host observer independence, complete distributed enforcement, hostile
worker isolation, SDK distributed support or external adoption is established.
The original v1 contract remains frozen, including its missing-report rejection.

The separate `K7 partial evidence review` CI job runs the new and original K7
tests, then generates and exactly replays the twelve fixture cases. The original
K7 tests perform fresh same-host captures; fixture generation and saved replay
perform none. The job uploads no raw logs, generated evidence or workspace
archives. Its commands can be run locally; a future GitHub PASS must be checked
on the submitted commit before merge.
