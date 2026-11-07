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

Reproduce from this checkout in the existing pinned LangGraph/Python environment:

```sh
python -m unittest integrations.langgraph.multitarget.tests.test_partial -v
python -m integrations.langgraph.multitarget.partial_report --out /tmp/k7-r1-new-output
```

The output directory must not exist. The second command creates twelve authored
transformations of historical captures, signs new controller fixture mappings
with an ephemeral key, and verifies exact replay from saved public trust inputs.
It performs no new runtime capture or model call. This fixture generator is not
a trust-discovery API: real consumers must supply their expected intent and role
trust separately to `partial.evaluate`.

Regression command (local Unix socket permission required):

```sh
python -m unittest integrations.langgraph.multitarget.tests.test_partial integrations.langgraph.multitarget.tests.test_multitarget -v
```

No cross-host observer independence, complete distributed enforcement, hostile
worker isolation, SDK distributed support or external adoption is established.
The original v1 contract remains frozen, including its missing-report rejection.
