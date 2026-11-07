# K7: three intended targets and direct delegation

Local experimental K7 module, separate from frozen beta semantics and SDK 0.1.0a3 support. Six measured captures use eighteen LangGraph worker processes. They are controlled same-host Unix-domain socket experiments, with no model inference, external service, A2A implementation or production agent protocol.

| Capture | Real injected behavior | Local bounded pause count |
|---|---|---|
| `fanout_all` | Controller dispatches to A, B and C | 3/3 |
| `fanout_unknown` | C really runs, but its selected control endpoint does not exist | 2/3; C remains UNKNOWN, with observed continued effects |
| `chain_all` | Controller→A→B→C; each worker directly forwards to the next worker | 3/3 |
| `chain_refused` | B receives but refuses; B does not forward to C | 1/3; B REFUSED, C UNKNOWN / NOT_ATTEMPTED |
| `chain_unknown` | B's selected C endpoint does not exist | 2/3; C UNKNOWN / TRANSPORT_UNKNOWN |
| `chain_retry` | C receives and pauses, then closes the first connection without returning its response; B retries | 3/3; four delivery attempts, three obligations, C executes its native pause once |

The chain has **three delivery links and two inter-target delegation links**. The operation is pause, not cancellation or dialog termination. This supports a bounded discussion of delegation correlation and unresolved outcomes; it is not a full implementation of AgentProto B3-9/10.

Three additional signed negative fixtures edit gateway refusal/unknown reporting or expand the signed scope. They are authored fixtures, not captured attacks. Both gateway fixtures have valid accepted signatures and locally consistent node projections, but fail cross-node byte/history binding. The full report contains nine views, not nine measured experiments.

## Reproduce

Tested with Linux, Python 3.12.3 and LangGraph 1.2.19. Use the unchanged durable experimental dependency lock; Node.js must be available for the existing native AIREP canonicalization/verifier dependency. No new dependency is added.

```sh
python3 -m venv /tmp/airep-k7-env
/tmp/airep-k7-env/bin/python -m pip install --require-hashes -r integrations/langgraph/durable/requirements.lock
/tmp/airep-k7-env/bin/python -B -m unittest discover -s integrations/langgraph/multitarget/tests -v
/tmp/airep-k7-env/bin/python -B -m integrations.langgraph.multitarget.report --out /tmp/airep-k7-run
/tmp/airep-k7-env/bin/python -B -m integrations.langgraph.multitarget.report --replay /tmp/airep-k7-run/inputs.json --out /tmp/airep-k7-replay
```

Output directories must not exist. Fresh capture needs permission to create local Unix-domain sockets and subprocesses. An outer sandbox may prohibit socket binding; there is no synthetic-capture fallback. Replay reads saved bytes without launching runtime workers or connecting to sockets. Native verification still invokes its existing local Node.js dependency.

The harness freezes A/B/C and the topology before dispatch, after reading actual initial checkpoints and runtime epochs. Each LangGraph node writes real append-only business rows until its pause handler interrupts. Receiver snapshots contain the actual native interrupt and checkpoint interrupt values. The harness samples complete file lines under a shared advisory lock after the control round, then snapshots worker reports and performs separately recorded cleanup. Refused/unreachable workers are forcibly cleaned up, never credited as paused.

A fresh Ed25519 key is generated in memory by each worker. Controller and worker roles have distinct keys. Reports, public trust inputs, exact command/reply bytes, business files and logs are exported; private keys are not written. All processes and the observer harness share the author's host account. **This module does not use T14's namespace isolation and does not inherit its protected-storage claim.** Cooperating workers, controller-selected paths/identities/trust, host administrator and event reporting remain trusted. Distinct signing processes are not independent observers.

## Consumer contract

`CONTRACT.json` bytes define the accepted basis. Consumers receive expected identities/topology and public trust separately from the signed controller report. Seven runtime identity fields are retained. The stable execution `attempt_id` differs from the transport `delivery_attempt_id`; only the latter changes on retry. Parent delivery identity and route path bind each forwarded request to the preceding receipt. Each process has its own monotonic clock; cross-process ticks are never numerically compared.

The consumer re-projects each signed worker source, then checks exact sender/receiver command and response bytes across every supplied hop. In the retry capture, the first sender transport outcome stays UNKNOWN/EOF while C's receipt and pause are present; the later response does not erase the first transport failure. No additional target obligation or second native pause is created.

The harness observation is first-party, signed as part of the controller source. Two equal file samples report bounded quiescence only. They are not continuous observation, permanent stop or causal proof. Source signatures do not prove honest or complete logging; colluding authors could manufacture source reports. The negative fixtures test contradictions within the supplied, separately bound reports, not truth against a hostile author.

AIREP's unchanged native verifier authenticates Decision mapping reports. Native reconciliation is retained verbatim: `INCOMPLETE`, including `intended_target_coverage: NOT_EVALUATED`. The local report's 3/3 count does not upgrade those fields or imply that all deployment execution paths were enumerated. No Control/Execution/Effect lifecycle chain or witness is fabricated.

## Presentation and IETF relation

The HTML fixture shows per-target receipt, execution, sampled effect, transport, retry count and cleanup, along with identity/parent-hop details and native qualifications. Reversing target order changes display only; the retry button selects the separately measured capture. It is not live transport ingestion.

The bounded results inform [ACDER-02](https://www.ietf.org/archive/id/draft-abak-agent-control-delivery-evidence-02.txt) R-CD-10/11/15/16 and the correlation/unresolved-outcome questions in [AgentProto requirements -07](https://datatracker.ietf.org/doc/html/draft-agentic-ai-usecases-requirements-07), B3-9/10. The Research evidence matrix pins the exact source hashes and limitations. A pause propagation experiment is not full cancellation, dialog termination, protocol interoperability or IETF conformance. No new normative draft revision follows merely from these test counts.

K7 local experiments do not publish source, merge PRs, release the SDK, revise the DOI or submit IETF documents. LightEval and actual outside trials remain separate work.
