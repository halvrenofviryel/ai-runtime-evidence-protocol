# Local target, race and observer-authority experiments

This experimental increment covers bounded November scenarios T12–T14. It builds on the separate durable T04–T08 track, and does not change the SDK 0.1.0a3 supported runtime contract or frozen AIREP schemas.

Four real LangGraph captures use six executor runtimes and four separate observer processes:

| Capture | Target evidence | Local interpretation |
|---|---|---|
| `both_paused` | A and B receive the exact command, expose native interrupts, and have matching quiet two-sample observations | `ALL_TARGETS_BOUNDED_PAUSE`, 2/2 |
| `one_unknown` | A has the above evidence; B actually starts but its command delivery and observation are deliberately unavailable | `PARTIAL`, 1/2; B remains in the denominator with MISSING stages and forced cleanup |
| `inflight` | A starts a side-effect thread, then receives pause and exposes a native interrupt; a later harness barrier allows the already-started effect to commit | `EFFECT_CONTINUED`; native pause and later effect are both retained |
| `timeout` | A receives but ignores pause, commits an effect, then requires timeout cleanup | `CLEANUP_TERMINATED`; cleanup is never successful control execution |

The first two captures each have two targets; the latter two each have one. Additional bubblewrap launcher/reaper processes are infrastructure, not extra experiments. An unconfined subprocess operates only on disposable canaries as a positive permission control. Two additional signed negative fixtures demonstrate a failed authority boundary and scope inflation; they are not measured runtime incidents. The report has six views total.

## Reproduce

Tested on Linux kernel 6.11.0-29-generic, bubblewrap 0.9.0, CPython 3.12.3 and LangGraph 1.2.19. The report also records the bubblewrap executable hash. No new Python dependency is added; use the existing experimental lock:

```sh
python3 -m venv /tmp/airep-boundary-env
/tmp/airep-boundary-env/bin/python -m pip install --require-hashes -r integrations/langgraph/durable/requirements.lock
/tmp/airep-boundary-env/bin/python -m unittest discover -s integrations/langgraph/boundaries/tests -v
/tmp/airep-boundary-env/bin/python -m integrations.langgraph.boundaries.report --out /tmp/airep-boundary-run
/tmp/airep-boundary-env/bin/python -m integrations.langgraph.boundaries.report --replay /tmp/airep-boundary-run/inputs.json --out /tmp/airep-boundary-replay
```

Fresh capture requires `/usr/bin/bwrap` and permitted unprivileged user/mount/pid/network namespace setup. A surrounding execution sandbox may deny the NETLINK socket used during namespace setup; run the experiment in a suitable permitted local environment. There is no unconfined fallback for executors. Replay does not launch workers, observers or namespaces, but this runner still reads `bwrap --version` and the executable hash for environment metadata.

Output directories must not exist. `inputs.json` carries exact signed source/projection bytes and explicit local trust inputs. `capture/` includes controller schedules, actual business files, observer public records and logs. Generated private observer keys are mode 0600 in a private directory and are written/read by the observer. The controller and observer use the same host account; executor access is restricted by its mount/namespace view, not a different Unix UID. Keys are removed before capture returns, including failures. No private key is exported in the kit.

## Tested authority boundary

Executors receive a minimal mount view: runtime and repository read-only; their own work directory writable; public observer records read-only; an empty read-only private-key mount; private proc/user/pid/network namespaces; zero capabilities; no-new-privileges; nested user namespaces disabled. Real observer key storage is not mounted in the executor. The observer remains outside this view and can still write its own records. The configuration uses [bubblewrap's mount and namespace controls](https://github.com/containers/bubblewrap/blob/main/bwrap.xml); the [project describes its security model and limitations](https://github.com/containers/bubblewrap/blob/main/README.md).

Each executor actually attempts record append, truncate, chmod, unlink, replacement and symlink-mediated write; key read, write and unlink; nested user-namespace creation; and remounting observer storage writable. All eleven operations must be denied with an expected OS error. A write to the executor's own directory must succeed. The observer's original record/key hashes and modes must remain unchanged, its later write must succeed, and namespace/capability metadata must match the tested configuration. Distinct controller and observer signing keys are required. The unconfined canary control must demonstrate that the same account can normally read a canary key and modify a canary record and its mode.

A missing key path produces ENOENT because storage is excluded, not because an ACL rejected a read. The tested kernel returns EROFS for read-only writes, EXDEV for cross-mount replacement, ENOSPC for disabled nested user namespaces and EPERM for remount. These operations and mounts are the tested boundary; they are not a general sandbox security audit. A hostile host administrator, kernel compromise, inherited alternative mounts or another sandbox configuration are outside scope. Same-host author trust and controller-supplied observer path/identity selection remain explicit. Technical separation does not establish institutional independence.

## Source binding and interpretation

`CONTRACT.json` defines a separate interpretation basis. Controller and observer each sign AIREP Decision mapping reports. The consumer authenticates with separately supplied trust, checks exact actor/scope/assertion/directive/basis/source/output bindings, and re-projects both exact sources. A valid signature on stronger scope is rejected locally while native authentication results are preserved. Native observer assessment stays `not_applicable` and no witness is invented.

The consumer receives the expected intent separately: unique intended target IDs remain the denominator. Source-side narrowing, omitted/replaced target identities, duplicate observation nonces, borrowed run/epoch/checkpoint/control IDs and mismatched command bytes cannot silently become complete coverage. Scope includes all seven identity fields.

The controller has a monotonically recorded sequence of acknowledged sends/receives and cleanup. Worker and observer ticks have separate explicit clock IDs; they are never numerically compared across processes. A unique observation nonce ties start acknowledgement, endpoint samples and end response to the chosen target and window. Committed effect rows carry exact identity and step sequence. In-flight ordering is derived from acknowledged barriers, not a shuffled event list. Cleanup follows the measured window and cannot generate pause/effect success.

Two equal observer samples establish only `QUIESCENT_REPORTED` for that window. No causal or permanent stop claim follows. Process termination is separately displayed. `ALL_TARGETS_BOUNDED_PAUSE` is a local report classification, not native lifecycle completeness, independent enforcement, or a general guarantee about distributed agents.

## Presentation and remaining work

The small `index.html` fixture separates native results, receipt, execution, sampled effect, target identity, window/cutoff, cleanup, authority probes and source limitations. Its reverse button changes target display order only. The second button switches to the separately measured unknown-target capture; neither simulates live network delivery. Core's earlier delayed-delivery/append DOM tests remain separate evidence.

K7 three-target fan-out and A→B→C propagation, the LightEval source-to-consumer path, external trials and publication/review decisions remain open. T04–T08 evidence remains in the prior local delivery. No public push, merge, release or IETF submission is performed by this module.

Review candidate: original measured inputs and reports are retained in `evidence/2026-11-07/`. From the repository root, run `python integrations/langgraph/review/check_saved.py boundaries` in the pinned environment after materializing the existing offline Node dependency. This compares parsed native and consumer views, not whole report provenance bytes. The dedicated CI job performs saved-input replay only; it does not rerun runtime experiments or browser checks. Local CI commands are checked separately from future GitHub runs.
