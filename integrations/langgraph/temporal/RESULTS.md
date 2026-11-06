# Captured-runtime Core result — 6 November 2026

This second local slice connects the temporal consumer to real captured
LangGraph 1.2.19 events. The earlier fixture-only delivery is retained below as a
historical result. No public release or independent reproduction is claimed.

| Check | Observed | Scope |
|---|---:|---|
| Temporal tests | 35 passed: 18 original + 17 captured-source tests | Real capture, projection, binding, mutation controls and saved-input replay |
| Existing K3 runtime tests | 13 passed | Original six scenarios, imported source bytes unchanged |
| D explain/CLI tests | 14 passed | Existing native and explanatory results preserved |
| New captured runs | 3 | Native pause; ignored controls with two real file writes; pause with no observer |
| Offline delivery views | 14/14 matched | T01–T03, T09–T11 and positive support |
| Saved-input replay | 14/14 identical parsed views | Parsed native-verifier and consumer view equality; no fresh runtime in replay |
| Browser check | 14 views + 2 buttons passed | Scope, sampled windows, time bases, failures and limits visible |
| Original fixture report | 8/8 matched | Original source policy still explicit and separate |

Replay equality means identical parsed native-verifier and consumer `views`,
not byte-for-byte identical output files. Capture and replay reports retain
different provenance metadata; the HTML can differ in JSON key serialization
order even when the parsed views are equal. Each file has its own recorded hash.

**G2-Core: local PASS for captured-runtime mapping and offline delivery replay.**
The runtime uses real InMemorySaver checkpoints, receiver command bytes, native
interrupt payloads and file snapshots. Query-supplied identities cannot relabel
those captured bytes even when an altered projection has a valid local signature.
The control/run identity negatives keep the old observation window and clock so
that mismatched windows cannot conceal a broken ID matcher.

Arrival order is scheduled during offline replay. It is not a live network
latency test. The HTML displays precomputed report views. Two identical file
samples support only a bounded sampled-quiescence report, not continuous stopping
or causal enforcement. Receipt, execution and effect remain separate. Run B can
be temporarily quiescent while its handler deliberately ignores a pause.

The mapping produces signed Decision reports, with the existing verifier's
native result retained. It does not upgrade them into native Control/Execution/
Effect artifacts or independent observation. The original native K3 lifecycle
adapter remains unchanged. The original 39-test beta validation from the first
slice is not counted as a new run here; the producer/verifier/reconciler sources
are unchanged and their source hashes are checked.

**Open:** G2-Extended durable restart/resume, node replay effects, observer write
privileges and multi-target behavior. G3 reusable application hooks, wheel
resources and clean installation outside a checkout remain separate work.

During development, the initial new report run was withheld by the native
verifier because its local test revocation snapshot ID lacked a namespace. The
reporting input was corrected; the verifier was not weakened. The initial
failure is not a passing result. Local browser serving required permission to
bind a loopback socket after the sandbox denied it; no public listener was used.

## Historical first slice

### First local implementation result — 6 November 2026

Base: AIREP main `10b4a9114d04b17fdcd7204a571dbe563d17e295`.
Imported D/K3 source: `76ecce0b378a6b391850795abf45fb6aca8e1d6b`;
see `../SOURCE_IMPORT.json` for exact imported paths and hashes.

| Check | Observed | Scope |
|---|---:|---|
| Existing beta regression tests | 39 passed | Python/Node parity and producer/reconciler/CLI behavior |
| Existing K3 runtime tests | 13 passed | Six real local LangGraph scenarios; original single-run setup |
| Restored D explain and CLI tests | 14 passed | Native statuses/qualifications retained; CLI admission and no-overwrite |
| New temporal consumer tests | 18 passed | Authored, signed fixture reports; includes positive controls |
| Expected/observed fixture views | 8/8 matched | T01–T03, T11 and exact-scope positive |
| Browser DOM smoke | 8 views + 2 buttons passed | Actual local DOM; precomputed fixture results, not live runtime ingestion |

The browser check selected every scenario, verified effect status and history row
count, checked scope fields and same-executor qualifications, then exercised the
late-observation and reverse-arrival buttons. Old observation ticks `5 / 5` and
arrival `[30]` remained visible while the newer window stayed CONTINUED_REPORTED.

T09–T10 additionally cover duplicate deliveries, one event in several signed
reports, conflicting same-ID content, signature corruption, altered source bytes,
wrong references, changed interpretation basis and signed identity relabeling.
No new signing or verification algorithm was introduced. The native verifier
output is preserved alongside the explicitly separate consumer result.

**G2-Core remains open.** The fixture consumer and DOM check do not yet prove the
live adapter's event mapping. Next: connect captured LangGraph events to this
contract and replay the bounded delivery-order negatives end to end. Real process
restart/resume, node replay and observer storage/key isolation remain Extended.
No outside user, independent observer or adoption result is claimed.

The initial temporary worktree's shared filesystem reported mode-only changes;
content checks used per-command `core.filemode=false`. Work was then copied into
isolated checkouts in the permanent project outputs directory, with the original
temporary worktrees preserved. No global Git trust/config setting changed.

The first broad beta check lacked the locked AJV dependency. Its failed log is
retained; the dependency was installed with npm ci and install scripts disabled.
A subsequent sandbox run hit Node spawnSync EPERM. The unchanged tests passed
with the required local-process permission. Both failed logs were preserved;
neither is counted as a successful run.
