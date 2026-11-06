# First local implementation result — 6 November 2026

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
