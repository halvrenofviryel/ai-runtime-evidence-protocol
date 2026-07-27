# Pinned versions

Captured **2026-07-26, before any system under test was run.** Every result in this comparison is
a statement about these exact revisions and nothing else. If a project changes after this date, the
result does not automatically transfer — re-pin and re-run.

Recorded via `gh api repos/<r>/commits/HEAD` and `.../releases/latest`.

## Systems under test

| System | Commit at pin time | Latest release at pin time |
|---|---|---|
| `microsoft/agent-governance-toolkit` | `179843b16ead` (2026-07-24 23:47:48Z) | **v4.1.0** (2026-06-09) |
| `openai/openai-agents-python` | `f663a06aea23` (2026-07-26 10:02:25Z) | **v0.18.3** (2026-07-17) |
| `NVIDIA-NeMo/Guardrails` | `e40c7f69862c` (2026-07-23 16:18:48Z) | **v0.23.0** (2026-07-01) |

## Ours

| Component | Revision |
|---|---|
| `halvrenofviryel/phionyx-research` | `1be8d0cc7f85` (2026-07-26 18:17:46Z) |
| `halvrenofviryel/ai-runtime-evidence-protocol` | `46152539ab45` (2026-07-26 18:16:26Z) |
| monorepo (private, for reproduction of the demo) | `b6876f3eec70`, branch `feat/vldr-ger-evidence-layer` |
| Python | 3.12.3 |

## Rules attached to these pins

1. **A result belongs to a revision.** No cell is written for a system at an unpinned revision.
2. **Re-pinning is a changelog event.** If a pin moves, `CRITERIA.md`'s changelog records the date
   and reason, and any affected cell is re-run rather than carried over.
3. **A release tag is not a substitute for a commit.** Both are recorded because a project's `main`
   may be well ahead of its last release — `agent-governance-toolkit`'s last release predates its
   pinned commit by six weeks, and results taken from `main` must not be reported as results for
   v4.1.0.
4. **Reading documentation is not running a system.** Documentation quotes are attributed to the
   docs, with the fetch date, and appear only in the `what the vendor documents` column.

## Status

Pins recorded. **No system under test has been run yet.** The only measurements taken so far are our
own Phase 1 build verification, recorded in [`results/PHASE1_SELFCHECK.md`](./results/PHASE1_SELFCHECK.md)
and explicitly not comparison results.
