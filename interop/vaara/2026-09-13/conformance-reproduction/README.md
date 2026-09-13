# Vaara SEP-2828 conformance reproduction — 13 September 2026

**Independent execution by Ali Toygar Abak / Phionyx of Vaara's published SEP-2828 conformance
checkers over Vaara's published vectors.**

In Vaara's own classification for its public conformance desk, this run is:

> Reproduction: the author's checkers over the author's vectors

"Independent execution" means the run happened **outside the maintainer's environment**. It does
**not** mean an independently authored checker, and it does not mean independently constructed
vectors. Both the checkers and the vectors are Vaara's, taken unmodified at a pinned commit.

No prior approval from Vaara was required, sought or claimed. The repository and corpus are public.

## External registry

Published as **Vaara Conformance Results row #7**:

[![Vaara Conformance Results row 7](https://vaara.io/badge/ali-toygar-abak.svg)](https://vaara.io/conformance.html)

Registry links:

- Conformance page: https://vaara.io/conformance.html
- Canonical row JSON: https://vaara.io/badge/ali-toygar-abak.json
- Printable row: https://vaara.io/badge/ali-toygar-abak.html

This external registry entry records a **reproduction of Vaara's published checkers over Vaara's
published vectors** at the pinned commit below. It does not establish an independent
implementation, independently constructed vectors, specification correctness, complete Vaara
product conformance, hosted-service interoperability, Vaara-AIREP interoperability, certification,
or endorsement.

## Result

| | |
| --- | --- |
| Run ID | `VAARA-SEP2828-REPRODUCTION-20260913T132310Z-96321b403812` |
| Repository | https://github.com/vaaraio/vaara |
| Commit | [`d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317`](https://github.com/vaaraio/vaara/tree/d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317) |
| Corpus | [`conformance/sep2828`](https://github.com/vaaraio/vaara/tree/d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317/conformance/sep2828), version `1.0.0` |
| Suites | `record_conformance_v0`, `record_set_v0` |
| Exit code | `0` |
| Totals | 2 suites, **2 passed**, 0 failed, 0 skipped |
| `all_passed` | `true` |
| Runner record digest | `96c56875bdc3d62e08360002ee412a4027116da723403b5843b26e42d74b15d6` |

Both suites returned `PASS` with return code 0. What exit code 0 means here, and nothing more:
every suite that ran matched its published expected verdicts.

### On the case count

The report shows `cases: null` per suite and `totals.cases_passed: 0`. That is a property of the
runner and this corpus layout, not a statement that nothing was graded. The aggregate runner derives
a *declared* case count from `expected.json["cases"]` or a `cases/` directory; these two suites key
`expected.json` by case name at top level and store inputs under `records/` and `sets/`, so no count
is derivable and `null` is reported. The checkers did execute and did match. The exact graded file
set is pinned by SHA-256 in `vaara-conformance-report.json` under `corpus.suites`.

### Two distinct digest constructions

Both are recorded, under their own names, and are **not** compared with each other:

- `MANIFEST.json` `corpusDigest` (byte-integrity preflight):
  `sha256:0baa437da95d6ffb6bda3185d657385b7738c79daba77819acc0c6280ac0ed7a`
- aggregate runner `corpus.corpus_sha256`:
  `0cfc3fc33646a58445a151efbc06ac376f0cabf19acbd64a9385c06d13be6fbd`

## How it was run

A fresh clone was checked out detached at the pinned commit. Before any checker ran, a
byte-integrity preflight confirmed the corpus bytes:

```
python3 conformance/sep2828/run.py --verify-manifest
```

which reported `MANIFEST OK: 32 files match` with the expected `corpusDigest`. The recorded run
then executed once:

```
python3 scripts/conformance_runner.py \
  --vectors-dir conformance/sep2828 \
  --corpus record_conformance_v0 \
  --corpus record_set_v0 \
  --json ../<run-id>/vaara-conformance-report.json
```

`--with-vaara` was not used. No additional suites were selected. No Vaara package, `rfc8785` or
`cryptography` was installed: the pinned `run.py` and both `_check_independent.py` checkers import
only the Python standard library and import no Vaara code, and this was verified on the pinned
source before execution. `git status --porcelain` was empty before and after; the 35 corpus source
files hash identically before and after; no Vaara source file was modified.

Full detail: `RUN_RECORD.json`, `ENVIRONMENT.md`, `COMMAND.txt`, and the raw captured streams.

Vaara fixture files are **not** copied into this repository. They are linked at their exact commit
paths above and pinned by SHA-256 inside `vaara-conformance-report.json`.

## What this establishes

Only the observed behavior of those pinned public checkers over those pinned public vectors, in the
environment recorded in `ENVIRONMENT.md`.

## What this does not establish

- an independent implementation written from the specification text;
- independently constructed vectors;
- correctness of the specification;
- signature authentication beyond what the checkers actually test;
- complete Vaara product conformance;
- hosted-service interoperability;
- AIREP interoperability, or any Vaara × AIREP mapping result;
- endorsement by Vaara or by its maintainer;
- certification.

This record is Phionyx's own. It is published under Phionyx's name and speaks for no one else.

## Provenance note

An earlier attempt, `VAARA-SEP2828-REPRODUCTION-20260913T125351Z-859f338d695f`, executed the same
two suites with the same PASS result, but its report recorded `commit: null`: the clone sat on a
root-owned mount, so the runner's plain `git rev-parse HEAD` subprocess was refused and the commit
could not be pinned in the record. Its `commit_dirty: false` came from that same failure rather than
from observing a clean tree. That attempt is preserved unmodified and unpublished; the run recorded
here is a separate, authorized run identity executed on a path where the runner's own git call
resolves. Nothing was re-run to obtain a better verdict — the verdict was identical.
