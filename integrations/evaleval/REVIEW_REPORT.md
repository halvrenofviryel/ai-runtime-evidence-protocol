# Pre-commit review report

Date: 2026-09-24. Scope: non-normative EEE ↔ AIREP crosswalk and same-source experiment.

## A–D. Pinned bases

- **A. AIREP starting commit:** `c77237e16902ada783f75f8056c5adf8c25c33f6`.
- **B. EEE code commit:** `d734a861e80e1aae136e617007b74bce5bfe156a`; tracked files
  remained clean during the study.
- **C. EEE schema:** aggregate `0.3.0`, SHA-256
  `c9c6195aec8a9dfa0b2aba4924ac1aa8a184c9d8ca97cee778cb531088e39b48`; instance
  schema SHA-256 `b16b7fa7f0aa32763444179d94ffb2336ddb12c3fd2903835fe491666c1ff3e6`.
  HF datastore was pinned separately at revision
  `0147f886c45d56b2a53db25bfd1c42e3239b0bf2`.
- **D. AIREP profile basis:** `airep.embedded-evaluation` 0.1 on carrier 0.2, schema
  SHA-256 `ce57bd493d1a3166051bc9029972d6be215793edcd3f1b314534959659b3da8b`.

## E–H. Experiment and validation

- **E. Source evaluation:** LightEval `0.13.1.dev0` / commit
  `6b9d193b48de24d1ee87f3089303643b993cf4f9`; `sshleifer/tiny-gpt2` revision
  `5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be`; `Rowan/hellaswag` revision
  `218ec52e09a7e7462a5400043bb9a69a41d06b76`; validation split; task
  `hellaswag|0`; two-sample CPU cap; `em=0.0`, `em_stderr=0.0`.
- **F. Source evidence digests:** aggregate JSON
  `1b3464e5237d77d648b1960b7a879f4674d59a3c04d97279135a1b0fa59e103b`;
  two-row Parquet `c4f6ea15515ff7f0d1cfc9a6c23e1079dfc5b07fa508dab717d12777f315b298`;
  UTC run window `e42b54daf171792af018ac1cfd309ae483cb4297f38d2bf83d807ccc91b6bc89`.
- **G. EEE validation:** pinned validator exit `0`, `valid: true`, no errors and no
  warnings. Generated record SHA-256
  `ae3f6c27bc2f5cc4ab6c0df6793940cf093d2fecf56857b849e7eec7af8a62fb`.
- **H. AIREP validation:** `schema_valid: true`, no errors, exact pinned basis above.
  Profile payload SHA-256
  `b4eb510d82fafc0d78aa4f2d69be773d24f2760dd31dd813fc290f324db7f5a8`.

## I–L. Findings and boundaries

- **I. Crosswalk counts (35 rows):** `EXACT_OR_NEAR_EXACT=4`, `PARTIAL=10`,
  `EEE_ONLY=6`, `AIREP_ONLY=7`, `DERIVABLE_WITH_QUALIFICATION=1`,
  `NOT_SAFELY_DERIVABLE=3`, `DIFFERENT_CLAIM=4`.
- **J. Most important gaps:** criterion/verdict vs raw score; execution state; evaluator
  relationship vs independence; access tier; metric direction/range/uncertainty; instance traces;
  evidence visibility/resolvability/hash origin; coverage denominator/retries; disclosure/scope;
  unresolved EEE `evaluation_timestamp` format.
- **K. Claim hazards:** ambiguous result selection; completion→PASS; direction/range loss;
  rounding across thresholds; criterion laundering; cap→complete coverage; configured→verified
  identity; third-party→independent; path/URL→available evidence; reported→recomputed digest;
  schema-valid→true/interoperable; downstream judgment→source verdict.
- **L. Non-claims:** no model capability/safety/quality conclusion; no result truth,
  representativeness, complete coverage, evaluator identity/independence, exact executed weights,
  general reproducibility, EvalEval adoption/endorsement, official converter status, or EEE–AIREP
  interoperability.

## M. Checks run

| Command/check | Result |
|---|---|
| `python3 -m unittest discover -s integrations/evaleval/tests -v` | 29 tests passed. |
| `python3 -m unittest discover -s integrations/lighteval/tests -v` | 19 tests passed. |
| `python3 scripts/check_beta.py --out /tmp/airep-beta-check-eee-2` | 56/56 commands passed. |
| `make demo-test` | 2 tests passed. |
| `python3 scripts/check_quickstart.py` | PASS, including Python/Node verification and negative case. |
| `python3 scripts/check_beta_docs.py` | 12 reading-path docs, 1,919 preserved historical files, 0 failures. |
| `run_experiment.py offline` with pinned EEE checkout | EEE and AIREP mapping/validation passed. |
| Parse every study `*.json` | All parsed. |
| `git diff --check` | Passed. |
| Profile schema SHA-256 recomputation | Exact pinned digest. |
| Diff from starting commit under `spec/airep/v0.1`, `spec/airep/v0.2`, `schemas`, `docs` | Empty. |

The initial sandboxed Node runs returned host `EPERM`; the same commands were rerun in the permitted
execution environment and passed. This was an execution-policy failure, not a test assertion.

## N. Exact changed files

- Root: `README.md` (one repository-map row).
- Study: `integrations/evaleval/{README.md,SOURCES.md,CROSSWALK.md,CROSSWALK.json,REVIEW_REPORT.md}`.
- Mapping/reproduction: `experimental_lighteval_to_eee.py`, `run_experiment.py`.
- Tests: `tests/test_claim_safety.py`, `tests/test_artifacts.py`.
- Experiment: `experiment/{COMPARISON.md,comparison.json}`, two context JSON files, native manifest,
  native result JSON, two-row Parquet, run-window JSON, generated EEE record/mapping/validation
  reports, and generated AIREP profile/evidence-manifest/validation report.

No normative schema, frozen v0.1/v0.1.2 file, pre-existing fixture, or external tracked checkout file
changed. No external PR, issue, submission, datastore update, announcement or push was made.

## Adversarial review pass

- Removed implicit `self_deployed`, `open_weights`, score type and range assumptions; all now require
  explicit context, and the mapper validates the numeric range.
- Reclassified metric direction/range from near-exact to `EEE_ONLY` because the AIREP profile has no
  dedicated equivalent.
- Confirmed score never becomes PASS/FAIL, run completion never becomes metric PASS, and the AIREP
  observation remains `INCONCLUSIVE` without a threshold.
- Confirmed `third_party` stays a relationship declaration and AIREP independence stays `unknown`.
- Confirmed the cap remains partial, evidence remains restricted/non-resolvable, and only supplied
  bytes receive recomputed digests.
- Confirmed native sample traces are evidence, not fabricated AIREP lifecycle artifacts.
- Confirmed every validation report states its bounded meaning and all adoption/interoperability
  implications are explicitly denied.
