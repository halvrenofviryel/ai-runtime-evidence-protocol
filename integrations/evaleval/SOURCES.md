# Pinned sources and inspected evidence

All observations below were made on 2026-09-24. Remote `main` branches are moving targets; the
identifiers and digests, not branch names, define this study's evidence basis.

## Every Eval Ever code

- Repository: <https://github.com/evaleval/every_eval_ever>
- Commit: `d734a861e80e1aae136e617007b74bce5bfe156a`
- Package version: `0.2.3rc1`
- Aggregate schema: `every_eval_ever/schemas/eval.schema.json`, SHA-256
  `c9c6195aec8a9dfa0b2aba4924ac1aa8a184c9d8ca97cee778cb531088e39b48`
- Instance schema: `every_eval_ever/schemas/instance_level_eval.schema.json`, SHA-256
  `b16b7fa7f0aa32763444179d94ffb2336ddb12c3fd2903835fe491666c1ff3e6`
- Generated aggregate model: `every_eval_ever/eval_types.py`, SHA-256
  `25aaeeea342a5cbdd5d14c378ea9e3ba1a9ba765940e157ee51c324b4126b020`
- Generated instance model: `every_eval_ever/instance_level_types.py`, SHA-256
  `99a2c74e36e9d1b2d2030ffddb203a8a584c126c6bf31f16bfa01ab280a2a5fd`
- Validator implementation inspected: `every_eval_ever/validator/validation_core.py` and
  `every_eval_ever/validator/validate.py`; the top-level files are compatibility wrappers.
- Field guidance inspected: `.agents/skills/eee-dataset-conversion/SKILL.md` and its `fields.md`,
  `instance-level.md`, `datastore-gate.md`, `gotchas.md`, `registry.md`, and `verification.md`.
- Official converter directories at this revision: Inspect, HELM, lm-eval, AlpacaEval. No official
  LightEval converter exists. Adapter directories are a distinct ingestion surface.

EEE issue [#237](https://github.com/evaleval/every_eval_ever/issues/237) is open at this pin and
documents an upstream ambiguity: `evaluation_timestamp` has no single defined wire format; current
producers use both Unix epoch text and ISO-8601. This study omits that field from its generated EEE
record rather than choosing a format silently.

## EEE datastore

- Dataset: <https://huggingface.co/datasets/evaleval/EEE_datastore>
- Dataset revision: `0147f886c45d56b2a53db25bfd1c42e3239b0bf2`
- Dataset card SHA-256: `25eea7a0192109a07afcbad9c38ab271f7e6931a6b65bec1219059a788524b14`
- `flat/latest_manifest.json` SHA-256:
  `5d777b1c8e55e6ae9c1c77475157e17eee2297fc9c66239f5f8e40dc32dca9ba`
- Manifest-selected entries snapshot: content id
  `sha256:69d72f0718e417aef7125c39f2832dae39fe8ce2074aa89e584a6069d5c45eb1`
- Dereferenced `entries.jsonl`: 38,154,828 bytes, SHA-256
  `f3c795cd47aa45e9d066fde288877a548a6ea51cb489cc7c4cd201a4dd59a7d6`
- Snapshot counts observed: 81,186 aggregate entries, 1,805 instance companions, 82,991 total,
  115 benchmark collections; schema versions `0.2.2` and `0.3.0` coexist.

The dataset card says `data/` is source truth and warns that collections are neither normalized nor
disjoint, model identifiers do not form a clean join key, and collection membership alone does not
make records comparable. `generation_config`, `eval_library`, and `source_data` must be examined.

Real snapshot records inspected:

| Producer | Flat object | SHA-256 | Observation |
|---|---|---|---|
| Inspect | `flat/objects/ab/91/ab91781f-b940-4801-aa11-4a84e276b099.json` | `f4ef264121587e1904665fdabfeca5151e810947d1cfabe480866c352791d381` | `source_type=evaluation_run`; epoch-text timestamp; `third_party` relationship. |
| Inspect instance companion | `flat/objects/ab/91/ab91781f-b940-4801-aa11-4a84e276b099_samples.jsonl` | `f40981f088fe042c0af14433789f02ffc8e81acb2764e977f8ebc4da5f4d8db8` | 1,319 sample rows with interaction, evaluation, token and performance detail. |
| lm-eval | `flat/objects/00/36/0036f037-d1c4-4a6b-8dca-c37a5fc5e58b.json` | `5951030d5386acdbeaab3786b0def3bca1256c4019fd8816007b6f47c3b6c5ad` | `source_type=documentation`; `lm-evaluation-harness` 0.4.0; multiple metrics. |
| HELM | `flat/objects/d5/8b/d58b1792-74a2-46d9-b406-66227fce6333.json` | `9e9bfc0a048821a864f92472f724af0be1b8d7414bb96879e7ae9451c5bad2ee` | `source_type=documentation`; `eval_library=helm`; unknown version is explicit. |

The Inspect aggregate's `detailed_evaluation_results.checksum` describes the converter/source
sidecar identity and differs from the flat datastore object's byte digest. The flat manifest digest
above identifies the retrieved snapshot bytes; the two values must not be collapsed.

## AIREP

- Repository starting commit: `c77237e16902ada783f75f8056c5adf8c25c33f6`
- Profile schema: `spec/airep/v0.2/profiles/embedded-evaluation/embedded-evaluation.schema.json`
- Profile id/version/carrier: `airep.embedded-evaluation` / `0.1` / `0.2`
- Schema SHA-256: `ce57bd493d1a3166051bc9029972d6be215793edcd3f1b314534959659b3da8b`
- Existing exporter: `integrations/lighteval/export_embedded_evaluation.py`
- Published analytical lens: <https://datatracker.ietf.org/doc/draft-abak-ai-evaluation-claim-preservation/>,
  revision `-00`, retrieved 2026-09-24. It is not vendored or treated as EEE policy.

## LightEval and evaluation inputs

- Repository: <https://github.com/huggingface/lighteval>
- Commit: `6b9d193b48de24d1ee87f3089303643b993cf4f9`
- Package version: `0.13.1.dev0`
- Model: `sshleifer/tiny-gpt2`, revision
  `5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be`
- Dataset: `Rowan/hellaswag`, revision
  `218ec52e09a7e7462a5400043bb9a69a41d06b76`, validation split
- Exact native output digests are in `experiment/native/native-manifest.json`.

