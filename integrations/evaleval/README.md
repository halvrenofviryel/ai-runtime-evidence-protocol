# EEE ↔ AIREP experimental crosswalk

> **Non-normative first-party mapping study. This is not EvalEval adoption,
> endorsement, an official EEE converter, or interoperability evidence.**

This directory compares the pinned [Every Eval Ever (EEE)](https://github.com/evaleval/every_eval_ever)
schema and runtime semantics with AIREP's experimental Embedded Evaluation Profile 0.1. It also
maps one real, deliberately tiny LightEval run into both representations without treating either
derived document as the authoritative evaluation result. The committed native LightEval bytes are
the source evidence.

The study tests a hypothesis: EEE and the AIREP profile overlap, but they may make different claims.
EEE is a rich evaluation-result and metadata schema with aggregate and instance-level forms. The
AIREP profile is a companion evaluation-evidence context: it makes execution state, declared
criterion, evidence state, evaluator context, disclosure and claim boundaries explicit. Neither
description implies that one format supersedes the other.

The [claim-preservation Internet-Draft](https://datatracker.ietf.org/doc/draft-abak-ai-evaluation-claim-preservation/)
is a separate, format-neutral analytical lens. EEE does not adopt it and this study does not make it
a requirement for EEE.

## What is pinned

- EEE code: `d734a861e80e1aae136e617007b74bce5bfe156a` (`0.2.3rc1`), including the
  aggregate/instance schemas, generated Pydantic models, validators, converters and adapters.
- EEE datastore: HF revision `0147f886c45d56b2a53db25bfd1c42e3239b0bf2`, independently
  pinned from the code revision and verified through `flat/latest_manifest.json`.
- AIREP Embedded Evaluation Profile: id `airep.embedded-evaluation`, profile version `0.1`,
  carrier `0.2`, schema SHA-256
  `ce57bd493d1a3166051bc9029972d6be215793edcd3f1b314534959659b3da8b`.
- LightEval source: commit `6b9d193b48de24d1ee87f3089303643b993cf4f9`, package
  `0.13.1.dev0`; model and dataset revisions are pinned in the experiment manifest.

See [SOURCES.md](./SOURCES.md) for the complete evidence inventory and [CROSSWALK.md](./CROSSWALK.md)
for the semantic analysis. [CROSSWALK.json](./CROSSWALK.json) is the machine-readable form.

## Experiment layout

```text
experiment/
  native/                 # authoritative LightEval results/details and run manifest
  context/                # explicit declarations not present in native output
  out/eee/                # local research mapping plus pinned-validator capture
  out/airep/              # existing AIREP exporter outputs
  COMPARISON.md
  comparison.json
```

`experimental_lighteval_to_eee.py` is deliberately narrow and fail-closed. It is an AIREP study
mapper, not an EvalEval converter. EvalEval currently has official converters for Inspect, HELM,
lm-eval and AlpacaEval, but no LightEval converter at the pinned revision. EEE adapters are a
separate ingestion mechanism and are not described as converters here.

## Reproduce

Offline mapping and validation can be repeated from the committed native evidence without model
downloads:

```bash
python3 integrations/evaleval/run_experiment.py offline \
  --eee-root /path/to/every_eval_ever-at-d734a861 \
  --out-root /tmp/eee-airep-study
```

The command refuses an EEE checkout at the wrong revision and verifies committed native digests
before mapping. To regenerate the native run (network and public model/dataset downloads required):

```bash
python3 integrations/evaleval/run_experiment.py generate-native \
  --lighteval-root /path/to/lighteval-at-6b9d193 \
  --output-dir /tmp/eee-airep-native
```

No API key, private credential or paid inference is used. The run is capped at two HellaSwag
validation examples on CPU using `sshleifer/tiny-gpt2`; it is not a model-quality result.

## Interpretation boundary

A schema-valid EEE record or AIREP payload establishes only conformance to its pinned schema and
validator behavior. This experiment does **not** establish result truth, model identity at runtime,
population completeness, evaluator independence, safety, reproducibility, EvalEval endorsement or
EEE–AIREP interoperability.

Canonical local references: [AIREP profile](../../spec/airep/v0.2/profiles/embedded-evaluation/README.md),
[AIREP LightEval exporter](../lighteval/README.md).
