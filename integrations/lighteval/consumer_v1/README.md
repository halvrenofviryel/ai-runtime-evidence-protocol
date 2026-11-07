# LightEval claim consumer 0.1.0

Experimental companion to the unchanged Embedded Evaluation Profile 0.1 exporter. This route retains a selected source scalar, configuration identity and declared qualifications, then applies an optional **receiver post-hoc scalar criterion** separately. It creates no AIREP Decision/Control/Execution/Effect artifacts or assurance class.

One committed September run is reused: LightEval `6b9d193b48de24d1ee87f3089303643b993cf4f9` (`0.13.1.dev0`), `sshleifer/tiny-gpt2` at `5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be`, HellaSwag validation at `218ec52e09a7e7462a5400043bb9a69a41d06b76`. The original results bytes and two-row Parquet are unchanged. **No new model inference is performed.** The native file reports `em = 0.0`; it contains neither an evaluator criterion nor verdict. It does not establish population coverage, executed weight identity or evaluator independence. The run ID and wall-clock times come from the original author's context, not a native globally unique identifier or filename timezone inference.

Source references: [committed native evidence](../../evaleval/experiment/native/native-manifest.json), [original context](../../evaleval/experiment/context/airep-context.json), and [pinned upstream tracker](https://github.com/huggingface/lighteval/blob/6b9d193b48de24d1ee87f3089303643b993cf4f9/src/lighteval/logging/evaluation_tracker.py). The upstream results property enumerates the supported native root fields; `save` uses a local, timezone-naive filename date ID.

## Reproduce

Tested with Linux x86_64, CPython 3.12.3. The wheel hashes in the separate lock cover this platform. PyArrow 25.0.0 reads the saved Parquet metadata; it is a replay dependency, not the historical run's recorded PyArrow 25.0.1 environment. No framework/model weights, account token or paid API is needed.

```sh
python3 -m venv /tmp/lighteval-consumer-env
/tmp/lighteval-consumer-env/bin/python -m pip install --require-hashes -r integrations/lighteval/consumer_v1/requirements.lock
/tmp/lighteval-consumer-env/bin/python -m unittest discover -s integrations/lighteval/consumer_v1/tests -v
/tmp/lighteval-consumer-env/bin/python -m unittest discover -s integrations/lighteval/tests -v
/tmp/lighteval-consumer-env/bin/python -m unittest discover -s integrations/evaleval/tests -v
/tmp/lighteval-consumer-env/bin/python -m integrations.lighteval.consumer_v1.experiment generate --out /tmp/lighteval-consumer-cases
/tmp/lighteval-consumer-env/bin/python -m integrations.lighteval.consumer_v1.experiment replay --out /tmp/lighteval-consumer-cases
```

The generation directory must not exist. Replay checks exact report bytes for 14 cases. Only `historical`/`profile-only` reuse the real source; NOT_RUN, 80/100, retry, rounding, amendment and stale cases are authored transformations. Wrong-selection and missing-input cases are receiver-side negative controls on the historical package. Fourteen cases are not fourteen runtime experiments. The current old suites have **19 exporter and 29 EEE tests**, correcting the November plan's shorthand of “19/30”.

Serve the generated directory locally and open `index.html`. Source criterion/verdict, declared execution/coverage/attempt history, receiver criterion and typed checks remain separate. `PRESERVED` is a preservation result, not model acceptance. A scalar can satisfy `>= 0.8` while coverage stays PARTIAL 80/100. Rounded `0.80` from exact `0.79996` does not satisfy it.

Single-package replay:

```sh
/tmp/lighteval-consumer-env/bin/python -m integrations.lighteval.consumer_v1.consumer \
  --inputs /tmp/lighteval-consumer-cases/historical/inputs \
  --package /tmp/lighteval-consumer-cases/historical/package.json \
  --query /tmp/lighteval-consumer-cases/historical/query.json \
  --out /tmp/lighteval-consumer-replayed.json
```

Exit 0 means the mapping is PRESERVED or explicitly QUALIFIED_LOSS; it never means a benchmark/model passed. Inspect the JSON status. Other decisions exit 2. Python API: `produce(inputs, accepted_basis)`, `consume(package_bytes, inputs, receiver_query_bytes, accepted_basis)`.

## Receiver contract and loss

The receiver supplies an independently chosen selection (model/revision, dataset/revision/splits, task, metric, declared run, current record) and exact input digests. **Do not regenerate receiver expectations from an untrusted package in production.** `query_for` is a demonstration helper; using it on producer-controlled inputs provides no independent acceptance policy.

The package pins `CONTRACT.json`, this mapping implementation, exporter, profile schema and registry. The consumer uses its installed accepted basis and reprojects supplied bytes. A producer cannot update the receiver's pinned inputs. Schema validity, byte binding and mapping equality are separate checks. None is authentication or source truth. Producer and consumer share projection code; this is same-author checking, not independent implementation interoperability.

Native raw bytes are retained. The sidecar carries the complete author context, exact selected numeric token, declared coverage/exclusions, declared attempts and one linked prior record. Existing exporter/profile bytes are unchanged. The narrower profile-only route explicitly reports **QUALIFIED_LOSS**, not lossless preservation. This result is conservative even where a particular optional qualification is absent.

Conditions and attempt errors are author declarations; the synthetic first-error case does not establish a real failed LightEval run. Missing attempt history stays null/NOT_REPORTED. The historical sample count is additionally checked against Parquet rows; its expected population remains unknown. Amendment support preserves a supplied prior-record byte sequence and its explicit link; it does not verify global latestness, an amendment graph, signature authority or real-world chronology. A receiver asking for v2 cannot obtain a current decision from v1.

Only the pinned source format and one selected numeric metric/attempt result are supported. Unknown native root fields are rejected rather than discarding a newly introduced verdict. Unknown context qualifications remain in the full sidecar. A source predeclared threshold is not supported by this first contract because there is no accepted chronology evidence; a receiver threshold is always labeled POST_HOC. The source criterion/verdict therefore remain NOT_REPORTED. Future predeclared-criterion support needs a separate accepted basis, not a relabelled post-hoc result.

## Review and outside trial

The dedicated LightEval workflow runs the three suites plus generation/replay. Until pushed and actually run, this is a locally tested CI candidate. The existing beta workflow alone does not establish this route's coverage.

For an outside trial, keep the commit and lock fixed, select expected input identity/digests yourself, run the positive and wrong-selection cases, and return the environment, command, exit status, full report and hashes. Report separately whether you only replayed the author's package, supplied your own native result, or implemented your own consumer. Retain failures and qualifications. Never send model credentials or private input data with a trial report. Publication, runtime integration, independent production and independent consumption are separate milestones.

This supplies bounded examples for CP-01 R-CP-1/2/3/4/5/6/8/9/10/11/12. It is not complete CP conformance. No normative draft revision, SDK release or DOI change follows from these local checks.
