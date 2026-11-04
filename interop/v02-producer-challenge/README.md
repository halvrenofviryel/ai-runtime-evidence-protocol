# AIREP v0.2 external producer challenge

This kit lowers the mechanical cost of testing an independently authored
producer against the exact `v0.2.0-beta.1` first-party consumer. It does not
provide a producer scaffold: copying maintainer producer code would not create
independent implementation evidence.

The runner is pinned to beta commit
`8a6c01ecce457aa94330c0ed7219e4c56ebfe771`. It exports that commit into a
temporary directory, verifies the submitted lifecycle with the release code,
reconciles it, and writes hashes plus command results. It does not use the
current branch's verifier for the measurement.

## Three useful contribution tracks

1. **Reproduce the supplied author packet.** Run the public
   [control-evidence study](https://github.com/halvrenofviryel/phionyx-research/blob/54682cfd312dc8c7935e926539811cfc29ea6568/docs/CONTROL_EVIDENCE_RESEARCH.md).
   This tests reproducibility of supplied code; it is not a separately authored
   implementation.
2. **Write a producer.** Implement the four artifact families from the beta
   specification, create the five files in [PRODUCER_CONTRACT.md](PRODUCER_CONTRACT.md),
   and run this kit. A compatible lifecycle, a reproducible rejection, or a
   specification ambiguity are all useful results.
3. **Write a consumer/verifier.** Evaluate the same frozen beta without importing
   the reference verifier. Record your own expected/observed verdicts. This is a
   different role and should remain separately attributed.

## Run a producer submission

Use CPython 3.12 in a full Git clone containing the beta tag. Install the beta's
recorded `cryptography` and `jsonschema` dependencies, then:

```sh
python3 interop/v02-producer-challenge/run_challenge.py \
  --submission /path/to/submission \
  --results /tmp/airep-v02-producer-result
```

The runner never executes code from the submission. It admits only five named
JSON files, refuses symlinks and oversized inputs, and invokes commands without
a shell. `RUN_RECORD.json` identifies the exact verifier source, input hashes,
exit status, and evidence limits.

## Interpret the result

- Exit `0` means the release-pinned verification and reconciliation commands
  completed. Inspect their JSON states; exit zero does not turn `FAILURE`,
  `MISSING`, `NOT_EVALUATED`, or `INDETERMINATE` into success.
- Exit `1` means the pinned verifier or reconciler rejected or could not evaluate
  the submission. The retained stdout/stderr is still useful evidence.
- Exit `2` means the local package or command invocation did not satisfy this
  runner's input contract.

The run record cannot prove who authored the producer, organizational
independence, deployment use, event truth, complete history, or general
interoperability. Review authorship and independence separately before adding a
result to `EXTERNAL_EVIDENCE.md`; publish identity only with permission.
