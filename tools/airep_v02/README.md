# AIREP v0.2 beta tools

First-party Python producer/library/CLI and lifecycle reconciler, plus Python
and Node verifier adapters. Version `0.2.0-beta.1`; artifact wire version `0.2`.

Read [SPEC.md](../../spec/airep/v0.2/SPEC.md), then the
[quickstart](../../spec/airep/v0.2/QUICKSTART.md). Run from the repository root:

```bash
python3 -m tools.airep_v02 --help
python3 -m unittest discover -s tests/v02 -v
```

| Module | Responsibility |
|---|---|
| `producer.py` | Four-family `Chain` API, explicit byte/JSON digests, Ed25519 signing, cursor continuation |
| `json_input.py` | AD-17 duplicate/Unicode/number admission before canonicalization |
| `basis.py` | Repository-relative loading of the preserved class verifier and JCS code |
| `verify.py` / `verify_node.mjs` | Beta input/profile adapters and corrected observer prerequisites |
| `profiles.py` | Exact registry/basis identities, self-contained schema evaluation |
| `reconcile.py` | Named lifecycle facts and missing/contradictory/unevaluated states |
| `__main__.py` | Key generation, four emit commands, digest, verify and reconcile CLI |

Dependencies are the existing `cryptography`, `jsonschema` and Node/Ajv bundles.
The producer does not depend on Node. Node is required to run the complete parity
suite, and is never silently skipped. These beta adapters were written together;
they do not claim independent authorship. Historical r1 engines and measurements
remain untouched; revised results are new beta regression evidence.

The cursor is single-writer and in-memory. Persist artifacts and resume with
`previous=…`/`--previous`. It is not a concurrent writer coordinator, production
key manager or authenticated remote checkpoint. Caller-supplied evidence must
describe actual observations; valid signatures do not make reports true.
