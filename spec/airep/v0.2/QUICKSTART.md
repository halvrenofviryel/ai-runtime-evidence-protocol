# A runnable v0.2 lifecycle in about ten minutes

Start with [SPEC.md](SPEC.md). Commands below run from a fresh repository root.
Python 3.12 and Node 20 are the reproduced axis (3.12.3 / 20.19.6). There are
no private packages, services, credentials or monorepo dependencies.

## 1. Install and run

```bash
git clone https://github.com/halvrenofviryel/ai-runtime-evidence-protocol.git
cd ai-runtime-evidence-protocol
# After publication: git checkout v0.2.0-beta.1
python3 -m venv .venv
.venv/bin/python -m pip install jsonschema==4.25.1 cryptography==48.0.0
python3 spec/airep/v0.2/class-verification/offline-node-deps/materialize_node_modules.py
.venv/bin/python examples/v02/run_lifecycle.py --out demo-output
```

For Linux x86-64 / CPython 3.12, the existing verified wheel bundle also supports
index-free setup. In place of the `venv` and `pip install` lines above, run:

```bash
python3 spec/airep/v0.2/class-verification/offline-python-deps/prepare_offline_venv.py --venv .venv
```

Use a fresh venv path: that historical helper replaces its target directory.
Runtime and Git installation are outside the offline dependency claim.

The example performs a local state change and writes five signed artifacts,
three test keys, operator policies, verification requests, reconciliation and
ten negative/qualification variants. It refuses to overwrite an existing output
directory. All included seeds are **public test keys**.

## 2. Generate or load a key; emit each family

To generate a new test key instead of loading the demonstration keys:

```bash
.venv/bin/python -m tools.airep_v02 keygen --out my-test-key.json
```

It prints the public key and writes a mode-0600 private seed file. A verifier
must independently accept a binding for that key; key generation alone grants
no class. The commands below **load** the demo keys and payloads, using fixed
IDs solely so the supplied example references resolve:

```bash
.venv/bin/python -m tools.airep_v02 emit-decision \
  --key demo-output/keys/governor.json --producer demo.governor \
  --chain-id demo.governance-chain --record-id demo.decision \
  --payload demo-output/payloads/decision.json --out decision.json

.venv/bin/python -m tools.airep_v02 emit-control \
  --key demo-output/keys/governor.json --producer demo.governor \
  --previous decision.json --record-id demo.dispatch \
  --payload demo-output/payloads/dispatch.json --out dispatch.json

.venv/bin/python -m tools.airep_v02 emit-control \
  --key demo-output/keys/executor.json --producer demo.executor \
  --chain-id demo.execution-chain --record-id demo.receipt \
  --payload demo-output/payloads/receipt.json --out receipt.json

.venv/bin/python -m tools.airep_v02 emit-execution \
  --key demo-output/keys/executor.json --producer demo.executor \
  --previous receipt.json --record-id demo.execution \
  --payload demo-output/payloads/execution.json --out execution.json

.venv/bin/python -m tools.airep_v02 emit-effect \
  --key demo-output/keys/observer.json --producer demo.observer \
  --chain-id demo.observation-chain --record-id demo.effect \
  --payload demo-output/payloads/effect.json --out effect.json

.venv/bin/python -c 'import json; from pathlib import Path; names=("decision","dispatch","receipt","execution","effect"); Path("lifecycle.json").write_text(json.dumps([json.loads(Path(n+".json").read_text()) for n in names]))'
```

For new application records, supply your actual family payload and captured
digests. Omit `--record-id`/`--chain-id` to generate UUIDs; take explicit references
from the emitted artifacts. `--previous` resumes the chain cursor. JSON payloads
cannot override producer-managed core fields. `--timestamp` supports fixed
fixture clocks; its default is current UTC.

Minimal library API (repository root on the Python import path):

```python
from tools.airep_v02 import Chain, digest_bytes, digest_json, reference
from tools.airep_v02.__main__ import load_key

chain = Chain(load_key("my-test-key.json"), "my.runtime")
# Supply the required family payload described in SPEC.md and the schemas.
decision = chain.emit_decision(payload)
decision_ref = reference(decision)
```

`emit_control`, `emit_execution`, `emit_effect` and `emit(family, payload)` use
the same API. `digest_bytes` hashes exact bytes; `digest_json` explicitly chooses
JCS JSON bytes. The producer never invents an observation to fill a lifecycle gap.

## 3. Verify and reconcile

```bash
.venv/bin/python -m tools.airep_v02 verify --input lifecycle.json \
  --bindings demo-output/bindings.json --revocation demo-output/revocation.json \
  --independence-policy demo-output/independence.json --out verified.json

.venv/bin/python -m tools.airep_v02 reconcile --input lifecycle.json \
  --bindings demo-output/bindings.json --revocation demo-output/revocation.json \
  --independence-policy demo-output/independence.json --out reconciled.json

node tools/airep_v02/verify_node.mjs \
  --request demo-output/requests/demo.effect.json \
  --bindings demo-output/bindings.json --revocation demo-output/revocation.json \
  --independence-policy demo-output/independence.json
```

The generated lifecycle has five `AIREP-Authenticated` records. No witness is
supplied, so Witnessed is explicitly withheld. Dispatch, receipt, instruction
binding, TOCTOU equality and Effect binding are SATISFIED **as reported evidence**.
The global summary is INCOMPLETE because intended-target coverage is
NOT_EVALUATED; the demo does not smuggle completeness into a success flag.

The last command independently exercises the existing Node class engine through
the beta admission/profile adapter. [VERIFICATION.md](VERIFICATION.md) describes
the request envelope, operator trust inputs, profile basis and exit semantics.

## 4. Observe a negative case

```bash
.venv/bin/python -m tools.airep_v02 reconcile \
  --input demo-output/variants/no-receipt.json \
  --bindings demo-output/bindings.json --revocation demo-output/revocation.json
```

`issuer_dispatch` is SATISFIED; `receiver_receipt` and `execution_evidence` are
MISSING; `toctou` is NOT_EVALUATED. This does not prove non-delivery. Try
`toctou-mismatch.json` for an explicit digest FAILURE or omit
`--independence-policy` on the complete lifecycle for an unproven independence
declaration. `same-executor.json` retains observation without claiming independent
corroboration. See the [variant catalogue](../../../examples/v02/README.md).

Exit zero means evaluation completed, including negative/withheld results.
Inspect the JSON states. Public test keys and an example policy cannot prove
external independence, real authority, report truth, full history, or deployment
interoperability. All roles in this example are first-party local code.
