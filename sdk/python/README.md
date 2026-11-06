# AIREP Python SDK — local experimental candidate

This package wraps the existing AIREP 0.2.0-beta.1 producer, verifier and
reconciler and adds a bounded hook for a caller-owned synchronous LangGraph.
It is a separate SDK version (0.1.0a1), not a new normative AIREP version.
It is not published to PyPI and does not establish external adoption.
The measured installation target is Linux x86-64 with CPython 3.12; broader
platform/version compatibility has not been established.

The source build copies an explicit closure of native Python, JCS, schema and
specification resources. SOURCE_MANIFEST.json records every source path/hash
and the source commit. The package loader verifies those bytes before loading
the preserved verifier. No checkout, Git, Node, editable install or top-level
`tools` package is required by the installed Python wheel.

## Three ways to use the candidate

1. Reproduce: build the wheel, install in a fresh environment, copy
   `examples/user_graph.py` outside the checkout and run paused/ignored/unobserved.
2. Connect your application: supply your own compiled graph with one wrapped
   synchronous state-only node, a fresh thread, explicit producer/key and optional
   FileObserver. The hook reads real checkpoint and interrupt results.
3. Write a producer/consumer: use `airep.Chain`, `evaluate_request`, `reconcile`
   and the versioned CONSUMER_CONTRACT.json. Consumer trust is supplied separately
   from evidence. Reference strings are opaque and never fetched.

Build from a committed checkout (Python build tooling installed):

```sh
python3 scripts/build_sdk.py --out /tmp/airep-sdk-build-new
python3 -m venv /tmp/airep-sdk-env-new
/tmp/airep-sdk-env-new/bin/pip install --require-hashes --only-binary=:all: -r integrations/langgraph/requirements.lock
/tmp/airep-sdk-env-new/bin/pip install --no-deps /tmp/airep-sdk-build-new/dist/airep_sdk-0.1.0a1-py3-none-any.whl
mkdir /tmp/airep-sdk-user-new
cp sdk/python/examples/user_graph.py /tmp/airep-sdk-user-new/
cd /tmp/airep-sdk-user-new
/tmp/airep-sdk-env-new/bin/python -I user_graph.py --out paused --mode paused
/tmp/airep-sdk-env-new/bin/airep consume --input paused/bundle.json --trust paused/trust.json --query paused/query.json --require-policy-match
```

Repeat with fresh output directories and `--mode ignored` or `--mode unobserved`.
The example generates a fresh **test-only ephemeral key**, keeps it in memory,
and exports only public self-selected test trust. The library creates no default
key or default trust. Same-host control, execution and observation are not
independent. File contents and application state are not exported by the hook;
the explicitly selected file's sizes/digests are captured.

The node is paused cooperatively before its body executes. Ignored mode is an
explicit negative control that runs the user node and reports continued execution.
The hook accepts a fresh checkpoint thread and a single attempt. Resume, durable
restart, concurrent branches, asynchronous nodes and remote transports are outside
this candidate. Application code runs in-process; the hook cannot forcibly stop
a blocking node. The CLI's verifier subprocess has its own enforced time limit.
Control dispatch/receipt is an in-process handoff to the wrapped node; it is not
a network transport measurement. Nodes preceding that boundary may already have
run. Ticks are monotonic elapsed nanoseconds within this invocation; comparison
across runs or hosts is not supported. The native Python `ProfileBases` API remains
available for explicitly supplied, digest-pinned profile registries; absent profile
bases retain NOT_EVALUATED and are not silently fetched.
The [LangGraph interrupt documentation](https://docs.langchain.com/oss/python/langgraph/interrupts)
describes cooperative interrupts; [persistence documentation](https://docs.langchain.com/oss/python/langgraph/persistence)
distinguishes in-memory checkpoints from durable storage. This candidate is tested
against pinned LangGraph 1.2.19 rather than assuming all later APIs are compatible.

## Consumer and process boundaries

`airep verify --input request.json --trust trust.json` evaluates a native request
envelope. `airep reconcile --input artifacts.json --trust trust.json` returns native
reconciliation unchanged. `airep consume` additionally checks exact hook-source
projection, producer/identity binding and a separately supplied identity query.

CLI exit **0 means evaluation completed**, including NO_MATCH or native FAILURE.
For `consume`, explicitly add `--require-policy-match` to return 3 on NO_MATCH.
Input rejection returns 1; timeout returns 124 and emits no result. Native
INCOMPLETE/NOT_EVALUATED coverage remains visible even if the narrow local policy
matches. The policy only asks for a matching receipt, reported cooperative pause
and equal bounded file samples; it does not mean production safety or permanent stop.

The CLI caps JSON at 1 MiB, depth at 32, nodes at 20,000, artifacts at 128 and
evaluation at 30 seconds maximum (15 default). Explicit file inputs and outputs
reject symlinks, non-regular files and overwrites. The FileObserver reads at most
64 KiB. Duplicate keys and out-of-range raw Core sequence tokens are rejected
before normalization. The low-level native Python API remains available; callers
using it directly own their resource/process limits.

The existing captured temporal replay harness remains a separate repository
experiment. This SDK hook uses native lifecycle artifacts and its own explicitly
versioned source mapping/consumer policy; it does not relabel the frozen temporal
Decision mapping reports or add results to the historical DOI.

Code is Apache-2.0; specification text and schemas are CC-BY-4.0. Both license
texts and per-file provenance travel in the wheel and source distribution.
