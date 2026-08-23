#!/usr/bin/env bash
# Clean-checkout reproduction: builder(x2) -> both engines(x2) -> comparator -> negative proofs.
# Prerequisites: python3 with requirements.lock packages; node with `npm ci` run in this dir.
set -euo pipefail
cd "$(dirname "$0")"
python3 build_schema_corpus.py; M1=$(sha256sum schema_corpus_manifest.json | cut -d' ' -f1)
python3 build_schema_corpus.py; M2=$(sha256sum schema_corpus_manifest.json | cut -d' ' -f1)
[ "$M1" = "$M2" ] || { echo "FAIL: builder nondeterministic"; exit 1; }
python3 run_python.py; P1=$(sha256sum results/results_python_schema.json | cut -d' ' -f1)
python3 run_python.py; P2=$(sha256sum results/results_python_schema.json | cut -d' ' -f1)
[ "$P1" = "$P2" ] || { echo "FAIL: python runner nondeterministic"; exit 1; }
node run_node.mjs; N1=$(sha256sum results/results_node_schema.json | cut -d' ' -f1)
node run_node.mjs; N2=$(sha256sum results/results_node_schema.json | cut -d' ' -f1)
[ "$N1" = "$N2" ] || { echo "FAIL: node runner nondeterministic"; exit 1; }
python3 compare_schema_results.py
python3 prove_schema_gates.py
echo "== REPRODUCTION OK =="
echo "corpus manifest sha256: $M1"; echo "results_python sha256: $P1"; echo "results_node sha256: $N1"
python3 -c "from importlib.metadata import version; import platform; print('python', platform.python_version(), '| jsonschema', version('jsonschema'), '| referencing', version('referencing'))"
node -e "console.log('node', process.version, '| ajv', require('ajv/package.json').version)"
