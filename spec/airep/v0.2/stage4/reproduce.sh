#!/usr/bin/env bash
# WP-a01 Stage-4 deterministic reproduction from a clean checkout:
#   corpus builder (x2, determinism) -> both integrity verifiers (x2 each, determinism)
#   -> parity/evidence comparator -> A5 auxiliary v0.1-acceptance check.
# Exit nonzero on any failure. No network, no clock dependence (fixture-supplied `now`).
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1. corpus build (twice; determinism) =="
python3 build_corpus.py
M1=$(sha256sum corpus_manifest.json | cut -d' ' -f1)
python3 build_corpus.py
M2=$(sha256sum corpus_manifest.json | cut -d' ' -f1)
[ "$M1" = "$M2" ] || { echo "FAIL: builder nondeterministic"; exit 1; }

echo "== 2. integrity verifiers (twice each; determinism) =="
python3 verifier_py/integrity_verifier.py
P1=$(sha256sum results/results_python.json | cut -d' ' -f1)
python3 verifier_py/integrity_verifier.py
P2=$(sha256sum results/results_python.json | cut -d' ' -f1)
[ "$P1" = "$P2" ] || { echo "FAIL: python verifier nondeterministic"; exit 1; }
node verifier_node/integrity_verifier.mjs
N1=$(sha256sum results/results_node.json | cut -d' ' -f1)
node verifier_node/integrity_verifier.mjs
N2=$(sha256sum results/results_node.json | cut -d' ' -f1)
[ "$N1" = "$N2" ] || { echo "FAIL: node verifier nondeterministic"; exit 1; }

echo "== 3. parity/evidence comparator =="
python3 parity_compare.py

echo "== 4. A5 auxiliary: the genuine v0.1 record VALUE embedded in A5-1 must still be accepted by the v0.1 verifier (freeze intact) =="
EX=".a5_extracted.json"
python3 -c "import json; json.dump(json.load(open('corpus/A5-1.json'))['inputs']['artifact'], open('$EX','w'), indent=1)"
python3 ../../v0.1/conformance/verify.py "$EX" > /dev/null
rm -f "$EX"

echo "== REPRODUCTION OK =="
echo "corpus_manifest sha256: $M1"
echo "results_python  sha256: $P1"
echo "results_node    sha256: $N1"
