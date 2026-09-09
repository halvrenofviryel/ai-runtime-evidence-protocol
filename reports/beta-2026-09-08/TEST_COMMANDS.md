# Exact final commands and results

Run from the canonical repository with:

```bash
python3 scripts/check_beta.py --with-v01-typescript --out reports/beta-2026-09-08/release-validation
```

The runner uses a disposable repository copy. Each working directory below is relative to that copy. The log contains complete stdout/stderr; no failed run was overwritten. `source-basis.json` records the tested implementation bytes.

| # | cwd | Exact argv (shell quoted) | Exit | Full output |
|---|---|---|---|---|
| 1 | `.` | `python3 -VV` | 0 | [01.log](release-validation/01.log) |
| 2 | `.` | `node --version` | 0 | [02.log](release-validation/02.log) |
| 3 | `spec/airep/v0.2/class-verification` | `python3 offline-node-deps/materialize_node_modules.py` | 0 | [03.log](release-validation/03.log) |
| 4 | `spec/airep/v0.2/class-verification` | `python3 offline-python-deps/prepare_offline_venv.py` | 0 | [04.log](release-validation/04.log) |
| 5 | `spec/airep/v0.2/class-verification` | `python3 preflight_offline_basis.py` | 0 | [05.log](release-validation/05.log) |
| 6 | `spec/airep/v0.2/vectors` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python generator_py/generate_vectors.py` | 0 | [06.log](release-validation/06.log) |
| 7 | `spec/airep/v0.2/vectors` | `node generator_node/generate_vectors.mjs` | 0 | [07.log](release-validation/07.log) |
| 8 | `spec/airep/v0.2/vectors` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python compare_vectors.py` | 0 | [08.log](release-validation/08.log) |
| 9 | `spec/airep/v0.2/vectors` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python prove_extra_field_gate.py` | 0 | [09.log](release-validation/09.log) |
| 10 | `spec/airep/v0.2/stage4` | `bash reproduce.sh` | 0 | [10.log](release-validation/10.log) |
| 11 | `spec/airep/v0.2/stage4` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python prove_envelope_gate.py` | 0 | [11.log](release-validation/11.log) |
| 12 | `spec/airep/v0.2` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python prove_signature_input_pinning.py` | 0 | [12.log](release-validation/12.log) |
| 13 | `spec/airep/v0.2` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python prove_jcs_exponent_artifact_path.py` | 0 | [13.log](release-validation/13.log) |
| 14 | `spec/airep/v0.2/schema-validation` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python run_python.py` | 0 | [14.log](release-validation/14.log) |
| 15 | `spec/airep/v0.2/schema-validation` | `ln -s ../class-verification/verifier_node_r2/node_modules node_modules` | 0 | [15.log](release-validation/15.log) |
| 16 | `spec/airep/v0.2/schema-validation` | `node run_node.mjs` | 0 | [16.log](release-validation/16.log) |
| 17 | `spec/airep/v0.2/schema-validation` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python compare_schema_results.py` | 0 | [17.log](release-validation/17.log) |
| 18 | `spec/airep/v0.2/schema-validation` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python prove_schema_gates.py` | 0 | [18.log](release-validation/18.log) |
| 19 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node class_verifier.mjs --corpus ../corpus --out out_run1.json` | 0 | [19.log](release-validation/19.log) |
| 20 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `cp out_run1.json out_run2.json` | 0 | [20.log](release-validation/20.log) |
| 21 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node selfcheck.mjs` | 0 | [21.log](release-validation/21.log) |
| 22 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node corpus_compare.mjs` | 0 | [22.log](release-validation/22.log) |
| 23 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node rulings_check.mjs` | 0 | [23.log](release-validation/23.log) |
| 24 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node errata_check.mjs` | 0 | [24.log](release-validation/24.log) |
| 25 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node exitcode_check.mjs` | 0 | [25.log](release-validation/25.log) |
| 26 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node exitcode_check_selftest.mjs` | 0 | [26.log](release-validation/26.log) |
| 27 | `spec/airep/v0.2/class-verification/verifier_node_r2` | `node preimage_check.mjs` | 0 | [27.log](release-validation/27.log) |
| 28 | `spec/airep/v0.2/class-verification/verifier_py` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python selfcheck_errata.py` | 0 | [28.log](release-validation/28.log) |
| 29 | `spec/airep/v0.2/class-verification/verifier_py` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python selfcheck_s9_round2.py` | 0 | [29.log](release-validation/29.log) |
| 30 | `spec/airep/v0.2/class-verification/verifier_py` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python selfcheck_s9_round3.py` | 0 | [30.log](release-validation/30.log) |
| 31 | `spec/airep/v0.2/class-verification/verifier_py` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python selfcheck_s9_round4.py` | 0 | [31.log](release-validation/31.log) |
| 32 | `spec/airep/v0.2/class-verification` | `python3 comparator/compare.py --root . --out-dir /tmp/airep-beta-check-bj6ma7_l/comparison-work --result /mnt/data/claude/airep-v02-beta-prep/reports/beta-2026-09-08/release-validation/parity.json --summary /mnt/data/claude/airep-v02-beta-prep/reports/beta-2026-09-08/release-validation/parity.txt` | 0 | [32.log](release-validation/32.log) |
| 33 | `spec/airep/v0.2/class-verification/comparator` | `python3 negative_proofs/run_all.py` | 0 | [33.log](release-validation/33.log) |
| 34 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python conformance/validate.py` | 0 | [34.log](release-validation/34.log) |
| 35 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python conformance/enas_profiles.py` | 0 | [35.log](release-validation/35.log) |
| 36 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python conformance/enas_obligation_reconciler.py` | 0 | [36.log](release-validation/36.log) |
| 37 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python conformance/test_jcs.py` | 0 | [37.log](release-validation/37.log) |
| 38 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python conformance/test_verifier_parity.py` | 0 | [38.log](release-validation/38.log) |
| 39 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python conformance/test_trusted_gates.py` | 0 | [39.log](release-validation/39.log) |
| 40 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python conformance/test_strict_trusted.py` | 0 | [40.log](release-validation/40.log) |
| 41 | `spec/airep/v0.1` | `python3 -m pytest conformance -q` | 0 | [41.log](release-validation/41.log) |
| 42 | `spec/airep/v0.1` | `node conformance/verify.mjs examples/chain.jsonl --pubkey examples/test_public_key.txt` | 0 | [42.log](release-validation/42.log) |
| 43 | `spec/airep/v0.1` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python examples/regenerate.py` | 0 | [43.log](release-validation/43.log) |
| 44 | `.` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python scripts/check_beta_docs.py` | 0 | [44.log](release-validation/44.log) |
| 45 | `producers/typescript` | `npm install --ignore-scripts --no-audit --no-fund` | 0 | [45.log](release-validation/45.log) |
| 46 | `producers/typescript` | `npm run build` | 0 | [46.log](release-validation/46.log) |
| 47 | `.` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python scripts/check_v01_typescript.py` | 0 | [47.log](release-validation/47.log) |
| 48 | `.` | `python3 tools/interop_pkg/test_crypto_projection.py` | 0 | [48.log](release-validation/48.log) |
| 49 | `.` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python spec/airep/v0.2/interop/interop_eval_py/test_interop_eval.py` | 0 | [49.log](release-validation/49.log) |
| 50 | `spec/airep/v0.2/interop/interop_eval_node` | `node selftest.mjs` | 0 | [50.log](release-validation/50.log) |
| 51 | `.` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python -m unittest discover -s tests/v02 -v` | 0 | [51.log](release-validation/51.log) |
| 52 | `.` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python examples/v02/run_lifecycle.py --out /mnt/data/claude/airep-v02-beta-prep/reports/beta-2026-09-08/release-validation/lifecycle` | 0 | [52.log](release-validation/52.log) |
| 53 | `.` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python scripts/check_quickstart.py` | 0 | [53.log](release-validation/53.log) |
| 54 | `.` | `/tmp/airep-beta-check-bj6ma7_l/repo/spec/airep/v0.2/class-verification/offline-python-deps/.venv/bin/python scripts/check_beta_docs.py` | 0 | [54.log](release-validation/54.log) |

**54/54 commands returned exit 0.** Process success is not substituted for individual semantic outcomes: negative controls intentionally assert FAILURE, WITHHELD, MISSING and NOT_EVALUATED.

W1: Python ran 423 tests, with one explicitly unmeasurable platform-specific directory-name branch skipped; all 20 mandatory blocks measured. Node reported 2,329 assertions passed / 0 failed / 0 skipped, with its opposite platform-specific branch explicitly NOT MEASURED. These branch qualifications are retained, not reported as passes.
