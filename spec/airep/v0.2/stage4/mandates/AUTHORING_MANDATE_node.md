# Authoring mandate — Stage-4 Node integrity verifier (process record)

> Recorded verbatim from the authoring instruction given to the isolated agent that wrote
> `verifier_node/integrity_verifier.mjs`. This is a process-constraint record for the
> code-independence gate; it is evidence of the mandate given, and makes no stronger claim
> (see STAGE4_CONTRACT §6 bounded-independence rule).

**Terminology rule:** the program is an *AIREP v0.2 WP-α01 integrity verifier* /
integrity-construction verifier — never a "full v0.2 verifier".

**Allowed reads (ONLY these):**

- `spec/airep/v0.2/INTEGRITY.md` (frozen normative construction — single source of truth)
- `spec/airep/v0.2/stage4/README.md`, `STAGE4_CONTRACT.md`, `REASON_CODES.md`, `FIXTURES.md`
- `spec/airep/v0.2/stage4/corpus/*.json` and `spec/airep/v0.2/stage4/corpus_manifest.json`
- `spec/airep/v0.2/vectors/INPUTS.json`, `VECTOR_PLAN.md`, committed vector outputs
  (`vectors/out/*.json`) and `AGREEMENT_MANIFEST.md`
- `spec/airep/v0.1/conformance/verify.mjs` — ONLY its RFC 8785 / JCS canonicalization logic
  may be reused; everything else in it is out of scope

**Strictly forbidden (do not read, glob, grep, or open):**

- `spec/airep/v0.2/stage4/build_corpus.py` — copying the construction from the corpus harness
  defeats independence
- `spec/airep/v0.2/vectors/generator_py/`, `spec/airep/v0.2/vectors/generator_node/`
- `spec/airep/v0.2/vectors/compare_vectors.py`, `spec/airep/v0.2/vectors/prove_extra_field_gate.py`
- the Python Stage-4 verifier (`spec/airep/v0.2/stage4/verifier_py/`) or its output/results
- **any fixture's `expected` member** — evaluation is from `inputs` only, as if `expected`
  did not exist; the author attests non-consultation in its report

**Behavioral obligations:** normalized result contract per STAGE4_CONTRACT §1 (single
first-decisive `REJECT` reason per §2a precedence; `PASS` = exactly `["OK"]`;
`PASS_WITH_CAVEAT` + `WIRE_ALG_IGNORED` for valid-signature wire-label substitution); suites
only from fixture-supplied verifier-accepted bindings; freshness only from the signed
`witnessed_at` vs fixture `now`/window with full §4.2 Gregorian validation (no reliance on
lenient `Date` parsing); head-derived witness tag version; head reconciliation; no
fallback/search anywhere; deterministic recursively-sorted results file with no metadata;
exit 0 iff every fixture received a result; two runs byte-identical.
