# Next steps — two separate outputs

This is a Phionyx first-party planning note. Neither step below has been run.

The upstream repository and its `conformance/sep2828` corpus are public. Running them requires no
prior approval, and nothing in this note claims any. The two outputs are **separate** and are
reported separately: reproducing the upstream project's own conformance surface says nothing about
AIREP, and the AIREP mapping measurement says nothing about upstream conformance.

## A. Vaara native conformance reproduction

Run the upstream project's own checkers over the upstream project's own vectors, at the pinned
commit, and report the result publicly.

- Pin: `vaaraio/vaara` @ `d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317`, corpus `conformance/sep2828`
  version `1.0.0`.
- Suites in scope: `record_conformance_v0` and `record_set_v0`.
- The corpus ships a self-contained runner (`conformance/sep2828/run.py`) that imports no upstream
  library code; the repository also carries an aggregate runner (`scripts/conformance_runner.py`)
  that discovers suites under `tests/vectors/`. Record which one was used, with its exact flags.
- Record the exact commands, interpreter, dependency versions, full stdout/stderr and exit status.
  Preserve first-run output; a correction is a new run identity, never a rewrite.

### What this row is, on the upstream public desk

The upstream project's public conformance desk requires every row to name its **kind**. Running the
author's checkers over the author's vectors is, in the desk's own vocabulary:

> Reproduction: the author's checkers over the author's vectors

This is **not** an independent implementation, and must never be described as one. The desk lists
three stronger, categorically different kinds — a construction reproduction, an independent
implementation from the text run against the author's vectors, and an independent implementation
run against independently constructed vectors. They are not degrees of the same thing. A
reproduction establishes that the artefact runs and is byte-stable somewhere other than the
author's machine, and nothing about the specification text.

Filing a row also requires a **public, linkable report**. Private mail and screenshots do not
qualify. So the sequence is: run it, publish the report somewhere public and linkable, then file the
row citing that link — and file it with Phionyx's own scoping, stating what the run does and does
not establish. The row is permanent once listed.

Neither the run nor the row filing is part of the current pull request.

## B. Independent five-unit AIREP mapping measurement

Measure whether the seven pinned source files can be represented under AIREP v0.2 semantics
without strengthening claims, suppressing negative findings or manufacturing provenance.

- Target: AIREP `v0.2.0-beta.1` @ `8a6c01ecce457aa94330c0ed7219e4c56ebfe771`, wire version `0.2`.
- Units: VAM-01 … VAM-05 exactly as fixed in `MAPPING_CONTRACT.md` §3. VAM-01 stays the complete
  three-record unit; VAM-04 and VAM-05 stay distinct negative units.
- Exposure: `OPEN_EXPECTED`, not expected-blind.
- Rules that bind the run: R1–R6, the per-family sufficiency gate, source-signature verification
  `NOT_EVALUATED`, no Control or Effect without source evidence, no result digest substituted for an
  instruction or executed-action digest. A partial mapping or an explicit no-map is a valid outcome;
  successful artifact emission is not required.
- Order of operations: freeze this plan and record its digests in `MEASUREMENT_PLAN_IDENTITY.json`;
  then pin adapter code, dependency versions, commands and environment; then run; then preserve the
  first-run output digests before any adjudication.
- Report the native results, the field-sufficiency and mapping report, and any AIREP
  verifier/reconciler output for artifacts actually emitted as three retained outputs, per
  `MAPPING_CONTRACT.md` §6.

No interoperability claim follows from either output, before or after measurement.
