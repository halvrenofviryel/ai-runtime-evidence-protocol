# AIREP v0.2.0-beta.1 — usable Decision→Control→Execution→Effect implementation target

**Beta prerelease — 2026-09-09.** Publication status, exact tag and downloadable
archives are recorded on the [GitHub release](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/releases/tag/v0.2.0-beta.1).
Artifact wire version remains `0.2`. v0.1 remains frozen and supported.

This beta adds a first-party reference producer, complete runnable local
lifecycle, structured reconciliation, AD-17 input admission and r3 profile
evaluation in the Python/Node developer path, and one normative implementation
entry point. The [quickstart](QUICKSTART.md) runs without private dependencies.
[BETA_READINESS.md](BETA_READINESS.md) binds release criteria to concrete tests.

Failures, missing evidence and unevaluated checks remain visible. A correct hash
and signature do not establish report truth; a complete correlated example
does not establish full lifecycle history or external independence. A self-declared
key cannot grant Authenticated. The normative classes and frozen integrity bytes
are preserved. New adapters correct the observer gate's wrong-family and ambiguous
identity acceptance without rewriting the pinned historical engines or evidence.

One earlier external v0.2 consumer/verifier result remains qualified as recorded
(17 AGREE / 1 DISAGREE; not expected-blind; historical r1 basis). No same-version
third-party v0.2 producer→consumer interoperability result exists. This release
is **not stable**, not a deployment interoperability claim, and not a new
independently authored two-verifier acceptance measurement.

## Known beta limits

* First-party producer only; public example keys and test-policy independence.
* Single-writer cursor, explicit captured payloads/digests, no production KMS/HSM.
* Reconciliation over the supplied set; no target inventory, URI fetching or
  whole-history/truth assurance. Missing evidence never becomes a pass.
* Generic profile evaluation with explicit self-contained test-only bases;
  no SCITT/AuthZEN E2E case or full MCP/A2A/OTel profile catalogue.
* No migration projector, hardware attestation or regulatory crosswalk refresh.
* Historical direct engines retain their historical scope. Use the beta adapters
  for raw-input admission and r3, and the old paths for pinned reproduction.

## Remaining RC and stable work

[RELEASE_STAGES.md](RELEASE_STAGES.md) records the broader RC corpus, external-
standard E2E programme and candidate freeze discipline. Stable still requires
genuine non-maintainer v0.2 production, same-candidate consumer/verifier evidence
and required producer-output/reconciliation corpus passes. Local green tests
cannot satisfy external independence. AD-01's migration-tooling discrepancy is
preserved explicitly and corrected prospectively.

## Tag, archive and publication checklist

Run these steps only after reviewing and committing the concrete beta changes
and obtaining publication authorization. This document is instructions, not a
record that any step has happened.

1. Confirm a clean release checkout, review the full diff, and run
   `python3 scripts/check_beta.py --out /tmp/airep-beta-release-check`.
   Check every exit/result and the preserved-byte audit; retain failed reruns.
2. Run GitHub CI for the **committed release candidate**, verify the exact commit
   SHA and attach those results. Local CI-equivalent output is not a hosted run.
3. Set `CITATION.cff`'s actual `date-released` at publication. Its current software
   version is the beta target and its top-level DOI is the existing concept DOI.
   Do not relabel the alpha version DOI as the beta DOI.
4. Create the annotated tag only on the reviewed commit:
   `git tag -a v0.2.0-beta.1 -m "AIREP v0.2.0-beta.1 — usable Decision→Control→Execution→Effect implementation target"`.
   Push it only with explicit authorization.
5. Build archives from that tag (`git archive` for tar/zip), record SHA-256 sums,
   and inspect their file list. Generated venvs, Node dependency directories, secret keys and comparator
   scratch links must not enter the source archive. Documented public test
   seeds and retained test evidence are intentional source material.
6. Create a GitHub **prerelease**, use the title above and these notes, attach
   checksum files and machine-readable readiness/test evidence. Verify the tag's
   commit and links after publication.
7. For Zenodo/DOI: create a new version deposit under the existing concept record;
   verify code/spec licenses, creators/ORCID, title/version, archive hashes and
   release URL. Reserve and record a **new beta version DOI**; do not invent one.
   Preserve all alpha/v0.1 deposits. Align citation/release metadata with the
   actual archive record and document any metadata-only follow-up.
