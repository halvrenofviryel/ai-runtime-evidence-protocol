# Status of this directory

**REVIEW FEEDBACK INCORPORATED / PROPOSED FREEZE CANDIDATE / NOT MUTUALLY FROZEN / NOT RUN / NOT MEASURED.**

Candidate revision: **`0.1.1-freeze-candidate`** (13 September 2026), superseding `0.1.0-review`.
Upstream maintainer review feedback on sections 3 to 5 and on the five-unit grouping has been
incorporated. External review is not interoperability evidence and does not substitute for a
measured run.

- Mapping contract: `MAPPING_CONTRACT.md`, revision `0.1.1-freeze-candidate`.
- `FREEZE_CANDIDATE.json` is the machine-readable first-party candidate identity record. It
  carries the computed SHA-256 of the contract, source manifest, source verification record and
  report template, and states `mutually_frozen: false`, `recorded_run: false` and
  `interoperability_result: false`.
- `SOURCE_MANIFEST.json` is the original prepared manifest, **unmodified and byte-exact**. Its
  digests are the collaborator-declared values as reproduced from the upstream manifest, and its
  recorded Internet-Draft revision is historical provenance, not a statement about the current
  revision of that draft.
- `SOURCE_VERIFICATION.json` is a **separate** first-party measurement record, preserved
  byte-exact: the seven selected Vaara source files and six native-surface files were retrieved
  read-only from `vaaraio/vaara` at the pinned commit
  `d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317` and their bytes were hashed. **All 7
  selected-artifact SHA-256 values match**; all 6 native-surface identities match by the identity
  actually declared for each (SHA-256 and/or Git blob). This is **source-byte identity only** —
  7/7 + 6/6. It is **not** a native checker run, **not** signature verification, **not** an
  adapter and **not** an interoperability measurement.
- `REVIEW_FILES.sha256` is preserved byte-exact as the original review-set manifest.
  `CANDIDATE_FILES.sha256` covers the current candidate file set.
- Source-pinned and reviewed do **not** mean mutually frozen. Exact mutual freeze requires both
  sides to accept this candidate's exact identity — the digests in `FREEZE_CANDIDATE.json`
  together with the pull request head commit. No input-freeze agreement exists yet.
- Seven files form **five** measurement units (VAM-01..VAM-05). The three-record
  `decision_without_outcome` set (S1, S2, S3) is one unit and is not split; the `escalate`
  decision's absent outcome stays visible inside that set.
- The two negative cases are distinct and are not interchangeable: VAM-04 is a
  result-projection digest mismatch; VAM-05 is a malformed backlink digest. They fail at
  different layers and are not merged.
- Exposure: **OPEN_EXPECTED**, not expected-blind. The fixtures and their published expectations
  are already public, so withholding expected values would not establish a blind evaluation.
- Rule 3 is carried forward substantively unchanged: a native `conforms: true` is not source
  authentication, establishes no source key claim, and does not bind source bytes to an accepted
  key. Source-signature verification remains **`NOT_EVALUATED`**.
- Reviewed scope is this mapping contract's sections 3 to 5, the five-unit grouping and the
  mapping/verifier handoff scope. The reciprocal AIREP verifier package's 60 class cases, its 117
  schema fixtures and its 11 example variants are **outside** this review.
- Native findings, `conforms: true`, native advisories, source-signature verification,
  mapping dispositions and AIREP verification findings are separate things.
- No Control or Effect record is produced without source evidence. Where required Decision
  or Execution bindings cannot be supported, the outcome is partial / no-map; an outcome
  digest is never substituted for an action digest.
- AIREP measurement target: `8a6c01ecce457aa94330c0ed7219e4c56ebfe771` (`v0.2.0-beta.1`).
  A later documentation commit — including the revision-independent Vaara citation in the active
  specification — is a separate identity and does not replace that baseline.

## Change log

- `0.1.1-freeze-candidate` (13 September 2026): incorporated upstream maintainer review feedback;
  `OPEN_EXPECTED` stated definitively and as not expected-blind; the related-draft row reworded as
  informative work in progress rather than a measured run input; reviewed-basis notes added to
  sections 3, 4 and 5 without redesigning them; acceptance/freeze procedure, citation split and
  status section updated; added `FREEZE_CANDIDATE.json`; regenerated `CANDIDATE_FILES.sha256`.
  `SOURCE_MANIFEST.json`, `SOURCE_VERIFICATION.json` and `REVIEW_FILES.sha256` unchanged, byte-exact.
- `0.1.0-review` + status/verification: added `SOURCE_VERIFICATION.json`
  (7/7 + 6/6 source identities measured) and this `STATUS.md`. Contract, manifest, template
  and README bytes unchanged from the prepared package.
