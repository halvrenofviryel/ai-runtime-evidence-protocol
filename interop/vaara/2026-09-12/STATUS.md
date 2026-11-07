# Status of this directory

**INDEPENDENT PHIONYX MEASUREMENT PLAN / PUBLIC SOURCE-PINNED CORPUS / OPEN_EXPECTED / NOT JOINTLY AUTHORED / NOT ENDORSED / NOT RUN / NOT MEASURED.**

Plan revision: **`0.2.0-independent-plan`** (13 September 2026), superseding `0.1.1-freeze-candidate`.

## Ownership and independence

- The upstream material measured here is **public**: the `vaaraio/vaara` repository and its
  `conformance/sep2828` corpus.
- **Phionyx alone** chooses, scopes and owns this measurement. Phionyx is solely responsible for it.
- **No upstream approval is required or claimed.** Citing public work, pinning a public commit and
  running public checkers need no agreement from the upstream project.
- Technical feedback received earlier **informed** this plan. It creates **no** joint ownership, **no**
  acceptance, **no** endorsement and **no** result obligation, and none is claimed. The plan is not
  attributed to anyone else, and no rule in it is described as accepted, frozen or approved by
  another party.
- This plan does **not** make Vaara an AIREP producer.
- This plan does **not** establish interoperability, before or after measurement.
- The earlier bilateral mutual-freeze model is **not being pursued**. It remains in this branch's git
  history; `FREEZE_CANDIDATE.json` is superseded by `MEASUREMENT_PLAN_IDENTITY.json`.

## Plan contents

- Measurement plan: `MAPPING_CONTRACT.md`, revision `0.2.0-independent-plan`.
- `MEASUREMENT_PLAN_IDENTITY.json` is the first-party machine-readable plan identity. It carries the
  computed SHA-256 of the plan, source manifest, source verification record, report template and
  next-steps note, and states `jointly_authored: false`, `externally_endorsed: false`,
  `external_acceptance_required: false`, `recorded_run: false`, `measured: false` and
  `interoperability_result: false`. It does not contain its own digest.
- `MEASUREMENT_NEXT_STEPS.md` describes the two **separate** outputs: reproducing the upstream
  project's public native conformance surface, and the independent five-unit AIREP mapping
  measurement.
- `SOURCE_MANIFEST.json` is the original prepared manifest, **unmodified and byte-exact**. Its digests
  are the collaborator-declared values as reproduced from the upstream manifest, and its recorded
  Internet-Draft revision is historical provenance, not a statement about that draft's current
  revision.
- `SOURCE_VERIFICATION.json` is a **separate** first-party measurement record, preserved byte-exact:
  the seven selected Vaara source files and six native-surface files were retrieved read-only from
  `vaaraio/vaara` at the pinned commit `d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317` and their bytes were
  hashed. **All 7 selected-artifact SHA-256 values match**; all 6 native-surface identities match by
  the identity actually declared for each (SHA-256 and/or Git blob). This is **source-byte identity
  only** — 7/7 + 6/6. It is **not** a native checker run, **not** signature verification, **not** an
  adapter and **not** an interoperability measurement.
- `REVIEW_FILES.sha256` is preserved byte-exact as the originally prepared package's manifest.
  `PLAN_FILES.sha256` covers the current plan file set.

## Measurement design (Phionyx's own rules)

- Seven files form **five** measurement units (VAM-01..VAM-05). The three-record
  `decision_without_outcome` set (S1, S2, S3) is one unit and is not split; the `escalate` decision's
  absent outcome stays visible inside that set.
- The two negative cases are distinct and not interchangeable: VAM-04 is a result-projection digest
  mismatch; VAM-05 is a malformed backlink digest. They fail at different layers and are not merged.
- Exposure: **OPEN_EXPECTED**, not expected-blind. The fixtures and their published expectations are
  already public, so withholding expected values would not establish a blind evaluation.
- Rule 3 is not weakened in any revision: a native `conforms: true` is not source authentication,
  establishes no source key claim, and does not bind source bytes to an accepted key.
  Source-signature verification remains **`NOT_EVALUATED`**.
- No Control or Effect record is produced without source evidence. Where required Decision or
  Execution bindings cannot be supported, the outcome is partial / no-map; a result digest is never
  substituted for an instruction or executed-action digest. Successful artifact emission is not
  required.
- Native findings, `conforms: true`, native advisories, source-signature verification, mapping
  dispositions and AIREP verification findings are separate things, reported separately.
- AIREP measurement target: `8a6c01ecce457aa94330c0ed7219e4c56ebfe771` (`v0.2.0-beta.1`). A later
  documentation commit — including the revision-independent Vaara citation in the active
  specification — is a separate identity and does not replace that baseline.

## Change log

- `0.2.0-independent-plan` (13 September 2026): reframed from a bilateral mutual-freeze candidate to
  an independent Phionyx measurement plan over public upstream material. Removed the mutual-freeze
  dependency and every request for upstream acceptance; replaced `FREEZE_CANDIDATE.json` with
  `MEASUREMENT_PLAN_IDENTITY.json`; renamed the plan manifest to `PLAN_FILES.sha256`; added
  `MEASUREMENT_NEXT_STEPS.md`. The substantive measurement design is unchanged: `OPEN_EXPECTED`,
  seven files as five units, VAM-01 indivisible, VAM-04 and VAM-05 distinct, R3 intact,
  source-signature verification `NOT_EVALUATED`, no fabricated Control or Effect, partial/no-map
  valid. `SOURCE_MANIFEST.json`, `SOURCE_VERIFICATION.json` and `REVIEW_FILES.sha256` unchanged,
  byte-exact.
- `0.1.1-freeze-candidate` (13 September 2026): incorporated external technical feedback and proposed
  a bilateral freeze. Superseded; retained in git history.
- `0.1.0-review` + status/verification: added `SOURCE_VERIFICATION.json` (7/7 + 6/6 source identities
  measured) and this `STATUS.md`. Contract, manifest, template and README bytes unchanged from the
  prepared package.
