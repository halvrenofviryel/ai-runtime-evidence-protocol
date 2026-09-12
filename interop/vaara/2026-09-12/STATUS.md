# Status of this directory

**DRAFT / PROPOSED / NOT MUTUALLY FROZEN / NOT RUN / NOT MEASURED.**

Candidate revision: **`0.1.0-review`** (contract text unchanged; this directory adds a
separate first-party source-verification record and this status note).

- Mapping contract: `MAPPING_CONTRACT.md`, revision `0.1.0-review`, byte-exact as prepared.
- `SOURCE_MANIFEST.json` is the original prepared manifest, **unmodified**. Its digests are
  the collaborator-declared values as reproduced from the upstream manifest.
- `SOURCE_VERIFICATION.json` is a **separate** first-party measurement record: the seven
  selected Vaara source files and six native-surface files were retrieved read-only from
  `vaaraio/vaara` at the pinned commit `d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317` and their
  bytes were hashed. **All 7 selected-artifact SHA-256 values match**; all 6 native-surface
  identities match by the identity actually declared for each (SHA-256 and/or Git blob).
  This is source-byte identity only. It is **not** a native checker run, **not** signature
  verification, **not** an adapter and **not** an interoperability measurement.
- Source-pinned does **not** mean mutually frozen. Henri Sirkkavaara has not reviewed or
  approved this contract; no input-freeze agreement exists.
- Seven files form **five** measurement units (VAM-01..VAM-05). The three-record
  `decision_without_outcome` set (S1, S2, S3) is one unit and is not split.
- The two negative cases are distinct and are not interchangeable: VAM-04 is a
  result-projection digest mismatch (recomputed predecessor mismatch); VAM-05 is a malformed
  backlink digest.
- Exposure: **OPEN_EXPECTED**, not expected-blind.
- Native findings, `conforms: true`, native advisories, source-signature verification
  (`NOT_EVALUATED`), mapping dispositions and AIREP verification findings are separate things.
- No Control or Effect record is produced without source evidence. Where required Decision
  or Execution bindings cannot be supported, the outcome is partial / no-map; an outcome
  digest is never substituted for an action digest.
- AIREP measurement target: `8a6c01ecce457aa94330c0ed7219e4c56ebfe771` (`v0.2.0-beta.1`).
  A later documentation commit is a separate identity and does not replace that baseline.

## Change log

- `0.1.0-review` + status/verification (this directory): added `SOURCE_VERIFICATION.json`
  (7/7 + 6/6 source identities measured) and this `STATUS.md`. Contract, manifest, template
  and README bytes unchanged from the prepared package.
