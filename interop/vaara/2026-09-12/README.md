# Vaara × AIREP measurement plan — 12 September 2026

**Status: independent Phionyx measurement plan / public source-pinned corpus / open-expected / not jointly authored / not endorsed / not run / not measured.**

Current revision: `0.2.0-independent-plan` (13 September 2026), superseding `0.1.1-freeze-candidate`.

This plan is written, scoped and owned by **Phionyx alone**. The upstream repository and its `conformance/sep2828` corpus are public, so no upstream approval is required to pin or measure them, and none is claimed. Earlier technical feedback informed this plan; it creates no joint ownership, acceptance, endorsement or result obligation. Nothing here makes Vaara an AIREP producer, and nothing here establishes interoperability.

Read `MAPPING_CONTRACT.md` first, then `SOURCE_MANIFEST.json`. `MEASUREMENT_PLAN_IDENTITY.json` is the first-party machine-readable plan identity with computed digests. `MEASUREMENT_NEXT_STEPS.md` describes the two separate outputs that follow. `STATUS.md` records the current status. `REPORT_TEMPLATE.json` contains no results; nulls and `NOT_RUN` are intentional.

The plan uses seven upstream source files as five measurement units. It does not contain copies of Vaara source or private correspondence. An absence of supported target fields may yield partial/no mapping; the presence of a source outcome alone is not authority to emit a complete AIREP lifecycle artifact.

AIREP beta behavior is pinned to commit `8a6c01ecce457aa94330c0ed7219e4c56ebfe771`; a later informative-reference documentation commit does not change the measurement basis. The reciprocal verifier package is separate work and outside this plan's scope.

`SOURCE_MANIFEST.json`, `SOURCE_VERIFICATION.json` and `REVIEW_FILES.sha256` are preserved byte-exact from the originally prepared package; `REVIEW_FILES.sha256` remains that package's original manifest. `PLAN_FILES.sha256` covers the current plan file set.

Do not edit a published revision in place. Record a superseding revision and preserve the cited predecessor; the earlier bilateral-freeze revision remains in this branch's git history. No current file constitutes a completed external-evidence entry.
