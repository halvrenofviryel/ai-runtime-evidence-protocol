---
name: Normative / core change
about: A change to core.schema.json, SPEC.md, the closed enums, or the integrity rule
title: "spec: "
labels: [normative, needs-design]
---

**What normative text / schema changes** (quote the SPEC clause or schema field):

**Why** (what it fixes or enables):

**Is it BREAKING?** (changes computed hashes, the closed vocabularies, or the required members)
- [ ] yes — needs a version bump + a `STATUS.md` **BREAKING** change-log entry + maintainer approval
- [ ] no — additive

**Updated example vectors** (normative text and conformance vectors change in lockstep):

**Conformance-class impact** (Core / Verified / TRUSTED_NOT_IMPLEMENTED / Trusted — see
`conformance/CONFORMANCE_CLASSES.md`; note the reference verifiers currently report only the
first three, and `Trusted` is withheld while its prerequisites are unenforced):
