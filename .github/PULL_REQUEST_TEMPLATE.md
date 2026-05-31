<!-- Thanks for contributing to AIREP. Conformance vectors and normative text change in lockstep;
keep the core neutral; honesty over polish. See CONTRIBUTING.md. -->

**What this changes:**

**Before you open this PR — check all:**

- [ ] `python3 spec/airep/v0.1/conformance/validate.py` prints `RESULT: all conformance checks PASSED`
- [ ] both verifiers agree — `verify.py` and `verify.mjs` reach the same verdict and the same bytes
- [ ] if a vector or schema changed, the normative text (`SPEC.md`) changed in the **same** PR
- [ ] if this is **BREAKING**, there is a `STATUS.md` **BREAKING** change-log entry + a version bump
- [ ] the neutral core stays neutral — no vendor content outside `profiles`
