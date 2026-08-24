# Comparator findings — official parity run 2

**Run 2 is CLEAN: zero findings. All fourteen hard gates PASS. Comparator exit 0.**

Stated explicitly rather than left to be inferred from an absent file: the
comparator produced **no** finding of any kind on run 2 — no divergence, no
contract mismatch, no envelope defect, no expected-value mismatch, no
determinism failure.

Measurement context: parity measurement authored in a third integration context,
comparator v1.0.0, offline, no network, no `git`.

| Input | Digest |
|---|---|
| `CLASS_VERIFIER_CONTRACT.md` | `sha256:d3b6ea307460f62c8058b4bc54813b6d3ad699d4311f1b9fe64666843643367d` (run 1: `2d028de6…`) |
| `verifier_py/class_verifier.py` | `sha256:5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc` — **byte-identical to run 1**, confirming Python received no code change |
| `verifier_node_r2/class_verifier.mjs` | `sha256:e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4` (run 1: `7e1a0ec9…`) — remediated side |
| corpus aggregate | `55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4` — **unchanged from run 1**; 265 files, 45 cases, every recorded digest and the aggregate rule recomputed and matching |

---

## Run 1 findings — both measured as closed

### FINDING 1 (run 1) — `--request FILE --out PATH` divergence → CLOSED under §9 R-9

R-9 pins: CLI usage error, **exit 2**, no verdict emitted, and `PATH` neither
created nor modified. The probe now asserts all four properties, for both
implementations, in two variants (a non-existent path, and a pre-written
sentinel path whose bytes *and* `mtime_ns` are compared before/after).

| impl | variant | exit | stdout bytes | out path created | out path modified |
|---|---|---|---|---|---|
| python | absent-path | 2 | 0 | no | no |
| python | sentinel-path | 2 | 0 | no | no |
| node | absent-path | 2 | 0 | no | no |
| node | sentinel-path | 2 | 0 | no | no |

Run 1 measured Node at exit 0 with a non-empty stdout and `--out` silently
ignored. That behaviour is gone.

### FINDING 2 (run 1) — duplicate-tuple rejection divergence → CLOSED under §9 R-10

R-10 pins: duplicate `(chain_id, record_id)` in the produced verdict set is
**verifier** run-invalidity — **exit 1**, **no results file emitted**, not a
class reason, no new registry code, not exit 2. Amended §2 now reads "the
verifier MUST reject; the comparator MUST independently gate", and amended §6.4
names batch-level run-identity invariant failure under exit 1.

| impl | variant | exit | results file created | sentinel modified | duplicate tuple emitted |
|---|---|---|---|---|---|
| python | absent-path | 1 | no | — | none |
| python | sentinel-path | 1 | — | no | none |
| node | absent-path | 1 | no | — | none |
| node | sentinel-path | 1 | — | no | none |

Both now reject with exit 1 and write nothing. Run 1 measured Node at exit 0
emitting a two-verdict file carrying the same tuple twice.

The comparator's own independent gate is unchanged and still enforced on both
official output files (G12: ordering and uniqueness both PASS).

---

## Non-vacuity of the two rewritten probes

A clean result is exactly when a comparator is most likely to pass for the wrong
reason, so both rewritten probes were replayed against **synthetic
pre-remediation behaviour** through a duck-typed runner (the real Python verifier
on one side, a stub reproducing run 1's Node behaviour on the other):

| Replayed behaviour | Findings produced |
|---|---|
| R-9, run-1 Node (exit 0, verdict on stdout, `--out` ignored) | `exit-code-contract-mismatch` (expected 2, actual 0) ×2 variants, `request-out-stdout-not-empty` ×2, `exit-code-divergence` ×2 — **6 findings** |
| R-9, hypothetical impl that exits 2 but still touches `PATH` | `request-out-path-created`, `request-out-path-modified` — **2 findings** |
| R-10, run-1 Node (exit 0, duplicate-bearing results file) | `exit-code-contract-mismatch` (expected 1, actual 0) ×2, `duplicate-results-file-created`, `duplicate-results-file-modified`, `duplicate-tuple-emitted` ×2, `duplicate-rejection-divergence` ×2 — **8 findings** |

The probes reproduce run 1's findings on run 1's behaviour. Their PASS on run 2
is therefore a measurement, not a silence.

---

## Limitations of run 2 (unchanged from run 1, restated — not rounded up)

- **Ordering is still exercised on ASCII identifiers only.** All 45 corpus
  identifiers are ASCII, where UTF-8 byte order and UTF-16 code-unit order
  coincide. G12 establishes that both outputs are correctly and identically
  ordered; it does **not** establish cross-runtime ordering agreement on the
  non-ASCII identifiers §2 explicitly admits. A corpus case with a ≥U+FF00 or
  non-BMP identifier would close this. It remains open.
- Semantic gates are measured on the batch (`--corpus`) path; the single-case
  (`--request`) path is measured for exit and side-effect semantics only.
- No cryptography, no artifact hash recomputation, no schema validation is
  performed by the comparator.
- Agreement between the two implementations is consistent with independent
  authoring; it is not proof of it. R-9 and R-10 were both closed by remediating
  one side to a maintainer ruling — that is conformance to a ruling, not
  evidence of independence.
- **This is implementer/measurement evidence, not acceptance.** No `ACCEPTED`
  verdict is assigned here.

## Auxiliary observation (not a gate)

The two run-2 output files are **byte-identical**
(`sha256:556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735` — the
same digest as run 1, since neither ruling touched semantic evaluation). This is
recorded as an observation about two serializers that happen to agree on key
order, indentation and encoding. It is **not** the parity result, it is neither
necessary nor sufficient for parity, and no gate depends on it.
