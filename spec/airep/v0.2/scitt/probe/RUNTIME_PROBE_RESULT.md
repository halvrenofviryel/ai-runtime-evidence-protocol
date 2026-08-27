# W2 runtime probe — observed result

Measured 2026-08-27 against a local deployment built from the basis in
[`RUNTIME_PROBE_BASIS.md`](./RUNTIME_PROBE_BASIS.md). Every value below was **observed**; nothing
is carried over from documentation.

**I am not declaring this probe passed.** `W2-PROBE-IR-1` requires the first response of a minimum
registration to be exactly `201 Created`. What was observed is more specific than pass/fail, and
the scoping call is the maintainer's — see §4.

## 1. Build

| | |
|---|---|
| Source commit | `c641e0d2cd4bb17e1085c0594a7dd23c55f640dd` (`0.19.0-0-gc641e0d`) |
| Base, resolved at pull | `mcr.microsoft.com/azurelinux/base/core@sha256:a30e18dd24a8080ee0b72d0f998a688e99380678a407bdd7c3a0ac7417b15eb3` |
| **Resulting image** | `sha256:88931df39f990673f618c2b003ddae5feed827a83d9cc68e678f0828df6bb648` (183,337,632 bytes) |

**On verifying the base digest actually used in the build.** The build log does not carry it: both
`#2 [internal] load metadata` and `#4 [base 1/1] FROM …` report `DONE 0.0s`, a BuildKit cache hit
that prints the tag and not the resolved digest. Pull-time resolution alone would therefore have
been the unverified claim the ruling warns about.

Verified by layer identity instead: the pulled base image has exactly one rootfs layer,
`sha256:d187899d10d2dc1eadb6f64b7a1de0f66c08b32ba185e0faa78dddb655dc244b`, and the built image's
**first rootfs layer is that same layer**, with seven layers added above it.

**Exact strength of that check:** it establishes that the built image's base layer *content* is the
content of the image pulled at `a30e18dd…`. It is layer-content identity, not a manifest-digest
attestation. A BuildKit provenance attestation (`--provenance=true`) would bind the manifest digest
directly; this build did not emit one. If that stronger form is required, the build must be re-run
with provenance enabled.

## 2. Registration — observed statuses

> **Correction (2026-08-27, maintainer-flagged).** The first version of this section reported
> `POST /entries` → `202` and concluded that "both the project's README and upstream issue #414 are
> stale". **That conclusion was wrong and is withdrawn.** The request carried no `api-version`, and
> the pinned source selects behaviour on exactly that: `is_scrapi_v9()` in `app/src/util.h` returns
> true **only** when the query contains `api-version=2026-03-26`. Without it, `operations_endpoints.h`
> takes the branch its own comment labels "Legacy flow: 202 Accepted with CBOR body and
> `Location: /operations/`". I measured the legacy compatibility path and drew a conclusion about
> the versioned one. The corrected measurements are below.

Three request shapes were driven with a raw HTTP client, redirects **not** followed, so the *first*
response is what is recorded. Payload throughout: the project's own
`test/payloads/manifest.spdx.json.sha384.digest.cose`, 4,296 bytes,
`sha256:feed68f19b4b8a5278fa1a79096caa8c9cd604eecccb71dea7a3e44112eccc90`.

| Request target | First status | `Location` | `Content-Type` |
|---|---|---|---|
| `/entries` — **no** `api-version` | `202 Accepted` | `/operations/2.19` | `application/cbor` |
| `/entries?api-version=2026-03-26` | **`303 See Other`** | `/entries/2.18` | — |
| `/entries?api-version=2026-03-26&waitForCommit=true` | **`201 Created`** | `/entries/2.16` | `application/scitt-receipt+cose` |

**What this actually shows.**

- The **versioned asynchronous** path is still **`303`**, exactly as the README's worked example
  shows and exactly as upstream issue #414 describes. **#414 is not stale.** My earlier claim that
  it was rested entirely on the legacy-path measurement.
- The `202` is a **backward-compatibility flow** for clients that send no `api-version`. It is not
  evidence that the SCRAPI async path has moved.
- The one thing that **is** stale in the README is its `--wait-for-commit` example, which shows
  `POST /entries?waitForCommit=true 200`. Measured here: **`201`**.

**A note on the source comment.** `operations_endpoints.h` says the legacy branch exists "for
backward compatibility with legacy clients (eg. .NET SDK) that expect `api-version=2026-03-26`",
which reads as though that value selects legacy. The logic in `util.h` says the opposite: that
value selects SCRAPI. The comment is misleading; the behaviour is what is recorded above.

### 2.1 `W2-PROBE-IR-2` confirmation

Request target, exactly as pinned by the ruling:

```
POST /entries?api-version=2026-03-26&waitForCommit=true
Content-Type: application/cose
```

| | |
|---|---|
| First HTTP status | **`201 Created`** |
| `Location` | `https://localhost:8000/entries/2.16` |
| `Content-Type` | **`application/scitt-receipt+cose`** |
| Receipt | 436 bytes, `sha256:b82289bbef7a93300c3a78c39825adf6f47baa6efc712f7706184103c46c46b4` |
| Other headers | `x-ms-ccf-transaction-id: 2.16`, `x-ms-request-id: d6c6bc7517c3526a` |
| Image | `sha256:88931df39f990673f618c2b003ddae5feed827a83d9cc68e678f0828df6bb648` — the same image, re-run, not rebuilt |

The media type is the differentiator worth noting: under the versioned selector the service returns
**`application/scitt-receipt+cose`**, the type registered by RFC 9943, rather than the bare
`application/cose` the legacy `waitForCommit` path returned. Same status, different declared type.

**`waitForCommit` is not a SCRAPI parameter.** It is this implementation's own mode selector. What
the observation supports is therefore bounded:

> On the pinned `scitt-ccf-ledger` 0.19.0 implementation, using its versioned SCITT API selector
> together with its synchronous wait-for-commit option produced the synchronous registration
> response shape corresponding to SCRAPI-11 §2.3.1.

Nothing more general than that sentence is claimed.

## 3. Receipt and VDS identifier

From the **`W2-PROBE-IR-2`** response body, 436 bytes,
`sha256:b82289bbef7a93300c3a78c39825adf6f47baa6efc712f7706184103c46c46b4`
(the legacy-path receipt measured earlier was 508 bytes,
`sha256:411dbdb14fc27921d043f7a75aa3e7f5927eabfd70bc5e4460a81ef57c7e07d1`; both carry the same
`vds` and proof type):

| Field | Observed |
|---|---|
| COSE tag | `18` (COSE_Sign1) |
| `alg` (1) | `-35` (ES384) |
| CWT claims (15) | issuer `127.0.0.1:8000`, subject `scitt.ccf.signature.v1`, iat `1787860661` |
| **`vds` (395)** | **`2`** |
| proofs (396) | present, proof type `-1` (inclusion) |
| `ccf.v1` | `{txid: 2.17}` — an implementation-specific header outside the profile. Note it differs from the `Location` txid `2.16`; recorded as observed, not reconciled |

**The `TBD_1` limitation is now measured, not predicted.** `draft-ietf-scitt-receipts-ccf-profile-04`
Table 1 registers `CCF_LEDGER_SHA256` as `TBD_1` with "(requested assignment 2)". The wire carries
`2` — the *requested but unassigned* value. Every receipt this service emits therefore identifies
its verifiable data structure by a number IANA has not allocated, under either the replaced
individual draft or the current WG draft. The inclusion-proof label `-1` does match the draft's
normative requirement.

## 4. Gate status

`W2-PROBE-IR-2` is satisfied on the measurement it names: the pinned request target returned an
observed `201 Created` with an inline receipt of the registered SCITT receipt media type.

The scoping question raised in the first version of this file — "which endpoint is the minimum
registration" — was settled by the maintainer rather than by me, and correctly: the qualifying call
is the **versioned** one, not merely `?waitForCommit=true`. Without `api-version=2026-03-26` the
service takes its legacy branch, which is a different code path with a different media type.

**S1–S6 has not been started.** It waits on the maintainer's gate.

## 5. Reproduction

Local dev deployment via `docker/run-dev.sh`, CCF virtual mode, service open at seqno 9, listening
on `localhost:8000`. Configuration is the repository's own `docker/dev-config.tmpl.json`, which the
README states is not production-suitable: ad-hoc governance member key, API authentication
disabled, permissive policy. Service identity as it appears in the receipt is `127.0.0.1:8000` /
`scitt.ccf.signature.v1`.

Two earlier submissions were rejected before a valid one was accepted, and both rejections are
informative rather than noise:

| Attempt | Response |
|---|---|
| self-signed statement, no CWT claims | `400`, `{-1: InvalidInput, -2: "Signed statement protected header must contain CWT_Claims with at least an issuer"}` |
| self-signed statement with an issuer | `400`, `{-1: InvalidInput, -2: "CWT_Claims issuer is unsupported"}` |

The first is the implementation enforcing the RFC 9943 requirement that issuer identity be bound in
the protected header — the same normative addition the compatibility analysis flagged as new
relative to Architecture Draft 11.
