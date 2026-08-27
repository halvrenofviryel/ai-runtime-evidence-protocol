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

Two paths exist, and they differ. Both were driven with a raw HTTP client, redirects **not**
followed, so the *first* response is what is recorded.

Payload: the project's own `test/payloads/manifest.spdx.json.sha384.digest.cose`, 4,296 bytes,
`sha256:feed68f19b4b8a5278fa1a79096caa8c9cd604eecccb71dea7a3e44112eccc90`.

| Request | First response | Location | Content-Type |
|---|---|---|---|
| `POST /entries` | **`202 Accepted`** | `/operations/2.13` | `application/cbor`, 33 bytes |
| `POST /entries?waitForCommit=true` | **`201 Created`** | `/entries/2.14` | `application/cose`, 508 bytes — the receipt itself |

**Both the project's README and upstream issue #414 are stale on this point.** The README's worked
example shows `POST /entries 303` followed by `302` redirects; issue #414 asks for the `302` to
become `202`. The observed default path already returns **`202`**, and the synchronous path returns
**`201`** with the receipt in the body — which is exactly SCRAPI-11 §2.3.1 ("If the Transparency
Service is able to produce a Receipt within a reasonable time, it MAY return it directly", `201
Created`, `Location` header MUST).

So the compatibility picture is **better than the delta analysis projected**, and for a reason that
document analysis could not have reached: the analysis compared SCRAPI-09 against SCRAPI-11 and
correctly identified `303`/`302` as the draft-09 shapes, but the implementation had already moved
past its own documentation.

**Neither the client `X-Request-ID` nor any echo of it appears in the response.** The service
returns its own `x-ms-request-id` with an unrelated value, plus `x-ms-ccf-transaction-id`.

## 3. Receipt and VDS identifier

From the `201` response body, 508 bytes,
`sha256:411dbdb14fc27921d043f7a75aa3e7f5927eabfd70bc5e4460a81ef57c7e07d1`:

| Field | Observed |
|---|---|
| COSE tag | `18` (COSE_Sign1) |
| `alg` (1) | `-35` (ES384) |
| CWT claims (15) | issuer `127.0.0.1:8000`, subject `scitt.ccf.signature.v1`, iat `1787859257` |
| **`vds` (395)** | **`2`** |
| proofs (396) | present, proof type `-1` (inclusion) |
| `ccf.v1` | `{txid: 2.15}` — an implementation-specific header outside the profile |

**The `TBD_1` limitation is now measured, not predicted.** `draft-ietf-scitt-receipts-ccf-profile-04`
Table 1 registers `CCF_LEDGER_SHA256` as `TBD_1` with "(requested assignment 2)". The wire carries
`2` — the *requested but unassigned* value. Every receipt this service emits therefore identifies
its verifiable data structure by a number IANA has not allocated, under either the replaced
individual draft or the current WG draft. The inclusion-proof label `-1` does match the draft's
normative requirement.

## 4. What this means for the gate — maintainer's call

`W2-PROBE-IR-1` says only an observed `201 Created` qualifies, and that `202` is a finding to be
scoped rather than a pass.

Both are present here, on two different endpoints:

- the **default** registration path returns `202` — an asynchronous operation handle;
- the **`waitForCommit=true`** path returns `201` with the receipt inline.

The question the ruling does not settle is which one is "the minimum registration". The `201` path
is not a fallback or a workaround — it is a documented first-class variant, and it is the shape
SCRAPI-11 §2.3.1 describes. But it is also opt-in via a query parameter, so calling it "the"
registration path is a scoping decision, not an observation.

**I have not proceeded to S1–S6.** Recommended framing, for the maintainer to accept or replace:
the PoC pins `waitForCommit=true` as its registration call, records that the default path is
asynchronous `202`, and claims the synchronous SCRAPI-11 §2.3.1 shape **only** for the pinned call.

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
