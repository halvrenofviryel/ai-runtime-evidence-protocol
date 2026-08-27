# W2 runtime probe — recorded basis

Authorized by `W2_SCITT_RUNTIME_PROBE_AUTHORIZED`. This file records the build basis. The probe
result itself is recorded separately, and **only after** it is observed.

## Source

| | |
|---|---|
| Repository | `microsoft/scitt-ccf-ledger` |
| Release | `0.19.0` |
| **Commit, verified on the clone** | `c641e0d2cd4bb17e1085c0594a7dd23c55f640dd` |
| `git describe --tags --long --always` | `0.19.0-0-gc641e0d` — zero commits ahead of the tag |

The clone was taken with `--branch 0.19.0` and its `HEAD` compared against the pinned commit
before anything was built. It matches.

## Base image

`docker/Dockerfile` pins its base by **tag**, not digest:

```
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260722 AS base
```

A tag is reassignable, so the tag alone does not pin the build. The digest resolved at pull time,
which is the thing that actually pins it:

```
mcr.microsoft.com/azurelinux/base/core@sha256:a30e18dd24a8080ee0b72d0f998a688e99380678a407bdd7c3a0ac7417b15eb3
```

This is why the preflight said the commit alone does not pin the image. Anyone reproducing this
probe needs **both** the commit and this base digest; if the base digest differs, it is a different
build and must be recorded as one.

Note the base tag is `3.0.20260722`, while `main` has since bumped past it — expected, since the
probe is pinned to the `0.19.0` tree rather than to `main`.

## What is not yet recorded

Deliberately absent until observed:

- the resulting image digest;
- whether a minimum valid registration takes the synchronous `201 Created` path;
- the receipt bytes;
- the observed VDS / CCF algorithm identifier on the wire.

**Stop condition, restated from the authorization:** if registration is observed taking the
asynchronous `302` / `303` path, the probe stops there. S1–S6 is not attempted, and the scoped
claim is re-scoped by the maintainer before any further work.
