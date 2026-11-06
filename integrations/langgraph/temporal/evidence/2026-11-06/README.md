# Local captured-runtime review evidence — 6 November 2026

Measured source commit: `d0bc8defef631c51493e5fb5931af1fe35d4d47c`.
This is author-side controlled evidence for a draft review candidate. It is not a
new release, independent reproduction or an addition to the frozen study DOI.

`inputs.json` contains exact captured source bytes, signed mapping reports,
public ephemeral test-key bindings and the 14 delivery schedules. `report.json`
contains native verifier results, bounded consumer results, source hashes and
pinned runtime dependency metadata. `index.html` presents the same results.
Three actual LangGraph runs supplied the source events; fourteen replay views
are not fourteen independent runtime runs.

Reproduce from the repository root with the pinned dependencies described in
`../../README.md`:

```sh
python -B -m integrations.langgraph.temporal.runtime_report \
  --replay integrations/langgraph/temporal/evidence/2026-11-06/inputs.json \
  --out /tmp/airep-public-replay-new
python -B -m integrations.langgraph.temporal.runtime_report --out /tmp/airep-fresh-capture-new
```

The saved-input replay must reproduce all fourteen parsed native-verifier and
consumer views. This is structural equality of parsed results, not byte-for-byte
equality of output files. Report metadata and HTML JSON key order may differ;
each file's integrity is checked against its own hash.
A fresh capture has new IDs, keys and timing; expected bounded outcomes must
still match. Output directories must not exist.

The logs record 35 temporal tests, 13 original runtime tests and 14 explain/CLI
tests. The pre-push logs additionally record all 39 beta regression tests.
The existing beta CI entry point now invokes `scripts/check_temporal.py`, which
runs these 101 tests, a fresh capture and saved-input replay. It provisions
hash-pinned Python wheels and materializes the existing offline Node archive.
CI results must be assessed on the PR's exact head, separately from these logs.

`DOM_CHECKS.json` records actual local browser observations from the earlier
capture displayed in `dom-candidate.html`. Its template and runtime source
hashes match the final capture. The loopback URL is omitted from the public
record; the measured observations and HTML hash are retained. Signed event/source
bytes were not redacted or altered. Unreferenced setup traces, personal paths,
private drafts, local environment dumps and private keys are not included.

Effect samples, run/control identities and source timing are distinct from the
offline arrival schedule. No live-network delay, durable restart, independent
observer or production SDK is established. The same-host trust limitation and
sampled-quiescence boundary remain visible. The code retains the repository's
Apache-2.0 license; restored D/K3 provenance is in `../../../SOURCE_IMPORT.json`.

`MANIFEST.json` seals this review subset and records the measured source commit.
