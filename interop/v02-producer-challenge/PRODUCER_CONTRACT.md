# Producer submission contract

Target exactly AIREP `v0.2.0-beta.1`, commit
`8a6c01ecce457aa94330c0ed7219e4c56ebfe771`. Produce a new directory containing
only these UTF-8 JSON files:

| File | Requirement |
|---|---|
| `SUBMISSION.json` | Provenance and reproduction metadata matching `SUBMISSION_TEMPLATE.json` |
| `lifecycle.json` | Non-empty array containing at least one Decision, Control, Execution, and Effect artifact |
| `bindings.json` | Verifier-side accepted key/role bindings for the submitted producer identities |
| `revocation.json` | Revocation snapshot used for evaluation |
| `independence.json` | Optional verifier-side relationship policy; omission must remain visible |

Do not include private keys, source archives, credentials, or personal data. The
runner rejects extra paths and files larger than 8 MiB. Repository and commit
identifiers in `SUBMISSION.json` are contributor-supplied provenance, not facts
independently established by the runner.

The producer command itself is intentionally outside the runner. Record its
argument vector and environment description in `SUBMISSION.json`; do not put
secrets in either field. A reviewer should be able to obtain the named source,
run the recorded command, regenerate a fresh directory, and compare hashes.

The verifier policies are inputs from the submitter. Acceptance shows
compatibility with the pinned consumer under those supplied policies. It does
not establish that identities, authority, independence, revocation state, or
reported events are true.
