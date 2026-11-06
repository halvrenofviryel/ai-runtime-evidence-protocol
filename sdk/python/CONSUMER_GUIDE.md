# Producer / consumer replay kit

The native API and the SDK hook policy are separate contracts. This candidate
preserves native AIREP 0.2.0-beta.1 semantics. The hook consumer additionally uses
`airep-sdk-local-pause-samples-v1` at the hash in CONSUMER_CONTRACT.json. It does
not claim that a native verifier by itself validates SDK event truth.

Input to `airep consume`: one exact hook bundle, one separately selected operator
trust file, and one expected identity file. The bundle contains exact source
strings, signed native artifacts, producer identity and the mapping-basis digest.
No URL or reference is fetched, and no submitted program is executed. The caller
chooses which run/control/node to query; the output reports the measured sample
window, not a universal or current stopped state.

Output: `evaluation_completed`, unchanged `native` reconciliation, and separate
`consumer` policy/result, source errors, query match and receipt/execution/effect
observations. A CLI exit 0 is completion. CI must inspect the result or explicitly
use `--require-policy-match` (exit 3 on NO_MATCH). Invalid input emits no result;
timeout is 124.

| Controlled example | Execution | Effect | Local policy | Native summary |
|---|---|---|---|---|
| paused | PAUSED_REPORTED | QUIESCENT_REPORTED | MATCH | INCOMPLETE |
| ignored | CONTINUED_REPORTED | CHANGED_REPORTED | NO_MATCH | FAILURE |
| unobserved | PAUSED_REPORTED | MISSING | NO_MATCH | INCOMPLETE |
| foreign identity query | MISSING | MISSING | NO_MATCH | Original native result retained |
| signed scope mismatch | INDETERMINATE | INDETERMINATE | NO_MATCH | Original native result retained |
| signature/source mismatch | INDETERMINATE | INDETERMINATE | NO_MATCH | Original native result retained |

Native INCOMPLETE includes intended-target coverage NOT_EVALUATED. Matching this
bounded policy never changes that native status. File equality means equality of
two samples only. The initial sample must finish before receipt and the final
sample must begin after the native runtime result. Application interrupts other
than the exact SDK control interrupt are rejected before evidence serialization. The graph, hook, observer and test key share a trust domain.
Input trust shipped by the example is merely a reproducible test choice; an
external consumer must explicitly decide whether that key/producer is accepted.

The signed scope of **every** artifact must exactly equal `artifact_scope` in
contract revision 2, including all exclusions and list order. An added assertion,
removed limitation or otherwise changed scope yields NO_MATCH even with valid
signatures and source links. The diagnostic is fixed and does not echo the
submitted scope. This is a closed SDK mapping rule, not an interpretation of
arbitrary scope text. The native API continues to evaluate native artifacts
under its original rules.

For an external trial, record the wheel/source/contract hashes, Python/LangGraph
versions, exact commands, expected/observed results and limitations using
EXTERNAL_RESULT_TEMPLATE.json. Distinguish replaying this author's example from
an original producer or original consumer. Both roles must identify the same
native beta basis. Keep failures and unknowns. A local author-run replay, a
reviewer reading logs or an AI review does not establish outside adoption.

The existing [producer challenge #62](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/issues/62)
remains the eventual discussion entry; this local candidate opens no new issue
and sends no invitation or result. No PyPI/release/Zenodo publication is implied.
