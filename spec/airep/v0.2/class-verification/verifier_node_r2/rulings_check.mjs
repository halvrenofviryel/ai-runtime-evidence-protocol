// Source-review ruling self-check (CLASS_VERIFIER_CONTRACT.md section 9,
// rulings R-1 / R-2 / R-3 / R-4 / R-7 / R-8). Every input is constructed here from a corpus
// case's bytes and written under the working directory; the frozen corpus is
// never added to or altered, and no fixture expected value is read. Each probe
// states the exact reason set it demands and fails loudly on mismatch.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const TMP = "tmp_rulingscheck";
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

const SCHEMAS = ["--schema-dir", "../../schemas"];
const P2 = "../corpus/cases/P2";
const CLOCK = ["--now", "2026-08-23T12:00:00Z", "--freshness-window", "3600"];
const OPS = ["--bindings", `${P2}/bindings.json`,
  "--independence-policy", `${P2}/independence.json`,
  "--revocation", `${P2}/revocation.json`];

let bad = 0;
const say = (m) => { bad++; console.log("FAIL:", m); };
const ok = (m) => console.log("  ok  " + m);

function run(args) {
  const r = spawnSync(process.execPath, ["class_verifier.mjs", ...SCHEMAS, ...args], { encoding: "utf8" });
  return { status: r.status, stderr: r.stderr, verdict: r.status === 0 ? JSON.parse(r.stdout) : null };
}
function writeJson(name, value) {
  const f = path.join(TMP, name);
  fs.writeFileSync(f, JSON.stringify(value, null, 1));
  return f;
}
const req = () => JSON.parse(fs.readFileSync(`${P2}/request.json`, "utf8"));
const bindings = () => JSON.parse(fs.readFileSync(`${P2}/bindings.json`, "utf8"));
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Assert the exact five channels (undefined = "not asserted by this probe").
function expect(label, args, want) {
  const { status, verdict, stderr } = run(args);
  if (status !== 0) { say(`${label}: expected a verdict, got exit ${status} :: ${stderr.trim()}`); return null; }
  const got = {
    class: verdict.class,
    af: verdict.authenticated_failures, aw: verdict.authenticated_withheld,
    ac: verdict.authenticated_caveats,
    wf: verdict.witnessed_failures, ww: verdict.witnessed_withheld,
  };
  const diffs = [];
  for (const k of Object.keys(want)) if (!eq(got[k], want[k])) diffs.push(`${k}: got ${JSON.stringify(got[k])} want ${JSON.stringify(want[k])}`);
  if (diffs.length) say(`${label}: ` + diffs.join(" | "));
  else ok(label);
  return verdict;
}

// Control: the untouched P2 case must be a clean Witnessed verdict, otherwise
// every probe below is measuring the wrong thing.
expect("control: untouched P2 is clean AIREP-Witnessed", ["--request", `${P2}/request.json`, ...OPS, ...CLOCK],
  { class: "AIREP-Witnessed", af: [], aw: [], ac: [], wf: [], ww: [] });

// ---------------------------------------------------------------------------
// R-1 - `claim` is NOT harness closure. An unknown claim member is a normal
// verdict carrying witness-claim-invalid, never a run-invalid abort.
// ---------------------------------------------------------------------------
{
  const r = req(); r.head_witness.claim.note = "extra";
  expect("R-1: unknown claim member => witness-claim-invalid, run stays valid",
    ["--request", writeJson("r1_unknown_claim_member.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: ["witness-claim-invalid"], ww: [] });
}
{
  const r = req(); delete r.head_witness.claim.length;
  expect("R-1: missing claim member => witness-claim-invalid",
    ["--request", writeJson("r1_missing_claim_member.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", wf: ["witness-claim-invalid"], ww: [] });
}
{
  const r = req(); r.head_witness.claim.sequence = "0";
  expect("R-1: wrong-typed claim member => witness-claim-invalid",
    ["--request", writeJson("r1_wrongtyped_claim_member.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", wf: ["witness-claim-invalid"], ww: [] });
}

// ---------------------------------------------------------------------------
// R-2 - stage 6 is a single dependent precedence 6a -> 6b -> 6c. Each probe
// injects TWO defects at once; only the earlier sub-step may report.
// ---------------------------------------------------------------------------
const OTHER_DIGEST = "sha256:" + "ab".repeat(32);

{ // 6a before 6b: claim defect + unresolvable head.
  const r = req();
  r.head_witness.claim.note = "extra";
  r.head_witness.head_ref.record_id = "no-such-record";
  expect("R-2: 6a precedes 6b (claim defect + unresolvable head) => claim-invalid alone",
    ["--request", writeJson("r2_6a_over_6b.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-claim-invalid"], ww: [] });
}
{ // 6a before 6c: claim defect + invalid witnessed_at.
  const r = req();
  r.head_witness.claim.note = "extra";
  r.head_witness.claim.witnessed_at = "2026-02-30T11:30:00Z";
  expect("R-2: 6a precedes 6c (claim defect + bad witnessed_at) => claim-invalid alone",
    ["--request", writeJson("r2_6a_over_6c.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-claim-invalid"], ww: [] });
}
{ // 6b before 6c, unresolved branch.
  const r = req();
  r.head_witness.head_ref.record_id = "no-such-record";
  r.head_witness.claim.witnessed_at = "2026-02-30T11:30:00Z";
  expect("R-2: 6b precedes 6c (unresolved head + bad witnessed_at) => head-unresolved alone",
    ["--request", writeJson("r2_6b_unresolved_over_6c.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-head-unresolved"], ww: [] });
}
{ // 6b before 6c, reconciliation branch (R-5 reason).
  const r = req();
  r.head_witness.claim.current = OTHER_DIGEST;          // still a valid digest lexeme
  r.head_witness.claim.witnessed_at = "2026-02-30T11:30:00Z";
  expect("R-2: 6b precedes 6c (non-reconciling head + bad witnessed_at) => head-mismatch alone",
    ["--request", writeJson("r2_6b_mismatch_over_6c.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-head-mismatch"], ww: [] });
}
{ // 6c reports only when 6a and 6b are clean; clock inputs play no part in it.
  const r = req();
  r.head_witness.claim.witnessed_at = "2026-02-30T11:30:00Z";
  const f = writeJson("r2_6c_only.json", r);
  expect("R-2: 6c alone, with clock => witness-time-invalid alone (never freshness)",
    ["--request", f, ...OPS, ...CLOCK], { wf: ["witness-time-invalid"], ww: [] });
  expect("R-2: 6c alone, no clock => witness-time-invalid alone (clock plays no part)",
    ["--request", f, ...OPS], { wf: ["witness-time-invalid"], ww: [] });
}
{ // Stage 6 clean => stages 7-10 do run (the precedence suppresses nothing else).
  const r = req();
  r.head_witness.claim.witnessed_at = "2020-01-01T00:00:00Z";   // valid, far outside the window
  // Rewriting witnessed_at also rewrites the signed claim, so stage 9 reports
  // too. Both reasons appearing is the point: stage 6 was clean, so stages
  // 7-10 all ran -- the precedence suppresses nothing beyond stage 6.
  expect("R-2: valid-but-stale witnessed_at reaches stages 9 and 10",
    ["--request", writeJson("r2_stage10_reached.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-freshness-outside-window", "witness-signature-invalid"], ww: [] });
}

// ---------------------------------------------------------------------------
// R-3 - structural malformation precedes the semantic trust decision.
// ---------------------------------------------------------------------------
{ // witness side: unknown member + trusted:false => malformed ONLY.
  const b = bindings();
  const id = b.witness_bindings[Object.keys(b.witness_bindings)[0]];
  b.bindings[id].note = "extra";
  b.bindings[id].trusted = false;
  expect("R-3: witness unknown member + trusted:false => binding-malformed alone",
    ["--request", `${P2}/request.json`, "--bindings", writeJson("r3_wit_mal_untrusted.json", b),
     "--independence-policy", `${P2}/independence.json`, "--revocation", `${P2}/revocation.json`, ...CLOCK],
    { wf: [], ww: ["witness-binding-malformed"] });
}
{ // witness side: structurally clean + trusted:false => not-trusted ONLY.
  const b = bindings();
  const id = b.witness_bindings[Object.keys(b.witness_bindings)[0]];
  b.bindings[id].trusted = false;
  expect("R-3: witness clean entry + trusted:false => binding-not-trusted alone",
    ["--request", `${P2}/request.json`, "--bindings", writeJson("r3_wit_untrusted.json", b),
     "--independence-policy", `${P2}/independence.json`, "--revocation", `${P2}/revocation.json`, ...CLOCK],
    { wf: ["witness-binding-not-trusted"], ww: [] });
}
{ // producer side: unknown member + trusted:false => malformed ONLY.
  const b = bindings();
  const id = b.producer_bindings[Object.keys(b.producer_bindings)[0]];
  b.bindings[id].note = "extra";
  b.bindings[id].trusted = false;
  expect("R-3: producer unknown member + trusted:false => binding-malformed alone",
    ["--request", `${P2}/request.json`, "--bindings", writeJson("r3_prod_mal_untrusted.json", b),
     "--independence-policy", `${P2}/independence.json`, "--revocation", `${P2}/revocation.json`, ...CLOCK],
    { class: "AIREP-Core", af: [], aw: ["producer-binding-malformed"], ac: [] });
}
{ // producer side: structurally clean + trusted:false => not-trusted ONLY.
  const b = bindings();
  const id = b.producer_bindings[Object.keys(b.producer_bindings)[0]];
  b.bindings[id].trusted = false;
  expect("R-3: producer clean entry + trusted:false => binding-not-trusted alone",
    ["--request", `${P2}/request.json`, "--bindings", writeJson("r3_prod_untrusted.json", b),
     "--independence-policy", `${P2}/independence.json`, "--revocation", `${P2}/revocation.json`, ...CLOCK],
    { class: "AIREP-Core", af: ["producer-binding-not-trusted"], aw: [], ac: [] });
}
{ // malformed required container + trusted:false on the referenced entry.
  const b = bindings();
  const id = b.producer_bindings[Object.keys(b.producer_bindings)[0]];
  b.bindings[id].trusted = false;
  delete b.witness_bindings;                       // required container absent
  expect("R-3: malformed container + trusted:false => binding-malformed alone",
    ["--request", `${P2}/request.json`, "--bindings", writeJson("r3_container_mal.json", b),
     "--independence-policy", `${P2}/independence.json`, "--revocation", `${P2}/revocation.json`, ...CLOCK],
    { class: "AIREP-Core", af: [], aw: ["producer-binding-malformed"], ac: [] });
}

// ---------------------------------------------------------------------------
// R-4 - nested closure is head_ref + signature only, and creates NO new
// requiredness on their members.
// ---------------------------------------------------------------------------
{ // closure retained: unknown member in head_ref / signature stays run-invalid.
  for (const [name, mutate] of [
    ["head_ref", (r) => { r.head_witness.head_ref.note = "x"; }],
    ["signature", (r) => { r.head_witness.signature.note = "x"; }],
  ]) {
    const r = req(); mutate(r);
    const { status } = run(["--request", writeJson(`r4_unknown_${name}.json`, r), ...OPS, ...CLOCK]);
    if (status !== 1) say(`R-4: unknown member in ${name} should be run-invalid (exit 1), got ${status}`);
    else ok(`R-4: unknown member in head_witness.${name} is run-invalid (exit 1)`);
  }
}
{ // no new requiredness: head_ref.record_id absent => witness-head-unresolved.
  const r = req(); delete r.head_witness.head_ref.record_id;
  expect("R-4: head_ref.record_id absent => witness-head-unresolved (not run-invalid)",
    ["--request", writeJson("r4_no_record_id.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", wf: ["witness-head-unresolved"], ww: [] });
}
{ // unusable head_ref.record_id (wrong type) => witness-head-unresolved.
  const r = req(); r.head_witness.head_ref.record_id = 12;
  expect("R-4: head_ref.record_id wrong-typed => witness-head-unresolved",
    ["--request", writeJson("r4_bad_record_id.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-head-unresolved"], ww: [] });
}
{ // signature.value absent => witness-signature-invalid.
  const r = req(); delete r.head_witness.signature.value;
  expect("R-4: signature.value absent => witness-signature-invalid (not run-invalid)",
    ["--request", writeJson("r4_no_sig_value.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", wf: ["witness-signature-invalid"], ww: [] });
}
{ // signature.value wrong-typed => witness-signature-invalid.
  const r = req(); r.head_witness.signature.value = 12;
  expect("R-4: signature.value wrong-typed => witness-signature-invalid",
    ["--request", writeJson("r4_bad_sig_value_type.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-signature-invalid"], ww: [] });
}
{ // cryptographically invalid signature.value => witness-signature-invalid.
  const r = req(); r.head_witness.signature.value = "0".repeat(128);
  expect("R-4: signature.value cryptographically invalid => witness-signature-invalid",
    ["--request", writeJson("r4_forged_sig.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-signature-invalid"], ww: [] });
}
{ // signature.alg informative-only: absence changes neither crypto nor class.
  const r = req(); delete r.head_witness.signature.alg;
  expect("R-4: signature.alg absent => still AIREP-Witnessed, no reason at all",
    ["--request", writeJson("r4_no_sig_alg.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Witnessed", af: [], aw: [], ac: [], wf: [], ww: [] });
}
{ // signature.alg present but naming something else still selects nothing.
  const r = req(); r.head_witness.signature.alg = "ecdsa-p256";
  expect("R-4: signature.alg naming another suite selects nothing => still AIREP-Witnessed",
    ["--request", writeJson("r4_other_sig_alg.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Witnessed", af: [], aw: [], ac: [], wf: [], ww: [] });
}

// ---------------------------------------------------------------------------
// R-7 - a MISSING KNOWN head_witness evidence member is a semantic
// failure/withholding on its own stage; only structure FOREIGN to the harness
// (null / non-object head_witness, or an unknown member) is run-invalid.
// One probe per row of the R-7 table, plus the two pinned divergence risks.
// ---------------------------------------------------------------------------

// Row 1 - head_witness entirely absent => no-witness-supplied (WITHHELD).
{
  const r = req(); delete r.head_witness;
  expect("R-7 row1: head_witness absent => no-witness-supplied in witnessed_withheld",
    ["--request", writeJson("r7_hw_absent.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: [], ww: ["no-witness-supplied"] });
}

// Row 2 - head_witness present but null / non-object => run-invalid, exit 1.
for (const [name, v] of [["null", null], ["array", []], ["string", "x"], ["number", 7], ["boolean", true]]) {
  const r = req(); r.head_witness = v;
  const { status } = run(["--request", writeJson(`r7_hw_${name}.json`, r), ...OPS, ...CLOCK]);
  if (status !== 1) say(`R-7 row2: head_witness as ${name} should be run-invalid (exit 1), got ${status}`);
  else ok(`R-7 row2: head_witness present as ${name} is run-invalid (exit 1)`);
}

// Row 3 - unknown member INSIDE head_witness => run-invalid (closure preserved).
{
  const r = req(); r.head_witness.note = "extra";
  const { status } = run(["--request", writeJson("r7_hw_unknown_member.json", r), ...OPS, ...CLOCK]);
  if (status !== 1) say(`R-7 row3: unknown member in head_witness should be run-invalid, got ${status}`);
  else ok("R-7 row3: unknown member inside head_witness is run-invalid (exit 1)");
}

// Row 4 - claim absent / non-object => witness-claim-invalid (FAILURE).
{
  const r = req(); delete r.head_witness.claim;
  expect("R-7 row4: claim absent => witness-claim-invalid in witnessed_failures",
    ["--request", writeJson("r7_claim_absent.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: ["witness-claim-invalid"], ww: [] });
}
for (const [name, v] of [["string", "x"], ["array", []], ["null", null], ["number", 3]]) {
  const r = req(); r.head_witness.claim = v;
  expect(`R-7 row4: claim as ${name} => witness-claim-invalid`,
    ["--request", writeJson(`r7_claim_${name}.json`, r), ...OPS, ...CLOCK],
    { wf: ["witness-claim-invalid"], ww: [] });
}

// Row 5 - head_ref absent / non-object => witness-head-unresolved (FAILURE),
// reached only because 6a (the claim) is clean.
{
  const r = req(); delete r.head_witness.head_ref;
  expect("R-7 row5: head_ref absent => witness-head-unresolved in witnessed_failures",
    ["--request", writeJson("r7_headref_absent.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: ["witness-head-unresolved"], ww: [] });
}
for (const [name, v] of [["string", "x"], ["array", []], ["null", null]]) {
  const r = req(); r.head_witness.head_ref = v;
  expect(`R-7 row5: head_ref as ${name} => witness-head-unresolved`,
    ["--request", writeJson(`r7_headref_${name}.json`, r), ...OPS, ...CLOCK],
    { wf: ["witness-head-unresolved"], ww: [] });
}

// Row 6 - witness_id absent / non-string => witness-binding-missing (WITHHELD),
// reached only because stage 6 is clean. Note the CHANNEL: this one is WITHHELD
// even though its neighbours on either side are FAILUREs.
{
  const r = req(); delete r.head_witness.witness_id;
  expect("R-7 row6: witness_id absent => witness-binding-missing in witnessed_WITHHELD",
    ["--request", writeJson("r7_witid_absent.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: [], ww: ["witness-binding-missing"] });
}
for (const [name, v] of [["number", 7], ["null", null], ["object", { a: 1 }]]) {
  const r = req(); r.head_witness.witness_id = v;
  expect(`R-7 row6: witness_id as ${name} => witness-binding-missing (withheld)`,
    ["--request", writeJson(`r7_witid_${name}.json`, r), ...OPS, ...CLOCK],
    { wf: [], ww: ["witness-binding-missing"] });
}

// Row 7 - signature absent / non-object, or signature.value absent / wrong-typed
// => witness-signature-invalid (FAILURE), reached only because stage 7 is clean.
{
  const r = req(); delete r.head_witness.signature;
  expect("R-7 row7: signature absent => witness-signature-invalid in witnessed_failures",
    ["--request", writeJson("r7_sig_absent.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: ["witness-signature-invalid"], ww: [] });
}
for (const [name, v] of [["string", "x"], ["array", []], ["null", null], ["number", 3]]) {
  const r = req(); r.head_witness.signature = v;
  expect(`R-7 row7: signature as ${name} => witness-signature-invalid`,
    ["--request", writeJson(`r7_sig_${name}.json`, r), ...OPS, ...CLOCK],
    { wf: ["witness-signature-invalid"], ww: [] });
}

// Row 8 - head_ref / signature present as an OBJECT carrying an unknown member
// stays run-invalid: R-4 is unchanged by R-7. (Re-asserted here so the two
// rulings are measured together rather than only in the R-4 block above.)
for (const [name, mutate] of [
  ["head_ref", (r) => { r.head_witness.head_ref.note = "x"; }],
  ["signature", (r) => { r.head_witness.signature.note = "x"; }],
]) {
  const r = req(); mutate(r);
  const { status } = run(["--request", writeJson(`r7_row8_unknown_${name}.json`, r), ...OPS, ...CLOCK]);
  if (status !== 1) say(`R-7 row8: unknown member in ${name} must stay run-invalid, got ${status}`);
  else ok(`R-7 row8: unknown member in head_witness.${name} stays run-invalid (R-4 unchanged)`);
}

// --- Divergence risk 1: channel assignment follows the closed section 5
// registry. Two WITHHELD reasons and three FAILURE reasons, each asserted in
// the array it belongs to AND asserted absent from the other array.
{
  const CHANNEL_CASES = [
    ["no-witness-supplied", "ww", (r) => { delete r.head_witness; }],
    ["witness-binding-missing", "ww", (r) => { delete r.head_witness.witness_id; }],
    ["witness-claim-invalid", "wf", (r) => { delete r.head_witness.claim; }],
    ["witness-head-unresolved", "wf", (r) => { delete r.head_witness.head_ref; }],
    ["witness-signature-invalid", "wf", (r) => { delete r.head_witness.signature; }],
  ];
  for (const [reason, channel, mutate] of CHANNEL_CASES) {
    const r = req(); mutate(r);
    const want = channel === "ww" ? { wf: [], ww: [reason] } : { wf: [reason], ww: [] };
    expect(`R-7 divergence1: ${reason} is ${channel === "ww" ? "WITHHELD" : "FAILURE"} per section 5`,
      ["--request", writeJson(`r7_channel_${reason}.json`, r), ...OPS, ...CLOCK], want);
  }
}

// --- Divergence risk 2: R-2's dependency precedence still governs. Each probe
// removes TWO known members at once; only the first REACHABLE reason may appear.
{
  const r = req(); delete r.head_witness.claim; delete r.head_witness.signature;
  expect("R-7 divergence2: claim AND signature absent => witness-claim-invalid ALONE",
    ["--request", writeJson("r7_prec_claim_sig.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-claim-invalid"], ww: [] });
}
{
  const r = req(); delete r.head_witness.claim; delete r.head_witness.head_ref;
  delete r.head_witness.witness_id; delete r.head_witness.signature;
  expect("R-7 divergence2: all four members absent => witness-claim-invalid ALONE",
    ["--request", writeJson("r7_prec_all_absent.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-claim-invalid"], ww: [] });
}
{
  const r = req(); r.head_witness = {};
  expect("R-7 divergence2: head_witness as an empty object => witness-claim-invalid ALONE",
    ["--request", writeJson("r7_prec_empty_hw.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: ["witness-claim-invalid"], ww: [] });
}
{
  const r = req(); delete r.head_witness.head_ref; delete r.head_witness.witness_id;
  expect("R-7 divergence2: head_ref AND witness_id absent => witness-head-unresolved ALONE",
    ["--request", writeJson("r7_prec_headref_witid.json", r), ...OPS, ...CLOCK],
    { wf: ["witness-head-unresolved"], ww: [] });
}
{
  const r = req(); delete r.head_witness.witness_id; delete r.head_witness.signature;
  expect("R-7 divergence2: witness_id AND signature absent => witness-binding-missing ALONE",
    ["--request", writeJson("r7_prec_witid_sig.json", r), ...OPS, ...CLOCK],
    { wf: [], ww: ["witness-binding-missing"] });
}
{
  // Stage 10 does NOT depend on stage 7, so an absent witness_id must not
  // suppress freshness: the withheld binding and the failed freshness both
  // report. This pins that R-7 suppressed nothing beyond its own prerequisite.
  const r = req(); delete r.head_witness.witness_id;
  expect("R-7 divergence2: witness_id absent still leaves stage 10 running (no clock => freshness withheld)",
    ["--request", writeJson("r7_prec_witid_noclock.json", r), ...OPS],
    { wf: [], ww: ["freshness-inputs-missing", "witness-binding-missing"] });
}

// ---------------------------------------------------------------------------
// R-8 - stage 7 is three dependent sub-steps: 7a witness identifier usability
// -> 7b binding-store resolution -> 7c revocation. 7a runs BEFORE the store is
// consulted, so an absent or non-string witness_id reports
// witness-binding-missing alone even when the store is malformed. The store is
// not excused: the producer path resolves its own wire id, reaches the gate,
// and still reports producer-binding-malformed for the same store.
// ---------------------------------------------------------------------------

// A store-level malformation: the required witness_bindings container is absent,
// so the whole operator document is malformed. Under the pre-R-8 order this was
// exactly the input that made an absent witness_id report -binding-malformed.
const malformedStore = (name) => {
  const b = bindings();
  delete b.witness_bindings;
  return writeJson(name, b);
};
// A second, independent store-level malformation: an unknown top-level member.
const malformedStore2 = (name) => {
  const b = bindings();
  b.note = "extra";
  return writeJson(name, b);
};
const withStore = (file) => ["--bindings", file,
  "--independence-policy", `${P2}/independence.json`,
  "--revocation", `${P2}/revocation.json`];

{ // The governing combination, stated verbatim by R-8.
  const r = req(); delete r.head_witness.witness_id;
  expect("R-8 governing: witness_id ABSENT + malformed store => witness-binding-missing ALONE",
    ["--request", writeJson("r8_absent_witid_malformed_store.json", r),
     ...withStore(malformedStore("r8_store_no_witness_container.json")), ...CLOCK],
    { class: "AIREP-Core", af: [], aw: ["producer-binding-malformed"], ac: [],
      wf: [], ww: ["witness-binding-missing"] });
}
{ // Same governing combination against the second malformation shape.
  const r = req(); delete r.head_witness.witness_id;
  expect("R-8 governing: witness_id ABSENT + store with unknown top member => witness-binding-missing ALONE",
    ["--request", writeJson("r8_absent_witid_malformed_store2.json", r),
     ...withStore(malformedStore2("r8_store_unknown_member.json")), ...CLOCK],
    { class: "AIREP-Core", af: [], aw: ["producer-binding-malformed"], ac: [],
      wf: [], ww: ["witness-binding-missing"] });
}
// 7a covers every non-string form of the wire id, not just absence.
for (const [name, v] of [["number", 7], ["null", null], ["object", { a: 1 }],
                         ["array", ["x"]], ["boolean", true], ["float", 1.5]]) {
  const r = req(); r.head_witness.witness_id = v;
  expect(`R-8 7a: witness_id as ${name} + malformed store => witness-binding-missing ALONE`,
    ["--request", writeJson(`r8_witid_${name}_malformed_store.json`, r),
     ...withStore(malformedStore(`r8_store_for_${name}.json`)), ...CLOCK],
    { af: [], aw: ["producer-binding-malformed"], ac: [], wf: [], ww: ["witness-binding-missing"] });
}
{ // DISCRIMINATION: the same malformed store, with a valid PRESENT witness_id,
  // must still reach 7b and report witness-binding-malformed. This proves the
  // R-8 fix reordered the gate rather than disabling the malformed path.
  expect("R-8 discrimination: malformed store + present valid witness_id => witness-binding-MALFORMED",
    ["--request", `${P2}/request.json`,
     ...withStore(malformedStore("r8_store_discrim.json")), ...CLOCK],
    { class: "AIREP-Core", af: [], aw: ["producer-binding-malformed"], ac: [],
      wf: [], ww: ["witness-binding-malformed"] });
}
{ // Same, second malformation shape.
  expect("R-8 discrimination: store with unknown top member + present witness_id => witness-binding-MALFORMED",
    ["--request", `${P2}/request.json`,
     ...withStore(malformedStore2("r8_store_discrim2.json")), ...CLOCK],
    { wf: [], ww: ["witness-binding-malformed"] });
}
{ // PRODUCER PATH: the producer resolves its own wire id and does reach the
  // gate, so the same malformed store still yields producer-binding-malformed
  // whether or not the witness id is usable. Asserted here on its own channel.
  const file = malformedStore("r8_store_producer_path.json");
  const v1 = expect("R-8 producer path: malformed store => producer-binding-malformed (witness_id present)",
    ["--request", `${P2}/request.json`, ...withStore(file), ...CLOCK],
    { class: "AIREP-Core", af: [], aw: ["producer-binding-malformed"], ac: [] });
  const r = req(); delete r.head_witness.witness_id;
  const v2 = expect("R-8 producer path: malformed store => producer-binding-malformed (witness_id absent)",
    ["--request", writeJson("r8_producer_path_no_witid.json", r), ...withStore(file), ...CLOCK],
    { class: "AIREP-Core", af: [], aw: ["producer-binding-malformed"], ac: [] });
  if (v1 && v2 && !eq(v1.authenticated_withheld, v2.authenticated_withheld)) {
    say("R-8 producer path: the witness wire id changed the producer channel");
  } else if (v1 && v2) {
    ok("R-8 producer path: identical producer channel with and without a usable witness_id");
  }
}
{ // 7b INTACT, branch 1: a WELL-FORMED store with no map entry for a present,
  // usable id is witness-binding-missing at 7b - a distinct path from 7a.
  const r = req(); r.head_witness.witness_id = "wire:no-such-witness";
  expect("R-8 7b: well-formed store, present id absent from the map => witness-binding-missing",
    ["--request", writeJson("r8_7b_unknown_wire_id.json", r), ...OPS, ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: [], ww: ["witness-binding-missing"] });
}
{ // 7b INTACT, branch 2: same outcome by deleting the map entry instead, with
  // the request's own witness_id left untouched.
  const b = bindings();
  const wireId = Object.keys(b.witness_bindings)[0];
  delete b.witness_bindings[wireId];
  expect("R-8 7b: well-formed store with the map entry removed => witness-binding-missing",
    ["--request", `${P2}/request.json`,
     ...withStore(writeJson("r8_7b_entry_removed.json", b)), ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: [], ww: ["witness-binding-missing"] });
}
{ // 7b INTACT, branch 3: R-3 still governs inside 7b - a malformed referenced
  // ENTRY (well-formed store) with trusted:false is malformed alone.
  const b = bindings();
  const id = b.witness_bindings[Object.keys(b.witness_bindings)[0]];
  b.bindings[id].note = "extra";
  b.bindings[id].trusted = false;
  expect("R-8 7b: R-3 unchanged inside 7b (malformed entry + trusted:false) => malformed alone",
    ["--request", `${P2}/request.json`,
     ...withStore(writeJson("r8_7b_r3_entry.json", b)), ...CLOCK],
    { class: "AIREP-Authenticated", af: [], aw: [], ac: [], wf: [], ww: ["witness-binding-malformed"] });
}
{ // 7c UNREACHED under 7a: an absent witness_id with a malformed revocation
  // snapshot emits no revocation reason at all (7c runs only after an accepted
  // binding), while stage 10 - which does not depend on stage 7 - still runs.
  const r = req(); delete r.head_witness.witness_id;
  expect("R-8 7c: absent witness_id + malformed store, no clock => binding-missing + freshness only",
    ["--request", writeJson("r8_7c_unreached.json", r),
     ...withStore(malformedStore("r8_store_7c.json"))],
    { wf: [], ww: ["freshness-inputs-missing", "witness-binding-missing"] });
}
{ // Regression guard: with a usable id and a well-formed store the untouched
  // case is still cleanly Witnessed - 7a admits the normal path unchanged.
  expect("R-8 regression: untouched P2 still clean AIREP-Witnessed after the 7a gate",
    ["--request", `${P2}/request.json`, ...OPS, ...CLOCK],
    { class: "AIREP-Witnessed", af: [], aw: [], ac: [], wf: [], ww: [] });
}

fs.rmSync(TMP, { recursive: true, force: true });
console.log(bad === 0 ? "RULINGS SELF-CHECK: clean" : `${bad} ruling problems`);
process.exit(bad === 0 ? 0 : 1);
