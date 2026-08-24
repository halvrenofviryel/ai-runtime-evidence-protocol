// Source-review ruling self-check (CLASS_VERIFIER_CONTRACT.md section 9,
// rulings R-1 / R-2 / R-3 / R-4). Every input is constructed here from a corpus
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

fs.rmSync(TMP, { recursive: true, force: true });
console.log(bad === 0 ? "RULINGS SELF-CHECK: clean" : `${bad} ruling problems`);
process.exit(bad === 0 ? 0 : 1);
