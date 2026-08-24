// Exit-code semantics check (contract 6.4, as amended by section 9 R-9 and R-10).
// Builds throwaway inputs inside the working directory only. No expected verdicts
// consulted.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const TMP = "tmp_exitcheck";
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

const P2 = "../corpus/cases/P2";
const base = ["--bindings", `${P2}/bindings.json`, "--independence-policy", `${P2}/independence.json`,
  "--revocation", `${P2}/revocation.json`, "--now", "2026-08-23T12:00:00Z", "--freshness-window", "3600"];

// Section 9 portability note: the committed default schema directory is
// ../../schemas, so this review snapshot passes --schema-dir explicitly.
const SCHEMAS = ["--schema-dir", "../../schemas"];

function run(args) {
  const r = spawnSync(process.execPath, ["class_verifier.mjs", ...SCHEMAS, ...args], { encoding: "utf8" });
  return r.status;
}

// Same, without the snapshot's --schema-dir prefix, for the cases that set it.
function runBare(args) {
  const r = spawnSync(process.execPath, ["class_verifier.mjs", ...args], { encoding: "utf8" });
  return r.status;
}

// exit 1 fixtures
const req = JSON.parse(fs.readFileSync(`${P2}/request.json`, "utf8"));
const mutated = JSON.parse(JSON.stringify(req));
mutated.artifact.integrity.current = "sha256:" + "0".repeat(64);
fs.writeFileSync(path.join(TMP, "hash_mismatch.json"), JSON.stringify(mutated));
const schemaBad = JSON.parse(JSON.stringify(req));
delete schemaBad.artifact.claim;
fs.writeFileSync(path.join(TMP, "schema_bad.json"), JSON.stringify(schemaBad));
fs.writeFileSync(path.join(TMP, "not_json.json"), "{ this is not json");
fs.writeFileSync(path.join(TMP, "bad_bindings.json"), "{ nope");

// E-4 as narrowed by section 9 R-4: the section-0 nested closure covers head_ref
// and signature only, and an unknown member in either is run-invalid (exit 1),
// not a class reason. R-1 withdrew `claim` from that closure.
const P2WIT = "../corpus/cases/P2";
for (const [name, mutate] of [
  ["head_ref", (r) => { r.head_witness.head_ref.note = "x"; }],
  ["signature", (r) => { r.head_witness.signature.note = "x"; }],
]) {
  const r = JSON.parse(fs.readFileSync(`${P2WIT}/request.json`, "utf8"));
  mutate(r);
  fs.writeFileSync(path.join(TMP, `unknown_${name}.json`), JSON.stringify(r));
}

const cases = [
  ["--help", ["--help"], 0],
  ["clean single case", ["--request", `${P2}/request.json`, ...base], 0],
  ["no operator inputs at all", ["--request", `${P2}/request.json`], 0],
  ["unparseable request", ["--request", `${TMP}/not_json.json`, ...base], 1],
  ["unparseable operator file", ["--request", `${P2}/request.json`, "--bindings", `${TMP}/bad_bindings.json`], 1],
  ["stage-1 hash mismatch", ["--request", `${TMP}/hash_mismatch.json`, ...base], 1],
  ["stage-0 schema invalid", ["--request", `${TMP}/schema_bad.json`, ...base], 1],
  ["missing --request", [...base], 2],
  ["unknown option", ["--request", `${P2}/request.json`, "--bogus", "x"], 2],
  ["option without value", ["--request"], 2],
  ["malformed --now (not a datetime)", ["--request", `${P2}/request.json`, "--now", "yesterday", "--freshness-window", "60"], 2],
  ["malformed --now (Feb 30)", ["--request", `${P2}/request.json`, "--now", "2026-02-30T00:00:00Z", "--freshness-window", "60"], 2],
  ["malformed --now (no Z)", ["--request", `${P2}/request.json`, "--now", "2026-08-23T12:00:00", "--freshness-window", "60"], 2],
  ["malformed --freshness-window (non-integer)", ["--request", `${P2}/request.json`, "--now", "2026-08-23T12:00:00Z", "--freshness-window", "1.5"], 2],
  ["malformed --freshness-window (negative)", ["--request", `${P2}/request.json`, "--now", "2026-08-23T12:00:00Z", "--freshness-window", "-1"], 2],
  ["--corpus without --out", ["--corpus", "../corpus"], 2],
  ["--request together with --corpus", ["--corpus", "../corpus", "--request", `${P2}/request.json`, "--out", `${TMP}/never.json`], 2],
  ["unknown member in head_witness.head_ref", ["--request", `${TMP}/unknown_head_ref.json`, ...base], 1],
  ["unknown member in head_witness.signature", ["--request", `${TMP}/unknown_signature.json`, ...base], 1],
];

let bad = 0;
// Section 9 portability note: an unresolvable --schema-dir is a config error.
{
  const got = runBare(["--request", `${P2}/request.json`, "--schema-dir", `${TMP}/nope`]);
  if (got !== 2) { console.log(`FAIL: unresolvable --schema-dir: expected exit 2, got ${got}`); bad++; }
  else console.log("  ok  exit 2  unresolvable --schema-dir");
}
for (const [name, args, want] of cases) {
  const got = run(args);
  if (got !== want) { console.log(`FAIL: ${name}: expected exit ${want}, got ${got}`); bad++; }
  else console.log(`  ok  exit ${got}  ${name}`);
}

// ---------------------------------------------------------------------------
// Section 9 R-9 / R-10 discrimination probes (run-validity / CLI closure).
// Both build every input themselves under TMP by COPYING frozen fixture bytes;
// the frozen corpus is never added to or altered, and no expected.json is read.
// ---------------------------------------------------------------------------

// R-9 -- `--request` together with `--out` is a CLI usage error. Three separate
// things are demanded, not just the exit code: exit 2, NO verdict on stdout, and
// the `--out` path neither created nor modified.
{
  const outPath = path.join(TMP, "r9_must_not_be_written.json");
  const r = spawnSync(process.execPath,
    ["class_verifier.mjs", ...SCHEMAS, "--request", `${P2}/request.json`, ...base, "--out", outPath],
    { encoding: "utf8" });
  const problems = [];
  if (r.status !== 2) problems.push(`expected exit 2, got ${r.status}`);
  if (r.stdout !== "") problems.push(`stdout not empty (${r.stdout.length} bytes) -- a verdict was emitted`);
  if (fs.existsSync(outPath)) problems.push("the --out path was created");
  if (problems.length) { console.log("FAIL: R-9 --request + --out: " + problems.join(" | ")); bad++; }
  else console.log("  ok  exit 2  R-9 --request + --out: no verdict on stdout, no file created");
}
{ // R-9, second half of "neither created nor modified": a PRE-EXISTING file at the
  // --out path must come back byte-identical.
  const outPath = path.join(TMP, "r9_preexisting.json");
  const sentinel = '{"sentinel":"untouched"}\n';
  fs.writeFileSync(outPath, sentinel);
  const r = spawnSync(process.execPath,
    ["class_verifier.mjs", ...SCHEMAS, "--request", `${P2}/request.json`, ...base, "--out", outPath],
    { encoding: "utf8" });
  const problems = [];
  if (r.status !== 2) problems.push(`expected exit 2, got ${r.status}`);
  if (r.stdout !== "") problems.push("stdout not empty -- a verdict was emitted");
  if (fs.readFileSync(outPath, "utf8") !== sentinel) problems.push("the pre-existing --out file was modified");
  if (problems.length) { console.log("FAIL: R-9 pre-existing --out: " + problems.join(" | ")); bad++; }
  else console.log("  ok  exit 2  R-9 --request + existing --out: file left byte-identical");
}
{ // R-9 discrimination: the same request WITHOUT --out is still a normal single
  // case -- exit 0 with the verdict on stdout. The gate rejects the flag, not the mode.
  const r = spawnSync(process.execPath,
    ["class_verifier.mjs", ...SCHEMAS, "--request", `${P2}/request.json`, ...base],
    { encoding: "utf8" });
  if (r.status !== 0 || r.stdout.trim() === "") {
    console.log(`FAIL: R-9 discrimination: --request alone expected exit 0 with a verdict, got exit ${r.status}, ${r.stdout.length} stdout bytes`);
    bad++;
  } else console.log("  ok  exit 0  R-9 discrimination: --request alone still emits a verdict to stdout");
}

// R-10 -- a duplicate (chain_id, record_id) tuple in the produced verdict set is
// run-invalid: exit 1 and NO results file. The duplicate corpus is assembled here
// by copying one frozen case's bytes into two scratch case directories.
function scratchCorpus(name, cases) {
  const root = path.join(TMP, name);
  const index = [];
  for (const [caseId, src] of cases) {
    const dst = path.join(root, "cases", caseId);
    fs.mkdirSync(dst, { recursive: true });
    const files = {};
    for (const [key, file] of [["bindings", "bindings.json"], ["clock", "clock.json"],
      ["independence", "independence.json"], ["request", "request.json"], ["revocation", "revocation.json"]]) {
      const from = path.join(src, file);
      if (!fs.existsSync(from)) continue;
      fs.copyFileSync(from, path.join(dst, file));
      files[key] = `cases/${caseId}/${file}`;
    }
    index.push({ case_id: caseId, files });
  }
  fs.writeFileSync(path.join(root, "case_index.json"), JSON.stringify(index));
  return root;
}
{
  // D1 and D2 are byte-copies of the same frozen case, so the two verdicts carry
  // the identical (chain_id, record_id) tuple.
  const dir = scratchCorpus("dup_corpus", [["D1", P2], ["D2", P2]]);
  const outPath = path.join(TMP, "r10_must_not_be_written.json");
  const r = spawnSync(process.execPath,
    ["class_verifier.mjs", ...SCHEMAS, "--corpus", dir, "--out", outPath], { encoding: "utf8" });
  const problems = [];
  if (r.status !== 1) problems.push(`expected exit 1, got ${r.status}`);
  if (fs.existsSync(outPath)) problems.push("a results file was emitted for an invalid run");
  if (problems.length) { console.log("FAIL: R-10 duplicate tuple: " + problems.join(" | ")); bad++; }
  else console.log("  ok  exit 1  R-10 duplicate (chain_id, record_id) tuple: no results file");
}
{ // R-10, write ordering: a PRE-EXISTING results file must also be left untouched
  // -- uniqueness is established before any write.
  const dir = scratchCorpus("dup_corpus2", [["D1", P2], ["D2", P2]]);
  const outPath = path.join(TMP, "r10_preexisting.json");
  const sentinel = '{"sentinel":"untouched"}\n';
  fs.writeFileSync(outPath, sentinel);
  const r = spawnSync(process.execPath,
    ["class_verifier.mjs", ...SCHEMAS, "--corpus", dir, "--out", outPath], { encoding: "utf8" });
  const problems = [];
  if (r.status !== 1) problems.push(`expected exit 1, got ${r.status}`);
  if (fs.readFileSync(outPath, "utf8") !== sentinel) problems.push("the pre-existing results file was overwritten");
  if (problems.length) { console.log("FAIL: R-10 write ordering: " + problems.join(" | ")); bad++; }
  else console.log("  ok  exit 1  R-10 write ordering: pre-existing results file left byte-identical");
}
{ // R-10 discrimination: the same two-case batch shape with DISTINCT tuples is a
  // normal valid run -- exit 0, results file with two verdicts. The gate rejects
  // duplicates, not multi-case batches.
  const dir = scratchCorpus("distinct_corpus", [["D1", "../corpus/cases/P1"], ["D2", P2]]);
  const outPath = path.join(TMP, "r10_distinct.json");
  const r = spawnSync(process.execPath,
    ["class_verifier.mjs", ...SCHEMAS, "--corpus", dir, "--out", outPath], { encoding: "utf8" });
  const problems = [];
  if (r.status !== 0) problems.push(`expected exit 0, got ${r.status} :: ${r.stderr.trim()}`);
  else {
    const v = JSON.parse(fs.readFileSync(outPath, "utf8")).verdicts;
    if (v.length !== 2) problems.push(`expected 2 verdicts, got ${v.length}`);
    else if (v[0].artifact_ref.chain_id === v[1].artifact_ref.chain_id
             && v[0].artifact_ref.record_id === v[1].artifact_ref.record_id) {
      problems.push("the control batch did not actually carry distinct tuples");
    }
  }
  if (problems.length) { console.log("FAIL: R-10 discrimination: " + problems.join(" | ")); bad++; }
  else console.log("  ok  exit 0  R-10 discrimination: distinct-tuple two-case batch still writes its results file");
}

fs.rmSync(TMP, { recursive: true, force: true });
console.log(bad === 0 ? "EXIT-CODE SELF-CHECK: clean" : `${bad} exit-code problems`);
// Failure MUST reach the process exit status. Without this line the script printed
// its failures and still exited 0, so any CI gate reading only the exit status would
// have read a failing exit-code surface as clean. Proven by exitcode_check_selftest.mjs.
process.exit(bad === 0 ? 0 : 1);
