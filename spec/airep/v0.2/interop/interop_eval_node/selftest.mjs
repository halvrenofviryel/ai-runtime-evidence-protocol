// Self-test for the Node reference interop evaluator (post-erratum).
//
// Synthetic inputs only, constructed here. NO corpus bytes and NO scenario
// bundle artifacts are created: corpus construction is on hold (evaluator
// contract section 12 / section 13), and a signed four-artifact bundle is
// precisely what this file must not invent. The consequence is stated plainly:
// the MEASURED end-to-end path -- real frozen-verifier invocation over sealed,
// bound artifacts -- is NOT covered here and cannot be until the corpus exists.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  jcs, byteCompare, decodeDecimal, checkNumberToken, scanJsonNumbers,
  checkBundlePath, resolveRef, predicateRA, predicateRB, predicateRC, mapLevel1,
  verdictShapeViolation, isDirectInvocation, parseArgs,
} from "./interop_eval.mjs";

// NODE-IMP-1: fileURLToPath, never new URL(import.meta.url).pathname. The old
// spelling percent-encoded this very path, so the self-test could not find the
// evaluator on a repository path containing a literal space.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const EVAL = path.join(HERE, "interop_eval.mjs");

let failures = 0;
let checks = 0;
function check(name, cond, detail) {
  checks++;
  if (!cond) { failures++; console.log(`FAIL: ${name}${detail ? " -- " + detail : ""}`); }
}
const show = (v) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? `${x}n` : x));
function eq(name, got, want) {
  check(name, show(got) === show(want), `got ${show(got)}, want ${show(want)}`);
}

const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// ---------------------------------------------------------------------------
// 1. JCS
// ---------------------------------------------------------------------------

eq("jcs sorts members", jcs({ b: 1, a: 2 }), '{"a":2,"b":1}');
eq("jcs preserves array order", jcs([3, 1, 2]), "[3,1,2]");
eq("jcs nests", jcs({ z: { y: [1, { x: null }] } }), '{"z":{"y":[1,{"x":null}]}}');
eq("jcs escapes", jcs({ "a/b": 'q"' }), '{"a/b":"q\\""}');
eq("jcs member order is UTF-16 code unit", jcs({ "ä": 1, z: 2 }), '{"z":2,"ä":1}');
eq("jcs is stable across member order", jcs({ a: 1, b: 2 }), jcs({ b: 2, a: 1 }));

// Independent reference: the byte string and digest below were produced OUTSIDE
// this module, by Python's json.dumps(sort_keys=True, separators=(",", ":")),
// which coincides with RFC 8785 for ASCII keys and integer numbers. Everything
// else in this file recomputes expected envelope digests with the module's own
// jcs(), so this is the one check that would catch a canonicalizer defect
// rather than reproduce it.
const REF_ARTIFACT = {
  airep_version: "0.2", artifact_type: "decision", chain_id: "synth.chain",
  record_id: "synth-a", sequence: 0,
};
const REF_BYTES = '{"artifact":{"airep_version":"0.2","artifact_type":"decision",'
  + '"chain_id":"synth.chain","record_id":"synth-a","sequence":0},"related_artifacts":[]}';
eq("jcs matches an independently produced canonical form",
  jcs({ artifact: REF_ARTIFACT, related_artifacts: [] }), REF_BYTES);
eq("its digest matches the independently computed one",
  sha(Buffer.from(REF_BYTES, "utf8")),
  "be7c67caa9483b5abb2c314646c0fab4411dcfbeed3f7f610e7405f6d6b97607");

// ---------------------------------------------------------------------------
// 2. UTF-8 byte ordering (sections 5, 5.1 and 8.4)
// ---------------------------------------------------------------------------

check("byteCompare a<b", byteCompare("a", "b") < 0);
check("byteCompare equal", byteCompare("a", "a") === 0);
// The case where UTF-8 byte order and UTF-16 code-unit order disagree:
// U+FF3A (fullwidth Z) vs U+1D400 (a surrogate pair). In UTF-16 the surrogate
// lead 0xD835 sorts BEFORE 0xFF3A; in UTF-8 the 4-byte 0xF0.. sorts AFTER.
const wide = "Ｚ";
const astral = "\u{1D400}";
check("byteCompare disagrees with default sort where it must",
  byteCompare(astral, wide) > 0 && [astral, wide].sort()[0] === astral);

// ---------------------------------------------------------------------------
// 3. Numeric preflight (section 5.1) -- the bound is on VALUE, not spelling
// ---------------------------------------------------------------------------

eq("integer at the bound passes", checkNumberToken("9007199254740991"), null);
eq("negative integer at the bound passes", checkNumberToken("-9007199254740991"), null);
check("integer one past the bound fails", checkNumberToken("9007199254740992") !== null);
check("integer far past the bound fails", checkNumberToken("9007199254740993") !== null);
check("1e20 is integer-valued and past the bound", checkNumberToken("1e20") !== null);
check("1.0e20 is the same value in another spelling", checkNumberToken("1.0e20") !== null);
check("9007199254740991e0 is at the bound and passes",
  checkNumberToken("9007199254740991e0") === null);
check("1e400 is not finite", checkNumberToken("1e400") === "not finite / not IEEE-754 representable");
check("-1e400 is not finite", checkNumberToken("-1e400") === "not finite / not IEEE-754 representable");
eq("0.1 round-trips", checkNumberToken("0.1"), null);
eq("0.10 round-trips (same value)", checkNumberToken("0.10"), null);
eq("zero passes", checkNumberToken("0"), null);
eq("-0 passes", checkNumberToken("-0"), null);
eq("1.5e-7 passes", checkNumberToken("1.5e-7"), null);
eq("1.5 is not integer-valued and is judged only on finiteness",
  checkNumberToken("1.5"), null);
check("over-precise decimal is rejected", checkNumberToken("1.00000000000000000001") !== null);
eq("sequence-like values pass", checkNumberToken("42"), null);

eq("decodeDecimal normalizes trailing zeros", decodeDecimal("1.500"), decodeDecimal("1.5"));
eq("decodeDecimal handles exponents", decodeDecimal("15e-1"), decodeDecimal("1.5"));

// ---------------------------------------------------------------------------
// 4. JSON number scanner -- pointers (RFC 6901)
// ---------------------------------------------------------------------------

const scanned = scanJsonNumbers(JSON.stringify({
  sequence: 3,
  profiles: { "airep.k": { deep: [0, { "a/b": 7, "c~d": 8 }] } },
  s: "not a number: 5",
}));
eq("scanner finds every number and escapes pointers",
  scanned.map((x) => x.pointer).sort(), [
    "/profiles/airep.k/deep/0",
    "/profiles/airep.k/deep/1/a~1b",
    "/profiles/airep.k/deep/1/c~0d",
    "/sequence",
  ]);
eq("scanner keeps the source spelling",
  scanJsonNumbers('{"n": 9007199254740993}')[0].token, "9007199254740993");
check("scanner ignores numerals inside strings", scanJsonNumbers('{"s":"1234"}').length === 0);

// ---------------------------------------------------------------------------
// 5. Manifest path rules (section 5)
// ---------------------------------------------------------------------------

eq("a normal bundle path is accepted", checkBundlePath("artifacts/decision.json"), null);
check("an absolute path is rejected", checkBundlePath("/etc/passwd") !== null);
check("a '..' segment is rejected", checkBundlePath("a/../b.json") !== null);
check("a bare '..' is rejected", checkBundlePath("..") !== null);
check("a backslash is rejected", checkBundlePath("a\\b.json") !== null);
check("a '.' segment is rejected", checkBundlePath("./a.json") !== null);
check("an empty segment is rejected", checkBundlePath("a//b.json") !== null);
check("a trailing slash is rejected", checkBundlePath("a/") !== null);
check("the root manifest must not be listed", checkBundlePath("manifest.json") !== null);
eq("a nested file called manifest.json is fine",
  checkBundlePath("sub/manifest.json"), null);

// ---------------------------------------------------------------------------
// 6. Reference resolution (section 5, frozen section 0 semantics)
// ---------------------------------------------------------------------------

const A = (record_id, chain_id) => ({ bundlePath: record_id, value: { record_id, chain_id } });
const set1 = [A("r1", "c1"), A("r2", "c1"), A("r1", "c2")];

eq("record_id + chain_id resolves uniquely",
  resolveRef({ record_id: "r1", chain_id: "c1" }, set1).state, "resolved");
eq("record_id alone is ambiguous when two chains carry it",
  resolveRef({ record_id: "r1" }, set1).state, "ambiguous");
eq("no match is unresolved", resolveRef({ record_id: "nope" }, set1).state, "unresolved");
eq("a non-object reference is unresolved", resolveRef("r1", set1).state, "unresolved");
eq("chain_id that matches nothing is unresolved",
  resolveRef({ record_id: "r1", chain_id: "c9" }, set1).state, "unresolved");

// ---------------------------------------------------------------------------
// 7. The three predicates (section 6)
// ---------------------------------------------------------------------------

function graph(overrides = {}) {
  const dec = { record_id: "iop-dec", chain_id: "c", artifact_type: "decision" };
  const ctl = {
    record_id: "iop-ctl", chain_id: "c", artifact_type: "control",
    decision_ref: { record_id: "iop-dec" },
    authorized_action_digest: "sha256:" + "a".repeat(64),
  };
  const exe = {
    record_id: "iop-exe", chain_id: "c", artifact_type: "execution",
    decision_ref: { record_id: "iop-dec" },
    executed_action_digest: "sha256:" + "a".repeat(64),
  };
  const eff = {
    record_id: "iop-eff", chain_id: "c", artifact_type: "effect",
    decision_ref: { record_id: "iop-dec" },
    execution_ref: { record_id: "iop-exe" },
    observer_relationship: "independent",
  };
  const values = { decision: dec, control: ctl, execution: exe, effect: eff };
  for (const [fam, patch] of Object.entries(overrides)) Object.assign(values[fam], patch);
  const arts = Object.values(values).map((v) => ({ bundlePath: v.record_id, value: v }));
  const byFamily = new Map(Object.entries(values)
    .map(([fam, v]) => [fam, arts.find((a) => a.value === v)]));
  return { arts, byFamily };
}

function verdicts(byFamily, observerAssessment) {
  const m = new Map();
  for (const [, a] of byFamily) {
    m.set(a.bundlePath, {
      verifierResult: {
        observer_assessment: a.value.artifact_type === "effect" ? observerAssessment : "not_applicable",
      },
    });
  }
  return m;
}

{
  const { arts, byFamily } = graph();
  eq("R-A passes on a fully resolving graph", predicateRA(byFamily, arts).outcome, "PASS");
  eq("R-B passes on equal digests", predicateRB(byFamily).outcome, "PASS");
  eq("R-C passes when the frozen assessment is independent",
    predicateRC(byFamily, verdicts(byFamily, "independent")).outcome, "PASS");
}
{
  // IOP-R-XREF shape: the Effect's decision_ref names no artifact in the bundle.
  const { arts, byFamily } = graph({ effect: { decision_ref: { record_id: "iop-absent-0000" } } });
  eq("R-A fails on an unresolved decision_ref", predicateRA(byFamily, arts).outcome, "FAIL");
  eq("R-B is unaffected by an XREF break", predicateRB(byFamily).outcome, "PASS");
}
{
  // IOP-R-TOCTOU shape: the Execution's executed digest diverges.
  const { arts, byFamily } = graph({ execution: { executed_action_digest: "sha256:" + "b".repeat(64) } });
  eq("R-A is unaffected by a TOCTOU break", predicateRA(byFamily, arts).outcome, "PASS");
  eq("R-B fails on unequal digests", predicateRB(byFamily).outcome, "FAIL");
}
{
  // Exact string comparison: no case folding, no normalization, no re-hashing.
  const { byFamily } = graph({ execution: { executed_action_digest: "sha256:" + "A".repeat(64) } });
  eq("R-B does not case-fold", predicateRB(byFamily).outcome, "FAIL");
}
{
  // R-A is unique reference resolution and nothing more: it does NOT check
  // that a decision_ref resolves to an artifact of the Decision family.
  const { arts, byFamily } = graph({ control: { decision_ref: { record_id: "iop-exe" } } });
  eq("R-A does not add an unpinned family check", predicateRA(byFamily, arts).outcome, "PASS");
}
{
  // IOP-R-INDEP shape: wire says independent, the frozen assessment is unknown.
  const { byFamily } = graph();
  eq("R-C fails on independent-vs-unknown",
    predicateRC(byFamily, verdicts(byFamily, "unknown")).outcome, "FAIL");
}
{
  const { byFamily } = graph({ effect: { observer_relationship: "unknown" } });
  eq("R-C passes when the wire does not claim independence",
    predicateRC(byFamily, verdicts(byFamily, "unknown")).outcome, "PASS");
}
{
  // The evaluator never re-derives independence; with no frozen verdict there
  // is nothing to take it from, and the predicate fails closed.
  const { byFamily } = graph();
  const empty = new Map([...byFamily].map(([, a]) => [a.bundlePath, { verifierResult: null }]));
  eq("R-C fails closed with no frozen verdict", predicateRC(byFamily, empty).outcome, "FAIL");
}

// ---------------------------------------------------------------------------
// 8. Frozen-verdict shape assertion
// ---------------------------------------------------------------------------

const OK_VERDICT = {
  class: "AIREP-Authenticated", observer_assessment: "not_applicable",
  authenticated_failures: [], authenticated_withheld: [], authenticated_caveats: [],
  witnessed_failures: [], witnessed_withheld: [],
};
eq("a well-shaped verdict passes", verdictShapeViolation(OK_VERDICT), null);
check("a missing channel is caught",
  verdictShapeViolation({ ...OK_VERDICT, authenticated_withheld: undefined }) !== null);
check("an illegal class is caught",
  verdictShapeViolation({ ...OK_VERDICT, class: "AIREP-Perfect" }) !== null);
check("an illegal observer_assessment is caught",
  verdictShapeViolation({ ...OK_VERDICT, observer_assessment: "probably" }) !== null);

// ---------------------------------------------------------------------------
// 9. Level-1 mapping order (section 7)
// ---------------------------------------------------------------------------

const NA = { R_A: "NOT_APPLICABLE", R_B: "NOT_APPLICABLE", R_C: "NOT_APPLICABLE" };
const PASS3 = { R_A: "PASS", R_B: "PASS", R_C: "PASS" };
eq("clean bundle maps to ACCEPT", mapLevel1(false, PASS3), "ACCEPT");
eq("single-artifact positive maps to ACCEPT", mapLevel1(false, NA), "ACCEPT");
eq("a rejecting artifact wins over everything",
  mapLevel1(true, { R_A: "FAIL", R_B: "FAIL", R_C: "FAIL" }), "REJECT");
eq("R-C precedes R-A/R-B",
  mapLevel1(false, { R_A: "FAIL", R_B: "FAIL", R_C: "FAIL" }), "INDEPENDENCE_NOT_ESTABLISHED");
eq("R-A failure maps to RECONCILIATION_MISMATCH",
  mapLevel1(false, { R_A: "FAIL", R_B: "PASS", R_C: "PASS" }), "RECONCILIATION_MISMATCH");
eq("R-B failure maps to RECONCILIATION_MISMATCH",
  mapLevel1(false, { R_A: "PASS", R_B: "FAIL", R_C: "PASS" }), "RECONCILIATION_MISMATCH");
eq("NOT_APPLICABLE is never read as a failure", mapLevel1(false, NA), "ACCEPT");

// ---------------------------------------------------------------------------
// 10. CLI parsing
// ---------------------------------------------------------------------------

function usageRejects(name, argv) {
  let threw = false;
  try { parseArgs(argv); } catch { threw = true; }
  check(name, threw);
}
usageRejects("--bundle is required", []);
usageRejects("an unknown option is rejected", ["--bundle", "d", "--nope", "x"]);
usageRejects("a repeated option is rejected", ["--bundle", "a", "--bundle", "b"]);
usageRejects("a valueless option is rejected", ["--bundle"]);
usageRejects("--help evaluates nothing", ["--help"]);
usageRejects("a positional argument is rejected", ["x"]);
// Clock flags are gone: no official W1 bundle carries a clock input.
usageRejects("--now is not an accepted option", ["--bundle", "d", "--now", "z"]);
usageRejects("--freshness-window is not an accepted option", ["--bundle", "d", "--freshness-window", "1"]);

// ---------------------------------------------------------------------------
// 11. Bundle fixtures and the process contract (sections 5, 8.2, 8.5)
// ---------------------------------------------------------------------------

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "interop-node-selftest-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));

function run(args, evalPath = EVAL) {
  const p = spawnSync(process.execPath, [evalPath, ...args], { encoding: "utf8" });
  return { code: p.status, out: p.stdout, err: p.stderr };
}

const BINDINGS = JSON.stringify({ bindings: {}, producer_bindings: {}, witness_bindings: {} });
const POLICY = JSON.stringify({ independent_pairs: [], non_independent_pairs: [] });
const REVOCATION = JSON.stringify({ snapshot_id: "synth.snapshot", bindings: {} });

// Builds a bundle whose manifest is correct by construction, then hands the
// manifest object to `mutate` so a single rule can be broken in isolation.
function mkBundle(name, {
  scenarioId = "IOP-P-DEC",
  artifacts = { "artifacts/a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision"}' },
  operator = { bindings: BINDINGS, independence_policy: POLICY, revocation: REVOCATION },
  extraFiles = {},
  mutate = null,
  corrupt = null,
} = {}) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const entries = [];
  const write = (rel, content, role) => {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
    entries.push({ path: rel, role, sha256: rel === corrupt ? "0".repeat(64) : sha(Buffer.from(content)) });
  };
  for (const [rel, content] of Object.entries(artifacts)) write(rel, content, "artifact");
  for (const [role, content] of Object.entries(operator)) {
    write(`operator/${role}.json`, content, role);
  }
  for (const [rel, spec] of Object.entries(extraFiles)) write(rel, spec.content, spec.role);
  entries.sort((a, b) => byteCompare(a.path, b.path));
  const manifest = { manifest_version: "1", scenario_id: scenarioId, files: entries };
  if (mutate !== null) mutate(manifest, dir);
  fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(manifest, null, 1));
  return dir;
}

const RESULT_MEMBERS = [
  "artifacts", "evaluator_version", "level1", "measurement_status", "nonmeasurement",
  "predicates", "scenario_id", "verifier_digests", "withheld_reasons",
];

function parseOne(name, out) {
  const v = JSON.parse(out);
  eq(`${name}: result object carries exactly the pinned member set`,
    Object.keys(v).sort(), RESULT_MEMBERS);
  return v;
}

// --- exit 2: CLI usage errors, stdout silent -------------------------------
for (const [name, args] of [
  ["no --bundle", []],
  ["unknown option", ["--bundle", tmp, "--nope", "x"]],
  ["repeated option", ["--bundle", "a", "--bundle", "b"]],
  ["--help", ["--help"]],
]) {
  const r = run(args);
  eq(`${name} exits 2`, r.code, 2);
  check(`${name} writes nothing to stdout`, r.out === "", JSON.stringify(r.out));
}

// --- exit 1: bundle identity never established, and ONLY that --------------
{
  const r = run(["--bundle", path.join(tmp, "absent-dir")]);
  eq("an absent bundle directory exits 1", r.code, 1);
  check("an absent bundle writes nothing to stdout", r.out === "");
}
{
  const dir = path.join(tmp, "nomanifest");
  fs.mkdirSync(dir, { recursive: true });
  const r = run(["--bundle", dir]);
  eq("an absent manifest.json exits 1", r.code, 1);
  check("an absent manifest writes nothing to stdout", r.out === "");
}
{
  const dir = path.join(tmp, "badmanifest");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "manifest.json"), "{ not json");
  const r = run(["--bundle", dir]);
  eq("an unparseable manifest exits 1", r.code, 1);
  check("an unparseable manifest writes nothing to stdout", r.out === "");
}
{
  const dir = path.join(tmp, "unknownscenario");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "manifest.json"),
    JSON.stringify({ manifest_version: "1", scenario_id: "SYNTH-1", files: [] }));
  const r = run(["--bundle", dir]);
  eq("a scenario_id outside the registered twelve exits 1", r.code, 1);
  check("an unregistered scenario writes nothing to stdout", r.out === "");
}
{
  const dir = path.join(tmp, "manifestarray");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "manifest.json"), "[]");
  eq("a manifest that is not an object exits 1", run(["--bundle", dir]).code, 1);
}

// --- exit 3: identity established, one result object -----------------------
// Every case below asserts the pinned reason AND the pinned status pairing.
function expectNonMeasured(name, dir, reason, status = "ERROR", extra = null) {
  const r = run(["--bundle", dir]);
  eq(`${name} exits 3`, r.code, 3);
  if (r.code !== 3) return null;
  const v = parseOne(name, r.out);
  eq(`${name} names the scenario`, typeof v.scenario_id, "string");
  eq(`${name} reason`, v.nonmeasurement.reason, reason);
  eq(`${name} status`, v.measurement_status, status);
  eq(`${name} level1 is null`, v.level1, null);
  eq(`${name} predicates is null`, v.predicates, null);
  eq(`${name} nonmeasurement is closed`,
    Object.keys(v.nonmeasurement).sort(),
    reason === "numeric-preflight-violation" ? ["detail", "json_pointer", "reason"] : ["detail", "reason"]);
  check(`${name} detail is a non-empty string`,
    typeof v.nonmeasurement.detail === "string" && v.nonmeasurement.detail.length > 0);
  if (extra !== null) extra(v, r);
  return v;
}

expectNonMeasured("an unknown manifest member",
  mkBundle("m-unknown", { mutate: (m) => { m.surprise = 1; } }), "manifest-invalid");
expectNonMeasured("a missing manifest_version",
  mkBundle("m-noversion", { mutate: (m) => { delete m.manifest_version; } }), "manifest-invalid");
expectNonMeasured("manifest_version as a number",
  mkBundle("m-numversion", { mutate: (m) => { m.manifest_version = 1; } }), "manifest-invalid");
expectNonMeasured("manifest_version other than \"1\"",
  mkBundle("m-v2", { mutate: (m) => { m.manifest_version = "2"; } }), "manifest-invalid");
expectNonMeasured("files out of byte order",
  mkBundle("m-unsorted", { mutate: (m) => { m.files.reverse(); } }), "manifest-invalid");
expectNonMeasured("a files[] entry with an extra member",
  mkBundle("m-extraentry", { mutate: (m) => { m.files[0].note = "x"; } }), "manifest-invalid");
expectNonMeasured("a files[] entry missing role",
  mkBundle("m-norole", { mutate: (m) => { delete m.files[0].role; } }), "manifest-invalid");
expectNonMeasured("a role outside the closed set",
  mkBundle("m-badrole", { mutate: (m) => { m.files[0].role = "head_witness"; } }), "manifest-invalid");
expectNonMeasured("a sha256 in the wire prefix form",
  mkBundle("m-prefixhex", { mutate: (m) => { m.files[0].sha256 = "sha256:" + "0".repeat(64); } }),
  "manifest-invalid");
expectNonMeasured("an uppercase sha256",
  mkBundle("m-upperhex", { mutate: (m) => { m.files[0].sha256 = m.files[0].sha256.toUpperCase(); } }),
  "manifest-invalid");
expectNonMeasured("a duplicate path",
  mkBundle("m-dup", { mutate: (m) => { m.files.splice(1, 0, { ...m.files[0] }); } }),
  "manifest-invalid");
expectNonMeasured("a path escaping the bundle",
  mkBundle("m-escape", { mutate: (m) => { m.files[0].path = "../outside.json"; } }),
  "manifest-invalid");
expectNonMeasured("the root manifest listed in files[]",
  mkBundle("m-selflisted", {
    mutate: (m) => {
      m.files.push({ path: "manifest.json", role: "artifact", sha256: "0".repeat(64) });
      m.files.sort((a, b) => byteCompare(a.path, b.path));
    },
  }), "manifest-invalid");
expectNonMeasured("a file on disk absent from files[]",
  mkBundle("m-unlisted", { mutate: (_m, dir) => { fs.writeFileSync(path.join(dir, "stray.json"), "{}"); } }),
  "manifest-invalid");
expectNonMeasured("a files[] entry with no file on disk",
  mkBundle("m-missing", {
    mutate: (m) => {
      m.files.push({ path: "zz-ghost.json", role: "artifact", sha256: "0".repeat(64) });
      m.files.sort((a, b) => byteCompare(a.path, b.path));
    },
  }), "bundle-file-missing");
expectNonMeasured("a file failing its manifest digest",
  mkBundle("m-digest", { corrupt: "artifacts/a.json" }), "manifest-digest-mismatch");
expectNonMeasured("a listed file that is not parseable JSON",
  mkBundle("m-nonjson", { artifacts: { "artifacts/a.json": "{ not json" } }), "bundle-json-invalid");

// Symbolic links are forbidden anywhere under the bundle, including one whose
// target resolves inside it.
{
  const dir = mkBundle("m-symlink");
  let made = true;
  try {
    fs.symlinkSync("a.json", path.join(dir, "artifacts", "link.json"));
  } catch { made = false; }
  if (made) {
    expectNonMeasured("a symlink inside the bundle", dir, "manifest-invalid",
      "ERROR", (v) => check("the symlink is named", /symbolic link/i.test(v.nonmeasurement.detail),
        v.nonmeasurement.detail));
  } else {
    console.log("SKIPPED: symlink check -- this filesystem refused symlink creation");
  }
}

// Bundle shape (section 5).
expectNonMeasured("a single-artifact scenario with two artifacts",
  mkBundle("s-twoart", {
    scenarioId: "IOP-B-DEC",
    artifacts: {
      "artifacts/a.json": '{"record_id":"r1","artifact_type":"decision"}',
      "artifacts/b.json": '{"record_id":"r2","artifact_type":"control"}',
    },
  }), "bundle-shape-invalid");
expectNonMeasured("a reconciliation scenario with one artifact",
  mkBundle("s-oneart", { scenarioId: "IOP-R-CLEAN" }), "bundle-shape-invalid");
expectNonMeasured("a reconciliation scenario missing a family",
  mkBundle("s-nofam", {
    scenarioId: "IOP-R-CLEAN",
    artifacts: {
      "artifacts/1.json": '{"record_id":"r1","artifact_type":"decision"}',
      "artifacts/2.json": '{"record_id":"r2","artifact_type":"control"}',
      "artifacts/3.json": '{"record_id":"r3","artifact_type":"execution"}',
      "artifacts/4.json": '{"record_id":"r4","artifact_type":"control"}',
    },
  }), "bundle-shape-invalid");
expectNonMeasured("a bundle with no bindings input",
  mkBundle("s-nobindings", { operator: { independence_policy: POLICY, revocation: REVOCATION } }),
  "bundle-shape-invalid");
expectNonMeasured("a bundle with two revocation inputs",
  mkBundle("s-tworevocation", {
    extraFiles: { "operator/revocation2.json": { content: REVOCATION, role: "revocation" } },
  }), "bundle-shape-invalid");
expectNonMeasured("a W1 bundle carrying a clock input",
  mkBundle("s-clock", {
    extraFiles: { "operator/clock.json": { content: '{"now":"2026-01-01T00:00:00Z"}', role: "clock" } },
  }), "bundle-shape-invalid");

// Numeric preflight -- json_pointer is mandatory and machine-readable.
expectNonMeasured("an out-of-envelope number",
  mkBundle("n-bignum", {
    artifacts: {
      "artifacts/a.json":
        '{"record_id":"r","chain_id":"c","artifact_type":"decision","profiles":{"x.y":{"n":9007199254740993}}}',
    },
  }), "numeric-preflight-violation", "ERROR",
  (v) => eq("the offending JSON Pointer is machine-readable",
    v.nonmeasurement.json_pointer, "/profiles/x.y/n"));
expectNonMeasured("1e20 written in exponential form",
  mkBundle("n-1e20", {
    artifacts: {
      "artifacts/a.json":
        '{"record_id":"r","chain_id":"c","artifact_type":"decision","profiles":{"x.y":{"big":1e20}}}',
    },
  }), "numeric-preflight-violation", "ERROR",
  (v) => eq("the pointer names the exponential value", v.nonmeasurement.json_pointer, "/profiles/x.y/big"));
expectNonMeasured("a number inside an operator input",
  mkBundle("n-opnum", {
    operator: {
      bindings: BINDINGS, independence_policy: POLICY,
      revocation: '{"snapshot_id":"synth.snapshot","bindings":{},"x":1e20}',
    },
  }), "numeric-preflight-violation");

// Frozen-verifier identity assertion.
{
  const stub = path.join(tmp, "stub_verifier.mjs");
  fs.writeFileSync(stub, "process.exit(0);\n");
  const dir = mkBundle("v-mismatch");
  const r = run(["--bundle", dir, "--verifier", stub]);
  eq("a frozen-verifier digest mismatch exits 3", r.code, 3);
  const v = parseOne("verifier digest mismatch", r.out);
  eq("the reason is verifier-digest-mismatch", v.nonmeasurement.reason, "verifier-digest-mismatch");
  eq("artifacts[] is empty before any invocation", v.artifacts, []);
  eq("verifier_digests carries exactly two own-lane members",
    Object.keys(v.verifier_digests).sort(), ["class_verifier", "class_verifier_contract"]);
  check("the observed verifier digest is recorded in prefixed form",
    /^sha256:[0-9a-f]{64}$/.test(v.verifier_digests.class_verifier),
    JSON.stringify(v.verifier_digests));
}

// Section 8.2.1: the peer lane's verifier digest appears NOWHERE.
{
  const PEER_DIGEST = "5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc";
  const source = fs.readFileSync(EVAL, "utf8");
  check("the peer verifier digest is not a constant in the evaluator source",
    !source.includes(PEER_DIGEST));
  check("the evaluator source never names the peer lane's verifier file",
    !source.includes("verifier_py") && !source.includes("class_verifier.py"));
  const r = run(["--bundle", mkBundle("v-peerscan")]);
  check("the peer verifier digest is absent from output",
    !r.out.includes(PEER_DIGEST) && !r.out.includes("verifier_py"), r.out.slice(0, 400));
}

// Determinism (section 8.4).
{
  const dir = mkBundle("d-determinism", { corrupt: "artifacts/a.json" });
  eq("identical input gives byte-identical output",
    run(["--bundle", dir]).out, run(["--bundle", dir]).out);
}

// Operator-input flags are assertions about the bundle's own files.
{
  const dir = mkBundle("o-flags");
  const r = run(["--bundle", dir, "--bindings", path.join(dir, "operator", "bindings.json")]);
  check("a flag naming the bundle's own bindings is accepted", r.code !== 2, r.err.trim());
  const outside = path.join(tmp, "outside_bindings.json");
  fs.writeFileSync(outside, BINDINGS);
  const r2 = run(["--bundle", dir, "--bindings", outside]);
  eq("a flag naming a file outside the bundle is a usage error", r2.code, 2);
  check("that usage error writes nothing to stdout", r2.out === "");
}

// ---------------------------------------------------------------------------
// 12. NODE-IMP-1 regression -- literal space, and friends, in the path
// ---------------------------------------------------------------------------
// The recorded defect: new URL(import.meta.url).pathname is percent-encoded, so
// on a repository path containing a literal space the direct-invocation guard
// evaluated false and the program exited 0 with EMPTY STDOUT -- the one output
// the section 8.5 table cannot defend against, since exit 0 asserts a measured
// result while stdout carries none.

eq("isDirectInvocation matches a path containing a literal space",
  isDirectInvocation(fileURLToPath(import.meta.url).replace(/selftest\.mjs$/, "selftest.mjs")),
  false); // selftest.mjs is not interop_eval.mjs -- negative control
check("isDirectInvocation rejects an empty entry point", isDirectInvocation("") === false);
check("isDirectInvocation rejects an undefined entry point", isDirectInvocation(undefined) === false);

for (const dirName of ["dir with space", "dir#with#hash", "dizin ünlü", "dir with  two  spaces"]) {
  let copyDir;
  try {
    copyDir = path.join(tmp, dirName);
    fs.mkdirSync(copyDir, { recursive: true });
    fs.copyFileSync(EVAL, path.join(copyDir, "interop_eval.mjs"));
  } catch (e) {
    console.log(`SKIPPED: path regression for ${JSON.stringify(dirName)} -- ${e.message}`);
    continue;
  }
  const copied = path.join(copyDir, "interop_eval.mjs");
  const label = JSON.stringify(dirName);

  // The guard must fire: a usage error is a usage error, not silence.
  const usage = run([], copied);
  eq(`${label}: no --bundle still exits 2`, usage.code, 2);
  check(`${label}: the direct-invocation guard produced diagnostics`,
    usage.err.includes("usage error"), usage.err.trim());

  // Identity not established: exit 1, stdout empty -- and NOT exit 0.
  const noManifest = path.join(copyDir, "emptybundle");
  fs.mkdirSync(noManifest, { recursive: true });
  const r1 = run(["--bundle", noManifest], copied);
  eq(`${label}: an absent manifest exits 1`, r1.code, 1);
  check(`${label}: exit 1 carries no result object`, r1.out === "");

  // Identity established: exit 3 with a result object naming the scenario.
  const bundle = mkBundle(path.join(dirName, "bundle"), { corrupt: "artifacts/a.json" });
  const r3 = run(["--bundle", bundle], copied);
  eq(`${label}: an identified but unmeasurable bundle exits 3`, r3.code, 3);
  check(`${label}: exit 3 carries a result object`, r3.out.trim().length > 0, r3.err.trim());
  if (r3.out.trim().length > 0) {
    const v = JSON.parse(r3.out);
    eq(`${label}: the scenario is named`, v.scenario_id, "IOP-P-DEC");
  }

  // The invariant, stated directly: exit 0 with empty stdout is unacceptable
  // under every condition.
  for (const [what, r] of [["usage", usage], ["identity", r1], ["unmeasurable", r3]]) {
    check(`${label}/${what}: never exit 0 with empty stdout`,
      !(r.code === 0 && r.out === ""), `code ${r.code}, stdout ${JSON.stringify(r.out)}`);
  }
}

// The same invariant asserted across every invocation this file has made:
// there is no argument vector above for which the evaluator exited 0 silently.
{
  const probes = [
    [], ["--help"], ["--bundle"], ["--bundle", path.join(tmp, "absent-dir")],
    ["--bundle", tmp], ["--bundle", mkBundle("z-final", { corrupt: "artifacts/a.json" })],
  ];
  for (const args of probes) {
    const r = run(args);
    check(`exit 0 with empty stdout never occurs for ${JSON.stringify(args)}`,
      !(r.code === 0 && r.out === ""), `code ${r.code}`);
  }
}

// ---------------------------------------------------------------------------
// 13. Live frozen-verifier invocation (envelope construction, section 5.1;
//     exit-1 causal guard, section 7.2; withheld handling, section 7.1)
// ---------------------------------------------------------------------------
// The inputs below are synthetic JSON objects written here, deliberately NOT
// valid AIREP artifacts and never sealed: they exist only to make the frozen
// verifier take its stage-0 path so the evaluator's handling of that path can
// be observed. They are not fixtures and no corpus bytes are produced.
//
// Skipped when the frozen verifier's vendored dependencies have not been
// materialized -- reported as skipped, never folded into the pass count.

const VERIFIER = path.join(HERE, "..", "..", "class-verification", "verifier_node_r2", "class_verifier.mjs");
const VERIFIER_DEPS = path.join(path.dirname(VERIFIER), "node_modules", "ajv");

if (!fs.existsSync(VERIFIER) || !fs.existsSync(VERIFIER_DEPS)) {
  console.log("SKIPPED: live frozen-verifier checks -- verifier_node_r2 or its node_modules "
    + "is not materialized (class-verification/offline-node-deps/materialize_node_modules.py)");
} else {
  const synth = (rid, type) => JSON.stringify({
    airep_version: "0.2", artifact_type: type, chain_id: "synth.chain",
    record_id: rid, sequence: 0,
  });

  // --- single artifact: related_artifacts is the empty array ---------------
  {
    const dir = mkBundle("live-nonqualifying", {
      scenarioId: "IOP-P-DEC",
      artifacts: { "artifacts/a.json": synth("synth-a", "decision") },
    });
    const r = run(["--bundle", dir]);
    eq("a non-qualifying scenario whose artifact exits 1 is ERROR, not REJECT", r.code, 3);
    const v = parseOne("non-qualifying exit 1", r.out);
    eq("its reason is verifier-run-invalid", v.nonmeasurement.reason, "verifier-run-invalid");
    eq("its level1 is null", v.level1, null);
    eq("its predicates is null", v.predicates, null);
    eq("one artifacts[] entry, because one invocation was attempted", v.artifacts.length, 1);
    eq("verifier_exit_code is recorded verbatim", v.artifacts[0].verifier_exit_code, 1);
    eq("verifier_result is null when the frozen verifier exits 1",
      v.artifacts[0].verifier_result, null);
    check("a stderr audit digest is recorded",
      /^sha256:[0-9a-f]{64}$/.test(v.artifacts[0].verifier_stderr_digest));
    const expected = "sha256:" + sha(Buffer.from(
      jcs({ artifact: JSON.parse(synth("synth-a", "decision")), related_artifacts: [] }), "utf8"));
    eq("a single-artifact envelope carries an empty related_artifacts",
      v.artifacts[0].request_envelope_digest, expected);
  }

  // --- the section 7.2 causal guard, the qualifying direction --------------
  for (const scenarioId of ["IOP-B-DEC", "IOP-B-CTL", "IOP-B-EFF"]) {
    const dir = mkBundle(`live-${scenarioId}`, {
      scenarioId,
      artifacts: { "artifacts/a.json": synth("synth-a", "decision") },
    });
    const r = run(["--bundle", dir]);
    eq(`${scenarioId} reads frozen exit 1 as REJECT`, r.code, 0);
    if (r.code !== 0) continue;
    const v = parseOne(scenarioId, r.out);
    eq(`${scenarioId} is MEASURED`, v.measurement_status, "MEASURED");
    eq(`${scenarioId} maps to REJECT`, v.level1, "REJECT");
    eq(`${scenarioId} runs no predicate`, v.predicates, NA);
    eq(`${scenarioId} carries no nonmeasurement`, v.nonmeasurement, null);
    eq(`${scenarioId} artifacts[] length matches the bundle shape`, v.artifacts.length, 1);
  }

  // --- IOP-B-EXE does NOT reach REJECT through an exit code ----------------
  {
    const dir = mkBundle("live-IOP-B-EXE", {
      scenarioId: "IOP-B-EXE",
      artifacts: { "artifacts/a.json": synth("synth-a", "decision") },
    });
    const r = run(["--bundle", dir]);
    eq("IOP-B-EXE never qualifies for the exit-1 REJECT reading", r.code, 3);
    if (r.code === 3) {
      eq("its reason is verifier-run-invalid",
        JSON.parse(r.out).nonmeasurement.reason, "verifier-run-invalid");
    }
  }

  // --- four artifacts: related_artifacts in record_id UTF-8 byte order -----
  {
    const artifacts = {
      "artifacts/d.json": synth("synth-4-dec", "decision"),
      "artifacts/c.json": synth("synth-1-ctl", "control"),
      "artifacts/x.json": synth("synth-3-exe", "execution"),
      "artifacts/e.json": synth("synth-2-eff", "effect"),
    };
    const dir = mkBundle("live-four", { scenarioId: "IOP-R-CLEAN", artifacts });
    const r = run(["--bundle", dir]);
    eq("a four-artifact bundle of invalid artifacts is ERROR", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("live four", r.out);
      eq("artifacts[] is ordered by record_id UTF-8 byte order",
        v.artifacts.map((a) => a.artifact_ref.record_id),
        ["synth-1-ctl", "synth-2-eff", "synth-3-exe", "synth-4-dec"]);
      const values = Object.values(artifacts).map((t) => JSON.parse(t));
      for (const entry of v.artifacts) {
        const primary = values.find((x) => x.record_id === entry.artifact_ref.record_id);
        const related = values.filter((x) => x !== primary)
          .sort((a, b) => byteCompare(a.record_id, b.record_id));
        const want = "sha256:" + sha(Buffer.from(
          jcs({ artifact: primary, related_artifacts: related }), "utf8"));
        eq(`envelope digest for ${entry.artifact_ref.record_id}`,
          entry.request_envelope_digest, want);
      }
    }
  }
}

console.log(`${checks - failures}/${checks} checks passed`);
if (failures > 0) process.exit(1);
