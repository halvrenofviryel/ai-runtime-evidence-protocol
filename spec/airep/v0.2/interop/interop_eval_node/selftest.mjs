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
  classifyProcessShape, classifyVerdictStdout, writeStdoutSync,
} from "./interop_eval.mjs";

// Section 8.3 entry shape, with artifact_path REQUIRED (AD15-IR-5).
const ARTIFACT_MEMBERS = [
  "artifact_path", "artifact_ref", "request_envelope_digest",
  "verifier_exit_code", "verifier_result", "verifier_stderr_digest",
];

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
usageRejects("a positional argument is rejected", ["x"]);

// E3-4. --help is a CLI META-ACTION, not a usage error and not an evaluation.
// The candidate being remediated raised UsageError here; that is superseded.
// Parsed through a guard: under the SUPERSEDED resolution parseArgs THREW on
// --help, and letting that propagate would abort the whole suite before the
// process-level E3-4 checks below could report. The guard turns it into a named
// failure so the discrimination is legible rather than a stack trace.
function parseMeta(name, argv) {
  try {
    return parseArgs(argv);
  } catch (e) {
    check(`${name}: --help must not raise a usage error`, false, String(e && e.message));
    return null;
  }
}
{
  const h = parseMeta("--help", ["--help"]);
  if (h) {
    eq("--help parses as the meta-action", h.help, true);
    check("--help does not require --bundle", h.flags.bundle === null);
  }
  const sh = parseMeta("-h", ["-h"]);
  if (sh) eq("-h is the same meta-action", sh.help, true);
}
eq("an ordinary invocation is not the meta-action",
  parseArgs(["--bundle", "d"]).help, false);
// The carve-out is exactly ONE FLAG WIDE: --help does not launder a bad command
// line into the meta-action. Without this control, "--help wins" would silently
// turn every usage error into exit 0.
usageRejects("--help does not excuse an unknown option", ["--help", "--nope", "x"]);
usageRejects("--help does not excuse a positional argument", ["--help", "junk"]);
usageRejects("--help does not excuse a repeated option",
  ["--help", "--bundle", "a", "--bundle", "b"]);
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
  ["unknown option alongside --help", ["--help", "--nope", "x"]],
]) {
  const r = run(args);
  eq(`${name} exits 2`, r.code, 2);
  check(`${name} writes nothing to stdout`, r.out === "", JSON.stringify(r.out));
}

// --- E3-4 discrimination: --help exits 0, prints help, emits NO result object
// The four properties are asserted separately, because three of them held under
// the superseded exit-2 resolution too and only the conjunction discriminates.
for (const flag of ["--help", "-h"]) {
  const r = run([flag]);
  eq(`${flag} exits 0`, r.code, 0);
  check(`${flag} writes human-readable help to stdout`,
    r.out.length > 0 && /--bundle/.test(r.out), JSON.stringify(r.out.slice(0, 120)));
  // "No result JSON object" is the load-bearing half: exit 0 on an EVALUATION
  // asserts a MEASURED result, and a help screen must not be mistakable for one.
  let parsedAsJson = true;
  try { JSON.parse(r.out); } catch { parsedAsJson = false; }
  check(`${flag} emits no result JSON object`, !parsedAsJson, r.out.slice(0, 200));
  // Not a regex on field names -- the help text legitimately DOCUMENTS
  // measurement_status in its exit table, so that probe would fail on correct
  // output. The property that matters is that stdout is not a result object.
  check(`${flag} output is not a JSON object at all`,
    r.out.trimStart()[0] !== "{", r.out.slice(0, 200));
  // It does not require --bundle, and it touches no bundle at all.
  check(`${flag} needs no --bundle`, r.code === 0);
}
// The exit-0 invariant guard must not have fired: it is keyed on invocation
// kind, so a meta-action satisfying it via stdout does NOT relax what an
// evaluation must satisfy. This control measures that the guard stayed silent.
{
  const r = run(["--help"]);
  check("--help does not trip the exit-0 invariant guard",
    !/internal invariant violated/.test(r.err), r.err.slice(0, 200));
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

// Section 8.2.1: the peer lane's verifier digest appears NOWHERE -- not in the
// output, and not as a carried-forward constant in the source. The check is
// deliberately CONSTANT-FREE: writing the peer digest here to assert its
// absence would put it back into this lane's tree, which is the thing the
// section forbids. Instead the set of 64-hex literals in the source is required
// to be exactly the two this lane pins.
{
  const source = fs.readFileSync(EVAL, "utf8");
  const hexLiterals = new Set(source.match(/\b[0-9a-f]{64}\b/g) ?? []);
  eq("the evaluator source pins exactly two 64-hex digests", hexLiterals.size, 2);
  check("the evaluator source never names the peer lane",
    !/verifier_py|class_verifier\.py|interop_eval_py/.test(source));

  const r = run(["--bundle", mkBundle("v-peerscan")]);
  const v = JSON.parse(r.out);
  eq("output carries exactly two verifier_digests members",
    Object.keys(v.verifier_digests).sort(), ["class_verifier", "class_verifier_contract"]);
  const outHex = new Set((r.out.match(/\b[0-9a-f]{64}\b/g) ?? []));
  const pinnedInSource = [...hexLiterals];
  const pinnedInOutput = [...outHex].filter((h) => pinnedInSource.includes(h));
  check("no unasserted third verifier digest is carried into the output",
    pinnedInOutput.length <= 2, JSON.stringify(pinnedInOutput));
  check("the output never names the peer lane",
    !/verifier_py|class_verifier\.py|interop_eval_py/.test(r.out), r.out.slice(0, 400));
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

  // --- AD15-IR-5: an artifact with NO usable record_id --------------------
  // The consequence the ruling exists for: a missing record_id must reach the
  // frozen stage-0 evaluation it belongs to, instead of being converted into
  // this evaluator's own preflight failure -- and nothing may be synthesized to
  // fill the identity field.
  {
    const noId = '{"airep_version":"0.2","artifact_type":"decision","chain_id":"synth.chain"}';
    const dir = mkBundle("live-norecordid", {
      scenarioId: "IOP-P-DEC",
      artifacts: { "artifacts/a.json": noId },
    });
    const r = run(["--bundle", dir]);
    eq("an artifact with no record_id is still evaluated, not refused", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("no record_id", r.out);
      eq("it reaches the frozen verifier rather than a preflight failure",
        v.nonmeasurement.reason, "verifier-run-invalid");
      eq("exactly one invocation was attempted", v.artifacts.length, 1);
      eq("artifact_path is present and is the entry's identity",
        v.artifacts[0].artifact_path, "artifacts/a.json");
      eq("artifact_ref is null, not a fabricated reference", v.artifacts[0].artifact_ref, null);
      eq("the entry still carries the full pinned member set",
        Object.keys(v.artifacts[0]).sort(), [...ARTIFACT_MEMBERS].sort());
      check("no record_id was synthesized anywhere in the output",
        !/record_id/.test(r.out), r.out.slice(0, 400));
    }
  }

  // --- four artifacts: related_artifacts in artifact_path UTF-8 byte order -
  {
    // record_id rank is the EXACT REVERSE of artifact_path rank
    // (c<d<e<x by path; 4>3>2>1 by record_id), so for every choice of primary
    // the remaining three order differently under the two keys. An earlier
    // arrangement put the outlier id on one artifact, and with that artifact as
    // primary the other three coincided -- the control silently measured
    // nothing for that case.
    const artifacts = {
      "artifacts/d.json": synth("synth-3-dec", "decision"),
      "artifacts/c.json": synth("synth-4-ctl", "control"),
      "artifacts/x.json": synth("synth-1-exe", "execution"),
      "artifacts/e.json": synth("synth-2-eff", "effect"),
    };
    const dir = mkBundle("live-four", { scenarioId: "IOP-R-CLEAN", artifacts });
    const r = run(["--bundle", dir]);
    eq("a four-artifact bundle of invalid artifacts is ERROR", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("live four", r.out);

      // AD15-IR-5. This fixture is built so that artifact_path order and
      // record_id order DISAGREE -- if they agreed, no check here could tell
      // the result-identity ruling from the envelope rule it must not disturb.
      eq("artifacts[] is ordered by artifact_path UTF-8 byte order",
        v.artifacts.map((a) => a.artifact_path),
        ["artifacts/c.json", "artifacts/d.json", "artifacts/e.json", "artifacts/x.json"]);
      eq("that ordering is deliberately NOT record_id order",
        v.artifacts.map((a) => a.artifact_ref.record_id),
        ["synth-4-ctl", "synth-3-dec", "synth-2-eff", "synth-1-exe"]);
      check("the two orders really do disagree, so the check discriminates",
        show(v.artifacts.map((a) => a.artifact_ref.record_id))
          !== show([...v.artifacts.map((a) => a.artifact_ref.record_id)].sort(byteCompare)));
      for (const entry of v.artifacts) {
        eq(`${entry.artifact_path}: entry carries exactly the pinned member set`,
          Object.keys(entry).sort(), [...ARTIFACT_MEMBERS].sort());
      }

      // AD15-IR-6 (E3-1). related_artifacts is now ordered by manifest-relative
      // artifact_path, NOT record_id. The fixture is built so the two orders
      // disagree, so this check discriminates the ruling rather than merely
      // restating it: under the superseded record_id rule every digest below
      // would differ.
      const byPath = Object.fromEntries(
        Object.entries(artifacts).map(([k, t]) => [k, JSON.parse(t)]));
      const pathOf = new Map(Object.entries(byPath).map(([k, val]) => [val, k]));
      for (const entry of v.artifacts) {
        const primary = byPath[entry.artifact_path];
        check(`${entry.artifact_path} is resolvable by its manifest path alone`,
          primary !== undefined);
        const others = Object.values(byPath).filter((x) => x !== primary);
        const byPathOrder = [...others]
          .sort((a, b) => byteCompare(pathOf.get(a), pathOf.get(b)));
        const byRecordOrder = [...others]
          .sort((a, b) => byteCompare(a.record_id, b.record_id));
        const digestOf = (related) => "sha256:" + sha(Buffer.from(
          jcs({ artifact: primary, related_artifacts: related }), "utf8"));
        eq(`envelope digest for ${entry.artifact_path} (related in artifact_path order)`,
          entry.request_envelope_digest, digestOf(byPathOrder));
        // Control: the two orderings really do produce different envelope
        // bytes here, so the assertion above could have failed. Without this,
        // a fixture where both orders coincided would pass while measuring
        // nothing -- and differing envelope bytes are exactly what aggregate
        // duty 2 compares across lanes.
        check(`${entry.artifact_path}: path order and record_id order give different envelopes`,
          digestOf(byPathOrder) !== digestOf(byRecordOrder),
          `${show(byPathOrder.map((x) => pathOf.get(x)))} vs ${show(byRecordOrder.map((x) => pathOf.get(x)))}`);
        check(`${entry.artifact_path}: the superseded record_id ordering is NOT what was emitted`,
          entry.request_envelope_digest !== digestOf(byRecordOrder));
      }
    }
  }

  // --- E3-1 discrimination: an artifact with NO record_id ------------------
  // This is the case AD15-IR-6 exists for. Under the superseded record_id
  // ordering such an artifact had no defined envelope at all, and the two
  // isolated lanes resolved it differently -- one sorting it under an empty
  // key (this lane), one refusing to build the envelope. Both are gone: the
  // key is artifact_path, which always exists, so the envelope is always
  // defined and the artifact reaches frozen stage 0 on its own merits.
  {
    const noId = JSON.stringify({
      airep_version: "0.2", artifact_type: "execution", chain_id: "synth.chain",
      sequence: 0,
    });
    const artifacts = {
      "artifacts/d.json": synth("synth-3-dec", "decision"),
      "artifacts/c.json": synth("synth-4-ctl", "control"),
      "artifacts/x.json": noId,                       // no record_id at all
      "artifacts/e.json": synth("synth-2-eff", "effect"),
    };
    const dir = mkBundle("e31-no-record-id", { scenarioId: "IOP-R-CLEAN", artifacts });
    const r = run(["--bundle", dir]);

    // (a) STAGE-0 REACHABILITY. The load-bearing half. A missing record_id must
    // NOT become this evaluator's own preflight failure: the artifact is handed
    // to the frozen verifier and rejected there, on the frozen contract's
    // terms. bundle-shape-invalid or numeric-preflight-violation here would
    // mean the evaluator pre-empted the measurement it exists to take.
    eq("a record_id-less artifact still produces a result object", r.code, 3);
    const v = parseOne("no record_id", r.out);
    eq("it reaches the frozen verifier, not a preflight refusal",
      v.nonmeasurement.reason, "verifier-run-invalid");
    eq("all four invocations were attempted", v.artifacts.length, 4);
    check("every artifact reached an invocation and has an exit code",
      v.artifacts.every((a) => typeof a.verifier_exit_code === "number"),
      show(v.artifacts.map((a) => a.verifier_exit_code)));

    // (b) NOTHING WAS FABRICATED. artifact_ref is null for that artifact, and
    // artifact_path still names it -- identity without invention.
    const entry = v.artifacts.find((a) => a.artifact_path === "artifacts/x.json");
    check("the record_id-less artifact has an entry", entry !== undefined);
    eq("its artifact_ref is null, never a synthesized record_id",
      entry.artifact_ref, null);
    eq("its artifact_path is still its identity", entry.artifact_path, "artifacts/x.json");

    // (c) DETERMINISTIC artifact_path ORDERING, including the unidentifiable
    // artifact, which under the superseded rule had no defined position.
    eq("artifacts[] is ordered by artifact_path even with a record_id absent",
      v.artifacts.map((a) => a.artifact_path),
      ["artifacts/c.json", "artifacts/d.json", "artifacts/e.json", "artifacts/x.json"]);

    // (d) THE ENVELOPE IS DEFINED for every artifact, and is the path-ordered
    // one. Recomputed here independently of the evaluator's own ordering code.
    const byPath = Object.fromEntries(
      Object.entries(artifacts).map(([k, t]) => [k, JSON.parse(t)]));
    for (const e of v.artifacts) {
      const primary = byPath[e.artifact_path];
      const related = Object.entries(byPath)
        .filter(([k]) => k !== e.artifact_path)
        .sort((a, b) => byteCompare(a[0], b[0]))
        .map(([, val]) => val);
      const want = "sha256:" + sha(Buffer.from(
        jcs({ artifact: primary, related_artifacts: related }), "utf8"));
      eq(`${e.artifact_path}: envelope defined and path-ordered despite a missing record_id`,
        e.request_envelope_digest, want);
    }

    // (e) DETERMINISM (section 8.4). Identical bundle, byte-identical output --
    // the property the superseded empty-key resolution could not guarantee
    // across lanes.
    const r2 = run(["--bundle", dir]);
    eq("a second run is byte-identical", r2.out, r.out);
    eq("a second run exits the same", r2.code, r.code);
  }
}

// ---------------------------------------------------------------------------
// 14. Erratum 2 / E2-1 -- the bundle-layout surface maps to manifest-invalid
// ---------------------------------------------------------------------------
// The enumeration is now NORMATIVE, so each member is asserted against the
// reason code rather than against this lane's earlier reading of it. The
// pre-erratum source recorded this as an open ambiguity; it is a rule now.

// A directory under the bundle is a container: descended, never listed, never a
// finding on its own. The negative control for everything below.
{
  const dir = mkBundle("e21-dir-ok", {
    artifacts: {
      "artifacts/nested/deep/a.json":
        '{"record_id":"r","chain_id":"c","artifact_type":"decision"}',
    },
  });
  const r = run(["--bundle", dir]);
  check("a nested directory is a container, not a layout violation",
    !(r.code === 3 && /manifest-invalid/.test(r.out)), r.out.slice(0, 300));
}

// A files[] entry whose target is a DIRECTORY: present, and the wrong kind.
// manifest-invalid -- specifically NOT bundle-file-missing, because nothing is
// missing. Directories are never files[] entries.
{
  const v = expectNonMeasured("a files[] entry naming a directory",
    mkBundle("e21-dir-listed", {
      mutate: (m, d) => {
        fs.mkdirSync(path.join(d, "zz-adir"), { recursive: true });
        m.files.push({ path: "zz-adir", role: "artifact", sha256: "0".repeat(64) });
        m.files.sort((a, b) => byteCompare(a.path, b.path));
      },
    }), "manifest-invalid");
  if (v) {
    check("the wrong file kind is named in the detail",
      /director/i.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
  }
}

// A FIFO under the bundle: neither regular nor directory.
{
  const dir = mkBundle("e21-fifo");
  const mk = spawnSync("mkfifo", [path.join(dir, "artifacts", "pipe")], { encoding: "utf8" });
  if (mk.status === 0) {
    const v = expectNonMeasured("a FIFO under the bundle", dir, "manifest-invalid");
    if (v) {
      check("the FIFO is named as a non-regular object",
        /FIFO|non-regular/i.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
    }
  } else {
    console.log("SKIPPED: FIFO check -- mkfifo is unavailable on this system");
  }
}

// A regular file on disk that files[] does not list.
{
  const v = expectNonMeasured("an unlisted regular file, per the E2-1 enumeration",
    mkBundle("e21-unlisted", {
      mutate: (_m, d) => { fs.writeFileSync(path.join(d, "artifacts", "zz-stray.json"), "{}"); },
    }), "manifest-invalid");
  if (v) {
    check("the unlisted file is named", /zz-stray/.test(v.nonmeasurement.detail),
      v.nonmeasurement.detail);
  }
}

// Only the ROOT manifest.json is the manifest. A nested file of that name is an
// ordinary bundle file and must be listed like any other -- this is where the
// erratum's "a manifest with the wrong name or location" lands.
{
  const v = expectNonMeasured("a nested manifest.json left unlisted",
    mkBundle("e21-nested-manifest", {
      mutate: (_m, d) => {
        fs.mkdirSync(path.join(d, "sub"), { recursive: true });
        fs.writeFileSync(path.join(d, "sub", "manifest.json"), "{}");
      },
    }), "manifest-invalid");
  if (v) {
    check("a nested manifest.json is treated as an ordinary unlisted file",
      /sub\/manifest\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
  }
}

// bundle-file-missing SURVIVES E2-1 and is not collapsed into manifest-invalid:
// nothing on disk at all remains its own reason. Without this the enumeration
// would have swallowed a distinct registry row.
expectNonMeasured("nothing on disk at all is still bundle-file-missing",
  mkBundle("e21-truly-missing", {
    mutate: (m) => {
      m.files.push({ path: "zz-ghost.json", role: "artifact", sha256: "0".repeat(64) });
      m.files.sort((a, b) => byteCompare(a.path, b.path));
    },
  }), "bundle-file-missing");

// ---------------------------------------------------------------------------
// 14b. Erratum 3 / E3-2 -- the four filesystem reasons are DISTINCT
// ---------------------------------------------------------------------------
// The registry now bounds them exactly. The point of this block is the
// SEPARATION: each condition must produce its own reason, and a test that only
// checked one of them would not notice three collapsing into one. The candidate
// being remediated reported an unreadable file as bundle-file-missing, which
// asserts something false about the bundle.
{
  // (1) absent -> bundle-file-missing (asserted above, restated here as the
  //     first member of the four-way comparison).
  const missing = mkBundle("e32-missing", {
    mutate: (m) => {
      m.files.push({ path: "zz-ghost.json", role: "artifact", sha256: "0".repeat(64) });
      m.files.sort((a, b) => byteCompare(a.path, b.path));
    },
  });
  const vMissing = expectNonMeasured("absent file", missing, "bundle-file-missing");

  // (2) present, regular, unreadable -> bundle-file-unreadable (NEW in E3-2).
  //     Skipped rather than faked where the mode cannot actually deny a read:
  //     running as root, or on a filesystem that silently drops chmod. The
  //     CONTROL below measures that the file really is unreadable before the
  //     assertion is allowed to count -- otherwise this test would pass by
  //     measuring an ordinary readable file.
  let vUnreadable = null;
  {
    const dir = mkBundle("e32-unreadable");
    const target = path.join(dir, "artifacts", "a.json");
    let denied = false;
    try {
      fs.chmodSync(target, 0o000);
      try { fs.readFileSync(target); } catch { denied = true; }
    } catch { /* chmod unsupported here */ }
    if (!denied) {
      console.log("SKIPPED: bundle-file-unreadable -- this process can read a 0o000 file "
        + "(root, or a filesystem that ignores chmod); the condition cannot be produced");
    } else {
      check("control: the target really is unreadable before the assertion counts", denied);
      vUnreadable = expectNonMeasured("present but unreadable file", dir, "bundle-file-unreadable");
      if (vUnreadable) {
        check("the detail says present-but-unreadable, not missing",
          /present/i.test(vUnreadable.nonmeasurement.detail)
          && !/\bmissing\b/i.test(vUnreadable.nonmeasurement.detail),
          vUnreadable.nonmeasurement.detail);
      }
      fs.chmodSync(target, 0o644);
    }
  }

  // (3) read but unparseable -> bundle-json-invalid.
  const vJson = expectNonMeasured("present, readable, not JSON",
    mkBundle("e32-nonjson", { artifacts: { "artifacts/a.json": "{ not json" } }),
    "bundle-json-invalid");

  // (4) read but digest mismatch -> manifest-digest-mismatch.
  const vDigest = expectNonMeasured("present, readable, wrong digest",
    mkBundle("e32-digest", { corrupt: "artifacts/a.json" }), "manifest-digest-mismatch");

  // THE DISCRIMINATION ITSELF: all reasons observed are pairwise distinct. A
  // collapse of any two -- which is exactly the defect E3-2 closed -- fails
  // here even though each individual assertion above would still pass.
  const observed = [vMissing, vUnreadable, vJson, vDigest]
    .filter((x) => x !== null).map((x) => x.nonmeasurement.reason);
  eq("every filesystem failure produced a distinct reason",
    observed.length, new Set(observed).size);
  check("the four-way boundary was exercised over at least three conditions",
    observed.length >= 3, show(observed));
}

// ---------------------------------------------------------------------------
// 14c. Erratum 3 / E3-3 -- NO manifest discovery is performed
// ---------------------------------------------------------------------------
// A bundle whose only manifest-shaped file is wrongly named establishes NO
// identity. It must exit 1 with empty stdout -- never manifest-invalid, which
// would require a scenario_id the evaluator does not have, and never a
// discovered manifest, which would make the identity depend on a search.
for (const wrongName of ["MANIFEST.json", "bundle.json", "manifest.JSON", "manifest.json.bak"]) {
  const dir = path.join(tmp, `e33-${wrongName.replace(/[^a-zA-Z0-9]/g, "_")}`);
  fs.mkdirSync(dir, { recursive: true });
  // Byte-for-byte a VALID manifest -- only the NAME is wrong. If any discovery
  // existed, this is the file it would find, so the test discriminates
  // discovery rather than merely the absence of a file.
  fs.writeFileSync(path.join(dir, wrongName), JSON.stringify({
    manifest_version: "1", scenario_id: "IOP-P-DEC", files: [],
  }));
  const r = run(["--bundle", dir]);
  eq(`only ${wrongName} present: exits 1`, r.code, 1);
  check(`only ${wrongName} present: stdout is empty`, r.out === "", JSON.stringify(r.out));
  check(`only ${wrongName} present: no result object, so no reason code either`,
    !/manifest-invalid|nonmeasurement/.test(r.out), r.out.slice(0, 200));
}
// A subdirectory manifest is not discovered either.
{
  const dir = path.join(tmp, "e33-nested-only");
  fs.mkdirSync(path.join(dir, "sub"), { recursive: true });
  fs.writeFileSync(path.join(dir, "sub", "manifest.json"), JSON.stringify({
    manifest_version: "1", scenario_id: "IOP-P-DEC", files: [],
  }));
  const r = run(["--bundle", dir]);
  eq("a manifest in a subdirectory is not discovered: exits 1", r.code, 1);
  check("a manifest in a subdirectory writes nothing to stdout", r.out === "");
}
// Negative control: with a ROOT manifest.json present, a wrongly-named file
// BESIDE it is an ordinary unlisted regular file and IS reported -- identity
// exists, so the ordinary layout rules apply and the reason is manifest-invalid.
{
  const v = expectNonMeasured("a wrongly-named manifest beside a valid root manifest",
    mkBundle("e33-beside", {
      mutate: (_m, d) => {
        fs.writeFileSync(path.join(d, "MANIFEST.json"), "{}");
      },
    }), "manifest-invalid");
  if (v) {
    check("it is caught as an ordinary unlisted file, not as a rival manifest",
      /MANIFEST\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
  }
}

// ---------------------------------------------------------------------------
// 15. Erratum 2 / E2-2 -- abnormal frozen runs map to verifier-run-invalid
// ---------------------------------------------------------------------------
// verifier-not-invocable is now ONLY a process that could not be spawned or
// executed at all. internal-error is now ONLY this evaluator's own fault. Both
// bands are pure functions, which is what makes them testable at all: reaching
// a misbehaving stub verifier THROUGH the evaluator is impossible by design,
// because the frozen digest assertion runs first and rejects any stub.
//
// The process shapes below are MEASURED from this runtime, not invented.
{
  const measured = [
    ["a binary that does not exist",
      spawnSync("/nonexistent/binary/xyz", []), "verifier-not-invocable"],
    ["a process killed by a signal",
      spawnSync(process.execPath, ["-e", "process.kill(process.pid,'SIGKILL')"]),
      "verifier-run-invalid"],
    ["a process whose output exceeded maxBuffer",
      spawnSync(process.execPath, ["-e", "process.stdout.write('x'.repeat(100000))"],
        { maxBuffer: 10 }), "verifier-run-invalid"],
    ["a process that timed out",
      spawnSync(process.execPath, ["-e", "const t=Date.now();while(Date.now()-t<3000);"],
        { timeout: 200 }), "verifier-run-invalid"],
  ];
  for (const [label, proc, want] of measured) {
    const got = classifyProcessShape(proc);
    eq(`${label} -> ${want}`, got === null ? null : got.reason, want);
  }
  // A normal exit -- ANY exit code -- is not a process-band failure. The code
  // itself is judged later, by the section 7.2 causal guard.
  for (const code of [0, 1, 2, 7]) {
    eq(`a normal exit ${code} is not a process-band failure`,
      classifyProcessShape(spawnSync(process.execPath, ["-e", `process.exit(${code})`])), null);
  }
}

// The discriminator is "did it start", and nothing else. spawnSync reports an
// unspawnable binary and a started-then-killed process through the SAME `error`
// member, so a classifier keyed on `error` would put both in one band -- which
// is precisely the collapse E2-2 forbids.
{
  eq("started-then-errored is run-invalid, not not-invocable",
    classifyProcessShape({ pid: 4242, error: new Error("ENOBUFS"), status: null }).reason,
    "verifier-run-invalid");
  eq("never-started is not-invocable",
    classifyProcessShape({ pid: 0, error: new Error("ENOENT"), status: null }).reason,
    "verifier-not-invocable");
  const bands = [
    classifyProcessShape({ pid: 0, error: new Error("x"), status: null }).reason,
    classifyProcessShape({ pid: 1, error: new Error("x"), status: null }).reason,
    classifyProcessShape({ pid: 1, status: null, signal: "SIGTERM" }).reason,
  ];
  check("no process-band failure is ever internal-error", !bands.includes("internal-error"),
    JSON.stringify(bands));
}

// Result band, for a frozen exit 0.
{
  const GOOD = {
    class: "AIREP-Core", observer_assessment: "not_applicable",
    authenticated_failures: [], authenticated_withheld: [], authenticated_caveats: [],
    witnessed_failures: [], witnessed_withheld: [],
  };
  eq("exit 0 with empty stdout is run-invalid",
    classifyVerdictStdout("").reason, "verifier-run-invalid");
  eq("exit 0 with whitespace-only stdout is run-invalid",
    classifyVerdictStdout("  \n\t ").reason, "verifier-run-invalid");
  check("the empty-stdout detail names the condition plainly",
    /empty stdout/.test(classifyVerdictStdout("").detail),
    classifyVerdictStdout("").detail);
  eq("exit 0 with non-JSON stdout is run-invalid",
    classifyVerdictStdout("not json at all").reason, "verifier-run-invalid");
  eq("exit 0 with two concatenated results is run-invalid",
    classifyVerdictStdout(JSON.stringify(GOOD) + JSON.stringify(GOOD)).reason,
    "verifier-run-invalid");
  eq("exit 0 with a JSON array is a wrong-shape result",
    classifyVerdictStdout("[]").reason, "verifier-run-invalid");
  eq("exit 0 with a JSON scalar is a wrong-shape result",
    classifyVerdictStdout("42").reason, "verifier-run-invalid");
  eq("exit 0 with null is a wrong-shape result",
    classifyVerdictStdout("null").reason, "verifier-run-invalid");
  eq("exit 0 with a malformed verdict object is run-invalid",
    classifyVerdictStdout('{"class":"AIREP-Core"}').reason, "verifier-run-invalid");
  eq("a well-shaped verdict passes the band",
    classifyVerdictStdout(JSON.stringify(GOOD)).verdict.class, "AIREP-Core");
  check("no result-band rejection is ever internal-error",
    ["", "  ", "x", "[]", "42", "null", '{"class":"AIREP-Core"}']
      .every((t) => classifyVerdictStdout(t).reason === "verifier-run-invalid"));
}

// ---------------------------------------------------------------------------
// 16. NODE-IMP-1, second route -- pipe-backed stdout truncation
// ---------------------------------------------------------------------------
// The Node context found a second way to reach the same forbidden output as the
// literal-space path defect: process.stdout.write is ASYNCHRONOUS on a pipe, so
// a following process.exit() can truncate or drop the result entirely. Both
// routes end at exit 0 with incomplete or empty stdout, and both must stay
// closed. Two mechanisms hold this one: writeStdoutSync loops on fs.writeSync
// until every byte is out, and the entry point sets process.exitCode instead of
// calling process.exit().
//
// A regression for truncation is worthless unless the payload actually exceeds
// the pipe buffer, so the platform's capability to EXHIBIT the defect is
// measured first. Without this control a green result would mean nothing.

const BIG_N = 2000000;
{
  const bug = spawnSync(process.execPath,
    ["-e", `process.stdout.write("x".repeat(${BIG_N})); process.exit(0)`],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const truncates = bug.stdout.length < BIG_N;
  check("CONTROL: the buggy async-write-then-exit pattern truncates on this platform",
    truncates,
    `received ${bug.stdout.length} of ${BIG_N} bytes -- if this ever passes cleanly, the `
    + "regressions below prove nothing and must be re-designed");

  if (!truncates) {
    console.log("SKIPPED: pipe-truncation regressions -- this platform did not exhibit the "
      + "defect even for the buggy pattern, so they cannot discriminate here");
  } else {
    // The mechanism, in isolation, driven with the EXACT defect pattern the
    // erratum names: a write immediately followed by process.exit(). Because
    // writeStdoutSync loops on fs.writeSync, every byte is already out before
    // exit runs; an async write here would be truncated exactly as the control
    // above just demonstrated.
    const driver = path.join(tmp, "pipe_driver.mjs");
    fs.writeFileSync(driver,
      `import { writeStdoutSync } from ${JSON.stringify(EVAL)};\n`
      + `writeStdoutSync("y".repeat(${BIG_N}));\n`
      + "process.exit(0);\n");
    const fixed = spawnSync(process.execPath, [driver],
      { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    eq("writeStdoutSync delivers every byte over a pipe", fixed.stdout.length, BIG_N);
    eq("and exits 0 having actually written the payload", fixed.status, 0);
    check("no byte of the payload is corrupted",
      /^y+$/.test(fixed.stdout), `first divergence in ${fixed.stdout.length} bytes`);
  }
}

// End to end, through the real emit path: a result object far larger than the
// pipe buffer must arrive complete and parseable. The size is driven by a
// synthetic manifest member name -- no corpus bytes and no artifact content.
{
  const hugeName = "z".repeat(400000);
  const dir = mkBundle("pipe-bigresult", { mutate: (m) => { m[hugeName] = 1; } });
  const r = run(["--bundle", dir]);
  eq("a very large result object still exits 3", r.code, 3);
  check("the large result object is not truncated on the pipe",
    r.out.length > 400000, `stdout was ${r.out.length} bytes`);
  let parsed = null;
  try { parsed = JSON.parse(r.out); } catch { /* left null: asserted below */ }
  check("the large result object parses as complete JSON", parsed !== null,
    `stdout tail: ${JSON.stringify(r.out.slice(-120))}`);
  if (parsed !== null) {
    eq("its reason is still the pinned one", parsed.nonmeasurement.reason, "manifest-invalid");
    check("the full detail survived the write",
      parsed.nonmeasurement.detail.includes(hugeName),
      `detail was ${parsed.nonmeasurement.detail.length} bytes`);
  }
  check("a large result never becomes exit 0 with empty stdout",
    !(r.code === 0 && r.out === ""));
}

console.log(`${checks - failures}/${checks} checks passed`);
if (failures > 0) process.exit(1);
