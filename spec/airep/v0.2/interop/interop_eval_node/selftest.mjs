// Self-test for the Node reference interop evaluator.
//
// Synthetic inputs only, constructed here. NO corpus bytes and NO scenario
// bundle artifacts are created: corpus construction is on hold (evaluator
// contract section 12), and a signed four-artifact bundle is precisely what
// this file must not invent. The consequence is stated plainly: the MEASURED
// end-to-end path -- real frozen-verifier invocation over sealed artifacts --
// is NOT covered here and cannot be until the corpus exists.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

import {
  jcs, byteCompare, decodeDecimal, checkNumberToken, scanJsonNumbers,
  resolveRef, predicateRA, predicateRB, predicateRC, mapLevel1,
} from "./interop_eval.mjs";

const HERE = path.dirname(new URL(import.meta.url).pathname);
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
// RFC 8785 3.2.3 sorts by UTF-16 code unit, which is JS default string sort.
eq("jcs member order is UTF-16 code unit", jcs({ "ä": 1, z: 2 }), '{"z":2,"ä":1}');
eq("jcs is stable across member order", jcs({ a: 1, b: 2 }), jcs({ b: 2, a: 1 }));

// ---------------------------------------------------------------------------
// 2. UTF-8 byte ordering (sections 5.1 and 8.4)
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
// 3. Numeric preflight (section 5.1)
// ---------------------------------------------------------------------------

eq("integer at the bound passes", checkNumberToken("9007199254740991"), null);
eq("negative integer at the bound passes", checkNumberToken("-9007199254740991"), null);
check("integer one past the bound fails", checkNumberToken("9007199254740992") !== null);
check("integer far past the bound fails", checkNumberToken("9007199254740993") !== null);
check("1e20 is an integer past the bound", checkNumberToken("1e20") !== null);
check("1e400 is not finite", checkNumberToken("1e400") === "not finite / not IEEE-754 representable");
check("-1e400 is not finite", checkNumberToken("-1e400") === "not finite / not IEEE-754 representable");
eq("0.1 round-trips", checkNumberToken("0.1"), null);
eq("0.10 round-trips (same value)", checkNumberToken("0.10"), null);
eq("zero passes", checkNumberToken("0"), null);
eq("-0 passes", checkNumberToken("-0"), null);
eq("1.5e-7 passes", checkNumberToken("1.5e-7"), null);
check("over-precise decimal is rejected", checkNumberToken("1.00000000000000000001") !== null);
eq("sequence-like values pass", checkNumberToken("42"), null);

eq("decodeDecimal normalizes trailing zeros",
  decodeDecimal("1.500"), decodeDecimal("1.5"));
eq("decodeDecimal handles exponents", decodeDecimal("15e-1"), decodeDecimal("1.5"));

// ---------------------------------------------------------------------------
// 4. JSON number scanner -- pointers (RFC 6901)
// ---------------------------------------------------------------------------

const scanned = scanJsonNumbers(JSON.stringify({
  sequence: 3,
  profiles: { "airep.k": { deep: [0, { "a/b": 7, "c~d": 8 }] } },
  s: "not a number: 5",
}));
const pointers = scanned.map((x) => x.pointer).sort();
eq("scanner finds every number and escapes pointers", pointers, [
  "/profiles/airep.k/deep/0",
  "/profiles/airep.k/deep/1/a~1b",
  "/profiles/airep.k/deep/1/c~0d",
  "/sequence",
]);
eq("scanner keeps the source spelling",
  scanJsonNumbers('{"n": 9007199254740993}')[0].token, "9007199254740993");
check("scanner ignores numerals inside strings",
  scanJsonNumbers('{"s":"1234"}').length === 0);

// ---------------------------------------------------------------------------
// 5. Reference resolution (section 5, frozen section 0 semantics)
// ---------------------------------------------------------------------------

const A = (record_id, chain_id, extra = {}) => ({ bundlePath: record_id, value: { record_id, chain_id, ...extra } });
const set1 = [A("r1", "c1"), A("r2", "c1"), A("r1", "c2")];

eq("record_id + chain_id resolves uniquely",
  resolveRef({ record_id: "r1", chain_id: "c1" }, set1).state, "resolved");
eq("record_id alone is ambiguous when two chains carry it",
  resolveRef({ record_id: "r1" }, set1).state, "ambiguous");
eq("no match is unresolved",
  resolveRef({ record_id: "nope" }, set1).state, "unresolved");
eq("a non-object reference is unresolved",
  resolveRef("r1", set1).state, "unresolved");
eq("chain_id that matches nothing is unresolved",
  resolveRef({ record_id: "r1", chain_id: "c9" }, set1).state, "unresolved");

// ---------------------------------------------------------------------------
// 6. The three predicates (section 6)
// ---------------------------------------------------------------------------

function bundle(overrides = {}) {
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
  const arts = Object.entries(values).map(([, v]) => ({ bundlePath: v.record_id, value: v }));
  const byType = new Map(Object.entries(values).map(([fam, v]) => [fam, arts.find((a) => a.value === v)]));
  return { arts, byType };
}

function results(byType, observerAssessment) {
  const m = new Map();
  for (const [, a] of byType) {
    m.set(a.bundlePath, {
      verifierResult: {
        observer_assessment: a.value.artifact_type === "effect" ? observerAssessment : "not_applicable",
      },
    });
  }
  return m;
}

{
  const { arts, byType } = bundle();
  eq("R-A passes on a fully resolving graph", predicateRA(byType, arts).outcome, "PASS");
  eq("R-B passes on equal digests", predicateRB(byType).outcome, "PASS");
  eq("R-C passes when the frozen assessment is independent",
    predicateRC(byType, results(byType, "independent")).outcome, "PASS");
}
{
  // IOP-R-XREF shape: the Effect's decision_ref names no artifact in the bundle.
  const { arts, byType } = bundle({ effect: { decision_ref: { record_id: "iop-absent-decision-0000" } } });
  eq("R-A fails on an unresolved decision_ref", predicateRA(byType, arts).outcome, "FAIL");
  eq("R-B is unaffected", predicateRB(byType).outcome, "PASS");
}
{
  // IOP-R-TOCTOU shape: the Execution's executed digest diverges.
  const { arts, byType } = bundle({ execution: { executed_action_digest: "sha256:" + "b".repeat(64) } });
  eq("R-A is unaffected", predicateRA(byType, arts).outcome, "PASS");
  eq("R-B fails on unequal digests", predicateRB(byType).outcome, "FAIL");
}
{
  // Exact string comparison: no case folding, no normalization, no re-hashing.
  const { byType } = bundle({ execution: { executed_action_digest: "sha256:" + "A".repeat(64) } });
  eq("R-B does not case-fold", predicateRB(byType).outcome, "FAIL");
}
{
  // IOP-R-INDEP shape: wire says independent, the frozen assessment is unknown.
  const { byType } = bundle();
  eq("R-C fails on independent-vs-unknown",
    predicateRC(byType, results(byType, "unknown")).outcome, "FAIL");
}
{
  // A wire value that is not `independent` is not this predicate's business.
  const { byType } = bundle({ effect: { observer_relationship: "unknown" } });
  eq("R-C passes when the wire does not claim independence",
    predicateRC(byType, results(byType, "unknown")).outcome, "PASS");
}
{
  // The evaluator never re-derives independence; with no frozen verdict there
  // is nothing to take it from, and the predicate fails closed.
  const { byType } = bundle();
  const empty = new Map([...byType].map(([, a]) => [a.bundlePath, { verifierResult: null }]));
  eq("R-C fails closed with no frozen verdict", predicateRC(byType, empty).outcome, "FAIL");
}

// ---------------------------------------------------------------------------
// 7. Level-1 mapping order (section 7)
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
// 8. CLI surface and the exit/stdout table (section 8.5)
// ---------------------------------------------------------------------------

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "interop-node-selftest-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));

function run(args) {
  const p = spawnSync(process.execPath, [EVAL, ...args], { encoding: "utf8" });
  return { code: p.status, out: p.stdout, err: p.stderr };
}

function mkBundle(name, { scenarioId = "SYNTH-1", files = {}, manifestExtra = {}, corruptDigest = null } = {}) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const digests = {};
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
    digests[rel] = rel === corruptDigest ? "0".repeat(64) : sha(Buffer.from(content));
  }
  const manifest = { scenario_id: scenarioId, files: digests, ...manifestExtra };
  fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(manifest, null, 1));
  return dir;
}

// exit 2 -- CLI usage
eq("no --bundle is a usage error", run([]).code, 2);
check("usage error writes nothing to stdout", run([]).out === "");
eq("unknown option is a usage error", run(["--bundle", tmp, "--nope", "x"]).code, 2);
eq("repeated option is a usage error", run(["--bundle", "a", "--bundle", "b"]).code, 2);
eq("--help does not measure and is a usage error", run(["--help"]).code, 2);
check("--help writes nothing to stdout", run(["--help"]).out === "");

// exit 1 -- bundle identity never established, stdout silent
{
  const r = run(["--bundle", path.join(tmp, "absent")]);
  eq("absent bundle directory exits 1", r.code, 1);
  check("absent bundle writes nothing to stdout", r.out === "");
}
{
  const dir = path.join(tmp, "nomanifest");
  fs.mkdirSync(dir, { recursive: true });
  const r = run(["--bundle", dir]);
  eq("missing manifest exits 1", r.code, 1);
  check("missing manifest writes nothing to stdout", r.out === "");
}
{
  const dir = path.join(tmp, "badmanifest");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "manifest.json"), "{ not json");
  const r = run(["--bundle", dir]);
  eq("unparseable manifest exits 1", r.code, 1);
  check("unparseable manifest writes nothing to stdout", r.out === "");
}
{
  const dir = path.join(tmp, "noid");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify({ files: {}, artifacts: ["a.json"] }));
  const r = run(["--bundle", dir]);
  eq("manifest without scenario_id exits 1 (identity unknown)", r.code, 1);
  check("no scenario_id writes nothing to stdout", r.out === "");
}
{
  const dir = mkBundle("absentfile", {
    files: { "a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision"}' },
    manifestExtra: { artifacts: ["a.json"] },
  });
  fs.rmSync(path.join(dir, "a.json"));
  const r = run(["--bundle", dir]);
  eq("a file listed in the manifest but absent exits 1", r.code, 1);
  check("absent file writes nothing to stdout", r.out === "");
}
{
  const dir = mkBundle("unknownmember", {
    files: { "a.json": "{}" },
    manifestExtra: { artifacts: ["a.json"], surprise: 1 },
  });
  eq("unknown manifest member exits 1", run(["--bundle", dir]).code, 1);
}
{
  const dir = mkBundle("escape", {
    files: { "a.json": "{}" },
    manifestExtra: { artifacts: ["a.json"] },
  });
  const m = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
  m.files["../outside.json"] = "0".repeat(64);
  fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(m));
  eq("a manifest path escaping the bundle exits 1", run(["--bundle", dir]).code, 1);
}

// exit 3 -- identity established, scenario unmeasurable, one result object
function parseOne(out) {
  const v = JSON.parse(out);
  check("result object carries the pinned member set",
    ["artifacts", "evaluator_version", "level1", "measurement_status", "predicates",
      "scenario_id", "verifier_digests", "withheld_reasons"]
      .every((k) => k in v), Object.keys(v).sort().join(","));
  return v;
}
{
  const dir = mkBundle("digestmismatch", {
    files: { "a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision"}' },
    manifestExtra: { artifacts: ["a.json"] },
    corruptDigest: "a.json",
  });
  const r = run(["--bundle", dir]);
  eq("a file failing its manifest digest exits 3", r.code, 3);
  const v = parseOne(r.out);
  eq("digest mismatch is ERROR", v.measurement_status, "ERROR");
  eq("digest mismatch carries level1 null", v.level1, null);
  eq("digest mismatch still names the scenario", v.scenario_id, "SYNTH-1");
}
{
  const stub = path.join(tmp, "stub_verifier.mjs");
  fs.writeFileSync(stub, "process.exit(0);\n");
  const dir = mkBundle("wrongverifier", {
    files: { "a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision"}' },
    manifestExtra: { artifacts: ["a.json"] },
  });
  const r = run(["--bundle", dir, "--verifier", stub]);
  eq("a frozen-verifier digest mismatch exits 3", r.code, 3);
  const v = parseOne(r.out);
  eq("digest assertion failure is ERROR", v.measurement_status, "ERROR");
  check("the mismatching digest is recorded",
    v.verifier_digests["verifier_node_r2/class_verifier.mjs"].asserted === false);
  check("the other lane's verifier is recorded but never asserted",
    v.verifier_digests["verifier_py/class_verifier.py"].asserted === false
    && v.verifier_digests["verifier_py/class_verifier.py"].observed === null);
}
{
  // Numeric preflight runs AFTER the digest assertion and BEFORE any envelope
  // is assembled, so this reaches preflight only because the real frozen
  // verifier is present at its default path -- and it stops before invoking it.
  const dir = mkBundle("bignum", {
    files: { "a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision","profiles":{"x.y":{"n":9007199254740993}}}' },
    manifestExtra: { artifacts: ["a.json"] },
  });
  const r = run(["--bundle", dir]);
  eq("an out-of-envelope number exits 3", r.code, 3);
  const v = parseOne(r.out);
  eq("numeric preflight rejection is ERROR", v.measurement_status, "ERROR");
  check("the offending JSON Pointer is reported",
    r.err.includes('"/profiles/x.y/n"'), r.err.trim());
}
{
  const dir = mkBundle("outsideinput", {
    files: { "a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision"}' },
    manifestExtra: { artifacts: ["a.json"] },
  });
  const outside = path.join(tmp, "outside_bindings.json");
  fs.writeFileSync(outside, "{}");
  const r = run(["--bundle", dir, "--bindings", outside]);
  eq("an operator input from outside the bundle is a usage error", r.code, 2);
  check("outside operator input writes nothing to stdout", r.out === "");
}

// determinism (section 8.4)
{
  const dir = mkBundle("determinism", {
    files: { "a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision"}' },
    manifestExtra: { artifacts: ["a.json"] },
    corruptDigest: "a.json",
  });
  const a = run(["--bundle", dir]).out;
  const b = run(["--bundle", dir]).out;
  check("identical input gives byte-identical output", a === b);
}

// ---------------------------------------------------------------------------
// 9. Live frozen-verifier invocation (envelope construction, section 5.1;
//    exit-1 causal guard, section 7.2)
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

if (!fs.existsSync(VERIFIER_DEPS)) {
  console.log("SKIPPED: live frozen-verifier checks -- verifier_node_r2/node_modules not materialized "
    + "(run class-verification/offline-node-deps/materialize_node_modules.py)");
} else {
  const synth = (rid, type) => JSON.stringify({
    airep_version: "0.2", artifact_type: type, chain_id: "synth.chain",
    record_id: rid, sequence: 0,
  });

  // --- single artifact: related_artifacts is the empty array ---------------
  {
    const dir = mkBundle("live-single", {
      scenarioId: "SYNTH-NOT-PINNED",
      files: { "a.json": synth("synth-a", "decision") },
      manifestExtra: { artifacts: ["a.json"] },
    });
    const r = run(["--bundle", dir]);
    eq("a non-pinned scenario whose artifact exits 1 is ERROR, not REJECT", r.code, 3);
    const v = parseOne(r.out);
    eq("that ERROR carries level1 null", v.level1, null);
    eq("measurement_status is ERROR", v.measurement_status, "ERROR");
    eq("one artifacts[] entry", v.artifacts.length, 1);
    eq("verifier_exit_code is recorded verbatim", v.artifacts[0].verifier_exit_code, 1);
    eq("verifier_result is null when the frozen verifier exits 1", v.artifacts[0].verifier_result, null);
    check("a stderr audit digest is recorded",
      /^sha256:[0-9a-f]{64}$/.test(v.artifacts[0].verifier_stderr_digest));
    const expected = "sha256:" + sha(Buffer.from(
      jcs({ artifact: JSON.parse(synth("synth-a", "decision")), related_artifacts: [] }), "utf8"));
    eq("single-artifact envelope carries an empty related_artifacts",
      v.artifacts[0].request_envelope_digest, expected);
  }

  // --- the section 7.2 causal guard, both directions -----------------------
  {
    const dir = mkBundle("live-pinned", {
      scenarioId: "IOP-B-DEC",
      files: { "a.json": synth("synth-a", "decision") },
      manifestExtra: { artifacts: ["a.json"] },
    });
    const r = run(["--bundle", dir]);
    eq("a pinned stage-0/1 scenario reads frozen exit 1 as REJECT", r.code, 0);
    const v = parseOne(r.out);
    eq("that scenario is MEASURED", v.measurement_status, "MEASURED");
    eq("its Level-1 verdict is REJECT", v.level1, "REJECT");
    eq("a single-artifact scenario runs no predicate", v.predicates, NA);
  }

  // --- four artifacts: related_artifacts in record_id UTF-8 byte order -----
  {
    const files = {
      "d.json": synth("synth-4-dec", "decision"),
      "c.json": synth("synth-1-ctl", "control"),
      "x.json": synth("synth-3-exe", "execution"),
      "e.json": synth("synth-2-eff", "effect"),
    };
    const dir = mkBundle("live-four", {
      scenarioId: "SYNTH-NOT-PINNED",
      files,
      manifestExtra: { artifacts: ["d.json", "c.json", "x.json", "e.json"] },
    });
    const r = run(["--bundle", dir]);
    eq("a four-artifact bundle of invalid artifacts is ERROR", r.code, 3);
    const v = parseOne(r.out);
    eq("artifacts[] is ordered by record_id UTF-8 byte order",
      v.artifacts.map((a) => a.artifact_ref.record_id),
      ["synth-1-ctl", "synth-2-eff", "synth-3-exe", "synth-4-dec"]);
    const values = Object.values(files).map((t) => JSON.parse(t));
    for (const entry of v.artifacts) {
      const primary = values.find((x) => x.record_id === entry.artifact_ref.record_id);
      const related = values.filter((x) => x !== primary)
        .sort((a, b) => byteCompare(a.record_id, b.record_id));
      const want = "sha256:" + sha(Buffer.from(jcs({ artifact: primary, related_artifacts: related }), "utf8"));
      eq(`envelope digest for ${entry.artifact_ref.record_id}`, entry.request_envelope_digest, want);
    }
  }
}

console.log(`${checks - failures}/${checks} checks passed`);
if (failures > 0) process.exit(1);
