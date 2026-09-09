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
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  jcs, byteCompare, decodeDecimal, checkNumberToken, scanJsonNumbers,
  checkBundlePath, resolveRef, predicateRA, predicateRB, predicateRC, mapLevel1,
  verdictShapeViolation, isDirectInvocation, parseArgs,
  classifyProcessShape, classifyVerdictStdout, writeStdoutSync,
  authenticatedWithheldViolation, artifactRefFromArtifact,
  checkJsonByteDomain, hasUnpairedSurrogate, scanJsonDocument,
  compareStageFailures, resultShapeViolation, normativeProjection, projectionBytes,
  STAGE, STAGE_REASON_ORDER, reasonRank,
  RESULT_MEMBERS as EVAL_RESULT_MEMBERS,
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

// Section 13 step 5. A block this run could not produce the precondition for is
// NOT MEASURED, and a summary that omits it from both numbers reports green for
// checks that never executed. That is the exact failure class Erratum 6's
// evidence-narrowing note records against this file's own earlier counts: 668
// reported green while 81 further checks, the AD15-IR-6 fixture among them,
// were silently absent because verifier_node_r2/node_modules had not been
// materialized. Skips are therefore counted, named, and -- in the default mode
// -- fatal.
let failures = 0;
let checks = 0;
let skips = 0;
const skippedBlocks = [];
function check(name, cond, detail) {
  checks++;
  if (!cond) { failures++; console.log(`FAIL: ${name}${detail ? " -- " + detail : ""}`); }
}

// The ONLY way to decline a block. Every site that cannot produce its
// precondition routes through here, so no block can leave the run silently: it
// is counted, it is named in the summary, and by default it makes the run
// non-zero. `block` names the block; `why` says what could not be produced.
function skip(block, why) {
  skips++;
  skippedBlocks.push(block);
  console.log(`SKIPPED: ${block} -- ${why}`);
}

// A BRANCH that is STRUCTURALLY UNREACHABLE on this runtime, recorded rather
// than skipped silently or counted as covered.
//
// This is NOT the same thing as skip(). W1-BLK-IR13 item 9 is the case it exists
// for: the section 8.6 name key is defined over WHAT THE PLATFORM'S API ACTUALLY
// PROVIDES, and the contract says in terms that "a lane whose API yields only
// lossless raw bytes cannot construct the Unicode-native branch, and vice versa;
// the unreachable branch is recorded NOT_MEASURED on that platform rather than
// skipped silently or counted as covered."
//
// Node's readdirSync({ encoding: "buffer" }) yields lossless raw name bytes on
// every platform this lane runs on, so the Unicode-native branch cannot be
// constructed here AT ALL -- not for an environmental reason a re-run could
// change. Routing it through skip() would make the OFFICIAL evidence command
// permanently non-zero and would therefore assert that the pinned BLOCK did not
// execute, which is false: the block's obligation is "the name-key branch ITS OWN
// PLATFORM SUPPLIES", and that branch is measured. The three states section 8.7
// pins are per-BLOCK; this is a per-BRANCH record inside a block that ran.
const notMeasuredBranches = [];
function notMeasuredBranch(branch, why) {
  notMeasuredBranches.push(`${branch} -- ${why}`);
  console.log(`NOT MEASURED (branch): ${branch} -- ${why}`);
}

// ---------------------------------------------------------------------------
// The CANONICAL MANDATORY BLOCK REGISTRY (section 8.7)
// ---------------------------------------------------------------------------
// "A mandatory test block actually executed" carried no criterion, so a lane
// could simply never register a required test, report zero skips, and look
// complete. E7-27 closes it, and the closure has a specific shape worth stating
// because it is the whole point:
//
//   THE REQUIRED BLOCK IDS ARE PINNED BY THE CONTRACT, NOT DECLARED BY THIS
//   IMPLEMENTATION. A registry a lane writes for itself is not a control -- an
//   implementer can delete the block AND its own registry entry and still
//   report `0 skipped`.
//
// So the array below is TRANSCRIBED FROM THE CONTRACT and is closed. Nothing in
// this file may add to it, and a block that goes missing shows up as
// NOT MEASURED rather than as silence.
//
//   * a block EXECUTED when its assertions ran and their outcomes are counted,
//     proved machine-readably by at least ONE assertion-counter increment AND a
//     block-completion record carrying the ID. A block that "ran" without
//     incrementing any counter asserted nothing, and is recorded as vacuous --
//     which is NOT MEASURED, never a pass;
//   * any pinned ID with NO execution record is reported as skipped;
//   * an UNKNOWN or DUPLICATE block ID makes the run NON-QUALIFYING -- unknown
//     because the set is closed, duplicate because two records under one ID make
//     "did it run" unanswerable;
//   * the summary distinguishes passed, failed and NOT MEASURED, and the default
//     mode exits non-zero if any pinned block is in the third.
//
// Sharing an ID vocabulary with the peer lane is not shared state and does not
// touch section 4 isolation: the two lanes derive their test code independently
// from the same contract, exactly as they derive their evaluators.
// E8-10 / E8-11. The registry began at W1-BLK-IR9: AD15-IR-4 through AD15-IR-8
// had NO BLOCK AT ALL, so five normative rulings -- including AD15-IR-8's 0o111
// worked case, a MEASURED convergence in Erratum 5 -- could each be violated by
// a lane while every mandatory block reported green. The set is now TWENTY.
//
// E8-12 states what this registry is, and it is worth carrying here because it
// bounds what a block may demand: it is a MINIMUM DISCRIMINATION SUITE, not a
// completeness proof. Absence of a block for a normative branch does not make
// that branch non-normative and does not grant implementation freedom; and no
// block may require an impossible fixture, an unprovable universal, peer
// material, or narrow a freedom the contract leaves open.
//
// The SIX-ID AGGREGATE registry (W1-AGG-D1 .. D6) is the HARNESS's, not this
// lane's: by section 4 a lane-local runner can never exercise anything requiring
// peer material. It is deliberately absent from this file and is not attempted.
const MANDATORY_BLOCKS = Object.freeze([
  "W1-BLK-IR4", "W1-BLK-IR5", "W1-BLK-IR6", "W1-BLK-IR7", "W1-BLK-IR8",
  "W1-BLK-IR9", "W1-BLK-IR10", "W1-BLK-IR11", "W1-BLK-IR12", "W1-BLK-IR13",
  "W1-BLK-IR14", "W1-BLK-IR15", "W1-BLK-IR16", "W1-BLK-IR17", "W1-BLK-JCS",
  "W1-BLK-LIVE", "W1-BLK-PARITY", "W1-BLK-ARTIFACT-REF", "W1-BLK-JSON-BYTES",
  "W1-BLK-PATH",
]);

// id -> { state, assertions, failures }. state is "passed" | "failed" |
// "not-measured". A registry violation is collected separately and is fatal in
// its own right.
const blockRecords = new Map();
const registryViolations = [];
let openBlock = null;

function beginBlock(id) {
  if (!MANDATORY_BLOCKS.includes(id)) {
    registryViolations.push(`unknown block ID ${JSON.stringify(id)} -- the pinned set is closed`);
  }
  if (blockRecords.has(id)) {
    registryViolations.push(
      `duplicate block ID ${JSON.stringify(id)} -- two records under one ID make `
      + '"did it run" unanswerable');
  }
  if (openBlock !== null) {
    registryViolations.push(`block ${openBlock.id} was never closed before ${id} opened`);
  }
  openBlock = { id, checks0: checks, failures0: failures, skipped: false };
}

// Declines the OPEN pinned block: its precondition could not be produced here.
// It is recorded as NOT MEASURED for that ID no matter how many incidental
// assertions the surrounding code ran, because the obligation was not exercised.
function skipBlock(why) {
  if (openBlock === null) {
    registryViolations.push(`skipBlock called with no open block: ${why}`);
    return;
  }
  openBlock.skipped = true;
  skips++;
  skippedBlocks.push(`${openBlock.id} (${why})`);
  console.log(`SKIPPED: ${openBlock.id} -- ${why}`);
}

function endBlock(id) {
  if (openBlock === null || openBlock.id !== id) {
    registryViolations.push(`endBlock(${id}) does not match the open block `
      + `${openBlock === null ? "(none)" : openBlock.id}`);
    openBlock = null;
    return;
  }
  const assertions = checks - openBlock.checks0;
  const failed = failures - openBlock.failures0;
  let state;
  if (openBlock.skipped) {
    state = "not-measured";
  } else if (assertions === 0) {
    // The vacuity criterion, stated because it is the failure E7-27 names: a
    // block that "ran" and asserted nothing is not evidence of anything.
    state = "not-measured";
    skips++;
    skippedBlocks.push(`${id} (asserted nothing -- no counter increment)`);
    console.log(`SKIPPED: ${id} -- the block completed without incrementing any assertion counter`);
  } else {
    state = failed > 0 ? "failed" : "passed";
  }
  blockRecords.set(id, { state, assertions, failures: failed });
  openBlock = null;
}

// Developer-only opt-in (section 13 step 5). It permits skips to be non-fatal
// while working on one block in an environment that cannot produce another.
// THE OFFICIAL EVIDENCE COMMAND MUST NOT USE IT: an official count is a claim
// about every block, and this flag is exactly the licence to make that claim
// while some did not run.
const ALLOW_SKIPS = process.argv.slice(2).includes("--allow-skips");
for (const a of process.argv.slice(2)) {
  if (a !== "--allow-skips") {
    console.log(`usage: selftest.mjs [--allow-skips]; unknown argument ${JSON.stringify(a)}`);
    process.exit(2);
  }
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

// E8-3 makes artifact_ref REQUIRED, TYPED and CLOSED on an accepted verdict, so
// a well-shaped verdict now carries one. The fixture is updated rather than the
// gate weakened: the ruling is what changed.
const OK_VERDICT = {
  artifact_ref: { chain_id: "c", record_id: "r" },
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
// E4-1. The carve-out is ONE EXACT INVOCATION, not one concept: the lone token
// `--help` and nothing else. Both halves are asserted, because each alone is
// satisfiable by a wrong implementation -- a lane that refuses everything would
// pass the negatives, and a lane that accepts everything would pass the
// positive.
{
  const h = parseMeta("--help", ["--help"]);
  if (h) {
    eq("--help alone parses as the meta-action", h.help, true);
    check("--help does not require --bundle", h.flags.bundle === null);
  }
}
eq("an ordinary invocation is not the meta-action",
  parseArgs(["--bundle", "d"]).help, false);
// -h is NOT an alias (E4-1). This lane previously accepted it; the erratum
// records that acceptance as one half of a MEASURED cross-lane divergence, and
// pins the other reading.
usageRejects("-h is not an alias for the meta-action", ["-h"]);
usageRejects("-h is rejected alongside a valid --bundle", ["--bundle", "d", "-h"]);
// --help combined with ANY other argument is not the meta-action (E4-1) --
// including combinations where every other argument is perfectly valid, which
// is the case a "--help wins" reading would let through.
usageRejects("--help does not excuse an unknown option", ["--help", "--nope", "x"]);
usageRejects("--help does not excuse a positional argument", ["--help", "junk"]);
usageRejects("--help does not excuse a repeated option",
  ["--help", "--bundle", "a", "--bundle", "b"]);
usageRejects("--help alongside a VALID --bundle is not the meta-action",
  ["--help", "--bundle", "d"]);
usageRejects("--bundle before --help is not the meta-action either",
  ["--bundle", "d", "--help"]);
usageRejects("--help twice is not the meta-action", ["--help", "--help"]);
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
  // Renders the manifest to BYTES. The default is the ordinary JSON encoding;
  // AD15-IR-17 and AD15-IR-20 need manifests that JSON.stringify cannot
  // produce -- a repeated member name, a UTF-16 encoding, a BOM -- so the
  // rendering is a hook rather than a fixed call.
  renderManifest = null,
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
  fs.writeFileSync(path.join(dir, "manifest.json"),
    renderManifest === null ? JSON.stringify(manifest, null, 1) : renderManifest(manifest));
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
{
  const r = run(["--help"]);
  eq("--help exits 0", r.code, 0);
  check("--help writes human-readable help to stdout",
    r.out.length > 0 && /--bundle/.test(r.out), JSON.stringify(r.out.slice(0, 120)));
  // "No result JSON object" is the load-bearing half: exit 0 on an EVALUATION
  // asserts a MEASURED result, and a help screen must not be mistakable for one.
  let parsedAsJson = true;
  try { JSON.parse(r.out); } catch { parsedAsJson = false; }
  check("--help emits no result JSON object", !parsedAsJson, r.out.slice(0, 200));
  // Not a regex on field names -- the help text legitimately DOCUMENTS
  // measurement_status in its exit table, so that probe would fail on correct
  // output. The property that matters is that stdout is not a result object.
  check("--help output is not a JSON object at all",
    r.out.trimStart()[0] !== "{", r.out.slice(0, 200));
  // It does not require --bundle, and it touches no bundle at all.
  check("--help needs no --bundle", r.code === 0);
}
// The exit-0 invariant guard must not have fired: it is keyed on invocation
// kind, so a meta-action satisfying it via stdout does NOT relax what an
// evaluation must satisfy. This control measures that the guard stayed silent.
{
  const r = run(["--help"]);
  check("--help does not trip the exit-0 invariant guard",
    !/internal invariant violated/.test(r.err), r.err.slice(0, 200));
}

// --- E4-1 discrimination: the meta-action is ONE EXACT INVOCATION -----------
// "Exactly one flag wide" was ambiguous and two isolated lanes measurably
// diverged on it; THIS lane accepted -h. The erratum pins the other reading, so
// the discriminating cases are asserted at the process level too, not only
// through parseArgs: exit code, empty stdout, and the absence of help text are
// three separable properties and a wrong implementation can satisfy some.
{
  const good = mkBundle("e41-help-probe");
  const notMeta = [
    ["-h alone", ["-h"]],
    ["-h alongside a valid bundle", ["--bundle", good, "-h"]],
    ["--help with a VALID --bundle", ["--help", "--bundle", good]],
    ["a valid --bundle before --help", ["--bundle", good, "--help"]],
    ["--help twice", ["--help", "--help"]],
    ["--help with a positional", ["--help", "junk"]],
  ];
  for (const [label, args] of notMeta) {
    const r = run(args);
    // Exit 2 specifically. Not 0 (the superseded meta-action reading), and not
    // 1 or 3 (which would mean the bundle was touched at all).
    eq(`${label} is a usage error, exit 2`, r.code, 2);
    check(`${label} writes nothing to stdout`, r.out === "", JSON.stringify(r.out.slice(0, 200)));
    // The load-bearing negative: no help text leaked to stdout. Under the
    // superseded reading each of these printed the usage screen and exited 0.
    check(`${label} prints no help screen on stdout`,
      !/--independence-policy/.test(r.out), r.out.slice(0, 200));
  }
  // Control: the bundle used above is a REAL, identifiable bundle, so the
  // exit-2 results above are attributable to the argument vector and not to a
  // broken bundle. Without this the whole block could pass while measuring
  // nothing but a bad --bundle value.
  {
    const r = run(["--bundle", good]);
    check("control: the probe bundle is identifiable, so exit 2 above is about the argv",
      r.code === 3 || r.code === 0, `bare --bundle gave exit ${r.code}`);
    check("control: the probe bundle names its scenario", /IOP-P-DEC/.test(r.out), r.out.slice(0, 200));
  }
  // Help CONTENT and byte length are explicitly NOT a parity requirement
  // (E4-1), so nothing here compares them across lanes or pins a length. The
  // only property asserted of the help text is that it exists and is not a
  // result object, which is checked above.
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

// The same assertions, for cases that need extra argv (a --verifier override,
// an operator-input flag). expectNonMeasured() takes a bundle directory; this
// takes the whole argument vector.
function expectNonMeasuredWith(name, args, reason, status = "ERROR") {
  const r = run(args);
  eq(`${name} exits 3`, r.code, 3);
  if (r.code !== 3) return null;
  const v = parseOne(name, r.out);
  eq(`${name} reason`, v.nonmeasurement.reason, reason);
  eq(`${name} status`, v.measurement_status, status);
  eq(`${name} level1 is null`, v.level1, null);
  eq(`${name} predicates is null`, v.predicates, null);
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
    skip("symlink check", "this filesystem refused symlink creation");
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
    skip(`NODE-IMP-1 path regression for ${JSON.stringify(dirName)}`, e.message);
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

// ---------------------------------------------------------------------------
// 11a. The frozen-verifier interceptor (shared by several blocks below)
// ---------------------------------------------------------------------------
// Several rulings are about what the evaluator does with a frozen-verifier
// PROCESS RESULT it cannot produce on demand: a spawn that fails, a process
// killed by a signal, an exit-0 verdict of a chosen shape. The frozen verifier
// is not modified, not wrapped and not replaced on disk. A tiny driver patches
// child_process.spawnSync IN ITS OWN PROCESS, before importing the evaluator,
// so the evaluator's `import { spawnSync }` binding resolves to the stub.
//
// The module under test is the real interop_eval.mjs, entered through its real
// exported main(), with the real argument parsing, the real bundle preflight
// and the real frozen-identity assertion -- which reads the GENUINE frozen
// files and must pass, or none of this is reached at all. The interceptor only
// decides what the subprocess would have returned, which is exactly the input
// surface these rulings govern. It is written to a temp file rather than
// shipped, so no stubbed verifier ever sits beside the evaluator.
const driver = path.join(tmp, "interceptor_driver.mjs");
fs.writeFileSync(driver,
  'import { createRequire } from "node:module";\n'
  + 'const require = createRequire(import.meta.url);\n'
  + 'const cp = require("node:child_process");\n'
  + '// Patched BEFORE the evaluator is imported, so its `import { spawnSync }`\n'
  + '// binding resolves to this function. Nothing else about the module changes.\n'
  + 'const plan = JSON.parse(process.env.AIREP_SELFTEST_PLAN);\n'
  + 'let calls = 0;\n'
  + 'cp.spawnSync = function () {\n'
  + '  const step = plan[calls] ?? plan[plan.length - 1];\n'
  + '  calls++;\n'
  + '  if (step.spawnFails) {\n'
  + '    // The exact shape spawnSync returns when no process was created.\n'
  + '    const err = new Error("spawn ENOENT");\n'
  + '    err.code = "ENOENT";\n'
  + '    return { pid: 0, status: null, signal: null, stdout: null, stderr: null,\n'
  + '             error: err, output: [] };\n'
  + '  }\n'
  + '  if (step.throws) {\n'
  + '    // Not a process outcome at all: spawnSync itself raises. The evaluator\n'
  + '    // has no registry reason for that, so it must reach the generic fault\n'
  + '    // path and report internal-error -- which is what W1-BLK-IR13 item 12\n'
  + '    // needs in order to show internal-error staying OUTSIDE the stage order.\n'
  + '    throw new Error("synthetic evaluator-internal fault at invocation");\n'
  + '  }\n'
  + '  if (step.signal) {\n'
  + '    // AD15-IR-15 middle row: the process STARTED (a real pid) and did not\n'
  + '    // exit normally. Node reports that as status null plus a signal name --\n'
  + '    // and there is no portable integer to put in verifier_exit_code.\n'
  + '    return { pid: 4243, status: null, signal: step.signal,\n'
  + '             stdout: Buffer.from(step.stdout ?? ""),\n'
  + '             stderr: Buffer.from(step.stderr ?? ""),\n'
  + '             error: undefined, output: [] };\n'
  + '  }\n'
  + '  return { pid: 4242, status: step.status, signal: null,\n'
  + '           stdout: Buffer.from(step.stdout ?? ""),\n'
  + '           stderr: Buffer.from(step.stderr ?? ""),\n'
  + '           error: undefined, output: [] };\n'
  + '};\n'
  + 'const mod = await import(process.env.AIREP_SELFTEST_EVAL);\n'
  + 'const code = mod.main(process.argv.slice(2));\n'
  + '// A control the assertions can read: how many invocations were actually\n'
  + '// attempted. Without it "artifacts[] has one entry" could pass vacuously\n'
  + '// because the loop never reached the second artifact at all.\n'
  + 'process.stderr.write(`SPAWN_CALLS=${calls}\\n`);\n'
  + 'process.exitCode = code;\n');

// ---------------------------------------------------------------------------
// 11b. The FILESYSTEM interceptor
// ---------------------------------------------------------------------------
// Two obligations need a filesystem state that cannot be produced by writing
// files, and both are pinned Class-1 behaviour:
//
//   * E8-2 -- a listed file PRESENT at stage 5 and giving a DEFINITE ENOENT on
//     read at stage 6. That is a race against the evaluator's own traversal;
//     writing and deleting files cannot land inside it deterministically.
//   * W1-BLK-IR13 item 8 -- the reported failure does not change with the
//     OPERATING SYSTEM'S enumeration order. readdir order is unspecified and
//     this filesystem happens to be stable, so the only way to measure the
//     property is to hand the evaluator a different order.
//
// Same discipline as the spawn interceptor: the real interop_eval.mjs is
// entered through its real exported main(), with the real preflight and the real
// frozen-identity assertion over the GENUINE frozen files. Only the two
// filesystem primitives named in the plan are diverted, and only for paths that
// match a declared suffix -- the manifest read and the frozen-identity reads go
// through untouched.
const fsDriver = path.join(tmp, "fs_driver.mjs");
fs.writeFileSync(fsDriver,
  'import { createRequire } from "node:module";\n'
  + 'const require = createRequire(import.meta.url);\n'
  + 'const fsmod = require("node:fs");\n'
  + 'const plan = JSON.parse(process.env.AIREP_SELFTEST_FSPLAN);\n'
  + 'const realRead = fsmod.readFileSync;\n'
  + 'const realReaddir = fsmod.readdirSync;\n'
  + 'fsmod.readFileSync = function (p, ...rest) {\n'
  + '  const sp = typeof p === "string" ? p : String(p);\n'
  + '  for (const rule of plan.readFileErrors ?? []) {\n'
  + '    if (sp.endsWith(rule.suffix)) {\n'
  + '      const err = new Error(`${rule.code}: synthetic, open ${sp}`);\n'
  + '      err.code = rule.code;\n'
  + '      err.syscall = "open";\n'
  + '      err.path = sp;\n'
  + '      throw err;\n'
  + '    }\n'
  + '  }\n'
  + '  return realRead.call(this, p, ...rest);\n'
  + '};\n'
  + 'fsmod.readdirSync = function (p, ...rest) {\n'
  + '  const out = realReaddir.call(this, p, ...rest);\n'
  + '  // The OS order this lane is handed is stable; reversing it is what makes\n'
  + '  // "the reported failure does not change with enumeration order" measurable\n'
  + '  // rather than asserted.\n'
  + '  return plan.reverseReaddir ? [...out].reverse() : out;\n'
  + '};\n'
  + 'const mod = await import(process.env.AIREP_SELFTEST_EVAL);\n'
  + 'process.exitCode = mod.main(process.argv.slice(2));\n');

function runFsIntercepted(bundleDir, fsplan, extraArgs = []) {
  const p = spawnSync(process.execPath, [fsDriver, "--bundle", bundleDir, ...extraArgs], {
    encoding: "utf8",
    env: { ...process.env,
      AIREP_SELFTEST_FSPLAN: JSON.stringify(fsplan),
      AIREP_SELFTEST_EVAL: pathToFileURL(EVAL).href },
  });
  return { code: p.status, out: p.stdout, err: p.stderr };
}

function runIntercepted(bundleDir, plan, extraArgs = []) {
  const p = spawnSync(process.execPath, [driver, "--bundle", bundleDir, ...extraArgs], {
    encoding: "utf8",
    env: { ...process.env,
      AIREP_SELFTEST_PLAN: JSON.stringify(plan),
      AIREP_SELFTEST_EVAL: pathToFileURL(EVAL).href },
  });
  const m = /SPAWN_CALLS=(\d+)/.exec(p.stderr ?? "");
  return { code: p.status, out: p.stdout, err: p.stderr, spawnCalls: m ? Number(m[1]) : null };
}

// A frozen verdict that is SHAPE-VALID per the class-verifier section 2
// envelope, so the evaluator accepts it as an emitted verdict rather than
// rejecting it as a wrong-shape result. `ref` defaults to the shape the frozen
// Node verifier actually emits: a closed { chain_id, record_id } pair.
const verdict = (withheld = [], ref = { chain_id: "c", record_id: "r" }, extra = {}) =>
  JSON.stringify({
    artifact_ref: ref,
    class: "AIREP-Core",
    observer_assessment: "not_applicable",
    authenticated_failures: [],
    authenticated_withheld: withheld,
    authenticated_caveats: [],
    witnessed_failures: [],
    witnessed_withheld: [],
    ...extra,
  });

// A four-artifact IOP-R bundle: one each of the four families, so the pinned
// bundle-shape check passes and four invocations are attempted in
// artifact_path order.
const four = (name, scenarioId = "IOP-R-CLEAN") => mkBundle(name, {
  scenarioId,
  artifacts: {
    "artifacts/1decision.json": '{"airep_version":"0.2","artifact_type":"decision","chain_id":"c","record_id":"r-dec","sequence":0}',
    "artifacts/2control.json": '{"airep_version":"0.2","artifact_type":"control","chain_id":"c","record_id":"r-ctl","sequence":1}',
    "artifacts/3execution.json": '{"airep_version":"0.2","artifact_type":"execution","chain_id":"c","record_id":"r-exe","sequence":2}',
    "artifacts/4effect.json": '{"airep_version":"0.2","artifact_type":"effect","chain_id":"c","record_id":"r-eff","sequence":3}',
  },
});

const VERIFIER = path.join(HERE, "..", "..", "class-verification", "verifier_node_r2", "class_verifier.mjs");
const VERIFIER_DEPS = path.join(path.dirname(VERIFIER), "node_modules", "ajv");

beginBlock("W1-BLK-LIVE");
if (!fs.existsSync(VERIFIER) || !fs.existsSync(VERIFIER_DEPS)) {
  // This is the block whose silent absence Erratum 6's evidence-narrowing note
  // records: it carries the AD15-IR-6 reverse-ranking fixture and the whole live
  // envelope/exit-code surface. It is a PINNED block now, so its absence is a
  // NOT MEASURED row against W1-BLK-LIVE rather than a line in a skip list.
  skipBlock("verifier_node_r2 or its node_modules is not materialized -- run "
    + "class-verification/offline-node-deps/materialize_node_modules.py");
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

  // --- four artifacts, LIVE: AD15-IR-12 order and abort, on real processes -
  //
  // These four synthetic artifacts all fail frozen stage 0, and IOP-R-CLEAN is
  // NOT one of the three scenarios section 7.2 admits for the exit-1 REJECT
  // reading -- so the FIRST invocation is a fatal verifier-run-invalid and
  // AD15-IR-12 aborts the scenario there.
  //
  // That is what makes this block an ORDER proof against genuine processes:
  // artifacts[] carries exactly ONE entry, and WHICH entry it is says which
  // artifact was invoked first. The fixture puts record_id rank in the EXACT
  // REVERSE of artifact_path rank, so the byte-first path and the byte-first
  // record_id are different artifacts and the check discriminates the key
  // rather than restating it.
  //
  // Before AD15-IR-12 this block asserted all four entries. That expectation is
  // now non-conforming, and the four-envelope discrimination it carried moved
  // to the intercepted run below, where no abort intervenes -- nothing was
  // dropped.
  {
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
      eq("its reason is verifier-run-invalid", v.nonmeasurement.reason, "verifier-run-invalid");
      // AD15-IR-12, both halves in one observation.
      eq("AD15-IR-12: the scenario aborted at the first fatal run", v.artifacts.length, 1);
      eq("AD15-IR-12: and the artifact invoked first is the byte-first artifact_path",
        v.artifacts[0].artifact_path, "artifacts/c.json");
      // The discrimination: byte-first PATH and byte-first RECORD_ID are
      // different artifacts in this fixture, so an implementation invoking in
      // record_id order would have aborted on artifacts/x.json instead.
      const byRecordFirst = Object.entries(artifacts)
        .sort((a, b) => byteCompare(JSON.parse(a[1]).record_id, JSON.parse(b[1]).record_id))[0][0];
      eq("control: record_id order would have chosen a different artifact first",
        byRecordFirst, "artifacts/x.json");
      eq("AD15-IR-12: the emitted entry is NOT the record_id-first artifact",
        v.artifacts[0].artifact_path !== byRecordFirst, true);
      // AD15-IR-18 Source B: no verdict exists, so artifact_ref is the
      // preliminary projection over the parsed artifact.
      // Member order is the emitted one: the result object is written with
      // stableStringify, which sorts members, so a literal in projection order
      // would compare unequal for a reason that is not a defect.
      eq("AD15-IR-18 Source B: artifact_ref is the projection over the artifact",
        v.artifacts[0].artifact_ref, { chain_id: "synth.chain", record_id: "synth-4-ctl" });
      eq("no verdict exists, so verifier_result is null", v.artifacts[0].verifier_result, null);
      eq("the process exited normally, so verifier_exit_code is an integer",
        v.artifacts[0].verifier_exit_code, 1);
      // AD15-IR-6 still discriminates on the one artifact that WAS invoked.
      const byPath = Object.fromEntries(
        Object.entries(artifacts).map(([k, t]) => [k, JSON.parse(t)]));
      const primary = byPath["artifacts/c.json"];
      const others = Object.entries(byPath).filter(([k]) => k !== "artifacts/c.json");
      const digestOf = (rel) => "sha256:" + sha(Buffer.from(
        jcs({ artifact: primary, related_artifacts: rel }), "utf8"));
      const pathOrder = [...others].sort((a, b) => byteCompare(a[0], b[0])).map(([, x]) => x);
      const recOrder = [...others]
        .sort((a, b) => byteCompare(a[1].record_id, b[1].record_id)).map(([, x]) => x);
      eq("AD15-IR-6: related_artifacts is in artifact_path order",
        v.artifacts[0].request_envelope_digest, digestOf(pathOrder));
      check("control: the two orderings really do give different envelope bytes",
        digestOf(pathOrder) !== digestOf(recOrder));
    }
  }

  // --- E3-1 / AD15-IR-6 discrimination, on an INTERCEPTED run --------------
  //
  // This is the case AD15-IR-6 exists for: under the superseded record_id
  // ordering an artifact with no record_id had no defined envelope at all, and
  // the two isolated lanes resolved it differently -- one sorting it under an
  // empty key (this lane), one refusing to build the envelope. Both are gone:
  // the key is artifact_path, which always exists.
  //
  // It runs through the interceptor rather than the genuine frozen verifier for
  // a reason AD15-IR-12 created: four synthetic artifacts all fail stage 0, and
  // on a non-qualifying scenario the FIRST fatal run now aborts the scenario --
  // so a live run can only ever show one of the four envelopes. The interceptor
  // supplies four clean exit-0 verdicts, which never abort, so all four
  // envelopes are emitted and every assertion this block used to make is still
  // made. Everything else is real: real preflight, real envelope construction,
  // real frozen-identity assertion against the genuine frozen files.
  const noIdArtifacts = {
    "artifacts/d.json": synth("synth-3-dec", "decision"),
    "artifacts/c.json": synth("synth-4-ctl", "control"),
    "artifacts/x.json": JSON.stringify({
      airep_version: "0.2", artifact_type: "execution", chain_id: "synth.chain", sequence: 0,
    }),                                              // no record_id at all
    "artifacts/e.json": synth("synth-2-eff", "effect"),
  };
  {
    const artifacts = noIdArtifacts;
    const dir = mkBundle("e31-no-record-id", { scenarioId: "IOP-R-CLEAN", artifacts });
    // Four distinct verdicts, one per invocation, so the pairing of entry to
    // invocation is observable: entry k must carry plan[k]'s artifact_ref.
    const plan = ["v0", "v1", "v2", "v3"].map((rid) => ({
      status: 0, stdout: verdict([], { chain_id: "vc", record_id: rid }),
    }));
    const r = runIntercepted(dir, plan);

    // (a) STAGE-0 REACHABILITY. The load-bearing half. A missing record_id must
    // NOT become this evaluator's own preflight failure: the artifact is handed
    // to the frozen verifier, not refused before it. bundle-shape-invalid or
    // numeric-preflight-violation here would mean the evaluator pre-empted the
    // measurement it exists to take.
    eq("a record_id-less artifact still reaches invocation", r.code, 0);
    eq("all four invocations were attempted", r.spawnCalls, 4);
    const v = parseOne("no record_id", r.out);
    eq("no preflight reason was raised", v.nonmeasurement, null);
    eq("artifacts[] carries all four entries", v.artifacts.length, 4);
    check("every artifact reached an invocation and has an exit code",
      v.artifacts.every((a) => typeof a.verifier_exit_code === "number"),
      show(v.artifacts.map((a) => a.verifier_exit_code)));

    // (b) DETERMINISTIC artifact_path ORDERING, including the unidentifiable
    // artifact, which under the superseded rule had no defined position -- and
    // AD15-IR-12's order, proved by the entry/invocation pairing.
    eq("artifacts[] is ordered by artifact_path even with a record_id absent",
      v.artifacts.map((a) => a.artifact_path),
      ["artifacts/c.json", "artifacts/d.json", "artifacts/e.json", "artifacts/x.json"]);
    eq("AD15-IR-12: invocation k paired with entry k, in artifact_path order",
      v.artifacts.map((a) => a.artifact_ref.record_id), ["v0", "v1", "v2", "v3"]);
    check("control: artifact_path order and record_id order really do disagree here",
      show(Object.keys(artifacts).sort(byteCompare))
        !== show(Object.entries(artifacts)
          .sort((a, b) => byteCompare(JSON.parse(a[1]).record_id ?? "", JSON.parse(b[1]).record_id ?? ""))
          .map(([k]) => k)));

    // (c) NOTHING WAS FABRICATED on the Source-B side. The projection over the
    // record_id-less artifact is null -- identity without invention -- which is
    // asserted directly on the projection function, because on THIS run every
    // entry took Source A (an accepted verdict) and therefore carries the
    // verdict's ref rather than the artifact's.
    eq("AD15-IR-18: the projection over the record_id-less artifact is null",
      artifactRefFromArtifact(JSON.parse(artifacts["artifacts/x.json"])), null);
    for (const entry of v.artifacts) {
      eq(`${entry.artifact_path}: entry carries exactly the pinned member set`,
        Object.keys(entry).sort(), [...ARTIFACT_MEMBERS].sort());
    }

    // (d) THE ENVELOPE IS DEFINED for every artifact, and is the path-ordered
    // one. Recomputed here independently of the evaluator's own ordering code,
    // with the record_id ordering shown to give different bytes -- so the
    // assertion discriminates the ruling rather than restating it. Differing
    // envelope bytes are exactly what aggregate duty 2 compares across lanes.
    const byPath = Object.fromEntries(
      Object.entries(artifacts).map(([k, t]) => [k, JSON.parse(t)]));
    for (const e of v.artifacts) {
      const primary = byPath[e.artifact_path];
      const others = Object.entries(byPath).filter(([k]) => k !== e.artifact_path);
      const digestOf = (rel) => "sha256:" + sha(Buffer.from(
        jcs({ artifact: primary, related_artifacts: rel }), "utf8"));
      const pathOrder = [...others].sort((a, b) => byteCompare(a[0], b[0])).map(([, x]) => x);
      const recOrder = [...others]
        .sort((a, b) => byteCompare(a[1].record_id ?? "", b[1].record_id ?? "")).map(([, x]) => x);
      eq(`${e.artifact_path}: envelope defined and path-ordered despite a missing record_id`,
        e.request_envelope_digest, digestOf(pathOrder));
      check(`${e.artifact_path}: path order and record_id order give different envelopes`,
        digestOf(pathOrder) !== digestOf(recOrder));
      check(`${e.artifact_path}: the superseded record_id ordering is NOT what was emitted`,
        e.request_envelope_digest !== digestOf(recOrder));
    }

    // (e) DETERMINISM (section 8.4). Identical bundle and identical operator
    // inputs give byte-identical output across repeat runs -- the property the
    // superseded empty-key resolution could not guarantee.
    const r2 = runIntercepted(dir, plan);
    eq("a second run is byte-identical", r2.out, r.out);
    eq("a second run exits the same", r2.code, r.code);
  }
}

endBlock("W1-BLK-LIVE");

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
    skip("FIFO check", "mkfifo is unavailable on this system");
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
      skip("bundle-file-unreadable",
        "this process can read a 0o000 file (root, or a filesystem that ignores chmod); "
        + "the condition cannot be produced");
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
// 14d. Erratum 4 / E4-2 -- the identity boundary is a DIRECT READ
// ---------------------------------------------------------------------------
// Identity comes from reading the bytes of DIR/manifest.json directly, never
// from enumerating the bundle first. All five listed conditions are identity
// NOT established: exit 1, stdout empty, no result object -- and therefore no
// reason code, because a reason belongs to a result object and there is no
// scenario to name one after.
//
// The two conditions that discriminate an enumerate-first implementation are
// (1) an inaccessible bundle ROOT and (3) a manifest that is present but
// unreadable: an evaluator that listed the bundle before reading the manifest
// would raise a registry reason for the first, and could reach for
// bundle-file-unreadable on the second. Both are asserted with a control that
// the condition was really produced, and skipped rather than faked otherwise.
{
  const cases = [];

  // (1) the bundle root itself cannot be accessed.
  {
    const dir = path.join(tmp, "e42-root-denied");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "manifest.json"),
      JSON.stringify({ manifest_version: "1", scenario_id: "IOP-P-DEC", files: [] }));
    let denied = false;
    try {
      fs.chmodSync(dir, 0o000);
      try { fs.readFileSync(path.join(dir, "manifest.json")); } catch { denied = true; }
    } catch { /* chmod unsupported here */ }
    if (!denied) {
      skip("E4-2 inaccessible bundle root",
        "this process can read through a 0o000 directory (root, or a filesystem that "
        + "ignores chmod)");
      try { fs.chmodSync(dir, 0o755); } catch { /* best effort */ }
    } else {
      check("control: the bundle root really is inaccessible before the assertion counts", denied);
      cases.push(["an inaccessible bundle root", dir, () => fs.chmodSync(dir, 0o755)]);
    }
  }

  // (2) DIR/manifest.json is not found.
  {
    const dir = path.join(tmp, "e42-absent");
    fs.mkdirSync(dir, { recursive: true });
    cases.push(["an absent root manifest", dir, null]);
  }

  // (3) present, but cannot be opened or read. This is the case the erratum
  //     names explicitly: it must NOT become bundle-file-unreadable.
  {
    const dir = path.join(tmp, "e42-unreadable");
    fs.mkdirSync(dir, { recursive: true });
    const mf = path.join(dir, "manifest.json");
    fs.writeFileSync(mf, JSON.stringify({ manifest_version: "1", scenario_id: "IOP-P-DEC", files: [] }));
    let denied = false;
    try {
      fs.chmodSync(mf, 0o000);
      try { fs.readFileSync(mf); } catch { denied = true; }
    } catch { /* chmod unsupported here */ }
    if (!denied) {
      skip("E4-2 unreadable root manifest", "this process can read a 0o000 file");
      try { fs.chmodSync(mf, 0o644); } catch { /* best effort */ }
    } else {
      check("control: the root manifest really is unreadable before the assertion counts", denied);
      cases.push(["a present but unreadable root manifest", dir, () => fs.chmodSync(mf, 0o644)]);
    }
  }

  // (4) bytes do not parse as strict JSON.
  {
    const dir = path.join(tmp, "e42-nonjson");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "manifest.json"), "{ not json");
    cases.push(["a root manifest that is not strict JSON", dir, null]);
  }

  // (5) no registered scenario_id can be obtained.
  {
    const dir = path.join(tmp, "e42-noscenario");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "manifest.json"),
      JSON.stringify({ manifest_version: "1", scenario_id: "NOT-A-SCENARIO", files: [] }));
    cases.push(["a root manifest with no registered scenario_id", dir, null]);
  }

  for (const [label, dir, restore] of cases) {
    const r = run(["--bundle", dir]);
    eq(`${label}: exits 1`, r.code, 1);
    check(`${label}: stdout is empty`, r.out === "", JSON.stringify(r.out.slice(0, 200)));
    // No result object means no reason code. bundle-file-unreadable in
    // particular must never appear: the root manifest is not a files[] entry,
    // and there is no scenario to name a reason against.
    check(`${label}: emits no registry reason at all`,
      !/bundle-file-unreadable|bundle-file-missing|bundle-directory-unreadable|manifest-invalid|nonmeasurement/
        .test(r.out), r.out.slice(0, 200));
    check(`${label}: not exit 3`, r.code !== 3, `exit ${r.code}`);
    if (restore) restore();
  }
  check("the E4-2 enumeration was exercised over at least four of its five conditions",
    cases.length >= 4, `${cases.length} conditions producible on this platform`);
}

// ---------------------------------------------------------------------------
// 14e. Erratum 4 / E4-3 -- bundle-directory-unreadable is its own reason
// ---------------------------------------------------------------------------
// After identity is established, a bundle traversal that cannot enumerate a
// directory is bundle-directory-unreadable, exit 3. Deliberately NOT
// manifest-invalid: that reason says the layout is WRONG, this one says the
// layout could not be MEASURED. This lane recorded exactly that discomfort as
// open ambiguity 5 and reported manifest-invalid rather than inventing a row;
// the erratum closed it with a dedicated one.
{
  const dir = mkBundle("e43-dir-denied");
  const sub = path.join(dir, "artifacts");
  let denied = false;
  try {
    fs.chmodSync(sub, 0o000);
    try { fs.readdirSync(sub); } catch { denied = true; }
  } catch { /* chmod unsupported here */ }
  if (!denied) {
    skip("bundle-directory-unreadable",
      "this process can enumerate a 0o000 directory (root, or a filesystem that ignores "
      + "chmod); the condition cannot be produced");
    try { fs.chmodSync(sub, 0o755); } catch { /* best effort */ }
  } else {
    check("control: the directory really cannot be enumerated before the assertion counts", denied);
    const vDir = expectNonMeasured("an unenumerable directory under the bundle", dir,
      "bundle-directory-unreadable");
    if (vDir) {
      check("the detail names enumeration, not a layout rule",
        /enumerate/i.test(vDir.nonmeasurement.detail), vDir.nonmeasurement.detail);
      check("it does not claim the layout is wrong",
        !/violat|not closed|must be sorted/i.test(vDir.nonmeasurement.detail),
        vDir.nonmeasurement.detail);
      // Identity WAS established, so the result object names the scenario --
      // which is the whole reason this is exit 3 and not exit 1.
      eq("the scenario is named", vDir.scenario_id, "IOP-P-DEC");
    }
    fs.chmodSync(sub, 0o755);

    // THE DISCRIMINATION: the new reason is distinct from all three neighbours
    // it could have been collapsed into. Each of the four is produced here and
    // the set is required to be pairwise distinct -- a collapse fails this even
    // though every individual assertion above would still pass.
    const vLayout = expectNonMeasured("a genuine layout violation, for contrast",
      mkBundle("e43-contrast-layout", { mutate: (m) => { m.files.reverse(); } }), "manifest-invalid");
    const vMissing = expectNonMeasured("a genuinely absent listed file, for contrast",
      mkBundle("e43-contrast-missing", {
        mutate: (m) => {
          m.files.push({ path: "zz-ghost.json", role: "artifact", sha256: "0".repeat(64) });
          m.files.sort((a, b) => byteCompare(a.path, b.path));
        },
      }), "bundle-file-missing");
    let vUnread = null;
    {
      const d2 = mkBundle("e43-contrast-unreadable");
      const target = path.join(d2, "artifacts", "a.json");
      let fdenied = false;
      try {
        fs.chmodSync(target, 0o000);
        try { fs.readFileSync(target); } catch { fdenied = true; }
      } catch { /* chmod unsupported */ }
      if (fdenied) {
        vUnread = expectNonMeasured("a listed regular file that cannot be read, for contrast",
          d2, "bundle-file-unreadable");
        fs.chmodSync(target, 0o644);
      }
    }
    const observed = [vDir, vLayout, vMissing, vUnread]
      .filter((x) => x !== null && x !== undefined).map((x) => x.nonmeasurement.reason);
    eq("directory-unreadable, layout-invalid, file-missing and file-unreadable are distinct",
      observed.length, new Set(observed).size);
    check("the boundary was exercised over at least three neighbouring conditions",
      observed.length >= 3, show(observed));
    check("an unenumerable directory is NOT reported as manifest-invalid",
      vDir === null || vDir.nonmeasurement.reason !== "manifest-invalid",
      vDir && vDir.nonmeasurement.reason);
  }
}
// Negative control: a readable nested directory is a container and produces no
// directory reason at all. Without this, an implementation that returned
// bundle-directory-unreadable for every directory would pass the block above.
{
  const dir = mkBundle("e43-dir-readable", {
    artifacts: {
      "artifacts/nested/deep/a.json": '{"record_id":"r","chain_id":"c","artifact_type":"decision"}',
    },
  });
  const r = run(["--bundle", dir]);
  check("a readable nested directory never yields bundle-directory-unreadable",
    !/bundle-directory-unreadable/.test(r.out), r.out.slice(0, 300));
}

// ---------------------------------------------------------------------------
// 14f. Erratum 4 / E4-4 (AD15-IR-7) -- duplicate semantic IDs are NOT preflight
//      invalidity
// ---------------------------------------------------------------------------
// No bundle-wide preflight gate on duplicate record_id or duplicate
// (chain_id, record_id). artifact_path is each artifact's total harness
// identity, so duplicated semantic IDs cannot make a bundle unidentifiable.
// Such artifacts still go to frozen stage evaluation; if a real reference
// lookup then produces more than one match, R-A and the frozen resolution
// semantics treat it as AMBIGUOUS. The evaluator never picks one and never
// synthesizes an ID.
//
// Frozen R-10 is a different surface -- a batch verifier's own emitted verdict
// set -- and must not be widened into a bundle preflight rule.

// The predicate side, as a pure function: duplicates are resolved as ambiguous,
// never picked. This is where the condition is SUPPOSED to be judged.
{
  const dup = [
    { bundlePath: "artifacts/a.json", value: { record_id: "same", chain_id: "c" } },
    { bundlePath: "artifacts/b.json", value: { record_id: "same", chain_id: "c" } },
    { bundlePath: "artifacts/c.json", value: { record_id: "other", chain_id: "c" } },
  ];
  const r = resolveRef({ record_id: "same" }, dup);
  eq("a reference matching two artifacts is ambiguous", r.state, "ambiguous");
  eq("both matches are counted", r.matches, 2);
  check("no match is picked", r.target === undefined);
  eq("a chain-qualified reference to a duplicated pair is still ambiguous",
    resolveRef({ record_id: "same", chain_id: "c" }, dup).state, "ambiguous");
  eq("a unique reference in the same bundle still resolves",
    resolveRef({ record_id: "other" }, dup).state, "resolved");
}

// The preflight side, end to end: a four-artifact bundle in which two artifacts
// share both record_id and chain_id must NOT be refused before invocation.
{
  const art = (type, rid) => JSON.stringify({
    airep_version: "0.2", artifact_type: type, chain_id: "synth.chain",
    record_id: rid, sequence: 0,
  });
  const dir = mkBundle("e44-duplicate-ids", {
    scenarioId: "IOP-R-CLEAN",
    artifacts: {
      "artifacts/1-dec.json": art("decision", "synth-duplicate"),
      "artifacts/2-ctl.json": art("control", "synth-duplicate"),
      "artifacts/3-exe.json": art("execution", "synth-exe"),
      "artifacts/4-eff.json": art("effect", "synth-eff"),
    },
  });
  // Intercepted, because AD15-IR-12 now aborts a non-qualifying bundle at its
  // FIRST fatal run: against the genuine frozen verifier only one of the four
  // synthetic artifacts would ever be submitted, and "every artifact was
  // submitted" is precisely what this block has to show. Four clean exit-0
  // verdicts never abort. Preflight is real, and preflight is where a
  // duplicate-record_id gate would have lived.
  const dupPlan = ["p0", "p1", "p2", "p3"].map((rid) => ({
    status: 0, stdout: verdict([], { chain_id: "synth.chain", record_id: rid }),
  }));
  const r = runIntercepted(dir, dupPlan);
  eq("a bundle with duplicate semantic IDs still produces a result object", r.code, 0);
  eq("no preflight gate stopped it: four invocations were attempted", r.spawnCalls, 4);
  if (r.code === 0 || r.code === 3) {
    const v = parseOne("duplicate semantic IDs", r.out);
    const reason = v.nonmeasurement === null ? "(none)" : v.nonmeasurement.reason;
    // THE DISCRIMINATION. A duplicate-record_id preflight gate would have to
    // raise one of these before any verifier was invoked; none of them may
    // appear. bundle-shape-invalid is the one a gate would most naturally use,
    // because it is where family composition is already checked.
    const PREFLIGHT_REASONS = [
      "manifest-invalid", "manifest-digest-mismatch", "bundle-file-missing",
      "bundle-file-unreadable", "bundle-directory-unreadable", "bundle-json-invalid",
      "bundle-shape-invalid", "numeric-preflight-violation",
    ];
    check("duplicate semantic IDs are not a preflight refusal",
      !PREFLIGHT_REASONS.includes(reason), `reason was ${reason}`);
    // Reaching frozen evaluation is the positive half: a gate would leave
    // artifacts[] empty (section 8.3.1 step 2, pre-invocation ERROR).
    check("the bundle reached frozen stage evaluation rather than being refused",
      v.artifacts.length > 0,
      `artifacts[] had ${v.artifacts.length} entries, reason ${reason}`);
    if (v.artifacts.length > 0) {
      eq("every artifact was submitted, including the duplicated pair", v.artifacts.length, 4);
      // Nothing was renamed, deduplicated or synthesized. On this run every
      // entry took AD15-IR-18 Source A, so the emitted artifact_ref is the
      // verdict's; the artifact-side proof that the duplicate survived intact
      // is the projection, asserted directly.
      eq("both duplicated artifacts appear, keyed by artifact_path",
        v.artifacts.map((a) => a.artifact_path),
        ["artifacts/1-dec.json", "artifacts/2-ctl.json",
         "artifacts/3-exe.json", "artifacts/4-eff.json"]);
      eq("the duplicated record_id survives the projection on the first of the pair",
        artifactRefFromArtifact(JSON.parse(art("decision", "synth-duplicate"))),
        { record_id: "synth-duplicate", chain_id: "synth.chain" });
      eq("and on the second, verbatim and un-deduplicated",
        artifactRefFromArtifact(JSON.parse(art("control", "synth-duplicate"))),
        { record_id: "synth-duplicate", chain_id: "synth.chain" });
    }
  }
  // Control: the identical bundle with UNIQUE ids behaves the same way, so the
  // assertions above are about the absence of a gate and not about some other
  // property of this fixture.
  {
    const uniq = mkBundle("e44-unique-ids", {
      scenarioId: "IOP-R-CLEAN",
      artifacts: {
        "artifacts/1-dec.json": art("decision", "synth-dec"),
        "artifacts/2-ctl.json": art("control", "synth-ctl"),
        "artifacts/3-exe.json": art("execution", "synth-exe"),
        "artifacts/4-eff.json": art("effect", "synth-eff"),
      },
    });
    const ru = runIntercepted(uniq, dupPlan);
    eq("control: the same bundle with unique ids exits the same way", ru.code, r.code);
    eq("control: and attempts the same number of invocations", ru.spawnCalls, r.spawnCalls);
    eq("control: and reaches the same band",
      JSON.parse(ru.out).measurement_status, JSON.parse(r.out).measurement_status);
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
  // itself is judged later, by the section 7.2 causal guard. AD15-IR-15 names
  // this the third row, "exited normally", and it is the ONLY row that carries
  // an integer verifier_exit_code.
  for (const code of [0, 1, 2, 7]) {
    const shape = classifyProcessShape(spawnSync(process.execPath, ["-e", `process.exit(${code})`]));
    eq(`a normal exit ${code} is the exited-normally outcome`, shape.outcome, "exited-normally");
    eq(`a normal exit ${code} is not a process-band failure`, shape.reason, null);
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
  // AD15-IR-15's THREE outcomes, kept apart by name and not only by reason: the
  // first two rows share nothing but the fact that neither produced an exit
  // code, and only ONE of them contributes an artifacts[] entry.
  eq("started-then-errored is the abnormal-termination outcome",
    classifyProcessShape({ pid: 4242, error: new Error("ENOBUFS"), status: null }).outcome,
    "abnormal-termination");
  eq("signal death is the abnormal-termination outcome",
    classifyProcessShape({ pid: 4242, status: null, signal: "SIGKILL" }).outcome,
    "abnormal-termination");
  eq("never-started is the never-started outcome",
    classifyProcessShape({ pid: 0, error: new Error("ENOENT"), status: null }).outcome,
    "never-started");
  eq("never-started is not-invocable",
    classifyProcessShape({ pid: 0, error: new Error("ENOENT"), status: null }).reason,
    "verifier-not-invocable");
  // No signal name or number reaches a NORMATIVE field. detail is Class-4
  // diagnostic-only under section 8.7, so it MAY carry it -- E7-14 exists
  // because an earlier draft forbade what its next sentence required.
  check("the signal may appear in detail, which is diagnostic-only",
    /SIGKILL/.test(classifyProcessShape({ pid: 4242, status: null, signal: "SIGKILL" }).detail));
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
  // E8-3: an accepted verdict now REQUIRES a typed, closed artifact_ref.
  const GOOD = {
    artifact_ref: { chain_id: "c", record_id: "r" },
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
    skip("NODE-IMP-1 pipe-truncation regressions",
      "this platform did not exhibit the defect even for the buggy pattern, so they "
      + "cannot discriminate here");
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

// ---------------------------------------------------------------------------
// 17. Erratum 5 -- the five closures
// ---------------------------------------------------------------------------

// --- 17a. E5-4: frozen-identity UNREADABLE is not frozen-identity MISMATCH --
//
// The superseded implementation ran the frozen-digest assertion at the END of
// preflight and reported an unreadable frozen file as verifier-digest-mismatch,
// emitting a two-entry verifier_digests whose members were null. Both halves
// were wrong: it fabricated a placeholder for a file it never read, and it
// asserted a comparison it never performed.
//
// The point of this block is the SEPARATION. Each condition must produce its
// own reason AND its own verifier_digests shape; a test that checked only one
// would not notice the two collapsing back into one.
{
  const dir = mkBundle("e54-frozen");
  const absent = path.join(tmp, "no-such-frozen-file.mjs");
  check("control: the substitute frozen path really is absent", !fs.existsSync(absent));

  // (1) own class verifier unreadable -> frozen-identity-unreadable, null.
  const vNoVerifier = (() => {
    const r = run(["--bundle", dir, "--verifier", absent]);
    eq("an unreadable frozen verifier exits 3", r.code, 3);
    if (r.code !== 3) return null;
    const v = parseOne("frozen verifier unreadable", r.out);
    eq("its reason is frozen-identity-unreadable",
      v.nonmeasurement.reason, "frozen-identity-unreadable");
    eq("its status is ERROR", v.measurement_status, "ERROR");
    eq("verifier_digests is NULL -- no digest is fabricated for a file never read",
      v.verifier_digests, null);
    eq("artifacts[] is empty: the failure is pre-invocation", v.artifacts, []);
    eq("level1 is null", v.level1, null);
    eq("predicates is null", v.predicates, null);
    return v;
  })();

  // (2) frozen CLASS CONTRACT unreadable -> the same reason. Both members of
  //     the identity pair are covered, not just the verifier.
  const vNoContract = (() => {
    const r = run(["--bundle", dir, "--verifier-contract", absent]);
    eq("an unreadable frozen class contract exits 3", r.code, 3);
    if (r.code !== 3) return null;
    const v = parseOne("frozen contract unreadable", r.out);
    eq("its reason is frozen-identity-unreadable too",
      v.nonmeasurement.reason, "frozen-identity-unreadable");
    eq("verifier_digests is NULL there as well", v.verifier_digests, null);
    eq("artifacts[] is empty", v.artifacts, []);
    return v;
  })();

  // (3) present and READABLE but the wrong bytes -> verifier-digest-mismatch,
  //     and the ACTUAL RECOMPUTED two-entry object is RETAINED. A reader needs
  //     to see what was actually there, not what was expected.
  const stub = path.join(tmp, "e54_stub_verifier.mjs");
  const stubBody = "process.exit(0);\n";
  fs.writeFileSync(stub, stubBody);
  const vMismatch = (() => {
    const r = run(["--bundle", dir, "--verifier", stub]);
    eq("a readable frozen verifier with the wrong bytes exits 3", r.code, 3);
    if (r.code !== 3) return null;
    const v = parseOne("frozen verifier mismatch", r.out);
    eq("its reason is verifier-digest-mismatch",
      v.nonmeasurement.reason, "verifier-digest-mismatch");
    check("verifier_digests is NOT null when both files were read",
      v.verifier_digests !== null, show(v.verifier_digests));
    eq("it carries EXACTLY the two own-lane entries",
      Object.keys(v.verifier_digests).sort(), ["class_verifier", "class_verifier_contract"]);
    // The load-bearing half: the retained value is the RECOMPUTED one. Computed
    // here independently of the evaluator, from the stub's own bytes.
    eq("the retained class_verifier digest is the ACTUAL recomputed value",
      v.verifier_digests.class_verifier, "sha256:" + sha(Buffer.from(stubBody)));
    eq("artifacts[] is empty: the failure is pre-invocation", v.artifacts, []);
    return v;
  })();

  // THE DISCRIMINATION ITSELF. Collapsing unreadable into mismatch -- the
  // defect E5-4 closed -- fails here even though several individual assertions
  // above would still pass under the collapse.
  if (vNoVerifier && vMismatch) {
    check("unreadable and mismatch are DIFFERENT reasons",
      vNoVerifier.nonmeasurement.reason !== vMismatch.nonmeasurement.reason,
      `${vNoVerifier.nonmeasurement.reason} vs ${vMismatch.nonmeasurement.reason}`);
    check("and they differ in verifier_digests nullability, not only in the reason string",
      (vNoVerifier.verifier_digests === null) !== (vMismatch.verifier_digests === null),
      `${show(vNoVerifier.verifier_digests)} vs ${show(vMismatch.verifier_digests)}`);
  }
  if (vNoContract && vMismatch) {
    check("the contract half is separated from mismatch too",
      vNoContract.nonmeasurement.reason !== vMismatch.nonmeasurement.reason);
  }

  // E5-4 ORDERING. Step 2 runs IMMEDIATELY after bundle identity and before all
  // other post-identity preflight, so EVERY other post-identity result carries a
  // POPULATED verifier_digests. Under the superseded ordering -- assertion last
  // -- every one of these emitted null, so this sweep is what measures the move.
  {
    const populated = [
      ["manifest closure violation", mkBundle("e54-ord-closure",
        { mutate: (m) => { m.extra = 1; } }), "manifest-invalid"],
      ["manifest sort violation", mkBundle("e54-ord-sort",
        { mutate: (m) => { m.files.reverse(); } }), "manifest-invalid"],
      ["digest mismatch", mkBundle("e54-ord-digest",
        { corrupt: "artifacts/a.json" }), "manifest-digest-mismatch"],
      ["absent listed file", mkBundle("e54-ord-missing", {
        mutate: (m) => {
          m.files.push({ path: "zz-ghost.json", role: "artifact", sha256: "0".repeat(64) });
          m.files.sort((a, b) => byteCompare(a.path, b.path));
        },
      }), "bundle-file-missing"],
      ["unparseable listed file", mkBundle("e54-ord-json",
        { artifacts: { "artifacts/a.json": "{ not json" } }), "bundle-json-invalid"],
      ["bundle shape violation", mkBundle("e54-ord-shape", {
        scenarioId: "IOP-R-CLEAN",
        artifacts: { "artifacts/a.json": '{"record_id":"r","artifact_type":"decision"}' },
      }), "bundle-shape-invalid"],
      ["numeric preflight violation", mkBundle("e54-ord-num", {
        artifacts: { "artifacts/a.json": '{"record_id":"r","artifact_type":"decision","n":1e20}' },
      }), "numeric-preflight-violation"],
    ];
    for (const [label, bdir, wantReason] of populated) {
      const r = run(["--bundle", bdir]);
      eq(`${label}: exits 3`, r.code, 3);
      if (r.code !== 3) continue;
      const v = JSON.parse(r.out);
      eq(`${label}: reason`, v.nonmeasurement.reason, wantReason);
      // The ordering assertion.
      check(`${label}: carries a POPULATED verifier_digests (step 2 preceded it)`,
        v.verifier_digests !== null, show(v.verifier_digests));
      if (v.verifier_digests !== null) {
        eq(`${label}: with exactly the two own-lane entries`,
          Object.keys(v.verifier_digests).sort(),
          ["class_verifier", "class_verifier_contract"]);
      }
    }
    // And the reservation stated directly: null is for frozen-identity-unreadable
    // ALONE. Nothing else in this whole file may emit it.
    check("verifier_digests: null is reserved for frozen-identity-unreadable alone",
      populated.every(([, bdir]) => {
        const v = JSON.parse(run(["--bundle", bdir]).out || "{}");
        return v.verifier_digests !== null;
      }));
  }
}

// --- 17b. E5-3: bundle-entry-uninspectable ---------------------------------
//
// The last gap in the filesystem taxonomy: an entry whose NAME was obtained but
// whose KIND could not be determined. Enumeration SUCCEEDED, so
// bundle-directory-unreadable does not fit; the layout was never inspected, so
// manifest-invalid would assert exactly what could not be established.
//
// The condition is produced with a directory that is READABLE but not
// SEARCHABLE (mode 0o444): readdir returns the names, and lstat on each name
// fails EACCES. A CONTROL measures that this really happens here before any
// assertion is allowed to count -- otherwise the block would pass by measuring
// an ordinary readable directory.
beginBlock("W1-BLK-IR9");
{
  const dir = mkBundle("e53-uninspectable");
  const sub = path.join(dir, "artifacts");
  let namesListed = false;
  let kindDeniable = false;
  try {
    fs.chmodSync(sub, 0o444);
    try {
      const names = fs.readdirSync(sub);
      namesListed = names.length > 0;
      for (const n of names) {
        try { fs.lstatSync(path.join(sub, n)); } catch { kindDeniable = true; }
      }
    } catch { /* enumeration itself failed: not this condition */ }
  } catch { /* chmod unsupported here */ }

  if (!(namesListed && kindDeniable)) {
    // Under euid 0, or on a filesystem that ignores chmod, the condition simply
    // cannot be produced. That is NOT MEASURED for this pinned block -- never a
    // pass, and never quietly absent.
    skipBlock("this platform does not produce 'readdir succeeds, lstat denied' (root, or a "
      + "filesystem that ignores chmod); the condition cannot be produced");
    try { fs.chmodSync(sub, 0o755); } catch { /* best effort */ }
  } else {
    check("control: entry names ARE obtained from the directory", namesListed);
    check("control: and their kind really cannot be determined", kindDeniable);
    const v = expectNonMeasured("an entry whose kind cannot be inspected", dir,
      "bundle-entry-uninspectable");
    if (v) {
      eq("the scenario is named -- identity was established", v.scenario_id, "IOP-P-DEC");
      eq("artifacts[] is empty: pre-invocation", v.artifacts, []);
      check("the detail says the kind could not be determined",
        /kind could not be determined/i.test(v.nonmeasurement.detail),
        v.nonmeasurement.detail);
      check("it does not claim the layout is wrong",
        !/violat|forbidden|not closed|must be sorted/i.test(v.nonmeasurement.detail),
        v.nonmeasurement.detail);
    }
    fs.chmodSync(sub, 0o755);

    // THE DISCRIMINATION: the new reason is distinct from BOTH neighbours it
    // sits between -- the enumeration failure above it and the layout violation
    // below it. E5-3 exists precisely because it was being folded into one of
    // these two.
    let vDirUnread = null;
    {
      const d2 = mkBundle("e53-contrast-dir");
      const s2 = path.join(d2, "artifacts");
      let denied = false;
      try {
        fs.chmodSync(s2, 0o000);
        try { fs.readdirSync(s2); } catch { denied = true; }
      } catch { /* chmod unsupported */ }
      if (denied) {
        vDirUnread = expectNonMeasured("an unenumerable directory, for contrast", d2,
          "bundle-directory-unreadable");
        fs.chmodSync(s2, 0o755);
      }
    }
    const vLayout = expectNonMeasured("a genuine layout violation, for contrast",
      mkBundle("e53-contrast-layout", { mutate: (m) => { m.files.reverse(); } }),
      "manifest-invalid");
    const observed = [v, vDirUnread, vLayout]
      .filter((x) => x !== null && x !== undefined).map((x) => x.nonmeasurement.reason);
    eq("uninspectable, directory-unreadable and layout-invalid are pairwise distinct",
      observed.length, new Set(observed).size);
    check("the boundary was exercised over at least three conditions",
      observed.length >= 3, show(observed));
    if (v) {
      check("an uninspectable entry is NOT reported as manifest-invalid",
        v.nonmeasurement.reason !== "manifest-invalid");
      check("an uninspectable entry is NOT reported as bundle-directory-unreadable",
        v.nonmeasurement.reason !== "bundle-directory-unreadable");
    }
  }
}
// Negative control: an ordinary readable bundle never yields the new reason.
// Without this, an implementation that returned bundle-entry-uninspectable for
// every entry would pass the block above.
{
  const r = run(["--bundle", mkBundle("e53-normal", { corrupt: "artifacts/a.json" })]);
  check("a fully inspectable bundle never yields bundle-entry-uninspectable",
    !/bundle-entry-uninspectable/.test(r.out), r.out.slice(0, 300));
}

// AD15-IR-9's OTHER half, which does not need a special filesystem: the
// enumeration-time type hint is NOT consulted at all. This lane requests NAMES
// (encoding "buffer") and never Dirents, so there is no d_type value in the
// traversal for an implementation to trust -- the property is structural and is
// asserted on the source, because on ext4 (which populates d_type) a
// behavioural test cannot distinguish "ignored the hint" from "the hint agreed".
{
  const src = fs.readFileSync(EVAL, "utf8");
  check("AD15-IR-9: the traversal never requests Dirents, so no d_type hint exists to trust",
    !/withFileTypes/.test(src), "withFileTypes appears in the evaluator source");
  check("AD15-IR-9: and it performs an explicit no-follow lstat per entry",
    /lstatSync\(childAbs\)/.test(src));
  check("AD15-IR-9: stat (which follows links) is never used to classify an entry",
    !/fs\.statSync/.test(src), "fs.statSync appears in the evaluator source");
}

endBlock("W1-BLK-IR9");

// --- 17c. E5-1 / AD15-IR-8: identity establishment is MONOTONIC ------------
//
// The worked case the ruling pins. Bundle root at mode 0o111: traverse
// permission lets open(DIR/manifest.json) succeed while readdir(DIR) fails
// EACCES. E4-2 lists "the bundle root cannot be accessed" as an exit-1 identity
// condition and E4-3 makes an unenumerable directory after identity
// bundle-directory-unreadable at exit 3 -- on POSIX they meet exactly here.
//
// The ruling: the manifest read succeeded and yielded a registered scenario_id,
// so identity WAS established and no later failure can retroactively unestablish
// it. The result is bundle-directory-unreadable at exit 3, NOT exit 1.
{
  const dir = mkBundle("e51-monotonic");
  let manifestReadable = false;
  let rootEnumerable = true;
  try {
    fs.chmodSync(dir, 0o111);
    try { fs.readFileSync(path.join(dir, "manifest.json")); manifestReadable = true; } catch { /* no */ }
    try { fs.readdirSync(dir); } catch { rootEnumerable = false; }
  } catch { /* chmod unsupported here */ }

  if (!(manifestReadable && !rootEnumerable)) {
    skip("AD15-IR-8 monotonic-identity worked case",
      "this platform does not produce 'manifest readable, root unenumerable' at mode "
      + "0o111; the overlap the ruling resolves cannot be reached here");
    try { fs.chmodSync(dir, 0o755); } catch { /* best effort */ }
  } else {
    // Both halves of the overlap measured, not assumed.
    check("control: the root manifest IS readable at mode 0o111", manifestReadable);
    check("control: the root is NOT enumerable at mode 0o111", !rootEnumerable);

    const r = run(["--bundle", dir]);
    // The load-bearing assertion: exit 3, not exit 1. An implementation reading
    // E4-2's "root cannot be accessed" as governing here would exit 1 silently.
    eq("an unlistable-but-readable bundle root exits 3, NOT 1", r.code, 3);
    check("it emits a result object rather than the exit-1 silence", r.out.trim().length > 0);
    if (r.out.trim().length > 0) {
      const v = parseOne("monotonic identity", r.out);
      eq("its reason is bundle-directory-unreadable",
        v.nonmeasurement.reason, "bundle-directory-unreadable");
      eq("identity survived: the scenario is named", v.scenario_id, "IOP-P-DEC");
      eq("artifacts[] is empty: pre-invocation", v.artifacts, []);
      check("verifier_digests is populated -- step 2 ran before traversal",
        v.verifier_digests !== null, show(v.verifier_digests));
    }
    fs.chmodSync(dir, 0o755);
  }
}

// --- 17d. E5-5: authenticated_withheld is SCENARIO-INDEPENDENT -------------
//
// The removed wording was "for any artifact the scenario expects to reach
// AIREP-Authenticated", which requires a per-scenario expected-tier table no
// evaluator has and none should have. A measuring instrument that consults an
// expected-outcome oracle is not measuring.
//
// The rule is now: ANY emitted verdict carrying a non-empty
// authenticated_withheld channel makes the scenario MEASUREMENT_INVALID,
// REGARDLESS OF SCENARIO ID.

// The structural half: the decision function cannot reach a scenario id,
// because it is not given one. Re-introducing the oracle would require changing
// this signature.
{
  eq("the section 7.1 rule takes exactly one parameter -- no scenario id",
    authenticatedWithheldViolation.length, 1);
  eq("an empty withheld set is no violation",
    authenticatedWithheldViolation([]), null);
  const authOnly = [{ artifact_path: "artifacts/a.json", artifact_ref: null,
    channel: "authenticated_withheld", reasons: ["producer-binding-missing"] }];
  const witOnly = [{ artifact_path: "artifacts/a.json", artifact_ref: null,
    channel: "witnessed_withheld", reasons: ["no-witness-supplied"] }];
  const viol = authenticatedWithheldViolation(authOnly);
  check("an authenticated_withheld record IS a violation", viol !== null);
  // Guarded so a regression here reports as failures rather than aborting the
  // run before the end-to-end sweep below can report its own.
  eq("and it carries the pinned reason", viol && viol.reason, "authenticated-withheld");
  eq("paired with MEASUREMENT_INVALID, not ERROR", viol && viol.status, "MEASUREMENT_INVALID");
  // The channel filter is exact: W1 carries no witness, so no-witness-supplied
  // is an ordinary diagnostic surface and must NOT be a measurement failure.
  eq("a witnessed_withheld record alone is NOT a violation",
    authenticatedWithheldViolation(witOnly), null);
}

// The end-to-end half, through the REAL frozen verifier. This needs an artifact
// that actually reaches the Authenticated tier, so it is built here to be
// schema-valid and hash-valid: the frozen stage-0 and stage-1 constructions are
// public and deterministic, and nothing about them is a corpus fixture. The
// artifact is NOT signed -- the whole point is to leave the tier unevaluated.
if (!fs.existsSync(VERIFIER) || !fs.existsSync(VERIFIER_DEPS)) {
  skip("E5-5 end-to-end scenario-independence",
    "the frozen verifier or its node_modules is not materialized");
} else {
  const D64 = "0".repeat(64);
  // A schema-valid v0.2 decision whose integrity.current is the frozen
  // INTEGRITY-2 recomputation: tag-bytes LF jcs-bytes over the artifact with
  // integrity.current and integrity.signature deleted.
  function validDecision() {
    const art = {
      airep_version: "0.2", artifact_type: "decision",
      chain_id: "synth.chain", record_id: "synth-dec", sequence: 0,
      subject: { producer: "synth.producer", timestamp_utc: "2026-01-01T00:00:00Z" },
      scope: { covers: ["c"], does_not_cover: ["d"] },
      input: { input_ref: "in", input_digest: "sha256:" + D64 },
      claim: { assertion: "a", basis: ["b"] },
      directive: { verb: "release", policy_basis: ["p"] },
      output: { result_ref: "out", result_digest: "sha256:" + D64 },
      evidence: [{ type: "other", ref: "r", resolvable: false, content_hash: "sha256:" + D64 }],
      integrity: {
        previous: "sha256:" + D64, current: "sha256:" + D64,
        signature: { alg: "ed25519", value: "ab".repeat(64) },
      },
    };
    const body = JSON.parse(JSON.stringify(art));
    delete body.integrity.current;
    delete body.integrity.signature;
    const pre = Buffer.concat([
      Buffer.from(`AIREP/${art.airep_version}/hash/${art.artifact_type}`, "ascii"),
      Buffer.from([0x0a]),
      Buffer.from(jcs(body), "utf8"),
    ]);
    art.integrity.current = "sha256:" + sha(pre);
    return JSON.stringify(art);
  }

  const ARTIFACT = validDecision();

  // CONTROL: the artifact really does reach the Authenticated tier and really
  // does leave authenticated_withheld non-empty. Without this the sweep below
  // could pass while measuring an artifact rejected at stage 0.
  {
    const probe = path.join(tmp, "e55-probe.json");
    fs.writeFileSync(probe, JSON.stringify({ artifact: JSON.parse(ARTIFACT), related_artifacts: [] }));
    const bfile = path.join(tmp, "e55-b.json"); fs.writeFileSync(bfile, BINDINGS);
    const pfile = path.join(tmp, "e55-p.json"); fs.writeFileSync(pfile, POLICY);
    const rfile = path.join(tmp, "e55-r.json"); fs.writeFileSync(rfile, REVOCATION);
    const p = spawnSync(process.execPath,
      [VERIFIER, "--request", probe, "--bindings", bfile,
        "--independence-policy", pfile, "--revocation", rfile], { encoding: "utf8" });
    eq("control: the probe artifact passes stage 0 and 1 (frozen exits 0)", p.status, 0);
    let verdict = null;
    try { verdict = JSON.parse(p.stdout); } catch { /* asserted below */ }
    check("control: the frozen verifier emitted a verdict", verdict !== null, p.stderr.slice(0, 300));
    if (verdict) {
      check("control: authenticated_withheld really is non-empty",
        Array.isArray(verdict.authenticated_withheld) && verdict.authenticated_withheld.length > 0,
        show(verdict.authenticated_withheld));
      check("control: and no authenticated_failures were produced, so this is a WITHHELD case "
        + "rather than a REJECT",
        Array.isArray(verdict.authenticated_failures) && verdict.authenticated_failures.length === 0,
        show(verdict.authenticated_failures));
    }
  }

  // THE DISCRIMINATION. The SAME artifact and the SAME operator inputs, under
  // every single-artifact scenario id. An expected-tier oracle would treat the
  // IOP-P-* family (expected to reach Authenticated) differently from the
  // IOP-B-* family (expected to be rejected), so a rule that consulted one
  // would diverge across this sweep. The rule must not.
  const singleArtifactScenarios = [
    "IOP-P-DEC", "IOP-P-CTL", "IOP-P-EXE", "IOP-P-EFF",
    "IOP-B-DEC", "IOP-B-CTL", "IOP-B-EXE", "IOP-B-EFF",
  ];
  const outcomes = [];
  for (const scenarioId of singleArtifactScenarios) {
    const dir = mkBundle(`e55-${scenarioId}`, {
      scenarioId, artifacts: { "artifacts/a.json": ARTIFACT },
    });
    const r = run(["--bundle", dir]);
    eq(`${scenarioId}: a withheld Authenticated tier exits 3`, r.code, 3);
    if (r.code !== 3) { outcomes.push(`exit${r.code}`); continue; }
    const v = parseOne(`e55 ${scenarioId}`, r.out);
    eq(`${scenarioId}: measurement_status is MEASUREMENT_INVALID`,
      v.measurement_status, "MEASUREMENT_INVALID");
    eq(`${scenarioId}: reason is authenticated-withheld`,
      v.nonmeasurement.reason, "authenticated-withheld");
    eq(`${scenarioId}: level1 is null -- withheld is neither ACCEPT nor REJECT`, v.level1, null);
    eq(`${scenarioId}: predicates is null`, v.predicates, null);
    // The withheld reasons are reported VERBATIM (section 8.2).
    const auth = v.withheld_reasons.filter((w) => w.channel === "authenticated_withheld");
    // AD15-IR-16: ONE ENTRY PER REASON STRING, exactly three members, the
    // reason VERBATIM from the frozen verdict.
    check(`${scenarioId}: the withheld reasons are reported verbatim`,
      auth.some((w) => w.reason === "producer-binding-missing"),
      show(v.withheld_reasons));
    check(`${scenarioId}: every withheld entry carries exactly the pinned members`,
      v.withheld_reasons.every((w) =>
        show(Object.keys(w).sort()) === show(["artifact_path", "channel", "reason"])),
      show(v.withheld_reasons));
    outcomes.push(`${v.measurement_status}/${v.nonmeasurement.reason}`);
  }
  // The scenario-independence assertion itself: ONE distinct outcome across all
  // eight. This is what an expected-tier oracle cannot satisfy -- it would split
  // the IOP-P-* family from the IOP-B-* family, giving two.
  eq("every single-artifact scenario gave the SAME outcome -- the rule consults no oracle",
    new Set(outcomes).size, 1);
  eq("and that outcome is the pinned one", outcomes[0], "MEASUREMENT_INVALID/authenticated-withheld");
  eq("all eight scenarios were actually exercised", outcomes.length, 8);

  // NEGATIVE CONTROL, and the second half of E5-5's channel precision. With the
  // producer binding RESOLVED and the revocation state ACTIVE, the very same
  // artifact leaves authenticated_withheld EMPTY while witnessed_withheld stays
  // non-empty (no-witness-supplied). That must NOT be MEASUREMENT_INVALID: it is
  // a definitive Authenticated-tier failure, which section 7 step 1 makes a
  // REJECT. Without this control, an implementation that treated ANY withheld
  // channel as a measurement failure would pass everything above.
  {
    const boundBindings = JSON.stringify({
      bindings: {
        "synth.binding": {
          subject_identity: "synth.producer", role: "producer",
          public_key_hex: "1".repeat(64), suite: "ed25519", trusted: true,
        },
      },
      producer_bindings: { "synth.producer": "synth.binding" },
      witness_bindings: {},
    });
    const activeRevocation = JSON.stringify({
      snapshot_id: "synth.snapshot", bindings: { "synth.binding": { state: "active" } },
    });
    const dir = mkBundle("e55-negative", {
      scenarioId: "IOP-P-DEC",
      artifacts: { "artifacts/a.json": ARTIFACT },
      operator: {
        bindings: boundBindings, independence_policy: POLICY, revocation: activeRevocation,
      },
    });
    const r = run(["--bundle", dir]);
    eq("a bound producer with an active revocation state is MEASURED, exit 0", r.code, 0);
    if (r.code === 0) {
      const v = parseOne("e55 negative control", r.out);
      eq("its status is MEASURED, not MEASUREMENT_INVALID", v.measurement_status, "MEASURED");
      // Section 7 step 1: a completed verdict left at AIREP-Core with a
      // populated authenticated_failures channel IS a REJECT.
      eq("a definitive Authenticated-tier failure maps to REJECT", v.level1, "REJECT");
      eq("no nonmeasurement object", v.nonmeasurement, null);
      const auth = v.withheld_reasons.filter((w) => w.channel === "authenticated_withheld");
      eq("authenticated_withheld really is empty here", auth.length, 0);
      // The half that makes this discriminate: witnessed_withheld IS non-empty,
      // and it did not make the scenario measurement-invalid.
      const wit = v.withheld_reasons.filter((w) => w.channel === "witnessed_withheld");
      check("control: witnessed_withheld IS non-empty, so the case is real",
        wit.some((w) => w.reason === "no-witness-supplied"),
        show(v.withheld_reasons));
      check("witnessed_withheld did NOT make the scenario measurement-invalid",
        v.measurement_status === "MEASURED", v.measurement_status);
      eq("the frozen verdict is carried verbatim", v.artifacts.length, 1);
      check("and it records the Authenticated-tier failure",
        v.artifacts[0].verifier_result
        && v.artifacts[0].verifier_result.authenticated_failures.includes("producer-signature-invalid"),
        show(v.artifacts[0].verifier_result && v.artifacts[0].verifier_result.authenticated_failures));
    }
  }
}

// --- 18. AD15-IR-10 and AD15-IR-11 (Erratum 6) -----------------------------
//
// Section 13 step 4: "Both lanes carry explicit tests for the AD15-IR-10
// ordering and the AD15-IR-11 spawn-failure behaviour, WHETHER OR NOT their
// current code already conforms. A rule that holds by accident is not tested."
// Source review found this lane already conforming on both. Nothing below
// changes behaviour; it measures it.
//
// WHY A SPAWN INTERCEPTOR, AND WHAT IS AND IS NOT STUBBED.
//
// Neither ruling is reachable through a real frozen-verifier run:
//
//  * AD15-IR-11 is about a spawn that FAILS. This lane spawns process.execPath
//    with the verifier as an ARGUMENT, so the spawn target always exists and a
//    missing or broken verifier yields a started process with an exit code --
//    a concrete process result, which is precisely the case the ruling
//    excludes. verifier-not-invocable is structurally unreachable here by
//    ordinary means, which is why classifyProcessShape is unit-driven above.
//  * AD15-IR-10 needs ONE bundle carrying BOTH a non-empty
//    authenticated_withheld channel AND an ERROR-class process/run invalidity.
//    No real verifier emits that pair on demand.
//
// So the FROZEN VERIFIER is replaced, and nothing else. The module under test
// is the real interop_eval.mjs, entered through its real exported main(), with
// the real argument parsing, the real bundle preflight, and the real
// frozen-identity assertion -- which reads the GENUINE frozen files and must
// pass, or none of this is reached at all. The interceptor only decides what
// the subprocess would have returned, which is exactly the input surface both
// rulings govern. It is written to a temp file rather than shipped, so no
// stubbed verifier ever sits beside the evaluator.
{
  // --- the interceptor itself is sound before anything rests on it ---------
  // If a plan of four ordinary exit-0 verdicts did not produce a MEASURED
  // result with four entries, every assertion below would be measuring the
  // harness rather than the rulings.
  {
    const r = runIntercepted(four("ir-control"), [{ status: 0, stdout: verdict() }]);
    eq("control: the interceptor drives a clean four-artifact run to exit 0", r.code, 0);
    eq("control: all four invocations were attempted", r.spawnCalls, 4);
    if (r.code === 0) {
      const v = parseOne("interceptor control", r.out);
      eq("control: the run is MEASURED", v.measurement_status, "MEASURED");
      eq("control: artifacts[] matches the bundle shape", v.artifacts.length, 4);
      check("control: the real frozen-identity assertion ran and passed",
        v.verifier_digests !== null
        && v.verifier_digests.class_verifier
          === "sha256:e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4",
        show(v.verifier_digests));
    }
  }

  beginBlock("W1-BLK-IR10");
  // --- AD15-IR-10: run validity precedes tier withheld ---------------------
  //
  // "Where an ERROR-class process or run invalidity and an
  // authenticated_withheld channel are both present on the same bundle, the
  // ERROR outcome is reported."
  //
  // Both conditions are made live on ONE bundle: the first artifact exits 0
  // carrying a non-empty authenticated_withheld channel (section 7.1 is live),
  // and the second exits 2, which the frozen contract permits for no
  // invocation (section 7.2 is live). The withheld channel is collected before
  // either guard runs, so the ordering is genuinely contested here rather than
  // decided by which condition happened to be noticed first.
  {
    const r = runIntercepted(four("ir10-both-live"),
      [{ status: 0, stdout: verdict(["producer-binding-missing"]) },
       { status: 2, stdout: "" }]);
    eq("AD15-IR-10: a bundle with both conditions live exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("AD15-IR-10 both live", r.out);
      // The control: section 7.1's precondition really was satisfied. Without
      // this the block would pass on a bundle where only section 7.2 applied,
      // and would measure no ordering at all.
      const auth = v.withheld_reasons.filter((w) => w.channel === "authenticated_withheld");
      check("control: an authenticated_withheld channel really is present on this bundle",
        auth.some((w) => w.reason === "producer-binding-missing"),
        show(v.withheld_reasons));
      // The ruling.
      eq("AD15-IR-10: the ERROR outcome is reported", v.measurement_status, "ERROR");
      eq("AD15-IR-10: and its reason is the run invalidity, not the withheld tier",
        v.nonmeasurement.reason, "verifier-run-invalid");
      check("AD15-IR-10: the withheld tier did NOT win",
        v.measurement_status !== "MEASUREMENT_INVALID"
        && v.nonmeasurement.reason !== "authenticated-withheld",
        `${v.measurement_status} / ${v.nonmeasurement.reason}`);
      eq("AD15-IR-10: level1 is null", v.level1, null);
      eq("AD15-IR-10: predicates is null", v.predicates, null);
    }
  }

  // The other half of the ordering, so the block cannot pass by an evaluator
  // that simply never reports authenticated-withheld at all: with section 7.2
  // NOT live, the same withheld channel DOES make the scenario
  // MEASUREMENT_INVALID.
  {
    const r = runIntercepted(four("ir10-withheld-alone"),
      [{ status: 0, stdout: verdict(["producer-binding-missing"]) },
       { status: 0, stdout: verdict() }]);
    eq("AD15-IR-10 counterpart: withheld alone still exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("AD15-IR-10 withheld alone", r.out);
      eq("with no run invalidity, the withheld tier IS the outcome",
        v.measurement_status, "MEASUREMENT_INVALID");
      eq("and its reason is authenticated-withheld",
        v.nonmeasurement.reason, "authenticated-withheld");
    }
  }

  endBlock("W1-BLK-IR10");

  beginBlock("W1-BLK-IR11");
  // --- AD15-IR-11: a spawn failure produces no artifacts[] entry -----------
  //
  // "Where the frozen verifier cannot be spawned at all
  // (verifier-not-invocable), the current artifact contributes NO artifacts[]
  // entry. Entries for invocations that completed earlier in the same bundle
  // are retained."
  //
  // The first artifact completes; the second cannot be spawned. Both halves of
  // the ruling are therefore load-bearing in one observation: an entry that
  // must be retained, and an entry that must not exist.
  {
    const r = runIntercepted(four("ir11-spawn-fails-second"),
      [{ status: 0, stdout: verdict() }, { spawnFails: true }]);
    eq("AD15-IR-11: a spawn failure exits 3", r.code, 3);
    // The control: the second invocation really was reached. Without it,
    // "artifacts[] has one entry" would also be true of a run that stopped
    // after the first artifact for some unrelated reason.
    eq("control: the second invocation really was attempted", r.spawnCalls, 2);
    if (r.code === 3) {
      const v = parseOne("AD15-IR-11 spawn failure", r.out);
      eq("AD15-IR-11: the reason is verifier-not-invocable",
        v.nonmeasurement.reason, "verifier-not-invocable");
      // The ruling, both halves.
      eq("AD15-IR-11: the spawn failure contributed NO entry", v.artifacts.length, 1);
      eq("AD15-IR-11: and the earlier completed entry is RETAINED",
        v.artifacts.map((a) => a.artifact_path), ["artifacts/1decision.json"]);
      // No placeholder anywhere: every retained entry is a real process result.
      for (const a of v.artifacts) {
        eq(`${a.artifact_path}: carries exactly the pinned member set`,
          Object.keys(a).sort(), ARTIFACT_MEMBERS);
        check(`${a.artifact_path}: its exit code is a real integer, not a placeholder`,
          Number.isInteger(a.verifier_exit_code), show(a.verifier_exit_code));
        check(`${a.artifact_path}: its stderr digest is a real digest, not a placeholder`,
          typeof a.verifier_stderr_digest === "string"
          && /^sha256:[0-9a-f]{64}$/.test(a.verifier_stderr_digest),
          show(a.verifier_stderr_digest));
        check(`${a.artifact_path}: it completed, so it carries a verdict`,
          a.verifier_result !== null, show(a.verifier_result));
      }
    }
  }

  // The first artifact failing to spawn leaves artifacts[] EMPTY -- not one
  // placeholder entry. The same rule, with nothing earlier to retain, so a
  // "keep the last entry" implementation cannot satisfy both this and the case
  // above.
  {
    const r = runIntercepted(four("ir11-spawn-fails-first"), [{ spawnFails: true }]);
    eq("AD15-IR-11: a spawn failure on the FIRST artifact exits 3", r.code, 3);
    eq("control: exactly one invocation was attempted", r.spawnCalls, 1);
    if (r.code === 3) {
      const v = parseOne("AD15-IR-11 first-artifact spawn failure", r.out);
      eq("its reason is verifier-not-invocable too",
        v.nonmeasurement.reason, "verifier-not-invocable");
      eq("and artifacts[] is EMPTY -- there is nothing to retain and nothing to invent",
        v.artifacts, []);
    }
  }
}

endBlock("W1-BLK-IR11");

// ---------------------------------------------------------------------------
// 18a. Byte helpers for the AD15-IR-20 fixtures
// ---------------------------------------------------------------------------
// Node has no UTF-16BE or UTF-32 encoder, so both are produced here from the
// UTF-16LE one. They exist only to be REFUSED; nothing decodes them.
function swap16(buf) {
  const out = Buffer.from(buf);
  for (let i = 0; i + 1 < out.length; i += 2) {
    const t = out[i]; out[i] = out[i + 1]; out[i + 1] = t;
  }
  return out;
}
function utf32(str, littleEndian) {
  const out = Buffer.alloc(str.length * 4);
  for (let i = 0; i < str.length; i++) {
    const cp = str.charCodeAt(i);
    if (littleEndian) out.writeUInt32LE(cp, i * 4);
    else out.writeUInt32BE(cp, i * 4);
  }
  return out;
}

// ---------------------------------------------------------------------------
// 19. Erratum 7 -- the pinned mandatory blocks
// ---------------------------------------------------------------------------
// Each block below carries one of the fifteen IDs section 8.7 pins. They are
// written from the contract text, not from the peer lane: sharing an ID
// vocabulary is not shared state, and nothing here reads, imports or compares
// against any Python material.

// ===========================================================================
// The five BACKFILLED blocks: W1-BLK-IR4 .. W1-BLK-IR8 (E8-10)
// ===========================================================================
// The registry began at W1-BLK-IR9 because it was written during Erratum 7 and
// only ever covered the rulings that erratum touched; nothing swept backwards.
// AD15-IR-4 through AD15-IR-8 therefore had NO BLOCK AT ALL, and each could be
// violated by a lane while every mandatory block reported green.
//
// Every digest constant below was computed OUTSIDE this program, by
// python3 json.dumps(sort_keys=True, separators=(",", ":")) over the same JSON
// value, which coincides with RFC 8785 for the ASCII keys and integer numbers
// these fixtures use. That is what makes the recomputation INDEPENDENT: a test
// that re-derived the digest with the evaluator's own jcs() would prove only
// that the module agrees with itself.

// --- W1-BLK-IR4: the LANE-LOCAL half of AD15-IR-4 --------------------------
//
// The aggregate branches -- pair key, mismatch making a run non-qualifying,
// mismatch never reaching an evaluator exit code -- are W1-AGG-D2 and MUST NOT
// be attempted here. A single invocation has no access to the peer lane's
// digest; it cannot observe, let alone enforce, a property of a run it is not
// part of. Nothing in this block reads, models or simulates a peer result.
//
// E8-7 also removed an UNPROVABLE UNIVERSAL from this block: "any envelope
// change moves the digest" quantifies over an infinite domain and is not even
// true as a contract invariant, since SHA-256 is not injective. THIS BLOCK
// ASSERTS NO INJECTIVITY. What it asserts is repeat determinism, an independent
// recomputation, and controlled mutations that change the canonical bytes.
beginBlock("W1-BLK-IR4");
{
  const IR4_BASE_DIGESTS = {
    "artifacts/1decision.json": "sha256:d11be51b5917a15bfa1d6257f28f6feedae504b73bfa6f1aef835ddd4d99bd27",
    "artifacts/2control.json": "sha256:5fedaff3f876ff15e2689d85bad952c068db094ebe28dfee62477c3fbf31c052",
    "artifacts/3execution.json": "sha256:a0dea157d96932c9dd83f7cc1ee4bf7e3e5c4e63d825cbbf461f76cd1d3bcf5b",
    "artifacts/4effect.json": "sha256:dead3bb70cc580803484c1205b4b5b12f82afcd2123999ea977b66d91b7a2426",
  };
  const SINGLE_DIGEST =
    "sha256:2c2199bc26d98d650c8382f5d631c24bff92e08b1638e25a6ec577cca890cf75";

  const clean = [{ status: 0, stdout: verdict() }];

  // (1) THE ENVELOPE IS BUILT EXACTLY PER SECTION 5.1, and its digest equals an
  //     INDEPENDENT recomputation of SHA-256 over the actual RFC 8785 canonical
  //     bytes. Both halves matter: an evaluator could canonicalize correctly and
  //     hash something else, or hash correctly over the wrong value.
  const base = runIntercepted(four("ir4-base"), clean);
  eq("AD15-IR-4: a four-artifact bundle is measured", base.code, 0);
  let baseEntries = [];
  if (base.code === 0) {
    const v = parseOne("ir4 base", base.out);
    baseEntries = v.artifacts;
    eq("AD15-IR-4: one entry per artifact", v.artifacts.length, 4);
    for (const e of v.artifacts) {
      eq(`AD15-IR-4: ${e.artifact_path} envelope digest equals the INDEPENDENT recomputation`,
        e.request_envelope_digest, IR4_BASE_DIGESTS[e.artifact_path]);
      check(`AD15-IR-4: ${e.artifact_path} digest is the pinned sha256: wire form`,
        /^sha256:[0-9a-f]{64}$/.test(e.request_envelope_digest), e.request_envelope_digest);
    }
  }

  // Section 5.1's single-artifact rule: related_artifacts is the EMPTY ARRAY --
  // not absent, not populated with unrelated artifacts. The independent digest
  // is over {"artifact":A,"related_artifacts":[]}, so an evaluator that omitted
  // the member would not match it.
  {
    const r = runIntercepted(mkBundle("ir4-single"), clean);
    eq("AD15-IR-4: a single-artifact bundle is measured", r.code, 0);
    if (r.code === 0) {
      const v = JSON.parse(r.out);
      eq("AD15-IR-4: the single-artifact envelope carries an EMPTY related_artifacts",
        v.artifacts[0].request_envelope_digest, SINGLE_DIGEST);
    }
  }

  // (2) REPEAT DETERMINISM on identical input (section 8.4). Byte-identical
  //     output, not merely an equal digest: the requirement is over the whole
  //     result object.
  {
    const again = runIntercepted(four("ir4-base"), clean);
    eq("AD15-IR-4: a repeat run over identical input exits the same", again.code, base.code);
    check("AD15-IR-4: and its output is BYTE-IDENTICAL", again.out === base.out,
      "repeat run differed");
  }

  // (3) CONTROLLED MUTATIONS, proving the evaluator RE-HASHES rather than
  //     carrying a digest forward. Each mutation changes the canonical bytes of
  //     the envelope, so each emitted digest must move -- and the mutation is
  //     named, finite and checked, never a universal claim over all inputs.
  {
    const mutated = mkBundle("ir4-mutated", {
      scenarioId: "IOP-R-CLEAN",
      artifacts: {
        "artifacts/1decision.json": '{"airep_version":"0.2","artifact_type":"decision","chain_id":"c","record_id":"r-dec","sequence":0}',
        "artifacts/2control.json": '{"airep_version":"0.2","artifact_type":"control","chain_id":"c","record_id":"r-ctl","sequence":1}',
        "artifacts/3execution.json": '{"airep_version":"0.2","artifact_type":"execution","chain_id":"c","record_id":"r-exe","sequence":2}',
        // The ONE controlled change: sequence 3 -> 4 on the effect.
        "artifacts/4effect.json": '{"airep_version":"0.2","artifact_type":"effect","chain_id":"c","record_id":"r-eff","sequence":4}',
      },
    });
    const r = runIntercepted(mutated, clean);
    eq("AD15-IR-4: the mutated bundle is measured too", r.code, 0);
    if (r.code === 0 && baseEntries.length === 4) {
      const v = JSON.parse(r.out);
      // The effect appears in EVERY other artifact's related_artifacts, so a
      // single value change moves all four digests. An evaluator carrying a
      // digest forward would move none of them.
      for (const e of v.artifacts) {
        const before = baseEntries.find((b) => b.artifact_path === e.artifact_path);
        check(`AD15-IR-4: mutating one artifact value moves ${e.artifact_path}'s digest`,
          e.request_envelope_digest !== before.request_envelope_digest,
          `${e.artifact_path} digest did not move`);
      }
    }
  }

  // The CONTROL that makes the mutation test a test of the CANONICAL BYTES
  // rather than of the file bytes: the same VALUES written with a different
  // member order in the file must give the SAME digests. JCS is a function of
  // the JSON value (section 5.1, byte rule, Layer 2), so a lane hashing file
  // bytes instead would fail here while passing everything above.
  {
    const reordered = mkBundle("ir4-reordered", {
      scenarioId: "IOP-R-CLEAN",
      artifacts: {
        "artifacts/1decision.json": '{"sequence":0,"record_id":"r-dec","chain_id":"c","artifact_type":"decision","airep_version":"0.2"}',
        "artifacts/2control.json": '{"sequence":1,"record_id":"r-ctl","chain_id":"c","artifact_type":"control","airep_version":"0.2"}',
        "artifacts/3execution.json": '{"sequence":2,"record_id":"r-exe","chain_id":"c","artifact_type":"execution","airep_version":"0.2"}',
        "artifacts/4effect.json": '{"sequence":3,"record_id":"r-eff","chain_id":"c","artifact_type":"effect","airep_version":"0.2"}',
      },
    });
    const r = runIntercepted(reordered, clean);
    eq("AD15-IR-4: the member-reordered bundle is measured", r.code, 0);
    if (r.code === 0) {
      const v = JSON.parse(r.out);
      for (const e of v.artifacts) {
        eq(`AD15-IR-4: ${e.artifact_path} digest is UNMOVED by file member order`,
          e.request_envelope_digest, IR4_BASE_DIGESTS[e.artifact_path]);
      }
    }
  }

  // The peer half, stated as a NEGATIVE property of this file rather than as an
  // assertion about a run it cannot see: no output of this evaluator names a
  // peer digest, and this block never constructs one.
  check("AD15-IR-4: the lane emits ONLY its own request_envelope_digest per artifact",
    baseEntries.every((e) => typeof e.request_envelope_digest === "string"
      && Object.keys(e).filter((k) => /envelope/.test(k)).length === 1));
}
endBlock("W1-BLK-IR4");

// --- W1-BLK-IR5: artifact_path is the TOTAL result identity ----------------
beginBlock("W1-BLK-IR5");
{
  // A bundle whose record_id order is the REVERSE of its artifact_path order,
  // so an evaluator still ordering by record_id is caught rather than passing
  // by coincidence.
  const reverseRanked = (name) => mkBundle(name, {
    scenarioId: "IOP-R-CLEAN",
    artifacts: {
      "artifacts/1decision.json": '{"airep_version":"0.2","artifact_type":"decision","chain_id":"c","record_id":"z-dec"}',
      "artifacts/2control.json": '{"airep_version":"0.2","artifact_type":"control","chain_id":"c","record_id":"y-ctl"}',
      "artifacts/3execution.json": '{"airep_version":"0.2","artifact_type":"execution","chain_id":"c","record_id":"x-exe"}',
      "artifacts/4effect.json": '{"airep_version":"0.2","artifact_type":"effect","chain_id":"c","record_id":"w-eff"}',
    },
  });

  // (1) artifacts[] IS ORDERED BY artifact_path.
  {
    const r = runIntercepted(reverseRanked("ir5-order"), [{ status: 0, stdout: verdict() }]);
    eq("AD15-IR-5: the reverse-ranked bundle is measured", r.code, 0);
    if (r.code === 0) {
      const v = JSON.parse(r.out);
      eq("AD15-IR-5: artifacts[] is in ascending artifact_path byte order",
        v.artifacts.map((e) => e.artifact_path),
        ["artifacts/1decision.json", "artifacts/2control.json",
          "artifacts/3execution.json", "artifacts/4effect.json"]);
      check("control: record_id order really is the REVERSE here, so the two disagree",
        byteCompare("z-dec", "w-eff") > 0);
    }
  }

  // (2) artifact_ref is NULL where the source carries no string record_id, and
  //     (3) NO record_id is ever synthesized. Driven on a SOURCE-B path, because
  //     on an accepted exit-0 verdict the ref comes from the verdict instead.
  {
    const dir = mkBundle("ir5-norecordid", {
      artifacts: { "artifacts/a.json": '{"chain_id":"c","artifact_type":"decision"}' },
    });
    const r = runIntercepted(dir, [{ status: 2, stderr: "usage" }]);
    eq("AD15-IR-5: a record_id-less artifact still reaches an invocation", r.spawnCalls, 1);
    eq("AD15-IR-5: exit 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir5 no record_id", r.out);
      eq("AD15-IR-5: it is the INVOCATION that failed, not a preflight refusal",
        v.nonmeasurement.reason, "verifier-run-invalid");
      eq("AD15-IR-5: the entry exists, so the artifact reached frozen stage 0",
        v.artifacts.length, 1);
      eq("AD15-IR-5: artifact_path is present and is the entry's identity",
        v.artifacts[0].artifact_path, "artifacts/a.json");
      eq("AD15-IR-5: artifact_ref is null -- no usable record_id", v.artifacts[0].artifact_ref, null);
      check("AD15-IR-5: NO record_id was synthesized anywhere in the output",
        !/record_id/.test(r.out), r.out.slice(0, 300));
    }
  }
  // The consequence the ruling exists to secure, stated as its own check: a
  // missing record_id reaches the frozen evaluation it belongs to instead of
  // being converted into the evaluator's own preflight failure.
  {
    const dir = mkBundle("ir5-reaches-stage0", {
      artifacts: { "artifacts/a.json": '{"chain_id":"c","artifact_type":"decision"}' },
    });
    const r = runIntercepted(dir, [{ status: 0, stdout: verdict() }]);
    eq("AD15-IR-5: a record_id-less artifact is NOT refused in preflight", r.code, 0);
    eq("AD15-IR-5: exactly one invocation was attempted", r.spawnCalls, 1);
  }

  // (4) R-A STILL KEYS ON record_id, NEVER ON artifact_path. The manifest path
  //     is harness and result identity only -- it is not wire semantics and
  //     never participates in reference resolution.
  {
    const arts = [
      { bundlePath: "artifacts/1decision.json", value: { record_id: "iop-dec", chain_id: "c" } },
      { bundlePath: "artifacts/2control.json", value: { record_id: "iop-ctl", chain_id: "c" } },
    ];
    eq("AD15-IR-5: a reference by record_id resolves",
      resolveRef({ record_id: "iop-dec" }, arts).state, "resolved");
    eq("AD15-IR-5: a reference naming an ARTIFACT_PATH does not resolve",
      resolveRef({ record_id: "artifacts/1decision.json" }, arts).state, "unresolved");
    check("AD15-IR-5: and no artifact_path ever appears as a resolution key",
      resolveRef({ record_id: "artifacts/2control.json" }, arts).matches === 0);
  }
}
endBlock("W1-BLK-IR5");

// --- W1-BLK-IR6: related_artifacts ordering is artifact_path too -----------
beginBlock("W1-BLK-IR6");
{
  // The digests below were computed OUTSIDE this program over the two candidate
  // orderings of the SAME three related artifacts, so the block discriminates
  // between them rather than merely asserting that some digest was emitted.
  const PATH_ORDER = "sha256:303cda757e6d9bc83b6d5a6e58ce684dd995e0f2ce54d92547393e4ea000446c";
  const RECORD_ID_ORDER = "sha256:fb0eb750d69f55b9868bc592c30fda7bece0905e9da9353535977c8e37e4c4a8";

  // record_id order is the EXACT REVERSE of artifact_path order, which is what
  // makes the two candidate envelopes different bytes.
  const dir = mkBundle("ir6-reverse", {
    scenarioId: "IOP-R-CLEAN",
    artifacts: {
      "artifacts/1decision.json": '{"airep_version":"0.2","artifact_type":"decision","chain_id":"c","record_id":"z-dec"}',
      "artifacts/2control.json": '{"airep_version":"0.2","artifact_type":"control","chain_id":"c","record_id":"y-ctl"}',
      "artifacts/3execution.json": '{"airep_version":"0.2","artifact_type":"execution","chain_id":"c","record_id":"x-exe"}',
      "artifacts/4effect.json": '{"airep_version":"0.2","artifact_type":"effect","chain_id":"c","record_id":"w-eff"}',
    },
  });
  const r = runIntercepted(dir, [{ status: 0, stdout: verdict() }]);
  eq("AD15-IR-6: the reverse-ranked bundle is measured", r.code, 0);
  if (r.code === 0) {
    const v = JSON.parse(r.out);
    const first = v.artifacts.find((e) => e.artifact_path === "artifacts/1decision.json");
    eq("AD15-IR-6: related_artifacts is ordered by artifact_path",
      first.request_envelope_digest, PATH_ORDER);
    check("AD15-IR-6: it is NOT the record_id ordering",
      first.request_envelope_digest !== RECORD_ID_ORDER, "record_id ordering was emitted");
    check("control: the two orderings really do give different envelope bytes",
      PATH_ORDER !== RECORD_ID_ORDER);
  }

  // The case that made record_id ordering UNUSABLE: an artifact with NO usable
  // record_id at all. Under the superseded ordering the envelope had no defined
  // form -- one lane sorted it under an empty key, the other refused to build it
  // -- and therefore no defined request_envelope_digest, which is exactly what
  // aggregate duty 2 compares. artifact_path always exists, so the envelope
  // stays well-defined.
  const NORID = {
    "artifacts/1decision.json": "sha256:aa28a03948cc42eac124e06dca1bfecf4ce8cb63c227ed6f2bd112da6eb888f8",
    "artifacts/2control.json": "sha256:c97c63b17764dab913f2ce00efed8f990205d49be2d6836143b165849a9b5291",
    "artifacts/3execution.json": "sha256:b6bfbeba37d67597cfc3f8ea32be332a15c1aeddb5af0d55cfd73a86e6cc7915",
    "artifacts/4effect.json": "sha256:a48ef7f624973fdf7c08a507738ed07a076789e9bebd265e288a21b1317fda60",
  };
  const dir2 = mkBundle("ir6-norecordid", {
    scenarioId: "IOP-R-CLEAN",
    artifacts: {
      "artifacts/1decision.json": '{"airep_version":"0.2","artifact_type":"decision","chain_id":"c","record_id":"r-dec"}',
      "artifacts/2control.json": '{"airep_version":"0.2","artifact_type":"control","chain_id":"c","record_id":"r-ctl"}',
      "artifacts/3execution.json": '{"airep_version":"0.2","artifact_type":"execution","chain_id":"c","record_id":"r-exe"}',
      // No record_id at all. It still has an artifact_path, so the envelope is
      // a function of the bundle alone.
      "artifacts/4effect.json": '{"airep_version":"0.2","artifact_type":"effect","chain_id":"c"}',
    },
  });
  const r2 = runIntercepted(dir2, [{ status: 0, stdout: verdict() }]);
  eq("AD15-IR-6: a bundle carrying a record_id-less artifact is still measured", r2.code, 0);
  if (r2.code === 0) {
    const v = JSON.parse(r2.out);
    eq("AD15-IR-6: every artifact has an envelope, including the record_id-less one",
      v.artifacts.length, 4);
    for (const e of v.artifacts) {
      eq(`AD15-IR-6: ${e.artifact_path} envelope is defined and path-ordered`,
        e.request_envelope_digest, NORID[e.artifact_path]);
    }
  }
}
endBlock("W1-BLK-IR6");

// --- W1-BLK-IR7: duplicate semantic IDs are not preflight invalidity -------
//
// Two branches, DISCRIMINATED INDEPENDENTLY (E8-9). The block previously tested
// only the first, so an evaluator that allowed duplicate record_id and rejected
// a duplicate (chain_id, record_id) tuple passed every mandatory block while
// violating the ruling.
//
// The obligation is ABSENCE OF A PREFLIGHT GATE, not absence of a later
// reconciliation finding: an exact duplicate tuple may perfectly properly fail
// R-A afterwards, so NOTHING HERE REQUIRES THE RESULT TO BE ACCEPT.
beginBlock("W1-BLK-IR7");
{
  const dupBundle = (name, decRid, decChain, ctlRid, ctlChain, extra = {}) => mkBundle(name, {
    scenarioId: "IOP-R-CLEAN",
    artifacts: {
      "artifacts/1decision.json": JSON.stringify({
        airep_version: "0.2", artifact_type: "decision", chain_id: decChain, record_id: decRid }),
      "artifacts/2control.json": JSON.stringify({
        airep_version: "0.2", artifact_type: "control", chain_id: ctlChain, record_id: ctlRid,
        ...(extra.control ?? {}) }),
      "artifacts/3execution.json": '{"airep_version":"0.2","artifact_type":"execution","chain_id":"c","record_id":"r-exe"}',
      "artifacts/4effect.json": JSON.stringify({
        airep_version: "0.2", artifact_type: "effect", chain_id: "c", record_id: "r-eff",
        ...(extra.effect ?? {}) }),
    },
  });
  const LEVEL1 = ["ACCEPT", "REJECT", "RECONCILIATION_MISMATCH", "INDEPENDENCE_NOT_ESTABLISHED"];

  // BRANCH A -- duplicate record_id with DISTINCT chain_id.
  {
    const r = runIntercepted(dupBundle("ir7-branch-a", "dup", "c1", "dup", "c2"),
      [{ status: 0, stdout: verdict() }]);
    eq("AD15-IR-7 branch A: duplicate record_id, distinct chain_id -- exit 0", r.code, 0);
    eq("AD15-IR-7 branch A: ALL FOUR artifacts reached frozen stage evaluation", r.spawnCalls, 4);
    if (r.code === 0) {
      const v = JSON.parse(r.out);
      eq("AD15-IR-7 branch A: no preflight reason was raised", v.nonmeasurement, null);
      check("AD15-IR-7 branch A: the verdict is a Level-1 value, and is NOT required to be ACCEPT",
        LEVEL1.includes(v.level1), show(v.level1));
    }
  }

  // BRANCH B -- duplicate EXACT (chain_id, record_id) tuple. This is the branch
  // frozen R-10 governs FOR A BATCH; it must NOT be generalized into a
  // bundle-level preflight, because this evaluator submits each artifact as a
  // SEPARATE request.
  {
    const r = runIntercepted(dupBundle("ir7-branch-b", "dup", "c", "dup", "c"),
      [{ status: 0, stdout: verdict() }]);
    eq("AD15-IR-7 branch B: duplicate (chain_id, record_id) -- exit 0", r.code, 0);
    eq("AD15-IR-7 branch B: ALL FOUR artifacts reached frozen stage evaluation", r.spawnCalls, 4);
    if (r.code === 0) {
      const v = JSON.parse(r.out);
      eq("AD15-IR-7 branch B: frozen R-10 was NOT generalized into a bundle preflight",
        v.nonmeasurement, null);
      check("AD15-IR-7 branch B: and the result is not required to be ACCEPT either",
        LEVEL1.includes(v.level1), show(v.level1));
    }
  }

  // A REAL AMBIGUOUS LOOKUP: R-A fails CLOSED and the evaluator does not pick
  // one. Without this the block would prove only that a gate is absent, not that
  // the predicate the gate would have made unreachable actually fires.
  {
    const r = runIntercepted(
      dupBundle("ir7-ambiguous", "dup", "c", "dup", "c",
        { effect: { decision_ref: { record_id: "dup" }, execution_ref: { record_id: "r-exe" } },
          control: { decision_ref: { record_id: "dup" } } }),
      [{ status: 0, stdout: verdict() }]);
    eq("AD15-IR-7: an ambiguous lookup still MEASURES -- it is a finding, not a refusal",
      r.code, 0);
    if (r.code === 0) {
      const v = JSON.parse(r.out);
      eq("AD15-IR-7: R-A FAILS CLOSED on the ambiguity", v.predicates.R_A, "FAIL");
      eq("AD15-IR-7: and the scenario is MEASURED, not an evaluator refusal",
        v.measurement_status, "MEASURED");
      eq("AD15-IR-7: the ambiguity is a RECONCILIATION finding", v.level1,
        "RECONCILIATION_MISMATCH");
    }
    // The resolution semantics themselves, so "fails closed" is proved to mean
    // AMBIGUOUS rather than merely "not resolved".
    const arts = [
      { bundlePath: "artifacts/1decision.json", value: { record_id: "dup", chain_id: "c" } },
      { bundlePath: "artifacts/2control.json", value: { record_id: "dup", chain_id: "c" } },
    ];
    const res = resolveRef({ record_id: "dup" }, arts);
    eq("AD15-IR-7: more than one match is AMBIGUOUS", res.state, "ambiguous");
    eq("AD15-IR-7: and it counts both, so neither was picked", res.matches, 2);
    check("AD15-IR-7: no target is returned -- the evaluator MUST NOT pick one",
      res.target === undefined, show(res.target));
    // Control: the same reference against a unique record_id resolves, so the
    // ambiguity above is attributable to the duplicate and not to the lookup.
    eq("control: a unique record_id resolves normally",
      resolveRef({ record_id: "dup" }, [arts[0]]).state, "resolved");
  }
}
endBlock("W1-BLK-IR7");

// --- W1-BLK-IR8: identity establishment is MONOTONIC -----------------------
//
// Once the root manifest.json bytes have been read, parsed as strict JSON and
// yielded a REGISTERED scenario_id, bundle identity is established, and no later
// filesystem, traversal or preflight failure unestablishes it.
//
// "More than one case" is not enough -- two traversal fixtures would leave two
// categories untested -- so the three categories are discriminated SEPARATELY.
beginBlock("W1-BLK-IR8");
{
  const owed = (label, r) => {
    eq(`AD15-IR-8 (${label}): exit 3, NEVER exit 1`, r.code, 3);
    if (r.code !== 3) return null;
    const v = parseOne(`ir8 ${label}`, r.out);
    eq(`AD15-IR-8 (${label}): the result object NAMES the scenario`, v.scenario_id, "IOP-P-DEC");
    eq(`AD15-IR-8 (${label}): level1 is null`, v.level1, null);
    eq(`AD15-IR-8 (${label}): predicates is null`, v.predicates, null);
    check(`AD15-IR-8 (${label}): stdout is a result object, not silence`, r.out.trim() !== "");
    return v;
  };

  // CATEGORY 1 -- a LISTED-FILE or DIGEST failure after identity.
  {
    const dir = mkBundle("ir8-missing");
    fs.rmSync(path.join(dir, "artifacts", "a.json"));
    const v = owed("listed file missing", run(["--bundle", dir]));
    if (v) eq("AD15-IR-8 (listed file missing): reason", v.nonmeasurement.reason,
      "bundle-file-missing");
  }
  {
    const v = owed("digest mismatch",
      run(["--bundle", mkBundle("ir8-digest", { corrupt: "artifacts/a.json" })]));
    if (v) eq("AD15-IR-8 (digest mismatch): reason", v.nonmeasurement.reason,
      "manifest-digest-mismatch");
  }

  // CATEGORY 2 -- a TRAVERSAL failure. THE WORKED 0o111 CASE: traverse
  // permission lets open(DIR/manifest.json) succeed while readdir(DIR) fails
  // EACCES. The manifest read succeeded and yielded a registered scenario_id, so
  // identity WAS established -- bundle-directory-unreadable at exit 3, not
  // exit 1.
  {
    const dir = mkBundle("ir8-mode111");
    let denied = false;
    try {
      fs.chmodSync(dir, 0o111);
      try { fs.readdirSync(dir); } catch { denied = true; }
    } catch { /* chmod unsupported on this filesystem */ }
    if (!denied) {
      // Reported as a SKIP, never as a pass. The contract permits a harness
      // unable to construct permission fixtures to skip this case.
      skip("W1-BLK-IR8 traversal category (0o111 worked case)",
        "this process can enumerate a 0o111 directory (euid 0, or a filesystem "
        + "ignoring chmod), so the worked case cannot be produced here");
    } else {
      const r = run(["--bundle", dir]);
      const v = owed("0o111 traversal", r);
      if (v) {
        eq("AD15-IR-8 (0o111 traversal): reason", v.nonmeasurement.reason,
          "bundle-directory-unreadable");
        check("AD15-IR-8 (0o111 traversal): identity survived a failure of the MEDIUM",
          v.nonmeasurement.reason !== "manifest-invalid", v.nonmeasurement.reason);
      }
      // Control: the manifest really WAS readable through the execute bit, so
      // the exit-3 result above is attributable to readdir and not to a bundle
      // the evaluator could not open at all.
      let manifestReadable = false;
      try { JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8")); manifestReadable = true; }
      catch { /* not readable */ }
      check("control: open(DIR/manifest.json) succeeds under 0o111", manifestReadable);
      fs.chmodSync(dir, 0o755);
    }
  }

  // CATEGORY 3 -- a NON-FILESYSTEM preflight failure. Four distinct producers,
  // because "manifest structure, bundle shape, numeric preflight or frozen-digest
  // mismatch" is a list of four and one of them is not the category.
  {
    const v = owed("manifest structure",
      run(["--bundle", mkBundle("ir8-structure", { mutate: (m) => { m.surprise = 1; } })]));
    if (v) eq("AD15-IR-8 (manifest structure): reason", v.nonmeasurement.reason, "manifest-invalid");
  }
  {
    const dir = mkBundle("ir8-shape", {
      artifacts: {
        "artifacts/a.json": '{"record_id":"r1","chain_id":"c","artifact_type":"decision"}',
        "artifacts/b.json": '{"record_id":"r2","chain_id":"c","artifact_type":"decision"}',
      },
    });
    const v = owed("bundle shape", run(["--bundle", dir]));
    if (v) eq("AD15-IR-8 (bundle shape): reason", v.nonmeasurement.reason, "bundle-shape-invalid");
  }
  {
    const dir = mkBundle("ir8-numeric", {
      artifacts: {
        "artifacts/a.json":
          '{"record_id":"r","chain_id":"c","artifact_type":"decision","profiles":{"p":1e400}}',
      },
    });
    const v = owed("numeric preflight", run(["--bundle", dir]));
    if (v) {
      eq("AD15-IR-8 (numeric preflight): reason", v.nonmeasurement.reason,
        "numeric-preflight-violation");
      eq("AD15-IR-8 (numeric preflight): and its json_pointer", v.nonmeasurement.json_pointer,
        "/profiles/p");
    }
  }
  {
    // A readable file whose digest is not the pin: identity is established, so a
    // result object is owed even though the evaluator refuses to run.
    const wrong = path.join(tmp, "ir8-wrong-verifier.mjs");
    fs.writeFileSync(wrong, "// not the frozen verifier\n");
    const v = owed("frozen digest mismatch",
      run(["--bundle", mkBundle("ir8-frozen"), "--verifier", wrong]));
    if (v) {
      eq("AD15-IR-8 (frozen digest mismatch): reason", v.nonmeasurement.reason,
        "verifier-digest-mismatch");
      check("AD15-IR-8 (frozen digest mismatch): the RECOMPUTED digests are retained",
        v.verifier_digests !== null && /^sha256:/.test(v.verifier_digests.class_verifier),
        show(v.verifier_digests));
    }
  }

  // THE CONTROL THAT MAKES MONOTONICITY MEAN SOMETHING: exit 1 is still
  // reachable. Without it every assertion above could be satisfied by an
  // evaluator that never exits 1 at all.
  {
    const noIdentity = path.join(tmp, "ir8-no-identity");
    fs.mkdirSync(noIdentity, { recursive: true });
    fs.writeFileSync(path.join(noIdentity, "manifest.json"), "{ not json");
    const r = run(["--bundle", noIdentity]);
    eq("control: identity NOT established is still exit 1", r.code, 1);
    check("control: and it writes no result object", r.out === "", r.out.slice(0, 200));
  }
}
endBlock("W1-BLK-IR8");

// --- W1-BLK-PATH: AD15-IR-19, the lexical path grammar ---------------------
//
// The contract's own case list, asserted against the grammar AS WRITTEN. Each
// rejection is checked twice over: once on the pure grammar function, and once
// END TO END, so that a grammar that were correct but never consulted could not
// pass. "normalized" is the word the ruling removes, and the reason it removes
// it is that a path helper will happily normalize a path INTO acceptance --
// path.posix.normalize("a/../b.json") is "b.json", which is accepted, and that
// is the defect.
beginBlock("W1-BLK-PATH");
{
  const CTRL = String.fromCharCode(1);
  const NUL = String.fromCharCode(0);
  const NON_ASCII = "caf" + String.fromCharCode(0xE9) + ".json";
  const BACKSLASH = "a" + String.fromCharCode(92) + "b.json";

  const rejected = [
    ["empty path", ""],
    ["a bare dot", "."],
    ["a bare double dot", ".."],
    ["a leading dot segment", "./a.json"],
    ["an interior dot segment", "a/./b.json"],
    ["an interior double-dot segment", "a/../b.json"],
    ["a doubled slash", "a//b.json"],
    ["a leading slash", "/a.json"],
    ["a trailing slash", "a.json/"],
    ["a drive prefix", "C:artifact.json"],
    ["a backslash", BACKSLASH],
    ["a control character", "a" + CTRL + ".json"],
    // NUL is listed apart from other controls because some runtimes TRUNCATE at
    // it rather than rejecting it.
    ["a NUL", "a" + NUL + ".json"],
    // E8-10: the grammar is a CLOSED ALPHABET, not a blocklist. A case list of
    // only exotic characters lets an evaluator pass while accepting an ordinary
    // space or "@", which the ABNF forbids just as firmly as a backslash.
    ["an ordinary space", "a b.json"],
    ["a leading space", " a.json"],
    ["a trailing space", "a.json "],
    ["an ordinary disallowed ASCII character (@)", "a@b.json"],
    ["another ordinary disallowed ASCII character (+)", "a+b.json"],
    ["a tilde", "a~b.json"],
    ["a percent", "a%20b.json"],
    ["a non-ASCII character", NON_ASCII],
    ["an unpaired surrogate", String.fromCharCode(0xD800) + ".json"],
    ["the root manifest, which files[] excludes", "manifest.json"],
  ];
  for (const [name, value] of rejected) {
    check(`AD15-IR-19 rejects ${name}`, checkBundlePath(value) !== null, JSON.stringify(value));
  }

  // The valid canonical controls. Without them the block would pass on a
  // grammar that rejected everything.
  for (const value of ["a.json", "artifacts/a.json", "a/b_c-1.json", "A.JSON",
    "nested/manifest.json", "x-1_2.3.json"]) {
    check(`AD15-IR-19 accepts the canonical control ${JSON.stringify(value)}`,
      checkBundlePath(value) === null, show(checkBundlePath(value)));
  }

  // NO NORMALIZATION INTO ACCEPTANCE. The discrimination that separates the
  // lexical grammar from a path library: every one of these normalizes to an
  // accepted path, and every one must still be refused.
  for (const value of ["a/../b.json", "./b.json", "a/./b.json", "b.json/"]) {
    const normalized = path.posix.normalize(value).replace(/\/$/, "");
    check(`AD15-IR-19: ${JSON.stringify(value)} normalizes to an ACCEPTED path, `
      + "and is still refused",
      checkBundlePath(normalized) === null && checkBundlePath(value) !== null,
      `${JSON.stringify(normalized)} -> ${show(checkBundlePath(normalized))}`);
  }

  // End to end, so the grammar is proved to be CONSULTED and to land on the
  // pinned reason and stage. A stage-4 failure is reported before the disk is
  // ever inspected, which is why the bundle below is otherwise perfectly valid.
  for (const [name, value] of [
    ["a dot segment", "artifacts/./a.json"],
    ["a double-dot segment", "artifacts/../a.json"],
    ["a leading slash", "/artifacts/a.json"],
    ["a drive prefix", "C:a.json"],
    ["a backslash", BACKSLASH],
    // The closed-alphabet half, end to end: these are what a blocklist-shaped
    // implementation lets through.
    ["an ordinary space", "artifacts/a b.json"],
    ["an at sign", "artifacts/a@b.json"],
  ]) {
    const dir = mkBundle(`path-e2e-${name.replace(/[^a-z]+/gi, "-")}`, {
      mutate: (m) => {
        const e = m.files.find((x) => x.role === "artifact");
        e.path = value;
      },
    });
    expectNonMeasured(`AD15-IR-19 end to end: ${name}`, dir, "manifest-invalid");
  }
}
endBlock("W1-BLK-PATH");

// --- W1-BLK-JSON-BYTES: AD15-IR-20, the closed JSON byte domain ------------
//
// Six encodings, for BOTH the root manifest and a listed JSON file -- the two
// sit on OPPOSITE SIDES of the identity boundary, so the same bytes give
// different outcomes and a block that tested only one would miss half the
// ruling:
//
//   manifest.json            -> identity NOT established: exit 1, empty stdout
//   a listed artifact/input  -> bundle-json-invalid at stage 8, exit 3
beginBlock("W1-BLK-JSON-BYTES");
{
  const DOC = '{"record_id":"r","chain_id":"c","artifact_type":"decision"}';
  const encodings = {
    "UTF-8 BOM": Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(DOC, "utf8")]),
    "malformed UTF-8": Buffer.concat([
      Buffer.from('{"a":"', "utf8"), Buffer.from([0xC3, 0x28]), Buffer.from('"}', "utf8")]),
    "UTF-16LE": Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(DOC, "utf16le")]),
    "UTF-16BE": Buffer.concat([Buffer.from([0xFE, 0xFF]), swap16(Buffer.from(DOC, "utf16le"))]),
    "UTF-32LE": Buffer.concat([Buffer.from([0xFF, 0xFE, 0x00, 0x00]), utf32(DOC, true)]),
    "UTF-32BE": Buffer.concat([Buffer.from([0x00, 0x00, 0xFE, 0xFF]), utf32(DOC, false)]),
  };

  // The pure gate first, so a failure downstream can be attributed.
  for (const [name, buf] of Object.entries(encodings)) {
    check(`AD15-IR-20 rejects ${name} bytes`, checkJsonByteDomain(buf) !== null, name);
  }
  check("AD15-IR-20 accepts ordinary UTF-8 with no BOM",
    checkJsonByteDomain(Buffer.from(DOC, "utf8")) === null);
  // The one repair a lenient runtime performs silently, refused explicitly:
  // Node's default TextDecoder STRIPS a UTF-8 BOM and would parse this fine.
  check("control: the BOM document is otherwise valid JSON, so only the BOM is at issue",
    JSON.parse(new TextDecoder("utf-8").decode(encodings["UTF-8 BOM"])).record_id === "r");

  // (a) THE ROOT MANIFEST: identity not established. exit 1, stdout EMPTY,
  //     and NEVER a reason -- a reason belongs to a result object, and at this
  //     point there is no scenario to name one after.
  for (const [name, buf] of Object.entries(encodings)) {
    const dir = path.join(tmp, `bytes-manifest-${name.replace(/[^a-z0-9]+/gi, "-")}`);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "manifest.json"), buf);
    const r = run(["--bundle", dir]);
    eq(`AD15-IR-20: a ${name} root manifest exits 1`, r.code, 1);
    check(`AD15-IR-20: a ${name} root manifest writes NOTHING to stdout`, r.out === "", r.out);
    check(`AD15-IR-20: and never names a reason for it`,
      !/manifest-invalid|bundle-json-invalid/.test(r.err), r.err.slice(0, 200));
  }

  // (b) A LISTED ARTIFACT FILE: identity IS established, so a result object is
  //     owed. bundle-json-invalid at stage 8, exit 3.
  for (const [name, buf] of Object.entries(encodings)) {
    const dir = mkBundle(`bytes-listed-${name.replace(/[^a-z0-9]+/gi, "-")}`, {
      artifacts: { "artifacts/a.json": buf },
    });
    const v = expectNonMeasured(`AD15-IR-20: a ${name} listed artifact`, dir,
      "bundle-json-invalid");
    if (v) {
      check(`AD15-IR-20: no repair or transcoding into acceptance for a ${name} artifact`,
        v.measurement_status === "ERROR" && v.level1 === null,
        "the document was accepted after repair");
    }
  }
  // (c) A LISTED OPERATOR-INPUT FILE -- the third position the ruling names, and
  //     E8-10 requires all SIX encodings here too, not only the BOM. An operator
  //     input is read on the same path as an artifact but is composed
  //     differently, so a lane gating only artifact files would pass with one
  //     encoding tested and fail the rest.
  for (const [name, buf] of Object.entries(encodings)) {
    const dir = mkBundle(`bytes-operator-${name.replace(/[^a-z0-9]+/gi, "-")}`, {
      operator: { bindings: buf, independence_policy: POLICY, revocation: REVOCATION },
    });
    const v = expectNonMeasured(`AD15-IR-20: a ${name} listed OPERATOR INPUT`, dir,
      "bundle-json-invalid");
    if (v) {
      check(`AD15-IR-20: and its detail names the operator-input file`,
        /operator/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
      check(`AD15-IR-20: no repair or transcoding into acceptance for a ${name} operator input`,
        v.measurement_status === "ERROR" && v.level1 === null,
        "the document was accepted after repair");
    }
  }
  // (d) NO REPAIR AT ANY OF THE THREE POSITIONS, stated as its own property.
  //     The BOM is the case a lenient runtime accepts silently: Node's default
  //     TextDecoder STRIPS it, so an evaluator using the default decoder would
  //     accept all three positions while reporting success.
  {
    const bom = encodings["UTF-8 BOM"];
    check("AD15-IR-20: the default decoder WOULD have repaired the BOM document",
      JSON.parse(new TextDecoder("utf-8").decode(bom)).record_id === "r");
    check("AD15-IR-20: and the pinned gate refuses it instead",
      checkJsonByteDomain(bom) !== null, show(checkJsonByteDomain(bom)));
    // The manifest position, where the same repair would have established an
    // identity the bundle does not have.
    const dir = path.join(tmp, "bytes-norepair-manifest");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "manifest.json"),
      Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]),
        Buffer.from(JSON.stringify({ manifest_version: "1", scenario_id: "IOP-P-DEC", files: [] }))]));
    const r = run(["--bundle", dir]);
    eq("AD15-IR-20: a BOM manifest that WOULD parse after repair still exits 1", r.code, 1);
    check("AD15-IR-20: and no identity was established from the repaired bytes",
      r.out === "" && !/IOP-P-DEC/.test(r.out), r.out.slice(0, 200));
  }
}
endBlock("W1-BLK-JSON-BYTES");

// --- W1-BLK-IR17: duplicate manifest members -------------------------------
//
// RFC 8259 permits an object to repeat a member name, both runtimes decode such
// an object last-wins by default, and THIS LANE recorded that as unpinned and
// relied on the default -- register entry 6, now closed. Relying on a runtime
// default is not a rule; it is a coincidence that two implementations currently
// agree.
//
// The NESTING DISTINCTION is the whole ruling, so all three bands are measured
// on the same shape of fixture:
//
//   duplicate TOP-LEVEL scenario_id  -> exit 1, no result object
//   duplicate NESTED  scenario_id    -> manifest-invalid, stage 4, exit 3
//   any other duplicate member       -> manifest-invalid, stage 4, exit 3
beginBlock("W1-BLK-IR17");
{
  // The scanner half first: JSON.parse cannot answer this question, so the
  // detection has to happen while parsing.
  {
    const doc = '{"a":1,"a":2,"b":{"c":1,"c":2},"d":[{"e":1,"e":2}]}';
    const dups = scanJsonDocument(doc).duplicates;
    eq("the scanner finds every duplicate, at every depth", dups.length, 3);
    eq("and records which object each one is in",
      dups.map((d) => `${d.objectPointer}:${d.name}`), [":a", "/b:c", "/d/0:e"]);
    eq("control: JSON.parse silently keeps the LAST occurrence and shows one member",
      Object.keys(JSON.parse(doc)).length, 3);
    eq("control: which is exactly the default the ruling forbids relying on",
      JSON.parse(doc).a, 2);
  }

  // (a) TOP-LEVEL scenario_id. This adds no new condition to the exit-1 band:
  // it is already the fifth condition of the section 5 direct-read identity
  // boundary -- no registered scenario_id is DETERMINISTICALLY obtainable.
  {
    const dir = mkBundle("ir17-top-dup", {
      renderManifest: (m) => JSON.stringify(m).replace(
        '"scenario_id":"IOP-P-DEC"', '"scenario_id":"IOP-P-DEC","scenario_id":"IOP-R-CLEAN"'),
    });
    const r = run(["--bundle", dir]);
    eq("AD15-IR-17: a duplicated top-level scenario_id exits 1", r.code, 1);
    check("AD15-IR-17: and writes no result object", r.out === "", r.out);
    // THE DISCRIMINATION. Both spellings are REGISTERED scenario ids, so a
    // last-wins implementation would have produced IOP-R-CLEAN and a first-wins
    // one IOP-P-DEC -- either way a perfectly ordinary run. Neither may happen.
    check("AD15-IR-17: neither the first nor the last occurrence was adopted",
      !/IOP-R-CLEAN|scenario_id/.test(r.out), r.out.slice(0, 200));
  }
  // Control: the same manifest with ONE scenario_id runs normally, so the exit 1
  // above is caused by the duplication and not by the rendering.
  {
    const dir = mkBundle("ir17-top-control", { renderManifest: (m) => JSON.stringify(m) });
    check("control: the same manifest without the duplicate establishes identity",
      run(["--bundle", dir]).code !== 1, show(run(["--bundle", dir]).code));
  }

  // (b) NESTED scenario_id. It does NOT erase a valid top-level identity:
  // reading it as identity-destroying would let a member buried in files[]
  // suppress a result object the evaluator can perfectly well produce, which is
  // the exit-1/exit-3 confusion AD15-IR-8 exists to prevent.
  {
    const dir = mkBundle("ir17-nested-dup", {
      renderManifest: (m) => JSON.stringify(m).replace(
        '"role":"artifact"', '"role":"artifact","scenario_id":"IOP-R-CLEAN"'),
    });
    const v = expectNonMeasured("AD15-IR-17: a nested scenario_id", dir, "manifest-invalid");
    if (v) {
      eq("AD15-IR-17: the top-level identity SURVIVED and is named", v.scenario_id, "IOP-P-DEC");
      eq("AD15-IR-17: it is a pre-invocation failure", v.artifacts, []);
      check("AD15-IR-17: and verifier_digests is populated, so stage 3 ran first",
        v.verifier_digests !== null, show(v.verifier_digests));
    }
  }
  // A nested scenario_id that is DUPLICATED, not merely present -- the ruling
  // names both, and the entry-closure rule alone would only catch the first.
  {
    const dir = mkBundle("ir17-nested-dup2", {
      renderManifest: (m) => JSON.stringify(m).replace(
        '"role":"artifact"', '"role":"artifact","scenario_id":"a","scenario_id":"b"'),
    });
    const v = expectNonMeasured("AD15-IR-17: a duplicated nested scenario_id", dir,
      "manifest-invalid");
    if (v) eq("AD15-IR-17: the top-level identity still survives", v.scenario_id, "IOP-P-DEC");
  }

  // (c) ANY OTHER duplicated member, at the top level and nested. Both are
  // manifest-invalid at stage 4 -- identity was established, so a result object
  // is owed (AD15-IR-8).
  {
    const dir = mkBundle("ir17-other-top", {
      renderManifest: (m) => JSON.stringify(m).replace(
        '"manifest_version":"1"', '"manifest_version":"1","manifest_version":"1"'),
    });
    const v = expectNonMeasured("AD15-IR-17: a duplicated top-level manifest_version", dir,
      "manifest-invalid");
    if (v) {
      eq("AD15-IR-17: identity was established, so the scenario is named",
        v.scenario_id, "IOP-P-DEC");
      // Both occurrences are IDENTICAL, so no closure, version or sort rule can
      // detect this. Only duplicate detection can, which is what makes this the
      // discriminating case.
      check("AD15-IR-17: the detail says a member was REPEATED",
        /repeats the member/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
    }
  }
  {
    const dir = mkBundle("ir17-other-nested", {
      renderManifest: (m) => JSON.stringify(m).replace('"role":"artifact"',
        '"role":"artifact","role":"artifact"'),
    });
    const v = expectNonMeasured("AD15-IR-17: a duplicated nested role", dir, "manifest-invalid");
    if (v) {
      check("AD15-IR-17: reported as a repeat, not as a closure violation",
        /repeats the member/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
    }
  }

  // The same rule one layer down (E7-22): a duplicate member in a LISTED file
  // is bundle-json-invalid at stage 8. Two lanes could otherwise canonicalize
  // {"k":1} and {"k":2} from the same bytes and emit different
  // request_envelope_digest values while both reported success.
  {
    const dir = mkBundle("ir17-listed-dup", {
      artifacts: {
        "artifacts/a.json":
          '{"record_id":"r","chain_id":"c","artifact_type":"decision","k":1,"k":2}',
      },
    });
    const v = expectNonMeasured("E7-22: a duplicate member in a listed artifact", dir,
      "bundle-json-invalid");
    if (v) {
      check("E7-22: neither first-wins nor last-wins was applied",
        /neither first-wins nor last-wins/.test(v.nonmeasurement.detail),
        v.nonmeasurement.detail);
    }
  }
}
endBlock("W1-BLK-IR17");

// --- W1-BLK-JCS: the stage-8 rules, repair refused, and the stage boundary --
//
// The block has three obligations, and the third is the one E7-33 added because
// E7-21 had just been closed by narrowing stage 8: a numeric JCS-domain failure
// such as 1e400 must be reported as numeric-preflight-violation at STAGE 10
// WITH ITS json_pointer, and NOT as bundle-json-invalid at stage 8. The broad
// "canonicalizability" wording had silently captured it, which would have lost
// the pointer section 8.7 makes normative.
beginBlock("W1-BLK-JCS");
{
  // (1) Stage-8 rule one: an unpaired surrogate. Strict JSON admits the escape;
  //     RFC 8785 cannot canonicalize it. The document PARSES CLEANLY and still
  //     has no canonical form.
  const LONE_HIGH = '{"record_id":"r","chain_id":"c","artifact_type":"decision","k":"\\ud800"}';
  const LONE_LOW = '{"record_id":"r","chain_id":"c","artifact_type":"decision","k":"\\udc00"}';
  check("control: an unpaired surrogate is accepted by JSON.parse",
    typeof JSON.parse(LONE_HIGH).k === "string");
  check("the surrogate detector sees a lone high surrogate",
    hasUnpairedSurrogate(JSON.parse(LONE_HIGH).k));
  check("the surrogate detector sees a lone low surrogate",
    hasUnpairedSurrogate(JSON.parse(LONE_LOW).k));
  check("control: a WELL-FORMED pair is not flagged",
    !hasUnpairedSurrogate(JSON.parse('{"k":"\\ud83d\\ude00"}').k));
  for (const [name, doc] of [["a lone high surrogate", LONE_HIGH],
    ["a lone low surrogate", LONE_LOW]]) {
    const v = expectNonMeasured(`stage 8: ${name}`, mkBundle(
      `jcs-surrogate-${name.replace(/[^a-z]+/gi, "-")}`, { artifacts: { "artifacts/a.json": doc } }),
      "bundle-json-invalid");
    if (v) {
      check(`stage 8: ${name} is not repaired by substitution`,
        !/�/.test(JSON.stringify(v)), "U+FFFD reached the output");
      check(`stage 8: ${name} names the surrogate, so it is not a generic parse failure`,
        /unpaired surrogate/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
    }
  }

  // (2) Stage-8 rule two -- duplicate member names -- is measured in
  //     W1-BLK-IR17 end to end; here the CANONICALIZER's own invariance is what
  //     matters, because that is where the divergence would show.
  eq("JCS is a function of the VALUE, so member order cannot move the bytes",
    jcs({ b: 1, a: 2 }), jcs({ a: 2, b: 1 }));
  check("and the two decodings of a duplicated member give DIFFERENT bytes, "
    + "which is why the duplicate is refused rather than resolved",
    jcs({ k: 1 }) !== jcs({ k: 2 }));

  // (3) THE STAGE BOUNDARY. 1e400 is outside the JCS numeric input domain, and
  //     it must NOT be folded into stage 8.
  {
    const doc = '{"record_id":"r","chain_id":"c","artifact_type":"decision",'
      + '"profiles":{"p":1e400}}';
    const v = expectNonMeasured("1e400 is a stage-10 numeric violation",
      mkBundle("jcs-1e400", { artifacts: { "artifacts/a.json": doc } }),
      "numeric-preflight-violation");
    if (v) {
      check("E7-33: it is NOT reported as bundle-json-invalid at stage 8",
        v.nonmeasurement.reason !== "bundle-json-invalid", v.nonmeasurement.reason);
      eq("E7-33: and it carries its json_pointer, which stage 8 would have lost",
        v.nonmeasurement.json_pointer, "/profiles/p");
      eq("E7-19: the pointer is RFC 6901 against the FILE, never the envelope -- "
        + "an envelope-relative pointer would read /artifact/profiles/p",
        v.nonmeasurement.json_pointer.startsWith("/artifact/"), false);
    }
  }

  // (2b) E8-10: stage-8 rule two END TO END, WITH REPAIR REFUSED. The block
  //      previously delegated the whole of this rule to W1-BLK-IR17, which
  //      measures it on the MANIFEST; the rule the JCS block owns is the one for
  //      a LISTED file, and "repair refused for each" is required of both rules,
  //      not only of the surrogate.
  {
    const dup = '{"record_id":"r","chain_id":"c","artifact_type":"decision","k":1,"k":2}';
    check("control: JSON.parse silently resolves the duplicate last-wins",
      JSON.parse(dup).k === 2, show(JSON.parse(dup).k));
    const v = expectNonMeasured("stage 8: a duplicate member name in a listed file",
      mkBundle("jcs-duplicate-member", { artifacts: { "artifacts/a.json": dup } }),
      "bundle-json-invalid");
    if (v) {
      check("stage 8: the duplicate is NAMED, so it is not a generic parse failure",
        /repeats the member/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
      check("stage 8: neither first-wins nor last-wins was applied -- no repair",
        /neither first-wins nor last-wins/.test(v.nonmeasurement.detail),
        v.nonmeasurement.detail);
    }
  }

  // (3b) E8-10: BOTH section 5.1 NUMERIC BRANCHES at stage 10, each with its
  //      json_pointer. The block previously carried only 1e400 -- the
  //      "not IEEE-754 representable" branch -- so a lane that accepted an
  //      integer beyond 2^53-1, or a value needing more than binary64 to
  //      round-trip, passed it.
  for (const [name, token, pointer] of [
    ["1e400 -- not IEEE-754 representable", "1e400", "/profiles/p"],
    ["1.0000000000000001 -- more precision than binary64 can round-trip",
      "1.0000000000000001", "/profiles/p"],
    ["1e20 -- integer-valued beyond 2^53-1", "1e20", "/profiles/p"],
    ["9007199254740992 -- the boundary's ADJACENT rejection", "9007199254740992",
      "/profiles/p"],
  ]) {
    const doc = '{"record_id":"r","chain_id":"c","artifact_type":"decision",'
      + `"profiles":{"p":${token}}}`;
    const v = expectNonMeasured(`stage 10: ${name}`,
      mkBundle(`jcs-num-${token.replace(/[^a-z0-9]+/gi, "-")}`,
        { artifacts: { "artifacts/a.json": doc } }),
      "numeric-preflight-violation");
    if (v) {
      check(`stage 10: ${name} is NOT folded into stage 8`,
        v.nonmeasurement.reason !== "bundle-json-invalid", v.nonmeasurement.reason);
      eq(`stage 10: ${name} carries its json_pointer`, v.nonmeasurement.json_pointer, pointer);
    }
    check(`the pure numeric gate rejects ${name}`, checkNumberToken(token) !== null, token);
  }

  // ACCEPTANCE CONTROLS, so the block cannot pass on an evaluator that
  // OVER-REJECTS. Each is a value the envelope permits, and 9007199254740991
  // sits immediately below the rejection above it.
  for (const [name, token] of [
    ["1.5 -- exactly representable and not integral", "1.5"],
    ["9007199254740991 -- the boundary itself", "9007199254740991"],
    ["0.1 -- a value whose double round-trips", "0.1"],
    ["-9007199254740991 -- the negative boundary", "-9007199254740991"],
  ]) {
    check(`the pure numeric gate ACCEPTS ${name}`, checkNumberToken(token) === null,
      show(checkNumberToken(token)));
    const doc = '{"record_id":"r","chain_id":"c","artifact_type":"decision",'
      + `"profiles":{"p":${token}}}`;
    const r = runIntercepted(
      mkBundle(`jcs-ok-${token.replace(/[^a-z0-9]+/gi, "-")}`,
        { artifacts: { "artifacts/a.json": doc } }),
      [{ status: 0, stdout: verdict() }]);
    eq(`stage 10 ACCEPTS ${name} end to end`, r.code, 0);
  }
  check("control: the boundary and its adjacent rejection really are adjacent",
    checkNumberToken("9007199254740991") === null
    && checkNumberToken("9007199254740992") !== null);

  // The control that makes the boundary a boundary: a document that is
  // genuinely unparseable still lands on stage 8.
  expectNonMeasured("control: an unparseable listed file is still stage-8",
    mkBundle("jcs-unparseable", { artifacts: { "artifacts/a.json": "{not json" } }),
    "bundle-json-invalid");
}
endBlock("W1-BLK-JCS");

// --- W1-BLK-IR13: stage barriers, and the comparison key -------------------
//
// Every fixture below carries TWO faults from DIFFERENT stages, and asserts
// that the EARLIER stage is reported. The barriers are what make this
// single-valued: an implementation validating each path end-to-end in manifest
// order would report the later fault, and that reading satisfied the old
// "complete the whole bundle preflight first" wording.
//
// The offending files are chosen so that the LATER-stage fault sorts FIRST by
// path. Without that, a "first failure in manifest order" implementation would
// pass every one of these by accident.
beginBlock("W1-BLK-IR13");
{
  const twoArtifacts = {
    "artifacts/a.json": '{"record_id":"r1","chain_id":"c","artifact_type":"decision"}',
    "artifacts/b.json": '{"record_id":"r2","chain_id":"c","artifact_type":"decision"}',
  };

  // stage 5 (missing) BEFORE stage 7 (digest). artifacts/a.json sorts first and
  // carries the LATER fault.
  {
    const dir = mkBundle("ir13-missing-vs-digest", {
      artifacts: twoArtifacts, corrupt: "artifacts/a.json",
    });
    fs.rmSync(path.join(dir, "artifacts", "b.json"));
    const v = expectNonMeasured("stage 5 before stage 7: missing beats digest mismatch",
      dir, "bundle-file-missing");
    if (v) {
      check("and it names the MISSING file, not the mismatching one",
        /b\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
    }
  }

  // stage 6 (unreadable) BEFORE stage 7 (digest). Same shape.
  {
    const dir = mkBundle("ir13-unreadable-vs-digest", {
      artifacts: twoArtifacts, corrupt: "artifacts/a.json",
    });
    const victim = path.join(dir, "artifacts", "b.json");
    let denied = false;
    try {
      fs.chmodSync(victim, 0o000);
      try { fs.readFileSync(victim); } catch { denied = true; }
    } catch { /* chmod unsupported */ }
    if (!denied) {
      // euid 0 reads a 0o000 file, so the fault cannot be produced. Reported as
      // an ordinary condition skip: the barrier itself is still measured by the
      // other fixtures in this block, so the BLOCK is not declined.
      skip("W1-BLK-IR13 stage-6/stage-7 barrier",
        "this process can read a 0o000 file (euid 0, or a filesystem ignoring chmod)");
    } else {
      const v = expectNonMeasured("stage 6 before stage 7: unreadable beats digest mismatch",
        dir, "bundle-file-unreadable");
      if (v) {
        check("and it names the UNREADABLE file, not the mismatching one",
          /b\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
      }
      fs.chmodSync(victim, 0o644);
    }
  }

  // stage 5 (missing) BEFORE stage 6 (unreadable). Both are file-level, so this
  // is the pair an implementation is most likely to collapse.
  {
    const dir = mkBundle("ir13-missing-vs-unreadable", { artifacts: twoArtifacts });
    const victim = path.join(dir, "artifacts", "a.json");
    let denied = false;
    try {
      fs.chmodSync(victim, 0o000);
      try { fs.readFileSync(victim); } catch { denied = true; }
    } catch { /* chmod unsupported */ }
    fs.rmSync(path.join(dir, "artifacts", "b.json"));
    if (!denied) {
      skip("W1-BLK-IR13 stage-5/stage-6 barrier",
        "this process can read a 0o000 file (euid 0, or a filesystem ignoring chmod)");
    } else {
      expectNonMeasured("stage 5 before stage 6: missing beats unreadable",
        dir, "bundle-file-missing");
      fs.chmodSync(victim, 0o644);
    }
  }

  // stage 4 (manifest object) BEFORE stage 7 (digest). A manifest that is
  // malformed on its own terms is reported before the disk is consulted.
  {
    const dir = mkBundle("ir13-manifest-vs-digest", {
      artifacts: twoArtifacts, corrupt: "artifacts/a.json",
      mutate: (m) => { m.surprise = true; },
    });
    expectNonMeasured("stage 4 before stage 7: manifest closure beats digest mismatch",
      dir, "manifest-invalid");
  }

  // stage 4 (manifest object) BEFORE stage 5 (filesystem layout). The split
  // between the two manifest-invalid producers is deliberate, so the control is
  // that stage 5 alone still reaches manifest-invalid -- proving the two really
  // are separate producers and not one merged check.
  {
    const dir = mkBundle("ir13-stage5-alone", { artifacts: twoArtifacts });
    fs.writeFileSync(path.join(dir, "artifacts", "unlisted.json"), "{}");
    const v = expectNonMeasured("stage 5 alone reaches manifest-invalid (layout closure)",
      dir, "manifest-invalid");
    if (v) {
      check("and it names the unlisted file", /unlisted\.json/.test(v.nonmeasurement.detail),
        v.nonmeasurement.detail);
    }
  }

  // stage 7 (digest) BEFORE stage 8 (JSON). The mismatching file is NOT the
  // unparseable one, so an end-to-end-per-file implementation would report the
  // parse failure.
  {
    const dir = mkBundle("ir13-digest-vs-json", {
      artifacts: {
        "artifacts/a.json": "{not json at all",
        "artifacts/b.json": '{"record_id":"r2","chain_id":"c","artifact_type":"decision"}',
      },
      corrupt: "artifacts/b.json",
    });
    const v = expectNonMeasured("stage 7 before stage 8: digest mismatch beats a parse failure",
      dir, "manifest-digest-mismatch");
    if (v) {
      check("and it names the MISMATCHING file, not the unparseable one",
        /b\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
    }
  }

  // stage 9 (shape) BEFORE stage 10 (numeric).
  {
    const dir = mkBundle("ir13-shape-vs-numeric", {
      scenarioId: "IOP-R-CLEAN",
      artifacts: {
        "artifacts/a.json":
          '{"record_id":"r","chain_id":"c","artifact_type":"decision","p":1e300}',
      },
    });
    expectNonMeasured("stage 9 before stage 10: shape beats the numeric envelope",
      dir, "bundle-shape-invalid");
  }

  // THE WORKED STAGE-9 CASE, verbatim from section 8.6: a manifest with two
  // independence_policy files (bundle-shape-invalid) and a --bindings flag
  // pointing at the revocation file (operator-input-assertion-mismatch). The
  // bundle's own composition is settled BEFORE any assertion an operator makes
  // ABOUT it -- so this is MECHANISM precedence within one stage, not a path
  // tie-break.
  {
    const dir = mkBundle("ir13-worked-stage9", {
      extraFiles: { "operator/policy2.json": { content: POLICY, role: "independence_policy" } },
    });
    const r = run(["--bundle", dir,
      "--bindings", path.join(dir, "operator", "revocation.json")]);
    eq("the worked stage-9 case exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("worked stage-9 case", r.out);
      eq("mechanism precedence within stage 9: composition wins",
        v.nonmeasurement.reason, "bundle-shape-invalid");
      check("and the operator assertion did NOT win",
        v.nonmeasurement.reason !== "operator-input-assertion-mismatch");
    }
    // Both controls: each fault ALONE produces its own reason, so the case
    // above really is a contest between two live faults.
    expectNonMeasured("control: the composition fault alone", mkBundle("ir13-comp-alone", {
      extraFiles: { "operator/policy2.json": { content: POLICY, role: "independence_policy" } },
    }), "bundle-shape-invalid");
    {
      const d2 = mkBundle("ir13-assert-alone");
      const r2 = run(["--bundle", d2,
        "--bindings", path.join(d2, "operator", "revocation.json")]);
      eq("control: the operator-assertion fault alone exits 3", r2.code, 3);
      if (r2.code === 3) {
        eq("control: and reaches its own reason",
          JSON.parse(r2.out).nonmeasurement.reason, "operator-input-assertion-mismatch");
      }
    }
  }

  // THE CONDITIONAL FOURTH COMPONENT of the comparison key. Two numbers in ONE
  // file share a stage, a reason and a path, and numeric-preflight-violation is
  // the one reason that carries an EMITTED json_pointer -- so here, and only
  // here, the selection is observable.
  //
  // BYTE order, not numeric order: /profiles/p/10 sorts BEFORE /profiles/p/9
  // because "1" precedes "9" as a byte. A rule comparing array indices
  // numerically would report /profiles/p/9 and would have to parse the index to
  // do it, which invites the two lanes to disagree about what is an index.
  {
    const arr = [0, 0, 0, 0, 0, 0, 0, 0, 0, "1e300", "2e300"];
    const doc = '{"record_id":"r","chain_id":"c","artifact_type":"decision",'
      + `"profiles":{"p":[${arr.map((x) => (typeof x === "string" ? x : "0")).join(",")}]}}`;
    const v = expectNonMeasured("two violations in one file: the pointer decides",
      mkBundle("ir13-pointer-tiebreak", { artifacts: { "artifacts/a.json": doc } }),
      "numeric-preflight-violation");
    if (v) {
      eq("ascending UTF-8 BYTE order of the pointer selects /profiles/p/10",
        v.nonmeasurement.json_pointer, "/profiles/p/10");
      check("control: numeric index order would have selected /profiles/p/9",
        byteCompare("/profiles/p/10", "/profiles/p/9") < 0
        && v.nonmeasurement.json_pointer !== "/profiles/p/9");
      check("control: /profiles/p/9 really is a violation too, so both were candidates",
        checkNumberToken("2e300") !== null && checkNumberToken("1e300") !== null);
    }
  }
  // Document order is not the key either: the violating member declared LAST
  // has the byte-smaller pointer, and it must win.
  {
    const doc = '{"record_id":"r","chain_id":"c","artifact_type":"decision",'
      + '"profiles":{"z":1e300,"a":1e300}}';
    const v = expectNonMeasured("document order is not the key",
      mkBundle("ir13-pointer-docorder", { artifacts: { "artifacts/a.json": doc } }),
      "numeric-preflight-violation");
    if (v) {
      eq("the byte-smaller pointer wins even though it is declared last",
        v.nonmeasurement.json_pointer, "/profiles/a");
    }
  }


  // =========================================================================
  // E8-10: the twelve-item branch list. AD15-IR-13 is the largest ruling in the
  // contract and a single multi-fault fixture discriminates almost none of it.
  // =========================================================================

  // ITEM 1, continued -- THE REMAINING STAGE BARRIERS. The fixtures above cover
  // 4/7, 5/6, 5/7, 6/7, 7/8 and 9/10; these close 2/3, 3/4, 4/5, 8/9, 10/11 and
  // 11/12, so every barrier at which two failures can be live is measured.

  // 2/3 -- identity (the exit-1 band) before frozen identity. A bundle whose
  // manifest will not parse AND whose --verifier cannot be read is exit 1 with
  // NO result object: there is no scenario to name one after.
  {
    const dir = path.join(tmp, "ir13-stage2-vs-3");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "manifest.json"), "{ not json");
    const absent = path.join(tmp, "ir13-absent-verifier.mjs");
    const r = run(["--bundle", dir, "--verifier", absent]);
    eq("stage 2 before stage 3: identity failure exits 1", r.code, 1);
    check("stage 2 before stage 3: and writes NO result object", r.out === "", r.out.slice(0, 200));
    // Control: with identity established the same unreadable verifier IS
    // reported, so stage 3 really was live.
    const v = expectNonMeasuredWith("control: the unreadable verifier alone",
      ["--bundle", mkBundle("ir13-stage3-alone"), "--verifier", absent],
      "frozen-identity-unreadable");
    if (v) eq("control: and verifier_digests is null, because neither could be computed",
      v.verifier_digests, null);
  }

  // 3/4 -- frozen identity before manifest structure. The manifest carries an
  // unknown member AND the pinned verifier digest does not match.
  {
    const wrong = path.join(tmp, "ir13-wrong-verifier.mjs");
    fs.writeFileSync(wrong, "// readable, and not the frozen verifier\n");
    const dir = mkBundle("ir13-stage3-vs-4", { mutate: (m) => { m.surprise = 1; } });
    expectNonMeasuredWith("stage 3 before stage 4: frozen identity beats manifest closure",
      ["--bundle", dir, "--verifier", wrong], "verifier-digest-mismatch");
    expectNonMeasured("control: the manifest fault alone",
      mkBundle("ir13-stage4-alone", { mutate: (m) => { m.surprise = 1; } }), "manifest-invalid");
  }

  // 4/5 -- manifest closure before filesystem closure. A manifest that is
  // malformed ON ITS OWN TERMS is reported before the disk is consulted, and the
  // two reasons differ here so the barrier is observable.
  {
    const dir = mkBundle("ir13-stage4-vs-5", { mutate: (m) => { m.surprise = 1; } });
    fs.rmSync(path.join(dir, "artifacts", "a.json"));
    expectNonMeasured("stage 4 before stage 5: manifest closure beats a missing file",
      dir, "manifest-invalid");
    const alone = mkBundle("ir13-stage5-missing-alone");
    fs.rmSync(path.join(alone, "artifacts", "a.json"));
    expectNonMeasured("control: the missing file alone", alone, "bundle-file-missing");
  }

  // 8/9 -- JSON parsing before shape. The bundle carries TWO artifacts for a
  // single-artifact scenario (stage 9) and one of them will not parse (stage 8).
  {
    const dir = mkBundle("ir13-stage8-vs-9", {
      artifacts: {
        "artifacts/a.json": "{not json at all",
        "artifacts/b.json": '{"record_id":"r2","chain_id":"c","artifact_type":"decision"}',
      },
    });
    expectNonMeasured("stage 8 before stage 9: a parse failure beats a shape violation",
      dir, "bundle-json-invalid");
    expectNonMeasured("control: the shape violation alone", mkBundle("ir13-stage9-alone", {
      artifacts: {
        "artifacts/a.json": '{"record_id":"r1","chain_id":"c","artifact_type":"decision"}',
        "artifacts/b.json": '{"record_id":"r2","chain_id":"c","artifact_type":"decision"}',
      },
    }), "bundle-shape-invalid");
  }

  // 10/11 -- numeric preflight before invocation. NO frozen verifier is invoked
  // until every preflight stage has passed (section 8.3.1 step 1), so the plan
  // below -- which would fail at the first spawn -- is never reached.
  {
    const dir = mkBundle("ir13-stage10-vs-11", {
      artifacts: { "artifacts/a.json":
        '{"record_id":"r","chain_id":"c","artifact_type":"decision","profiles":{"p":1e400}}' },
    });
    const r = runIntercepted(dir, [{ spawnFails: true }]);
    eq("stage 10 before stage 11: the numeric violation exits 3", r.code, 3);
    eq("stage 10 before stage 11: NO invocation was attempted at all", r.spawnCalls, 0);
    if (r.code === 3) {
      const v = parseOne("ir13 stage10 vs 11", r.out);
      eq("stage 10 before stage 11: reason", v.nonmeasurement.reason,
        "numeric-preflight-violation");
      eq("stage 10 before stage 11: and artifacts[] is empty", v.artifacts, []);
    }
    // Control: without the numeric fault the same plan DOES reach the spawn, so
    // stage 11 really was live.
    const r2 = runIntercepted(mkBundle("ir13-stage11-alone"), [{ spawnFails: true }]);
    eq("control: the spawn failure alone is reached", r2.spawnCalls, 1);
    if (r2.code === 3) {
      eq("control: and reaches its own reason",
        JSON.parse(r2.out).nonmeasurement.reason, "verifier-not-invocable");
    }
  }

  // 11/12 -- invocation before the withheld tier (AD15-IR-10 as a BARRIER). A
  // verifier that misbehaved AS A PROCESS cannot be trusted to have produced a
  // meaningful withheld channel either.
  {
    const plan = [
      { status: 0, stdout: verdict(["withheld-on-artifact-1"]) },
      { status: 2, stdout: "" },
    ];
    const r = runIntercepted(four("ir13-stage11-vs-12"), plan);
    eq("stage 11 before stage 12: exit 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir13 stage11 vs 12", r.out);
      eq("stage 11 before stage 12: the RUN invalidity is reported",
        v.nonmeasurement.reason, "verifier-run-invalid");
      eq("stage 11 before stage 12: so the status is ERROR, not MEASUREMENT_INVALID",
        v.measurement_status, "ERROR");
      check("control: the withheld channel really was live on this bundle",
        v.withheld_reasons.length === 1, show(v.withheld_reasons));
    }
    const r2 = runIntercepted(four("ir13-stage12-alone"),
      [{ status: 0, stdout: verdict(["withheld-on-artifact-1"]) }]);
    if (r2.code === 3) {
      eq("control: the withheld tier alone IS the outcome",
        JSON.parse(r2.out).nonmeasurement.reason, "authenticated-withheld");
    }
  }

  // ITEM 2 -- WITHIN-STAGE REASON PRECEDENCE, for every stage listing more than
  // one reason: stage 3, stage 5, stage 6 (E8-2) and stage 9 (above).

  // Stage 3: frozen-identity-unreadable BEFORE verifier-digest-mismatch.
  {
    const absent = path.join(tmp, "ir13-absent-verifier.mjs");
    const wrongContract = path.join(tmp, "ir13-wrong-contract.md");
    fs.writeFileSync(wrongContract, "# readable, and not the frozen contract\n");
    expectNonMeasuredWith("stage 3 mechanism order: unreadable beats digest mismatch",
      ["--bundle", mkBundle("ir13-stage3-order"), "--verifier", absent,
        "--verifier-contract", wrongContract],
      "frozen-identity-unreadable");
    expectNonMeasuredWith("control: the readable-but-wrong contract alone is a MISMATCH",
      ["--bundle", mkBundle("ir13-stage3-order-ctl"), "--verifier-contract", wrongContract],
      "verifier-digest-mismatch");
  }

  // Stage 5: manifest-invalid BEFORE bundle-file-missing. This fixture is ALSO
  // ITEM 3 -- MECHANISM BEFORE PATH: the manifest-invalid entry is `zzz.json`,
  // which sorts AFTER the missing `artifacts/a.json`, so an implementation
  // tie-breaking on path first would report the missing file.
  {
    const dir = mkBundle("ir13-stage5-order");
    fs.writeFileSync(path.join(dir, "zzz.json"), "{}");
    fs.rmSync(path.join(dir, "artifacts", "a.json"));
    const v = expectNonMeasured(
      "stage 5 mechanism order: an unlisted file beats a missing listed file", dir,
      "manifest-invalid");
    if (v) {
      check("item 3: the earlier-ranked reason wins on a LATER-sorting path",
        /zzz\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
      check("control: artifacts/a.json really does sort first",
        byteCompare("artifacts/a.json", "zzz.json") < 0);
    }
  }

  // Stage 6, E8-2 -- bundle-file-missing BEFORE bundle-file-unreadable, and a
  // DEFINITE ENOENT ON READ is bundle-file-missing even though stage 5 had
  // already established the file's presence.
  //
  // This is a MEASURED CROSS-LANE DIVERGENCE and a BEHAVIOURAL CHANGE IN THIS
  // LANE: the superseded code reported the ENOENT case as
  // bundle-file-unreadable, on the reasoning that bundle-file-missing belonged
  // to a stage that had already settled.
  //
  // The state -- present at stage 5, gone before stage 6 -- is a race against
  // the evaluator's own traversal, so it is produced through the filesystem
  // interceptor rather than by deleting a file and hoping.
  {
    const two = {
      "artifacts/a.json": '{"record_id":"r1","chain_id":"c","artifact_type":"decision"}',
      "artifacts/b.json": '{"record_id":"r2","chain_id":"c","artifact_type":"decision"}',
    };
    // (a) ENOENT on read alone -> bundle-file-missing, NOT unreadable.
    {
      const r = runFsIntercepted(
        mkBundle("ir13-e82-enoent", { scenarioId: "IOP-R-CLEAN", artifacts: two }),
        { readFileErrors: [{ suffix: "artifacts/b.json", code: "ENOENT" }] });
      eq("E8-2: a definite ENOENT while READING a listed file exits 3", r.code, 3);
      if (r.code === 3) {
        const v = parseOne("ir13 E8-2 enoent", r.out);
        eq("E8-2: it is bundle-file-missing, not bundle-file-unreadable",
          v.nonmeasurement.reason, "bundle-file-missing");
        check("E8-2: and it names the file that vanished",
          /b\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
        check("E8-2: the detail records that the ENOENT came from the READ",
          /ENOENT|read/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
      }
    }
    // (b) The CONTROL that makes (a) a discrimination rather than a coincidence:
    //     any OTHER read error on the same file is still bundle-file-unreadable.
    {
      const r = runFsIntercepted(
        mkBundle("ir13-e82-eacces", { scenarioId: "IOP-R-CLEAN", artifacts: two }),
        { readFileErrors: [{ suffix: "artifacts/b.json", code: "EACCES" }] });
      eq("E8-2 control: an EACCES on the same file exits 3", r.code, 3);
      if (r.code === 3) {
        eq("E8-2 control: and it IS bundle-file-unreadable",
          JSON.parse(r.out).nonmeasurement.reason, "bundle-file-unreadable");
      }
    }
    // (c) BOTH LIVE WITHIN STAGE 6, on paths chosen so that a path-first
    //     implementation would report the unreadable one: artifacts/a.json
    //     (EACCES) sorts BEFORE artifacts/b.json (ENOENT), and missing must
    //     still win.
    {
      const r = runFsIntercepted(
        mkBundle("ir13-e82-both", { scenarioId: "IOP-R-CLEAN", artifacts: two }),
        { readFileErrors: [
          { suffix: "artifacts/a.json", code: "EACCES" },
          { suffix: "artifacts/b.json", code: "ENOENT" }] });
      eq("E8-2: with both live in stage 6, exit 3", r.code, 3);
      if (r.code === 3) {
        const v = parseOne("ir13 E8-2 both", r.out);
        eq("E8-2: bundle-file-missing OUTRANKS bundle-file-unreadable",
          v.nonmeasurement.reason, "bundle-file-missing");
        check("E8-2: the earlier-ranked reason won on the LATER-sorting path",
          /b\.json/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
      }
    }
    // (d) The stage-6 row itself, as declared data rather than as an inference
    //     from one fixture: two reasons, in that order.
    eq("E8-2: the stage-6 row declares exactly two reasons, missing first",
      STAGE_REASON_ORDER[STAGE.FILE_READS], ["bundle-file-missing", "bundle-file-unreadable"]);
    check("E8-2: and the rank really does order them",
      reasonRank(STAGE.FILE_READS, "bundle-file-missing")
        < reasonRank(STAGE.FILE_READS, "bundle-file-unreadable"));
  }

  // ITEM 5 -- SAME-REASON SELECTION DOES NOT MOVE THE PARITY SURFACE. Given two
  // same-stage, same-reason failures, the SECTION 8.7 PROJECTION is identical
  // whichever the evaluator selects.
  //
  // The block asserts that invariance ON THE PROJECTION ONLY. `detail` is
  // Class 4 and may legitimately name whichever failure was selected, so
  // requiring the whole emitted result to be identical would narrow the same
  // freedom one level down (E8-14). NOTHING HERE ASSERTS WHICH FAILURE WAS
  // CHOSEN: AD15-IR-13 says an evaluator may select either, and requiring
  // ascending path selection or an empty internal key would narrow a freedom the
  // contract deliberately leaves open (E8-13).
  {
    const dir = mkBundle("ir13-same-reason", {
      scenarioId: "IOP-R-CLEAN",
      artifacts: {
        "artifacts/a.json": '{"record_id":"r1","chain_id":"c","artifact_type":"decision"}',
        "artifacts/b.json": '{"record_id":"r2","chain_id":"c","artifact_type":"control"}',
      },
    });
    fs.rmSync(path.join(dir, "artifacts", "a.json"));
    fs.rmSync(path.join(dir, "artifacts", "b.json"));
    const v = expectNonMeasured("two same-stage same-reason failures", dir,
      "bundle-file-missing");
    if (v) {
      const other = JSON.parse(JSON.stringify(v));
      // The ONLY thing that could differ between the two selections is `detail`.
      other.nonmeasurement.detail =
        "files[] lists artifacts/b.json but no such file is present under the bundle";
      check("item 5: the two selections really do give different DETAIL",
        other.nonmeasurement.detail !== v.nonmeasurement.detail);
      eq("item 5: and an IDENTICAL section 8.7 projection",
        projectionBytes(other), projectionBytes(v));
      check("item 5: detail is Class 4, so it is removed from the projection",
        !/no such file/.test(projectionBytes(v)), projectionBytes(v).slice(0, 300));
    }
  }

  // ITEM 6 -- STAGE 11'S SEQUENTIAL EXCEPTION. Artifact invocation is sequential
  // in AD15-IR-12's order and stops at the first fatal run, so the reported
  // reason is whichever fatal run is REACHED FIRST. No comparison between
  // reasons arises, and the two orderings below prove it by swapping them.
  {
    const a = runIntercepted(four("ir13-stage11-seq-a"), [
      { status: 0, stdout: verdict() }, { status: 2, stdout: "" },
      { spawnFails: true }, { status: 0, stdout: verdict() }]);
    eq("item 6: the run-invalid at position 2 is reported", a.code, 3);
    if (a.code === 3) {
      const v = parseOne("ir13 stage11 seq a", a.out);
      eq("item 6: reason", v.nonmeasurement.reason, "verifier-run-invalid");
      eq("item 6: the scenario aborted there -- position 3 was never reached", a.spawnCalls, 2);
      eq("item 6: and the failing artifact contributed its entry", v.artifacts.length, 2);
    }
    const b = runIntercepted(four("ir13-stage11-seq-b"), [
      { status: 0, stdout: verdict() }, { spawnFails: true },
      { status: 2, stdout: "" }, { status: 0, stdout: verdict() }]);
    eq("item 6: with the two swapped, the spawn failure is reported instead", b.code, 3);
    if (b.code === 3) {
      const v = parseOne("ir13 stage11 seq b", b.out);
      eq("item 6: reason", v.nonmeasurement.reason, "verifier-not-invocable");
      eq("item 6: the scenario aborted at the same position", b.spawnCalls, 2);
      eq("item 6: and the spawn failure contributed NO entry", v.artifacts.length, 1);
    }
  }

  // ITEM 7 -- STAGE-4 MANIFEST CLOSURE VERSUS STAGE-5 FILESYSTEM CLOSURE, BOTH
  // PRODUCING manifest-invalid. The split is deliberate: stage 4 is what the
  // JSON document violates on its own terms, stage 5 is what the bundle on disk
  // violates.
  {
    expectNonMeasured("item 7: stage 4 alone -- manifest closure",
      mkBundle("ir13-item7-stage4", { mutate: (m) => { m.surprise = 1; } }), "manifest-invalid");
    const disk = mkBundle("ir13-item7-stage5");
    fs.writeFileSync(path.join(disk, "zzz.json"), "{}");
    const v5 = expectNonMeasured("item 7: stage 5 alone -- filesystem closure", disk,
      "manifest-invalid");
    if (v5) check("item 7: and stage 5's detail names the DISK violation",
      /zzz\.json/.test(v5.nonmeasurement.detail), v5.nonmeasurement.detail);
    // Both live: the manifest is reported before the disk is consulted.
    const both = mkBundle("ir13-item7-both", { mutate: (m) => { m.surprise = 1; } });
    fs.writeFileSync(path.join(both, "zzz.json"), "{}");
    const vb = expectNonMeasured("item 7: with both live, the manifest is reported first", both,
      "manifest-invalid");
    if (vb) {
      check("item 7: the detail names the MANIFEST rule, not the unlisted file",
        !/zzz\.json/.test(vb.nonmeasurement.detail), vb.nonmeasurement.detail);
    }
  }

  // ITEM 8 -- DETERMINISTIC SORTED TRAVERSAL: the reported failure does not
  // change with OS enumeration order. readdir order is unspecified and varies by
  // filesystem, so a lane reporting the first failure in enumeration order is
  // not deterministic. This filesystem happens to be stable, so the only way to
  // MEASURE the property is to hand the evaluator a different order.
  {
    const mk = (name) => {
      const d = mkBundle(name);
      fs.writeFileSync(path.join(d, "aaa-unlisted.json"), "{}");
      fs.writeFileSync(path.join(d, "zzz-unlisted.json"), "{}");
      return d;
    };
    const forward = runFsIntercepted(mk("ir13-order-fwd"), { reverseReaddir: false });
    const reverse = runFsIntercepted(mk("ir13-order-rev"), { reverseReaddir: true });
    eq("item 8: both enumeration orders exit 3", `${forward.code}/${reverse.code}`, "3/3");
    if (forward.code === 3 && reverse.code === 3) {
      const f = JSON.parse(forward.out);
      const r = JSON.parse(reverse.out);
      eq("item 8: the same reason is reported in both orders",
        f.nonmeasurement.reason, r.nonmeasurement.reason);
      eq("item 8: and the SAME offending entry is selected",
        f.nonmeasurement.detail, r.nonmeasurement.detail);
      check("item 8: two candidates really were present, so the order mattered",
        /aaa-unlisted|zzz-unlisted/.test(f.nonmeasurement.detail), f.nonmeasurement.detail);
    }
    // Control: the interceptor really did reverse what the evaluator was handed.
    {
      const d = mk("ir13-order-probe");
      const names = fs.readdirSync(d);
      check("control: the reversing interceptor changes the list it returns",
        [...names].reverse().join(",") !== names.join(","), names.join(","));
    }
  }

  // ITEM 9 -- THE NAME-KEY BRANCH THIS PLATFORM SUPPLIES, and that NO
  // normalization, case folding or locale mapping is applied.
  //
  // Section 8.6 defines the key over WHAT THE API ACTUALLY PROVIDES, in two
  // mutually exclusive branches. Node's readdirSync({ encoding: "buffer" })
  // yields LOSSLESS RAW NAME BYTES, so this lane is on the first branch and
  // cannot construct the Unicode-native branch at all.
  {
    const probe = path.join(tmp, "ir13-namekey-probe");
    fs.mkdirSync(probe, { recursive: true });
    const rawName = Buffer.from([0x61, 0xFF, 0xFE, 0x62]);   // not valid UTF-8
    let lossless = false;
    try {
      fs.writeFileSync(Buffer.concat([Buffer.from(probe + "/"), rawName]), "{}");
      const back = fs.readdirSync(probe, { encoding: "buffer" });
      lossless = back.length === 1 && Buffer.compare(back[0], rawName) === 0;
    } catch { lossless = false; }
    check("item 9: this platform's directory API yields LOSSLESS RAW NAME BYTES",
      lossless, "the raw name did not survive a round trip");
    // The unreachable branch, RECORDED rather than skipped silently or counted
    // as covered.
    notMeasuredBranch("W1-BLK-IR13 item 9, Unicode-native name-key branch",
      "Node's readdirSync({ encoding: \"buffer\" }) always returns lossless raw bytes on this "
      + "runtime, so a Unicode-native directory API -- the other of the two mutually exclusive "
      + "branches section 8.6 defines -- cannot be constructed by this lane at all");

    // NO NORMALIZATION. Two names that are NFC and NFD forms of the same string
    // are DISTINCT byte sequences and must stay distinct: a normalizing key
    // makes them collide on one platform and not on another, which is the
    // cross-platform determinism defect AD15-IR-9 exists to close, one layer
    // down.
    const NFC = "caf\u00e9.json";       // U+00E9
    const NFD = "cafe\u0301.json";      // e + U+0301
    check("item 9: NFC and NFD really are different byte sequences",
      Buffer.compare(Buffer.from(NFC, "utf8"), Buffer.from(NFD, "utf8")) !== 0);
    check("item 9: and normalizing them WOULD collide, which is what is forbidden",
      NFC.normalize("NFC") === NFD.normalize("NFC"));
    const nrm = mkBundle("ir13-normalization");
    let bothWritten = false;
    try {
      fs.writeFileSync(path.join(nrm, NFC), "{}");
      fs.writeFileSync(path.join(nrm, NFD), "{}");
      bothWritten = fs.readdirSync(nrm).filter((n) => /caf/.test(n)).length === 2;
    } catch { bothWritten = false; }
    if (!bothWritten) {
      skip("W1-BLK-IR13 item 9 normalization fixture",
        "this filesystem folds NFC and NFD to one name, so two distinct entries "
        + "cannot be created");
    } else {
      const v = expectNonMeasured("item 9: an unlisted non-ASCII entry is manifest-invalid",
        nrm, "manifest-invalid");
      if (v) {
        check("item 9: it is reported as an UNLISTED ENTRY, with no name repaired into a match",
          /absent from files\[\]|not representable/.test(v.nonmeasurement.detail),
          v.nonmeasurement.detail);
      }
      // The source-level half, in the same idiom W1-BLK-IR9 uses for lstat: the
      // traversal takes buffer names, compares them as unsigned bytes, and never
      // calls a normalizer.
      const src = fs.readFileSync(EVAL, "utf8");
      const body = src.slice(src.indexOf("export function traverseBundle"),
        src.indexOf("// 7. CLI"));
      check("item 9: the traversal enumerates with encoding \"buffer\"",
        /readdirSync\([^)]*encoding:\s*"buffer"/.test(body), "buffer encoding not requested");
      check("item 9: and sorts by UNSIGNED BYTES (Buffer.compare)",
        /\.sort\(Buffer\.compare\)/.test(body), "Buffer.compare sort not found");
      check("item 9: no normalization, case folding or locale mapping is applied",
        !/\.normalize\(|toLowerCase\(|toUpperCase\(|localeCompare\(/.test(body),
        "a normalizing or case-mapping call is present in the traversal");
    }
  }

  // ITEM 10 -- A NON-UTF-8 DIRECTORY NAME AS AN UNLISTED ENTRY. A manifest
  // `path` is a JSON string, so no such entry can ever be listed in files[].
  {
    const dir = mkBundle("ir13-nonutf8-dir");
    let made = false;
    try {
      fs.mkdirSync(Buffer.concat([Buffer.from(dir + "/"), Buffer.from([0xFF, 0xFE])]));
      made = true;
    } catch { made = false; }
    if (!made) {
      skip("W1-BLK-IR13 item 10", "this filesystem refuses a non-UTF-8 directory name");
    } else {
      const v = expectNonMeasured("item 10: a non-UTF-8 DIRECTORY name", dir, "manifest-invalid");
      if (v) {
        check("item 10: it is reported as unrepresentable, not as a missing or unreadable file",
          /not representable/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
      }
    }
  }

  // ITEM 11 -- A MANIFEST `path` CONTAINING AN UNPAIRED SURROGATE, at STAGE 4.
  // Strict JSON admits the escape \ud800 with no pair; it does not encode to
  // well-formed UTF-8 and so cannot denote any filesystem name. It fails on the
  // manifest's OWN TERMS, before the disk is consulted.
  {
    const dir = mkBundle("ir13-surrogate-path", {
      renderManifest: (m) => {
        const j = JSON.stringify(m, null, 1);
        // The artifact entry's path, replaced with a lone high surrogate escape.
        return j.replace('"artifacts/a.json"', '"\\ud800.json"');
      },
    });
    const v = expectNonMeasured("item 11: a manifest path with an unpaired surrogate", dir,
      "manifest-invalid");
    if (v) {
      check("item 11: reported at stage 4, so artifacts[] is empty and nothing was read",
        Array.isArray(v.artifacts) && v.artifacts.length === 0, show(v.artifacts));
      check("item 11: no U+FFFD replacement reached the output",
        !/�/.test(JSON.stringify(v)), "a replacement character reached the result");
    }
    // The grammar half, so the end-to-end result is attributable.
    check("item 11: the path grammar rejects an unpaired surrogate outright",
      checkBundlePath("\ud800.json") !== null);
  }

  // ITEM 12 -- internal-error STAYS OUTSIDE THE ORDER and never masks an
  // already-determined failure. It is not a stage: it is raised wherever an
  // unexpected evaluator fault occurs after identity is established.
  {
    // (a) It is not in the order at all: no stage declares it.
    let declaredAnywhere = false;
    for (const stage of Object.keys(STAGE_REASON_ORDER)) {
      if (STAGE_REASON_ORDER[stage].includes("internal-error")) declaredAnywhere = true;
    }
    check("item 12: internal-error is declared by NO stage in the order", !declaredAnywhere);
    let ranked = false;
    try { reasonRank(STAGE.INVOCATION, "internal-error"); ranked = true; } catch { ranked = false; }
    check("item 12: and it cannot be given a rank within one", !ranked,
      "internal-error was ranked inside a stage");

    // (b) An unexpected fault at stage 11 IS reported as internal-error, with a
    //     result object naming the scenario rather than a crash the harness has
    //     to infer.
    const r = runIntercepted(mkBundle("ir13-internal-alone"), [{ throws: true }]);
    eq("item 12: an unexpected evaluator fault after identity exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir13 internal-error", r.out);
      eq("item 12: reason", v.nonmeasurement.reason, "internal-error");
      eq("item 12: and the result object NAMES the scenario", v.scenario_id, "IOP-P-DEC");
      check("item 12: detail carries enough to locate the fault",
        /synthetic evaluator-internal fault/.test(v.nonmeasurement.detail),
        v.nonmeasurement.detail);
    }

    // (c) THE DISCRIMINATION: with an EARLIER-STAGE failure also present, the
    //     earlier failure is what is reported. A stage that has produced its
    //     failure has produced the reported reason, and a later fault does not
    //     replace it.
    const r2 = runIntercepted(
      mkBundle("ir13-internal-masked", { corrupt: "artifacts/a.json" }), [{ throws: true }]);
    eq("item 12: the earlier-stage failure still exits 3", r2.code, 3);
    if (r2.code === 3) {
      const v = parseOne("ir13 internal not masking", r2.out);
      eq("item 12: internal-error did NOT mask the already-determined failure",
        v.nonmeasurement.reason, "manifest-digest-mismatch");
    }
    eq("item 12: and the fault was never reached, because preflight settled first",
      r2.spawnCalls, 0);
  }

  // The key itself, as a pure function, over the components the fixtures above
  // cannot all reach -- a PATHLESS whole-bundle violation uses the EMPTY BYTE
  // STRING, which is what makes the ordering total in that case (E7-SR-N1).
  {
    const f = (rank, pathKey, ptr = null) => ({ rank, pathKey, jsonPointer: ptr });
    check("mechanism outranks path", compareStageFailures(f(0, "z"), f(1, "a")) < 0);
    check("path decides at equal mechanism", compareStageFailures(f(1, "a"), f(1, "b")) < 0);
    check("a pathless violation sorts under the empty byte string",
      compareStageFailures(f(1, ""), f(1, "a")) < 0);
    check("no real path is empty, so the empty key never collides",
      checkBundlePath("") !== null);
    check("the pointer decides only when both carry one",
      compareStageFailures(f(1, "a", "/b"), f(1, "a", "/a")) > 0);
    check("and the key is total: equal on all components compares equal",
      compareStageFailures(f(1, "a", "/a"), f(1, "a", "/a")) === 0);
  }
}
endBlock("W1-BLK-IR13");

// --- W1-BLK-IR14: a post-identity operator assertion is result-bearing -----
//
// This lane's superseded behaviour raised a UsageError here: exit 2, empty
// stdout. That contradicted AD15-IR-8's rule that an established identity is
// owed a result object. The dividing line is WHEN the fault becomes detectable.
beginBlock("W1-BLK-IR14");
{
  const dir = mkBundle("ir14-mismatch");
  const outside = path.join(tmp, "ir14_outside_bindings.json");
  fs.writeFileSync(outside, BINDINGS);

  // (a) A flag naming a file OUTSIDE the bundle.
  {
    const r = run(["--bundle", dir, "--bindings", outside]);
    eq("AD15-IR-14: an operator-input mismatch exits 3, not 2", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("AD15-IR-14 outside file", r.out);
      eq("AD15-IR-14: the reason is operator-input-assertion-mismatch",
        v.nonmeasurement.reason, "operator-input-assertion-mismatch");
      eq("AD15-IR-14: it is an ERROR", v.measurement_status, "ERROR");
      eq("AD15-IR-14: and the result object NAMES the scenario", v.scenario_id, "IOP-P-DEC");
      eq("AD15-IR-14: level1 is null", v.level1, null);
      eq("AD15-IR-14: predicates is null", v.predicates, null);
      eq("AD15-IR-14: it is pre-invocation, so artifacts[] is empty", v.artifacts, []);
    }
  }

  // (b) A flag naming a file INSIDE the bundle but carrying the WRONG ROLE.
  // Same ruling, and it is the case a naive "is it under the bundle" check
  // would let through.
  {
    const r = run(["--bundle", dir, "--bindings", path.join(dir, "operator", "revocation.json")]);
    eq("AD15-IR-14: a flag naming the wrong role also exits 3", r.code, 3);
    if (r.code === 3) {
      eq("AD15-IR-14: with the same reason",
        JSON.parse(r.out).nonmeasurement.reason, "operator-input-assertion-mismatch");
    }
  }

  // THE DIVIDING LINE. A CLI SYNTAX error is detectable BEFORE anything is
  // read, so it stays exit 2 with empty stdout. Without this control the block
  // would be satisfied by an implementation that had simply moved every usage
  // error to exit 3.
  for (const [name, args] of [
    ["an unknown option", ["--bundle", dir, "--nope", "x"]],
    ["a missing value", ["--bundle", dir, "--bindings"]],
    ["a repeated option", ["--bundle", dir, "--bundle", dir]],
    ["a bare argument", ["--bundle", dir, "junk"]],
  ]) {
    const r = run(args);
    eq(`control: ${name} is still a CLI syntax error at exit 2`, r.code, 2);
    check(`control: ${name} writes nothing to stdout`, r.out === "", r.out);
  }
  // And the positive control: a flag naming the RIGHT file is accepted.
  {
    const r = run(["--bundle", dir, "--bindings", path.join(dir, "operator", "bindings.json")]);
    check("control: a flag naming the bundle's own bindings is not a mismatch",
      !/operator-input-assertion-mismatch/.test(r.out), r.out.slice(0, 300));
  }
  // The official harness passes no operator-input flags, so this reason is
  // unreachable in an official run. It is pinned anyway, because "unreachable in
  // the official run" is exactly the class of gap that produced the --help
  // divergence in Erratum 4 and the entry-kind divergence in Erratum 6.
  {
    const r = run(["--bundle", dir]);
    check("control: with no flags at all the reason is unreachable",
      !/operator-input-assertion-mismatch/.test(r.out), r.out.slice(0, 300));
  }
}
endBlock("W1-BLK-IR14");

// --- W1-BLK-IR12: invocation order, and the abort at the first fatal run ---
//
// Adversarial review found a four-artifact bundle failing at its SECOND
// artifact admitted [A], [C, D] and [A, C, D] -- all three conforming. The
// worked case is now single-valued: [A, B, C, D] whose B cannot be spawned
// yields artifacts[] = [A].
beginBlock("W1-BLK-IR12");
{
  // ORDER. Four distinct verdicts, one per invocation, so the pairing of entry
  // to invocation is observable rather than assumed.
  {
    const plan = ["k0", "k1", "k2", "k3"].map((rid) => ({
      status: 0, stdout: verdict([], { chain_id: "c", record_id: rid }),
    }));
    const r = runIntercepted(four("ir12-order"), plan);
    eq("AD15-IR-12: a clean four-artifact run exits 0", r.code, 0);
    eq("AD15-IR-12: four invocations were attempted", r.spawnCalls, 4);
    if (r.code === 0) {
      const v = parseOne("AD15-IR-12 order", r.out);
      eq("AD15-IR-12: artifacts[] is in ascending artifact_path byte order",
        v.artifacts.map((a) => a.artifact_path),
        ["artifacts/1decision.json", "artifacts/2control.json",
         "artifacts/3execution.json", "artifacts/4effect.json"]);
      eq("AD15-IR-12: invocation k really was paired with entry k",
        v.artifacts.map((a) => a.artifact_ref.record_id), ["k0", "k1", "k2", "k3"]);
    }
  }

  // ABORT, spawn-failure flavour, at every position. The position matters:
  // [A] must be produced when B fails, and an implementation that kept going
  // and then dropped the failed entry would produce [A, C, D].
  for (const failAt of [0, 1, 2, 3]) {
    const plan = [];
    for (let k = 0; k < 4; k++) {
      plan.push(k === failAt ? { spawnFails: true } : { status: 0, stdout: verdict() });
    }
    const r = runIntercepted(four(`ir12-spawnfail-${failAt}`), plan);
    eq(`AD15-IR-12: a spawn failure at position ${failAt} exits 3`, r.code, 3);
    eq(`AD15-IR-12: exactly ${failAt + 1} invocation(s) were attempted -- the scenario aborted`,
      r.spawnCalls, failAt + 1);
    if (r.code === 3) {
      const v = parseOne(`AD15-IR-12 spawnfail ${failAt}`, r.out);
      eq(`AD15-IR-12: the reason is verifier-not-invocable`,
        v.nonmeasurement.reason, "verifier-not-invocable");
      eq(`AD15-IR-12: artifacts[] is the byte-ordered PREFIX of length ${failAt}`,
        v.artifacts.map((a) => a.artifact_path),
        ["artifacts/1decision.json", "artifacts/2control.json",
         "artifacts/3execution.json", "artifacts/4effect.json"].slice(0, failAt));
    }
  }

  // ABORT, run-invalid flavour. The difference from the row above is the whole
  // of AD15-IR-11 + AD15-IR-15: a concrete process result exists, so the
  // current artifact DOES contribute its entry before the abort.
  for (const failAt of [0, 1, 2, 3]) {
    const plan = [];
    for (let k = 0; k < 4; k++) {
      plan.push(k === failAt ? { status: 2, stdout: "" } : { status: 0, stdout: verdict() });
    }
    const r = runIntercepted(four(`ir12-runinvalid-${failAt}`), plan);
    eq(`AD15-IR-12: exit 2 at position ${failAt} exits 3`, r.code, 3);
    eq(`AD15-IR-12: the scenario aborted after ${failAt + 1} invocation(s)`,
      r.spawnCalls, failAt + 1);
    if (r.code === 3) {
      const v = parseOne(`AD15-IR-12 runinvalid ${failAt}`, r.out);
      eq("AD15-IR-12: the reason is verifier-run-invalid",
        v.nonmeasurement.reason, "verifier-run-invalid");
      eq(`AD15-IR-12: artifacts[] carries ${failAt + 1} entries -- the failing one INCLUDED`,
        v.artifacts.length, failAt + 1);
    }
  }

  // A CLEAN exit-0 verdict NEVER aborts, EVEN carrying a non-empty
  // authenticated_withheld channel: under AD15-IR-10 the remaining artifacts
  // must still be evaluated for run validity before section 7.1 applies at all.
  {
    const plan = [{ status: 0, stdout: verdict(["producer-binding-missing"]) },
      { status: 0, stdout: verdict() }];
    const r = runIntercepted(four("ir12-withheld-does-not-abort"), plan);
    eq("AD15-IR-12: a withheld channel does not abort -- all four ran", r.spawnCalls, 4);
    eq("AD15-IR-12: and the scenario is MEASUREMENT_INVALID, not aborted early", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir12 withheld", r.out);
      eq("its status is MEASUREMENT_INVALID", v.measurement_status, "MEASUREMENT_INVALID");
      eq("and all four entries are present", v.artifacts.length, 4);
    }
  }
}
endBlock("W1-BLK-IR12");

// --- W1-BLK-IR15: the three process outcomes, distinguished ----------------
//
// The middle row is the one the ruling exists for. Abnormal termination is the
// absence of an EXIT CODE, not of a PROCESS ATTEMPT -- and it is emphatically
// not the same shape as AD15-IR-11.
beginBlock("W1-BLK-IR15");
{
  const ROWS = [
    ["never started", { spawnFails: true }, "verifier-not-invocable", 0],
    ["started, did not exit normally", { signal: "SIGKILL", stderr: "boom" },
      "verifier-run-invalid", 1],
    ["exited normally", { status: 2, stdout: "" }, "verifier-run-invalid", 1],
  ];
  for (const [name, step, reason, entries] of ROWS) {
    const r = runIntercepted(four(`ir15-${name.replace(/[^a-z]+/gi, "-")}`),
      [{ status: 0, stdout: verdict() }, step]);
    eq(`AD15-IR-15 (${name}): exits 3`, r.code, 3);
    eq(`AD15-IR-15 (${name}): the second invocation really was reached`, r.spawnCalls, 2);
    if (r.code !== 3) continue;
    const v = parseOne(`AD15-IR-15 ${name}`, r.out);
    eq(`AD15-IR-15 (${name}): reason`, v.nonmeasurement.reason, reason);
    // The row's OWN entry: present or absent, and nothing in between.
    eq(`AD15-IR-15 (${name}): the failing artifact contributes ${entries} entr(y/ies)`,
      v.artifacts.length, 1 + entries);
    // The first artifact's entry is retained in every row.
    eq(`AD15-IR-15 (${name}): the earlier completed entry is retained`,
      v.artifacts[0].artifact_path, "artifacts/1decision.json");
    check(`AD15-IR-15 (${name}): the retained entry carries a real integer exit code`,
      Number.isInteger(v.artifacts[0].verifier_exit_code), show(v.artifacts[0]));
  }

  // THE MIDDLE ROW IN FULL. A full entry -- artifact_path, artifact_ref,
  // request_envelope_digest and a stderr digest over what the child actually
  // wrote -- in which exactly TWO measurements are missing.
  {
    const r = runIntercepted(four("ir15-abnormal-detail"),
      [{ status: 0, stdout: verdict() }, { signal: "SIGKILL", stderr: "child diagnostics" }]);
    eq("AD15-IR-15: abnormal termination exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("AD15-IR-15 abnormal", r.out);
      const e = v.artifacts[1];
      check("AD15-IR-15: the abnormally terminated process DID contribute an entry",
        e !== undefined, show(v.artifacts.map((a) => a.artifact_path)));
      if (e !== undefined) {
        eq("AD15-IR-15: verifier_exit_code is null -- there is no portable integer",
          e.verifier_exit_code, null);
        eq("AD15-IR-15: verifier_result is null -- no verdict exists", e.verifier_result, null);
        check("AD15-IR-15: verifier_stderr_digest is PRESENT and is a real digest",
          /^sha256:[0-9a-f]{64}$/.test(e.verifier_stderr_digest), show(e.verifier_stderr_digest));
        eq("AD15-IR-15: and it is the digest of what the child actually wrote",
          e.verifier_stderr_digest, "sha256:" + sha(Buffer.from("child diagnostics")));
        check("AD15-IR-15: artifact_path is present", typeof e.artifact_path === "string");
        check("AD15-IR-15: request_envelope_digest is present",
          /^sha256:[0-9a-f]{64}$/.test(e.request_envelope_digest));
        eq("AD15-IR-15: the entry carries exactly the pinned member set",
          Object.keys(e).sort(), [...ARTIFACT_MEMBERS].sort());
      }
      // NO SIGNAL NAME, NUMBER OR SYNTHESIZED CODE in ANY normative field. The
      // projection is exactly the set of normative members, so this is checked
      // over the projection rather than over a hand-listed set of fields.
      const projected = JSON.stringify(normativeProjection(v));
      check("AD15-IR-15: no signal name reaches any normative field",
        !/SIGKILL|SIGTERM|SIGSEGV/.test(projected), projected.slice(0, 400));
      check("AD15-IR-15: and no negative or synthesized exit code appears either",
        !/"verifier_exit_code":\s*-/.test(projected), projected.slice(0, 400));
      // detail is Class-4 diagnostic-only, so it MAY carry the signal -- E7-14
      // exists because an earlier draft forbade what its next sentence required.
      check("AD15-IR-15: the signal MAY appear in detail, which is diagnostic-only",
        /SIGKILL/.test(v.nonmeasurement.detail), v.nonmeasurement.detail);
    }
  }

  // THE SHAPES ARE NOT THE SAME. A spawn failure and an abnormal termination at
  // the SAME position give a different artifacts[] length -- which is exactly
  // what AD15-IR-12 made observable and what E7-23 removed the "same shape as
  // AD15-IR-11" sentence for.
  {
    const spawn = runIntercepted(four("ir15-contrast-spawn"),
      [{ status: 0, stdout: verdict() }, { spawnFails: true }]);
    const abnormal = runIntercepted(four("ir15-contrast-abnormal"),
      [{ status: 0, stdout: verdict() }, { signal: "SIGKILL" }]);
    const a = JSON.parse(spawn.out);
    const b = JSON.parse(abnormal.out);
    eq("control: both reached the second invocation", [spawn.spawnCalls, abnormal.spawnCalls],
      [2, 2]);
    eq("AD15-IR-15: a spawn failure contributes NO entry", a.artifacts.length, 1);
    eq("AD15-IR-15: an abnormal termination contributes ONE", b.artifacts.length, 2);
    check("AD15-IR-15: so the two are NOT the same shape",
      a.artifacts.length !== b.artifacts.length);
    eq("control: and they carry different reasons",
      [a.nonmeasurement.reason, b.nonmeasurement.reason],
      ["verifier-not-invocable", "verifier-run-invalid"]);
  }
}
endBlock("W1-BLK-IR15");

// --- W1-BLK-IR16: withheld_reasons, unconditional and pinned ---------------
//
// This lane CHOSE an entry shape for itself while the member sat outside the
// parity surface -- it carried an artifact_ref member and an array-valued
// `reasons`. Section 8.7 moved the member inside, so an unpinned entry shape is
// two lanes emitting different objects for the same withheld channel and
// calling it conformance.
beginBlock("W1-BLK-IR16");
{
  // (a) EMITTED UNCONDITIONALLY, [] when nothing is withheld -- on a MEASURED
  //     result, on a pre-invocation ERROR, and on a post-invocation ERROR. The
  //     third is the one an implementation that built the member only on the
  //     success path would fail.
  {
    const r = runIntercepted(four("ir16-empty-measured"), [{ status: 0, stdout: verdict() }]);
    const v = parseOne("ir16 measured", r.out);
    eq("withheld_reasons is [] on a MEASURED result", v.withheld_reasons, []);
  }
  {
    const v = expectNonMeasured("a pre-invocation ERROR",
      mkBundle("ir16-empty-pre", { corrupt: "artifacts/a.json" }), "manifest-digest-mismatch");
    if (v) eq("withheld_reasons is [] on a pre-invocation ERROR", v.withheld_reasons, []);
  }
  {
    const r = runIntercepted(four("ir16-empty-post"),
      [{ status: 0, stdout: verdict() }, { status: 2, stdout: "" }]);
    const v = parseOne("ir16 post-invocation error", r.out);
    eq("withheld_reasons is [] on a post-invocation ERROR", v.withheld_reasons, []);
  }

  // (b) THE PINNED ENTRY SHAPE. Exactly three members, ONE ENTRY PER REASON
  //     STRING, and the reason VERBATIM.
  {
    const plan = [
      { status: 0, stdout: verdict(["zeta-reason", "alpha-reason"]) },
      { status: 0, stdout: verdict(["alpha-reason"]) },
      { status: 0, stdout: verdict() },
      { status: 0, stdout: verdict() },
    ];
    const r = runIntercepted(four("ir16-shape"), plan);
    eq("a withheld channel makes the scenario MEASUREMENT_INVALID", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir16 shape", r.out);
      eq("its reason is authenticated-withheld",
        v.nonmeasurement.reason, "authenticated-withheld");
      eq("ONE ENTRY PER REASON STRING, not one per channel", v.withheld_reasons.length, 3);
      for (const w of v.withheld_reasons) {
        eq(`${w.artifact_path}/${w.reason}: exactly the pinned members`,
          Object.keys(w).sort(), ["artifact_path", "channel", "reason"]);
        check(`${w.artifact_path}/${w.reason}: reason is a string, never an array`,
          typeof w.reason === "string", show(w.reason));
      }
      // The superseded shape, named so a regression is legible.
      check("no entry carries the superseded artifact_ref member",
        v.withheld_reasons.every((w) => !("artifact_ref" in w)), show(v.withheld_reasons));
      check("no entry carries the superseded array-valued `reasons` member",
        v.withheld_reasons.every((w) => !("reasons" in w)), show(v.withheld_reasons));

      // (c) ORDER: (artifact_path, channel, reason) in UTF-8 byte order. The
      //     fixture emits "zeta" BEFORE "alpha" inside one channel, so emission
      //     order and sorted order genuinely disagree.
      const key = (w) => `${w.artifact_path} ${w.channel} ${w.reason}`;
      const sorted = [...v.withheld_reasons].sort((x, y) => byteCompare(key(x), key(y)));
      eq("withheld_reasons is ordered by (artifact_path, channel, reason)",
        v.withheld_reasons.map(key), sorted.map(key));
      eq("and the fixture really did emit them out of order, so the sort is measured",
        v.withheld_reasons[0].reason, "alpha-reason");
      // Reasons are VERBATIM: an evaluator that paraphrases has substituted its
      // own text for a measurement.
      check("every reason string appears verbatim",
        v.withheld_reasons.every((w) => ["zeta-reason", "alpha-reason"].includes(w.reason)),
        show(v.withheld_reasons));
    }
  }

  // (d) BOTH CHANNEL NAMES are carried verbatim, and witnessed_withheld does
  //     NOT make the scenario measurement-invalid -- W1 carries no witness, so
  //     no-witness-supplied is an ordinary diagnostic surface.
  {
    const wit = JSON.stringify({
      artifact_ref: { chain_id: "c", record_id: "r" },
      class: "AIREP-Core", observer_assessment: "not_applicable",
      authenticated_failures: [], authenticated_withheld: [], authenticated_caveats: [],
      witnessed_failures: [], witnessed_withheld: ["no-witness-supplied"],
    });
    const r = runIntercepted(four("ir16-witnessed"), [{ status: 0, stdout: wit }]);
    eq("a witnessed_withheld channel alone is still MEASURED", r.code, 0);
    if (r.code === 0) {
      const v = parseOne("ir16 witnessed", r.out);
      eq("the scenario is MEASURED", v.measurement_status, "MEASURED");
      eq("and all four channels are reported", v.withheld_reasons.length, 4);
      check("the channel name is carried verbatim",
        v.withheld_reasons.every((w) => w.channel === "witnessed_withheld"),
        show(v.withheld_reasons));
    }
  }

  // (e) E8-1 -- A FATAL STAGE-11 RESULT DOES NOT ERASE CHANNELS ALREADY
  //     OBSERVED. withheld_reasons on EVERY result-bearing path is the
  //     projection of the accepted verdicts ACTUALLY RETAINED in artifacts[]
  //     before termination.
  //
  //     The fixture: artifact 1 exits 0 with an accepted verdict carrying a
  //     withheld channel; artifact 2 exits 2, which is a fatal run and aborts
  //     the scenario at stage 11. AD15-IR-10 makes the reported outcome the
  //     ERROR rather than the withheld tier -- but that orders the REPORTED
  //     REASON, not what may be discarded. The channel from artifact 1 is
  //     evidence of a run that genuinely happened.
  {
    const plan = [
      { status: 0, stdout: verdict(["observed-before-the-fatal-run"]) },
      { status: 2, stdout: "" },
    ];
    const r = runIntercepted(four("ir16-e81-fatal"), plan);
    eq("E8-1: the fatal stage-11 run exits 3", r.code, 3);
    eq("E8-1: exactly two invocations were attempted -- the scenario aborted", r.spawnCalls, 2);
    if (r.code === 3) {
      const v = parseOne("ir16 E8-1", r.out);
      // AD15-IR-10 still decides the reason.
      eq("E8-1: the reported reason is the RUN invalidity, not the withheld tier",
        v.nonmeasurement.reason, "verifier-run-invalid");
      eq("E8-1: and yet the earlier accepted verdict's channel is RETAINED",
        v.withheld_reasons.length, 1);
      eq("E8-1: from the artifact that was actually evaluated",
        v.withheld_reasons[0].artifact_path, "artifacts/1decision.json");
      eq("E8-1: verbatim", v.withheld_reasons[0].reason, "observed-before-the-fatal-run");
      eq("E8-1: on the pinned channel", v.withheld_reasons[0].channel, "authenticated_withheld");
      // The discriminating control: the same bundle WITHOUT the withheld channel
      // reports [] for the same fatal run, so the entry above is attributable to
      // the channel and not to the abort.
      const r2 = runIntercepted(four("ir16-e81-control"),
        [{ status: 0, stdout: verdict() }, { status: 2, stdout: "" }]);
      if (r2.code === 3) {
        eq("control: the same fatal run with NO withheld channel reports []",
          JSON.parse(r2.out).withheld_reasons, []);
      }
    }
  }

  // (f) E8-1, second half -- A MALFORMED OR GATE-REJECTED OUTPUT CONTRIBUTES
  //     NONE, because it is not an ACCEPTED verdict. This is the half that
  //     separates "a verdict was emitted" from "a verdict was accepted": the
  //     rejected object below CARRIES a populated authenticated_withheld
  //     channel, and it must not reach withheld_reasons.
  {
    const rejected = JSON.stringify({
      // E8-3 gate violation: an extra member in the closed artifact_ref object.
      artifact_ref: { chain_id: "c", record_id: "r", extra: 1 },
      class: "AIREP-Core", observer_assessment: "not_applicable",
      authenticated_failures: [], authenticated_withheld: ["must-not-be-reported"],
      authenticated_caveats: [], witnessed_failures: [], witnessed_withheld: [],
    });
    const r = runIntercepted(four("ir16-gate-rejected"), [{ status: 0, stdout: rejected }]);
    eq("E8-1: a gate-rejected exit-0 output exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir16 gate-rejected", r.out);
      eq("E8-1: its reason is verifier-run-invalid", v.nonmeasurement.reason,
        "verifier-run-invalid");
      eq("E8-1: a GATE-REJECTED output contributes NO withheld reason",
        v.withheld_reasons, []);
      check("E8-1: and its channel text does not appear anywhere in the result",
        !/must-not-be-reported/.test(r.out), r.out.slice(0, 400));
      // Control: the SAME channel on a verdict the gate ACCEPTS is reported, so
      // the [] above is attributable to the rejection and not to the channel.
      const accepted = JSON.stringify({
        artifact_ref: { chain_id: "c", record_id: "r" },
        class: "AIREP-Core", observer_assessment: "not_applicable",
        authenticated_failures: [], authenticated_withheld: ["must-not-be-reported"],
        authenticated_caveats: [], witnessed_failures: [], witnessed_withheld: [],
      });
      const r2 = runIntercepted(four("ir16-gate-accepted"), [{ status: 0, stdout: accepted }]);
      if (r2.code === 3) {
        const v2 = JSON.parse(r2.out);
        eq("control: the same channel on an ACCEPTED verdict IS reported",
          v2.withheld_reasons.length, 4);
        eq("control: and the scenario is MEASUREMENT_INVALID, not a run failure",
          v2.measurement_status, "MEASUREMENT_INVALID");
      }
    }
  }

  // (g) A MALFORMED output -- stdout that is not a verdict at all -- likewise
  //     contributes none. The gate-rejection case above is the subtler half;
  //     this is the one an implementation reading channels off raw stdout would
  //     fail.
  {
    const r = runIntercepted(four("ir16-malformed"),
      [{ status: 0, stdout: '{"authenticated_withheld":["scraped-from-stdout"]}' }]);
    eq("E8-1: a malformed exit-0 output exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir16 malformed", r.out);
      eq("E8-1: a MALFORMED output contributes NO withheld reason", v.withheld_reasons, []);
      check("E8-1: nothing was scraped out of the rejected stdout",
        !/scraped-from-stdout/.test(r.out), r.out.slice(0, 400));
    }
  }

  // (h) "[] means no withheld reason was OBSERVED AMONG THE ACCEPTED VERDICTS
  //     ACTUALLY OBTAINED -- it says nothing about invocations never reached."
  //     A spawn failure on artifact 1 reaches no verdict at all, so [] here is
  //     the absence of an observation, and the block says so explicitly rather
  //     than letting [] be read as "nothing is withheld in this bundle".
  {
    const r = runIntercepted(four("ir16-never-reached"), [{ spawnFails: true }]);
    eq("E8-1: a spawn failure on the first artifact exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("ir16 never reached", r.out);
      eq("E8-1: no accepted verdict was obtained, so withheld_reasons is []",
        v.withheld_reasons, []);
      eq("E8-1: and artifacts[] is empty, so [] is not a claim about the bundle",
        v.artifacts, []);
    }
  }
}
endBlock("W1-BLK-IR16");

// --- W1-BLK-ARTIFACT-REF: AD15-IR-18, the projection and its three sources --
//
// Two halves, kept apart because the frozen schema makes the full cross-product
// unbuildable (E7-SR-8): common.schema.json requires record_id and chain_id to
// be strings in artifact_core, so a schema-invalid ID can never produce an
// exit-0 verdict. Only `schema-invalid x Source A` is excluded; everything else
// remains required, through Source B.
beginBlock("W1-BLK-ARTIFACT-REF");
{
  // (1) THE PROJECTION FUNCTION, over the FULL value matrix, with no
  //     requirement that the value could ever yield a frozen verdict.
  const VALUES = [
    ["absent", undefined], ["null", null], ["boolean", true], ["number", 7],
    ["empty string", ""], ["non-empty string", "x"],
  ];
  let matrixCells = 0;
  for (const [rn, rv] of VALUES) {
    for (const [cn, cv] of VALUES) {
      const value = {};
      if (rn !== "absent") value.record_id = rv;
      if (cn !== "absent") value.chain_id = cv;
      const got = artifactRefFromArtifact(value);
      matrixCells++;
      if (typeof rv !== "string") {
        // Step 2: a non-string record_id gives null, whatever chain_id is.
        eq(`projection(record_id=${rn}, chain_id=${cn}) is null`, got, null);
        continue;
      }
      const want = typeof cv === "string" ? { record_id: rv, chain_id: cv } : { record_id: rv };
      eq(`projection(record_id=${rn}, chain_id=${cn})`, got, want);
      // Step 4: a missing or non-string chain_id is OMITTED, NEVER null. An
      // omitted member and a null member are different JSON values and
      // therefore different RFC 8785 canonical bytes, which is what duty 6
      // compares.
      if (typeof cv !== "string") {
        check(`projection(record_id=${rn}, chain_id=${cn}) OMITS chain_id rather than nulling it`,
          !("chain_id" in got), show(got));
      }
    }
  }
  eq("the full 6x6 value matrix was exercised", matrixCells, 36);
  // Step 1: not a JSON object at all.
  for (const [name, value] of [["null", null], ["an array", [1, 2]], ["a string", "x"],
    ["a number", 7], ["a boolean", false]]) {
    eq(`projection over ${name} is null`, artifactRefFromArtifact(value), null);
  }
  // Step 5: empty strings remain strings; no minLength rule is invented.
  eq("an empty record_id is a string and survives",
    artifactRefFromArtifact({ record_id: "", chain_id: "" }), { record_id: "", chain_id: "" });
  // Step 6: no coercion, normalization, case mapping, repair or synthesis.
  eq("no Unicode normalization is applied",
    artifactRefFromArtifact({ record_id: "e" + String.fromCharCode(0x301) }).record_id,
    "e" + String.fromCharCode(0x301));
  eq("no case mapping is applied",
    artifactRefFromArtifact({ record_id: "AbC" }).record_id, "AbC");
  eq("a numeric record_id is NOT stringified into acceptance",
    artifactRefFromArtifact({ record_id: 12 }), null);

  // (2) SOURCE A -- the accepted exit-0 verdict, copied VERBATIM.
  {
    const r = runIntercepted(four("aref-sourceA"),
      [{ status: 0, stdout: verdict([], { chain_id: "VC", record_id: "VR" }) }]);
    eq("Source A: a clean run exits 0", r.code, 0);
    if (r.code === 0) {
      const v = parseOne("Source A", r.out);
      for (const e of v.artifacts) {
        eq(`${e.artifact_path}: artifact_ref is the VERDICT's, copied verbatim`,
          e.artifact_ref, { chain_id: "VC", record_id: "VR" });
      }
      // The discrimination: the artifacts' own record_ids are r-dec/r-ctl/...,
      // so a lane emitting the preliminary projection here would differ.
      check("Source A: it is NOT the preliminary projection over the artifact",
        v.artifacts.every((e) => e.artifact_ref.record_id !== "r-dec"),
        show(v.artifacts.map((e) => e.artifact_ref)));
    }
  }
  // SOURCE A NEGATIVE GATE. A verdict whose artifact_ref carries an extra
  // member is verifier-run-invalid, NOT a verbatim copy. This is a gate W1
  // ADDS: the frozen contract permits the extra member.
  {
    const bad = JSON.stringify({
      artifact_ref: { chain_id: "c", record_id: "r", extra: "smuggled" },
      class: "AIREP-Core", observer_assessment: "not_applicable",
      authenticated_failures: [], authenticated_withheld: [], authenticated_caveats: [],
      witnessed_failures: [], witnessed_withheld: [],
    });
    const r = runIntercepted(four("aref-gate"), [{ status: 0, stdout: bad }]);
    eq("Source A gate: an extra artifact_ref member exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("Source A gate", r.out);
      eq("Source A gate: the reason is verifier-run-invalid",
        v.nonmeasurement.reason, "verifier-run-invalid");
      check("Source A gate: the extra member was NOT copied into the output",
        !/smuggled/.test(r.out), r.out.slice(0, 400));
      eq("Source A gate: and the scenario aborted at that artifact", v.artifacts.length, 1);
    }
    // The gate as a pure function, so its verdict is attributable.
    check("the result-shape gate rejects an open artifact_ref",
      verdictShapeViolation(JSON.parse(bad)) !== null, show(verdictShapeViolation(JSON.parse(bad))));
    check("control: the same verdict WITHOUT the extra member is accepted",
      verdictShapeViolation(JSON.parse(verdict())) === null);
  }

  // E8-3 -- THE SOURCE-A GATE IN FULL. A BEHAVIOURAL CHANGE IN THIS LANE: the
  // superseded gate was CLOSED but neither REQUIRED nor TYPED, so an ABSENT
  // artifact_ref, a NULL one, and one with no record_id were all accepted and
  // silently converted to null on the emitted entry. This lane read it that
  // way; the peer lane did not; artifact_ref is Class-1.
  //
  // EVERY one of the six rejections the ruling names is exercised, on the pure
  // gate AND end to end, because a gate that is correct but never consulted
  // would pass a pure-function-only test.
  {
    const withRef = (ref, omit = false) => {
      const v = {
        artifact_ref: ref,
        class: "AIREP-Core", observer_assessment: "not_applicable",
        authenticated_failures: [], authenticated_withheld: [], authenticated_caveats: [],
        witnessed_failures: [], witnessed_withheld: [],
      };
      if (omit) delete v.artifact_ref;
      return v;
    };
    const rejections = [
      ["absent", withRef(undefined, true)],
      ["null", withRef(null)],
      ["a non-object (string)", withRef("r")],
      ["a non-object (array)", withRef([])],
      ["a missing record_id", withRef({ chain_id: "c" })],
      ["a non-string record_id", withRef({ record_id: 12, chain_id: "c" })],
      ["a null record_id", withRef({ record_id: null, chain_id: "c" })],
      ["a non-string chain_id", withRef({ record_id: "r", chain_id: 12 })],
      ["a null chain_id", withRef({ record_id: "r", chain_id: null })],
      ["an extra member", withRef({ record_id: "r", chain_id: "c", extra: "smuggled" })],
    ];
    for (const [name, v] of rejections) {
      check(`E8-3: the gate rejects an artifact_ref that is ${name}`,
        verdictShapeViolation(v) !== null, `${name} was accepted`);
      // End to end: verifier-run-invalid, and NOT a repair.
      const dir = mkBundle(`aref-e83-${name.replace(/[^a-z0-9]+/gi, "-")}`, {
        scenarioId: "IOP-P-DEC",
        artifacts: { "artifacts/a.json":
          '{"airep_version":"0.2","artifact_type":"decision","record_id":"prelim","chain_id":"pc"}' },
      });
      const r = runIntercepted(dir, [{ status: 0, stdout: JSON.stringify(v) }]);
      eq(`E8-3 (${name}): exits 3`, r.code, 3);
      if (r.code === 3) {
        const out = parseOne(`E8-3 ${name}`, r.out);
        eq(`E8-3 (${name}): the reason is verifier-run-invalid`,
          out.nonmeasurement.reason, "verifier-run-invalid");
        // E8-4, on the same fixture and for every rejection route: the entry
        // stands, the exit code is 0 verbatim, the result is null, and the ref
        // is the Source-B preliminary projection.
        eq(`E8-3/E8-4 (${name}): verifier_exit_code is 0, verbatim`,
          out.artifacts[0].verifier_exit_code, 0);
        eq(`E8-3/E8-4 (${name}): verifier_result is null -- the object is NOT a verdict`,
          out.artifacts[0].verifier_result, null);
        eq(`E8-3/E8-4 (${name}): artifact_ref is the Source-B preliminary projection`,
          out.artifacts[0].artifact_ref, { chain_id: "pc", record_id: "prelim" });
        check(`E8-3 (${name}): nothing was repaired or coerced into acceptance`,
          !/smuggled/.test(r.out), r.out.slice(0, 400));
      }
    }
    // ACCEPTANCE CONTROLS. Without them the block would pass on a gate that
    // rejected every verdict, and the two legal shapes -- with and without
    // chain_id -- are separately reachable.
    check("control: { record_id } alone is ACCEPTED -- chain_id is optional",
      verdictShapeViolation(withRef({ record_id: "r" })) === null);
    check("control: { record_id, chain_id } is ACCEPTED",
      verdictShapeViolation(withRef({ record_id: "r", chain_id: "c" })) === null);
    check("control: an EMPTY-STRING record_id is a string and is ACCEPTED -- no minLength "
      + "rule is added that the frozen schema does not have",
      verdictShapeViolation(withRef({ record_id: "" })) === null);
    {
      const dir = mkBundle("aref-e83-accepted", {
        scenarioId: "IOP-P-DEC",
        artifacts: { "artifacts/a.json":
          '{"airep_version":"0.2","artifact_type":"decision","record_id":"prelim","chain_id":"pc"}' },
      });
      const r = runIntercepted(dir,
        [{ status: 0, stdout: JSON.stringify(withRef({ record_id: "VR" })) }]);
      eq("control: an accepted verdict with a legal artifact_ref is MEASURED", r.code, 0);
      if (r.code === 0) {
        const out = JSON.parse(r.out);
        eq("control: and its artifact_ref is the VERDICT's, copied verbatim -- with chain_id "
          + "OMITTED rather than nulled", out.artifacts[0].artifact_ref, { record_id: "VR" });
      }
    }
  }

  // (3) SOURCE B -- every OTHER emitted entry. Defined by EXCLUSION, not by an
  //     enumeration: an outcome list is what made the exclusivity error
  //     possible in the first place (E7-SR-9).
  //
  //     SCHEMA-INVALID IDs are required on AT LEAST THREE DISTINCT Source-B
  //     paths. These cells are reachable because stage-0 schema validity gates
  //     the VERDICT, not the ENTRY.
  const SCHEMA_INVALID = JSON.stringify({
    airep_version: "0.2", artifact_type: "decision", record_id: 12, chain_id: false,
  });
  eq("control: the projection over the schema-invalid artifact is null",
    artifactRefFromArtifact(JSON.parse(SCHEMA_INVALID)), null);

  const sourceBPaths = [];

  // B-1: a QUALIFYING stage-0 exit 1 (IOP-B-CTL), against the GENUINE frozen
  //      verifier -- the artifact really does fail stage 0 there.
  if (fs.existsSync(VERIFIER) && fs.existsSync(VERIFIER_DEPS)) {
    const dir = mkBundle("aref-B1-qualifying", {
      scenarioId: "IOP-B-CTL", artifacts: { "artifacts/a.json": SCHEMA_INVALID },
    });
    const r = run(["--bundle", dir]);
    eq("Source B-1: a qualifying stage-0 exit 1 is MEASURED as REJECT", r.code, 0);
    if (r.code === 0) {
      const v = parseOne("Source B-1", r.out);
      eq("Source B-1: level1 is REJECT", v.level1, "REJECT");
      eq("Source B-1: no verdict exists", v.artifacts[0].verifier_result, null);
      eq("Source B-1: artifact_ref is the projection -- null for a schema-invalid ID",
        v.artifacts[0].artifact_ref, null);
      check("Source B-1: nothing was synthesized to fill it",
        !/record_id/.test(r.out), r.out.slice(0, 400));
      sourceBPaths.push("qualifying stage-0 exit 1");
    }
  } else {
    skip("W1-BLK-ARTIFACT-REF Source B-1 (live qualifying stage-0 exit 1)",
      "the frozen verifier or its node_modules is not materialized");
  }

  // B-2: a NON-QUALIFYING exit 1. Section 7.2 admits only IOP-B-DEC, IOP-B-CTL
  //      and IOP-B-EFF, so the SAME artifact under any other scenario lands
  //      here as verifier-run-invalid. This is the cell the superseded
  //      "only the qualifying stage-0 exit 1" correction dropped.
  {
    const dir = mkBundle("aref-B2-nonqualifying", {
      scenarioId: "IOP-P-DEC", artifacts: { "artifacts/a.json": SCHEMA_INVALID },
    });
    const r = runIntercepted(dir, [{ status: 1, stdout: "" }]);
    eq("Source B-2: a non-qualifying exit 1 exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("Source B-2", r.out);
      eq("Source B-2: reason", v.nonmeasurement.reason, "verifier-run-invalid");
      eq("Source B-2: the entry exists", v.artifacts.length, 1);
      eq("Source B-2: artifact_ref is the projection -- null", v.artifacts[0].artifact_ref, null);
      sourceBPaths.push("non-qualifying exit 1");
    }
  }

  // B-3: ABNORMAL TERMINATION, which can occur BEFORE the frozen verifier
  //      reaches stage 0 at all and therefore carries ANY artifact.
  {
    const dir = mkBundle("aref-B3-abnormal", {
      scenarioId: "IOP-P-DEC", artifacts: { "artifacts/a.json": SCHEMA_INVALID },
    });
    const r = runIntercepted(dir, [{ signal: "SIGKILL" }]);
    eq("Source B-3: abnormal termination exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("Source B-3", r.out);
      eq("Source B-3: reason", v.nonmeasurement.reason, "verifier-run-invalid");
      eq("Source B-3: the entry exists", v.artifacts.length, 1);
      eq("Source B-3: artifact_ref is the projection -- null", v.artifacts[0].artifact_ref, null);
      eq("Source B-3: with no exit code", v.artifacts[0].verifier_exit_code, null);
      sourceBPaths.push("abnormal termination");
    }
  }

  // B-4: exit 2, which emits no verdict.
  {
    const dir = mkBundle("aref-B4-exit2", {
      scenarioId: "IOP-P-DEC", artifacts: { "artifacts/a.json": SCHEMA_INVALID },
    });
    const r = runIntercepted(dir, [{ status: 2, stdout: "" }]);
    if (r.code === 3) {
      const v = parseOne("Source B-4", r.out);
      eq("Source B-4: exit 2 emits an entry with a null artifact_ref",
        v.artifacts[0].artifact_ref, null);
      eq("Source B-4: and an integer exit code, because it exited normally",
        v.artifacts[0].verifier_exit_code, 2);
      sourceBPaths.push("exit 2");
    }
  }

  // B-5: exit 0 whose output the result-shape gate REJECTS. The entry is
  //      emitted with the preliminary projection, because no verdict was
  //      accepted -- which is what "Source B is everything that is not an
  //      ACCEPTED exit-0 verdict" means.
  {
    const dir = mkBundle("aref-B5-badshape", {
      scenarioId: "IOP-P-DEC",
      artifacts: { "artifacts/a.json":
        '{"airep_version":"0.2","artifact_type":"decision","record_id":"kept","chain_id":"kc"}' },
    });
    const r = runIntercepted(dir, [{ status: 0, stdout: '{"class":"AIREP-Core"}' }]);
    eq("Source B-5: a rejected exit-0 shape exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("Source B-5", r.out);
      eq("Source B-5: reason", v.nonmeasurement.reason, "verifier-run-invalid");
      eq("Source B-5: artifact_ref is the PRELIMINARY projection, not the rejected verdict's",
        v.artifacts[0].artifact_ref, { chain_id: "kc", record_id: "kept" });
      eq("Source B-5: and verifier_result is null, because none was accepted",
        v.artifacts[0].verifier_result, null);
      sourceBPaths.push("rejected exit-0 shape");
    }
  }

  check("schema-invalid IDs were measured on at least THREE distinct Source-B paths",
    sourceBPaths.filter((x) => x !== "rejected exit-0 shape").length >= 3, show(sourceBPaths));

  // (4) SOURCE C -- no entry at all, therefore no artifact_ref.
  {
    const r = runIntercepted(four("aref-sourceC"), [{ spawnFails: true }]);
    eq("Source C: a spawn failure exits 3", r.code, 3);
    if (r.code === 3) {
      const v = parseOne("Source C", r.out);
      eq("Source C: there is NO entry, so there is no artifact_ref", v.artifacts, []);
    }
  }
  {
    const v = expectNonMeasured("Source C: a pre-invocation failure",
      mkBundle("aref-sourceC-pre", { corrupt: "artifacts/a.json" }), "manifest-digest-mismatch");
    if (v) eq("Source C: a pre-invocation failure emits no entries", v.artifacts, []);
  }
}
endBlock("W1-BLK-ARTIFACT-REF");

// --- W1-BLK-PARITY: the four-class model and the duty-6 projection ---------
//
// THIS BLOCK IS PER-LANE AND MUST BE EXECUTABLE WITHOUT PEER MATERIAL. The real
// cross-lane comparison is aggregate-harness duty 6, which sees both trees;
// section 4 forbids a lane's runner from seeing its peer, so a lane-local block
// demanding a Python-versus-Node comparison would be unsatisfiable except by
// breaking isolation. As first written, W1-BLK-PARITY demanded exactly that,
// and also demanded an inequality of the two lanes' stderr digests that the
// frozen sources make impossible -- both frozen verifiers write stderr only in
// their usage-error and invalid branches, so on a normal verdict both digests
// are SHA-256 of the empty byte string. NEITHER is asserted here.
//
// What this lane proves ALONE is that the model SEPARATES THE CLASSES, which is
// peer-safe because it is a property of the projection, not of the peer.
beginBlock("W1-BLK-PARITY");
{
  // Two real results, so the block covers both the MEASURED and the ERROR
  // shapes -- the second is where nonmeasurement.reason and json_pointer live.
  const measured = JSON.parse(
    runIntercepted(four("parity-measured"), [{ status: 0, stdout: verdict() }]).out);
  const errored = JSON.parse(run(["--bundle", mkBundle("parity-errored", {
    artifacts: { "artifacts/a.json":
      '{"record_id":"r","chain_id":"c","artifact_type":"decision","p":1e300}' },
  })]).out);
  eq("control: the MEASURED fixture really is MEASURED", measured.measurement_status, "MEASURED");
  eq("control: the ERROR fixture really carries a json_pointer",
    typeof errored.nonmeasurement.json_pointer, "string");

  const clone = (v) => JSON.parse(JSON.stringify(v));
  const proj = (v) => projectionBytes(v);

  for (const [label, base] of [["MEASURED", measured], ["ERROR", errored]]) {
    // (a) THE PROJECTION IS INVARIANT under Class-3 and Class-2 substitution.
    //     This is the half a passing cross-lane comparison never exercises.
    if (base.artifacts.length > 0) {
      const c3 = clone(base);
      c3.artifacts[0].verifier_stderr_digest = "sha256:" + "0".repeat(64);
      eq(`${label}: replacing verifier_stderr_digest (Class 3) does NOT move the projection`,
        proj(c3), proj(base));
    }
    {
      const c2 = clone(base);
      if (c2.verifier_digests !== null) {
        c2.verifier_digests.class_verifier = "sha256:" + "1".repeat(64);
        eq(`${label}: replacing verifier_digests.class_verifier (Class 2) does NOT move it`,
          proj(c2), proj(base));
      }
      const c2b = clone(base);
      c2b.evaluator_version = "some_other_lane/9.9.9";
      eq(`${label}: replacing evaluator_version (Class 2) does NOT move it`,
        proj(c2b), proj(base));
    }
    {
      const c4 = clone(base);
      if (c4.nonmeasurement !== null) {
        c4.nonmeasurement.detail = "an entirely different human sentence";
        eq(`${label}: replacing nonmeasurement.detail (Class 4) does NOT move it`,
          proj(c4), proj(base));
      }
    }

    // (b) THE PROJECTION MOVES under ANY Class-1 change. Every top-level and
    //     nested normative field is mutated INDIVIDUALLY and the outcome
    //     recorded, so a field that is silently uncompared shows up as a
    //     mutation that did not move the projection.
    const mutations = [
      ["scenario_id", (v) => { v.scenario_id = "IOP-R-XREF"; }],
      ["measurement_status", (v) => { v.measurement_status = "ERROR"; }],
      ["level1", (v) => { v.level1 = v.level1 === null ? "ACCEPT" : null; }],
      ["predicates", (v) => {
        v.predicates = v.predicates === null
          ? { R_A: "PASS", R_B: "PASS", R_C: "PASS" } : null;
      }],
      ["withheld_reasons", (v) => {
        v.withheld_reasons = [{ artifact_path: "artifacts/a.json",
          channel: "authenticated_withheld", reason: "invented" }];
      }],
      ["verifier_digests.class_verifier_contract", (v) => {
        if (v.verifier_digests !== null) {
          v.verifier_digests.class_verifier_contract = "sha256:" + "2".repeat(64);
        }
      }],
      ["nonmeasurement.reason", (v) => {
        if (v.nonmeasurement !== null) v.nonmeasurement.reason = "internal-error";
      }],
      ["nonmeasurement.json_pointer", (v) => {
        if (v.nonmeasurement !== null && "json_pointer" in v.nonmeasurement) {
          v.nonmeasurement.json_pointer = "/somewhere/else";
        }
      }],
      ["artifacts[] membership", (v) => { v.artifacts = v.artifacts.slice(1); }],
      ["artifacts[] order", (v) => { v.artifacts = [...v.artifacts].reverse(); }],
      ["artifact_path", (v) => {
        if (v.artifacts.length > 0) v.artifacts[0].artifact_path = "artifacts/zzz.json";
      }],
      ["artifact_ref", (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].artifact_ref = v.artifacts[0].artifact_ref === null
            ? { record_id: "invented" } : null;
        }
      }],
      ["request_envelope_digest", (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].request_envelope_digest = "sha256:" + "3".repeat(64);
        }
      }],
      ["verifier_exit_code", (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].verifier_exit_code =
            v.artifacts[0].verifier_exit_code === 0 ? 1 : 0;
        }
      }],
      ["verifier_result", (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].verifier_result = v.artifacts[0].verifier_result === null
            ? JSON.parse(verdict()) : null;
        }
      }],
    ];
    for (const [name, mutate] of mutations) {
      const m = clone(base);
      mutate(m);
      if (JSON.stringify(m) === JSON.stringify(base)) continue;   // not applicable to this shape
      check(`${label}: mutating ${name} (Class 1) MOVES the projection`,
        proj(m) !== proj(base), `${name} was not detected`);
    }
    // Named explicitly, because it is the field the earlier surface omitted
    // ENTIRELY -- a run where the two lanes disagreed on the scenario label
    // would have passed every duty.
    {
      const m = clone(base);
      m.scenario_id = "IOP-R-XREF";
      check(`${label}: a scenario_id mutation MUST be detected`, proj(m) !== proj(base));
    }
  }

  // (c) THE PROJECTION IS THE CLOSED MEMBER SET. An unknown member at any
  //     closed level is INVALID, not silently dropped -- otherwise a lane could
  //     smuggle an uncompared field into a result that still passed duty 6.
  for (const [where, mutate] of [
    ["the result object", (v) => { v.smuggled = 1; }],
    ["nonmeasurement", (v) => { if (v.nonmeasurement !== null) v.nonmeasurement.smuggled = 1; }],
    ["predicates", (v) => { if (v.predicates !== null) v.predicates.R_D = "PASS"; }],
    ["verifier_digests", (v) => {
      if (v.verifier_digests !== null) v.verifier_digests.peer_lane = "sha256:x";
    }],
    ["an artifacts[] entry", (v) => { if (v.artifacts.length > 0) v.artifacts[0].smuggled = 1; }],
    ["artifact_ref", (v) => {
      if (v.artifacts.length > 0 && v.artifacts[0].artifact_ref !== null) {
        v.artifacts[0].artifact_ref.smuggled = 1;
      }
    }],
    ["a withheld_reasons entry", (v) => {
      v.withheld_reasons = [{ artifact_path: "a", channel: "authenticated_withheld",
        reason: "r", smuggled: 1 }];
    }],
  ]) {
    for (const base of [measured, errored]) {
      const m = clone(base);
      mutate(m);
      if (JSON.stringify(m) === JSON.stringify(base)) continue;
      check(`an unknown member in ${where} makes the result unprojectable`,
        resultShapeViolation(m) !== null, `${where} was accepted`);
      let threw = false;
      try { normativeProjection(m); } catch { threw = true; }
      check(`and projecting it REFUSES rather than dropping the member`, threw);
    }
  }
  // Control: the real results ARE closed, so the checks above are about the
  // added member and not about some pre-existing shape defect.
  eq("control: the MEASURED result is closed", resultShapeViolation(measured), null);
  eq("control: the ERROR result is closed", resultShapeViolation(errored), null);
  eq("control: the pinned result member set matches the evaluator's own",
    [...EVAL_RESULT_MEMBERS].sort(), [...RESULT_MEMBERS].sort());

  // (d) THE REMOVED SET IS EXACTLY FOUR MEMBERS, and everything else is
  //     retained -- including verifier_digests.class_verifier_contract, which
  //     the two lanes MUST assert identically.
  {
    const p = normativeProjection(measured);
    check("evaluator_version is removed from the projection", !("evaluator_version" in p));
    check("verifier_digests.class_verifier is removed",
      p.verifier_digests !== null && !("class_verifier" in p.verifier_digests));
    check("verifier_digests.class_verifier_contract is RETAINED",
      p.verifier_digests !== null && "class_verifier_contract" in p.verifier_digests);
    check("verifier_stderr_digest is removed from every entry",
      p.artifacts.every((e) => !("verifier_stderr_digest" in e)));
    check("every other artifacts[] member is retained",
      p.artifacts.every((e) => ["artifact_path", "artifact_ref", "request_envelope_digest",
        "verifier_exit_code", "verifier_result"].every((k) => k in e)));
    const pe = normativeProjection(errored);
    check("nonmeasurement.detail is removed", !("detail" in pe.nonmeasurement));
    check("nonmeasurement.reason is RETAINED", "reason" in pe.nonmeasurement);
    check("nonmeasurement.json_pointer is RETAINED", "json_pointer" in pe.nonmeasurement);
  }

  // (e) EQUALITY IS OF THE CLOSED JSON VALUE, operationalized through RFC 8785
  //     canonical bytes -- so member order, whitespace and number spelling
  //     cannot make two equal values compare unequal, nor two unequal values
  //     compare equal.
  {
    const reordered = JSON.parse(JSON.stringify(measured));
    const shuffled = {};
    for (const k of Object.keys(reordered).reverse()) shuffled[k] = reordered[k];
    eq("member order does not move the canonical projection bytes",
      projectionBytes(shuffled), projectionBytes(measured));
    check("and the two objects really did have different member order",
      JSON.stringify(shuffled) !== JSON.stringify(measured));
  }

  // (f) PEER-SAFETY, asserted POSITIVELY. An earlier draft of this check read
  //     this file's own source looking for the peer lane's name -- which the
  //     check itself then contained, so it could never pass. The property is
  //     asserted on what the block DOES instead:
  //
  //     1. the projection is a function of ONE result. It has no parameter
  //        through which a peer result could arrive, so a lane-local
  //        cross-lane comparison is not merely unwritten, it is unexpressible;
  //     2. the block demands NO inequality of the two lanes' stderr digests.
  //        The positive form of that is the case the unsatisfiable draft would
  //        have failed: both frozen verifiers write stderr only in their
  //        usage-error and invalid branches, so on a normal verdict every
  //        stderr digest is SHA-256 of the EMPTY BYTE STRING -- identical
  //        within a lane and across the pair. That must be accepted.
  eq("the projection takes exactly one result, so no peer result can reach it",
    normativeProjection.length, 1);
  eq("and so does the byte form", projectionBytes.length, 1);
  {
    const EMPTY_DIGEST = "sha256:" + sha(Buffer.alloc(0));
    check("control: a clean intercepted run really does produce empty-stderr digests",
      measured.artifacts.every((e) => e.verifier_stderr_digest === EMPTY_DIGEST),
      show(measured.artifacts.map((e) => e.verifier_stderr_digest)));
    check("identical stderr digests across every entry are ACCEPTED, not a failure",
      resultShapeViolation(measured) === null);
    const same = clone(measured);
    for (const e of same.artifacts) e.verifier_stderr_digest = EMPTY_DIGEST;
    eq("and forcing them all equal does not move the projection either",
      proj(same), proj(measured));
  }

  // (f) THE RECORDED CLASSIFICATION. Section 8.7 requires this block to mutate
  //     EACH TOP-LEVEL AND NESTED RESULT FIELD INDIVIDUALLY and RECORD, for
  //     each, which of four things the mutation causes:
  //
  //       - cross-lane projection failure   (Class 1)
  //       - lane-local pin failure          (Class 2)
  //       - audit-evidence failure          (Class 3)
  //       - legitimately diagnostic-only    (Class 4)
  //
  //     The checks above prove the first and the negatives; what was missing was
  //     the ENUMERATION -- a field with no row is a field nobody classified.
  //     Class 2, 3 and 4 are asserted NOT to move the projection, which is the
  //     half of the model a passing cross-lane comparison never exercises.
  {
    const CLASSIFY = [
      // Class 1 -- cross-lane equality fields.
      ["scenario_id", 1, (v) => { v.scenario_id = "IOP-R-XREF"; }],
      ["measurement_status", 1, (v) => {
        v.measurement_status = v.measurement_status === "MEASURED" ? "ERROR" : "MEASURED"; }],
      ["level1", 1, (v) => { v.level1 = v.level1 === null ? "REJECT" : null; }],
      ["predicates", 1, (v) => {
        v.predicates = v.predicates === null
          ? { R_A: "PASS", R_B: "PASS", R_C: "PASS" }
          : { ...v.predicates, R_A: v.predicates.R_A === "PASS" ? "FAIL" : "PASS" }; }],
      ["nonmeasurement.reason", 1, (v) => {
        if (v.nonmeasurement !== null) v.nonmeasurement.reason = "internal-error"; }],
      ["nonmeasurement.json_pointer", 1, (v) => {
        if (v.nonmeasurement !== null && "json_pointer" in v.nonmeasurement) {
          v.nonmeasurement.json_pointer = "/elsewhere"; } }],
      ["artifacts[] membership", 1, (v) => { v.artifacts = v.artifacts.slice(1); }],
      ["artifacts[] order", 1, (v) => { v.artifacts = [...v.artifacts].reverse(); }],
      ["artifacts[].artifact_path", 1, (v) => {
        if (v.artifacts.length > 0) v.artifacts[0].artifact_path = "artifacts/zzz.json"; }],
      ["artifacts[].artifact_ref", 1, (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].artifact_ref = v.artifacts[0].artifact_ref === null
            ? { record_id: "invented" } : null; } }],
      ["artifacts[].request_envelope_digest", 1, (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].request_envelope_digest = "sha256:" + "3".repeat(64); } }],
      ["artifacts[].verifier_exit_code", 1, (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].verifier_exit_code =
            v.artifacts[0].verifier_exit_code === 0 ? 1 : 0; } }],
      ["artifacts[].verifier_result", 1, (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].verifier_result = v.artifacts[0].verifier_result === null
            ? JSON.parse(verdict()) : null; } }],
      ["withheld_reasons", 1, (v) => {
        v.withheld_reasons = [{ artifact_path: "artifacts/a.json",
          channel: "authenticated_withheld", reason: "invented" }]; }],
      ["verifier_digests.class_verifier_contract", 1, (v) => {
        if (v.verifier_digests !== null) {
          v.verifier_digests.class_verifier_contract = "sha256:" + "2".repeat(64); } }],
      // Class 2 -- lane-local normative assertions, never compared across lanes.
      ["evaluator_version", 2, (v) => { v.evaluator_version = "other_lane/9.9.9"; }],
      ["verifier_digests.class_verifier", 2, (v) => {
        if (v.verifier_digests !== null) {
          v.verifier_digests.class_verifier = "sha256:" + "4".repeat(64); } }],
      // Class 3 -- audit-only result evidence.
      ["artifacts[].verifier_stderr_digest", 3, (v) => {
        if (v.artifacts.length > 0) {
          v.artifacts[0].verifier_stderr_digest = "sha256:" + "5".repeat(64); } }],
      // Class 4 -- diagnostic-only.
      ["nonmeasurement.detail", 4, (v) => {
        if (v.nonmeasurement !== null) v.nonmeasurement.detail = "a different wording"; }],
    ];
    const classified = new Set();
    for (const base of [measured, errored]) {
      const label = base === measured ? "MEASURED" : "ERROR";
      for (const [name, cls, mutate] of CLASSIFY) {
        const m = clone(base);
        mutate(m);
        if (JSON.stringify(m) === JSON.stringify(base)) continue;  // not present on this shape
        classified.add(name);
        const moved = proj(m) !== proj(base);
        if (cls === 1) {
          check(`${label}: ${name} is Class 1 -- the mutation MOVES the projection`, moved,
            `${name} was not detected`);
        } else {
          check(`${label}: ${name} is Class ${cls} -- the mutation does NOT move the projection`,
            !moved, `${name} moved the projection`);
        }
      }
    }
    // Every field in the closed result shape has a row. Without this the table
    // could silently omit the one field that mattered -- which is exactly how
    // scenario_id went uncompared in the first place.
    for (const top of EVAL_RESULT_MEMBERS) {
      check(`the classification table has a row reaching ${top}`,
        [...classified].some((n) => n === top || n.startsWith(`${top}.`)
          || n.startsWith(`${top}[]`)),
        `${top} is unclassified`);
    }

    // Class 2 and Class 3 are NOT "unchecked": they fail LANE-LOCALLY and as
    // AUDIT EVIDENCE respectively, which is what makes them a different class
    // rather than a licence.
    eq("Class 2 lane-local pin: evaluator_version is THIS lane's",
      /^interop_eval_node\//.test(measured.evaluator_version), true);
    eq("Class 2 lane-local pin: class_verifier is THIS lane's own frozen digest",
      measured.verifier_digests.class_verifier,
      "sha256:" + sha(fs.readFileSync(VERIFIER)));
    check("Class 3 audit evidence: verifier_stderr_digest is REQUIRED on every entry",
      measured.artifacts.every((e) => /^sha256:[0-9a-f]{64}$/.test(e.verifier_stderr_digest)),
      show(measured.artifacts.map((e) => e.verifier_stderr_digest)));
  }

  // This lane invokes ITS OWN frozen verifier, and the assertion is on the pin
  // it recomputed -- a positive statement about this tree that names no other.
  eq("this lane asserted its own frozen verifier digest",
    measured.verifier_digests.class_verifier,
    "sha256:e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4");
  eq("verifier_digests carries exactly two entries -- no third, unasserted digest",
    Object.keys(measured.verifier_digests).sort(),
    ["class_verifier", "class_verifier_contract"]);
}
endBlock("W1-BLK-PARITY");

// ---------------------------------------------------------------------------
// Summary (section 13 step 5)
// ---------------------------------------------------------------------------
// Three numbers, never two. `passed + failed` is what executed; `skipped` is
// what did not, and it is reported beside them rather than deducted from the
// denominator. A block that could not run is NOT_MEASURED -- it is neither a
// pass nor a failure, and collapsing it into either loses the one fact a reader
// needs in order to know what the count covers.
// The pinned block accounting, BEFORE the totals, because it is the one part of
// this summary that is a per-lane NORMATIVE property (section 8.7, Class 2)
// rather than a diagnostic count. Every pinned ID is listed whether it ran or
// not: an omitted block has to be VISIBLE, and a table that only shows what
// happened to execute is exactly how an omission stays invisible.
let unexecutedBlocks = 0;
console.log("");
console.log("MANDATORY BLOCK REGISTRY (pinned by the contract, not by this file):");
for (const id of MANDATORY_BLOCKS) {
  const rec = blockRecords.get(id);
  if (rec === undefined) {
    unexecutedBlocks++;
    console.log(`  NOT MEASURED  ${id} -- no execution record`);
    continue;
  }
  if (rec.state === "not-measured") {
    unexecutedBlocks++;
    console.log(`  NOT MEASURED  ${id} -- ${rec.assertions} assertion(s), block declined`);
    continue;
  }
  console.log(`  ${rec.state === "passed" ? "passed      " : "FAILED      "}${id}`
    + ` -- ${rec.assertions} assertion(s), ${rec.failures} failed`);
}
// An unknown or duplicate ID makes the run non-qualifying in its own right.
for (const v of registryViolations) console.log(`  REGISTRY VIOLATION: ${v}`);
console.log("");

if (notMeasuredBranches.length > 0) {
  console.log(`NOT MEASURED branches (${notMeasuredBranches.length}), inside blocks that ran:`);
  for (const b of notMeasuredBranches) console.log(`  ${b}`);
  console.log("");
}
console.log(`${checks - failures} passed / ${failures} failed / ${skips} skipped`);
if (skips > 0) {
  console.log(`NOT MEASURED (${skips}): ${skippedBlocks.join("; ")}`);
}

// Exit codes are kept apart so the two conditions are distinguishable by a
// caller that only sees the status:
//   1 -- something executed and FAILED;
//   2 -- everything that executed passed, but some block was NOT MEASURED.
// A failure outranks an unmeasured block: it is the stronger finding.
if (registryViolations.length > 0) {
  console.log("the block registry is violated, so the run is NON-QUALIFYING regardless of "
    + "what executed; --allow-skips does not cover this");
  process.exit(1);
}
if (failures > 0) process.exit(1);
// Section 8.7: the default mode exits non-zero if any pinned block is in the
// third state. This is checked SEPARATELY from the general skip count so that a
// missing pinned block cannot be waved through by a run that happens to have no
// other skips.
if (unexecutedBlocks > 0 && !ALLOW_SKIPS) {
  console.log(`default mode: ${unexecutedBlocks} pinned mandatory block(s) did not execute; `
    + "an official count is a claim about every block");
  process.exit(2);
}
if (skips > 0 && !ALLOW_SKIPS) {
  console.log("default mode: a skipped block is not a pass; re-run where the conditions "
    + "can be produced, or pass --allow-skips to accept a PARTIAL, NON-OFFICIAL count");
  process.exit(2);
}
