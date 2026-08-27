#!/usr/bin/env node
// AIREP v0.2 reference interop evaluator -- Node lane.
//
// Implements INTEROP_REFERENCE_EVALUATOR_CONTRACT.md (AD15-IR-2) sections 5-8.
// Bundle-level AD-03 reconciliation only: every per-artifact schema / hash /
// signature / class result is taken verbatim from the frozen Node class
// verifier, which is invoked as a subprocess and never imported, vendored,
// modified or re-implemented. Only the Node lane's verifier is ever invoked
// (contract section 3, lane-crossing prohibition).
//
// Explicitly NOT implemented, by ruling AD15-IR-4: cross-lane envelope-digest
// comparison. A single invocation cannot observe the other lane's digest; this
// program emits only its own, and the aggregate harness compares them.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// 0. Constants
// ---------------------------------------------------------------------------

const EVALUATOR_VERSION = "interop_eval_node/0.1.0";

const ARTIFACT_TYPES = ["decision", "control", "execution", "effect"];

// Frozen-verifier digests, contract section 3. These are asserted before use
// and recorded in the output.
const PINNED_DIGESTS = {
  "verifier_py/class_verifier.py":
    "5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc",
  "verifier_node_r2/class_verifier.mjs":
    "e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4",
  "CLASS_VERIFIER_CONTRACT.md":
    "7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885",
};

// Contract section 7.2: frozen `exit 1` may be read as Level-1 REJECT only for
// these scenarios -- the ones whose targeted predicate IS stage-0 / stage-1
// artifact invalidity. Pinned by the contract by name; not inferred.
const EXIT1_REJECT_SCENARIOS = new Set(["IOP-B-DEC", "IOP-B-CTL", "IOP-B-EFF"]);

const MAX_SAFE_INT = 9007199254740991n;

// Committed repository layout: this file sits at
// <root>/v0.2/interop/interop_eval_node/interop_eval.mjs, the frozen Node
// verifier at <root>/v0.2/class-verification/verifier_node_r2/. Any other
// layout supplies --verifier / --verifier-contract.
// fileURLToPath, not URL.pathname: the latter is percent-encoded, so a repo
// path containing a space or a non-ASCII character would silently mis-resolve
// both the default verifier location and the direct-invocation guard below.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_VERIFIER = path.join(
  HERE, "..", "..", "class-verification", "verifier_node_r2", "class_verifier.mjs");
const DEFAULT_VERIFIER_CONTRACT = path.join(
  HERE, "..", "..", "class-verification", "CLASS_VERIFIER_CONTRACT.md");

const HEX64 = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// 1. Error kinds -- one per exit code of contract section 8.5
// ---------------------------------------------------------------------------

// exit 2: CLI usage error, stdout empty.
class UsageError extends Error {}

// exit 1: bundle/manifest preflight could not be performed, bundle identity
// unknown, or a required file absent. No result object.
class PreflightError extends Error {}

// exit 3: bundle identity WAS established, but the scenario could not be
// measured. One result object, level1 null.
class UnmeasurableError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status; // "ERROR" | "MEASUREMENT_INVALID"
  }
}

// ---------------------------------------------------------------------------
// 2. RFC 8785 (JCS) canonicalization
// ---------------------------------------------------------------------------
// Written here as a general-purpose serializer; no AIREP semantics and no
// frozen-verifier code. RFC 8785 3.2.3 sorts object members by UTF-16 code
// unit, which is exactly JavaScript's default Array.prototype.sort on strings.
// String escaping is JSON.stringify's (well-formed since ES2019), which is the
// escaping JCS mandates; numbers use the ES6 Number-to-String form.

export function jcs(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort()
      .map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  if (typeof v === "number" && !Number.isFinite(v)) {
    // Unreachable after the numeric preflight; kept fail-closed.
    throw new UnmeasurableError("ERROR", "non-finite number cannot be canonicalized");
  }
  return JSON.stringify(v);
}

// Deterministic, human-readable rendering of the result object. Key order is
// fixed (sorted) so identical input gives byte-identical output (section 8.4).
export function stableStringify(v, indent = 2) {
  return JSON.stringify(v, (_k, val) => {
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      const out = {};
      for (const k of Object.keys(val).sort()) out[k] = val[k];
      return out;
    }
    return val;
  }, indent);
}

// ---------------------------------------------------------------------------
// 3. Ordering and digests
// ---------------------------------------------------------------------------
// Section 8.4 and section 5.1 order by UTF-8 BYTE order, not by code point and
// not by UTF-16 code unit -- the one order both runtimes implement identically.

export function byteCompare(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256Prefixed(buf) {
  return "sha256:" + sha256Hex(buf);
}

// ---------------------------------------------------------------------------
// 4. Numeric preflight (contract section 5.1, "Numeric preflight")
// ---------------------------------------------------------------------------
// The checks run on the SOURCE TOKEN, not on the parsed double: an integer
// beyond 2^53-1 is already destroyed by the time JSON.parse has returned it,
// so a post-parse check cannot see the defect it exists to catch.

// Exact decimal value of a JSON number token, as mantissa * 10^exponent with
// the mantissa normalized (no trailing zeros) so two spellings of one value
// compare equal.
export function decodeDecimal(token) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  if (m === null) return null;
  const sign = m[1] === "-" ? -1n : 1n;
  const frac = m[3] === undefined ? "" : m[3];
  let mant = BigInt(m[2] + frac);
  let exp = (m[4] === undefined ? 0 : Number(m[4])) - frac.length;
  if (mant === 0n) return { mant: 0n, exp: 0 };
  while (mant % 10n === 0n) { mant /= 10n; exp += 1; }
  return { mant: sign * mant, exp };
}

function decimalEqual(a, b) {
  return a !== null && b !== null && a.mant === b.mant && a.exp === b.exp;
}

// Returns null when the token is inside the pinned envelope, or a reason string.
export function checkNumberToken(token) {
  const value = Number(token);
  if (!Number.isFinite(value)) {
    return "not finite / not IEEE-754 representable";
  }
  const exact = decodeDecimal(token);
  if (exact === null) return "unrecognized number token";

  // Integers: absolute value <= 2^53-1.
  if (exact.exp >= 0) {
    let intValue = exact.mant;
    for (let i = 0; i < exact.exp; i++) intValue *= 10n;
    const abs = intValue < 0n ? -intValue : intValue;
    if (abs > MAX_SAFE_INT) {
      return "integer magnitude exceeds 2^53-1";
    }
  }

  // "no value requiring more than double precision to round-trip": the token
  // must denote exactly the decimal that the shortest round-trip form of its
  // double denotes. 0.1 passes (both spell 1/10); 1.00000000000000000001 does
  // not (its double spells 1).
  if (!decimalEqual(exact, decodeDecimal(String(value)))) {
    return "requires more than double precision to round-trip";
  }
  return null;
}

// ---------------------------------------------------------------------------
// 5. JSON number scanner -- source tokens with RFC 6901 pointers
// ---------------------------------------------------------------------------
// The document has already been accepted by JSON.parse before this runs; the
// scanner re-walks the text only to recover each number's source spelling and
// its location.

function pointerEscape(token) {
  return String(token).replace(/~/g, "~0").replace(/\//g, "~1");
}

export function scanJsonNumbers(text) {
  const found = [];
  let i = 0;
  const n = text.length;

  function fail(msg) { throw new SyntaxError(`${msg} at offset ${i}`); }
  function ws() {
    while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  }
  function literal(word) {
    if (text.startsWith(word, i)) { i += word.length; return; }
    fail(`expected ${word}`);
  }
  function parseString() {
    if (text[i] !== '"') fail("expected string");
    let j = i + 1;
    let buf = "";
    while (j < n) {
      const c = text[j];
      if (c === '"') { i = j + 1; return buf; }
      if (c === "\\") {
        const e = text[j + 1];
        if (e === "u") {
          buf += String.fromCharCode(parseInt(text.slice(j + 2, j + 6), 16));
          j += 6;
        } else {
          const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
          if (!(e in map)) fail("bad string escape");
          buf += map[e];
          j += 2;
        }
      } else { buf += c; j++; }
    }
    fail("unterminated string");
  }
  function parseValue(pointer) {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; ws();
      if (text[i] === "}") { i++; return; }
      for (;;) {
        ws();
        const key = parseString();
        ws();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        parseValue(pointer + "/" + pointerEscape(key));
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return; }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++; ws();
      if (text[i] === "]") { i++; return; }
      let idx = 0;
      for (;;) {
        parseValue(pointer + "/" + idx);
        idx++;
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return; }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') { parseString(); return; }
    if (c === "t") { literal("true"); return; }
    if (c === "f") { literal("false"); return; }
    if (c === "n") { literal("null"); return; }
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (m === null) fail("unexpected token");
    found.push({ pointer, token: m[0] });
    i += m[0].length;
  }

  parseValue("");
  ws();
  if (i !== n) fail("trailing content");
  return found;
}

// ---------------------------------------------------------------------------
// 6. Bundle manifest
// ---------------------------------------------------------------------------
// NOTE (recorded, not resolved): the evaluator contract fixes what the manifest
// must CARRY -- `scenario_id` plus every shipped file with a sha256 over its
// original bytes (section 5) -- but pins no encoding for it. The shape below
// follows the house style of the existing corpus manifests in this repository
// (`files` as a path -> 64-lowercase-hex map). It is an ASSUMED shape and is
// flagged for maintainer pinning; see README.md.

const MANIFEST_MEMBERS = new Set([
  "scenario_id", "files", "artifacts", "operator_inputs", "clock", "head_witness",
]);
const OPERATOR_INPUT_KINDS = new Set(["bindings", "independence_policy", "revocation"]);
const CLOCK_MEMBERS = new Set(["now", "freshness_window_seconds"]);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function checkBundleRelative(p, what) {
  if (typeof p !== "string" || p.length === 0) {
    throw new PreflightError(`${what}: path must be a non-empty string`);
  }
  if (path.isAbsolute(p) || p.includes("\\")) {
    throw new PreflightError(`${what}: path must be bundle-relative: ${p}`);
  }
  const norm = path.normalize(p);
  if (norm === ".." || norm.startsWith("../") || norm.startsWith("./") || norm !== p) {
    throw new PreflightError(`${what}: path must be normalized and inside the bundle: ${p}`);
  }
  return p;
}

export function loadManifest(bundleDir) {
  const manifestPath = path.join(bundleDir, "manifest.json");
  let text;
  try {
    text = fs.readFileSync(manifestPath, "utf8");
  } catch (e) {
    throw new PreflightError(`manifest unreadable at ${manifestPath}: ${e.message}`);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new PreflightError(`manifest is not parseable JSON: ${e.message}`);
  }
  if (!isPlainObject(doc)) throw new PreflightError("manifest is not a JSON object");
  for (const k of Object.keys(doc)) {
    if (!MANIFEST_MEMBERS.has(k)) throw new PreflightError(`manifest carries unknown member: ${k}`);
  }
  if (typeof doc.scenario_id !== "string" || doc.scenario_id.length === 0) {
    throw new PreflightError("manifest has no usable scenario_id; bundle identity unknown");
  }
  // Bundle identity is established from here on.
  if (!isPlainObject(doc.files)) throw new PreflightError("manifest.files must be an object");
  const files = new Map();
  for (const [p, digest] of Object.entries(doc.files)) {
    checkBundleRelative(p, "manifest.files");
    if (typeof digest !== "string" || !HEX64.test(digest)) {
      throw new PreflightError(`manifest.files["${p}"] must be 64 lowercase hex characters`);
    }
    files.set(p, digest);
  }
  if (!Array.isArray(doc.artifacts) || doc.artifacts.length === 0) {
    throw new PreflightError("manifest.artifacts must be a non-empty array of bundle paths");
  }
  const artifacts = [];
  for (const p of doc.artifacts) {
    checkBundleRelative(p, "manifest.artifacts");
    if (!files.has(p)) throw new PreflightError(`manifest.artifacts entry not listed in files: ${p}`);
    if (artifacts.includes(p)) throw new PreflightError(`manifest.artifacts lists ${p} twice`);
    artifacts.push(p);
  }
  const operatorInputs = {};
  if (doc.operator_inputs !== undefined) {
    if (!isPlainObject(doc.operator_inputs)) {
      throw new PreflightError("manifest.operator_inputs must be an object");
    }
    for (const [kind, p] of Object.entries(doc.operator_inputs)) {
      if (!OPERATOR_INPUT_KINDS.has(kind)) {
        throw new PreflightError(`manifest.operator_inputs carries unknown kind: ${kind}`);
      }
      checkBundleRelative(p, `manifest.operator_inputs.${kind}`);
      if (!files.has(p)) {
        throw new PreflightError(`manifest.operator_inputs.${kind} not listed in files: ${p}`);
      }
      operatorInputs[kind] = p;
    }
  }
  let clock = { now: null, freshnessWindow: null };
  if (doc.clock !== undefined) {
    if (!isPlainObject(doc.clock)) throw new PreflightError("manifest.clock must be an object");
    for (const k of Object.keys(doc.clock)) {
      if (!CLOCK_MEMBERS.has(k)) throw new PreflightError(`manifest.clock carries unknown member: ${k}`);
    }
    if (doc.clock.now !== undefined) {
      if (typeof doc.clock.now !== "string") throw new PreflightError("manifest.clock.now must be a string");
      clock.now = doc.clock.now;
    }
    if (doc.clock.freshness_window_seconds !== undefined) {
      // Carried as a STRING so it reaches the frozen verifier as the bundle
      // spelled it. Parsing a JSON number and re-emitting it would be exactly
      // the "synthesize / re-emit" that section 5.1 forbids, and two runtimes
      // have no reason to re-spell one float identically.
      if (typeof doc.clock.freshness_window_seconds !== "string") {
        throw new PreflightError(
          "manifest.clock.freshness_window_seconds must be a string, passed through unchanged");
      }
      clock.freshnessWindow = doc.clock.freshness_window_seconds;
    }
  }
  let headWitness = null;
  if (doc.head_witness !== undefined) {
    checkBundleRelative(doc.head_witness, "manifest.head_witness");
    if (!files.has(doc.head_witness)) {
      throw new PreflightError(`manifest.head_witness not listed in files: ${doc.head_witness}`);
    }
    headWitness = doc.head_witness;
  }
  return {
    scenarioId: doc.scenario_id,
    files,
    artifacts,
    operatorInputs,
    clock,
    headWitness,
    manifestPath,
  };
}

// ---------------------------------------------------------------------------
// 7. CLI
// ---------------------------------------------------------------------------
// Section 8.5 pins exit 0 to "exactly one result object". A --help path that
// printed usage to stdout and exited 0 would contradict that, so usage text
// goes to stderr and --help is an exit-2 usage error like any other
// non-measuring invocation.

const USAGE = `interop_eval.mjs - AIREP v0.2 reference interop evaluator (Node lane)

  node interop_eval.mjs --bundle DIR
                        [--bindings FILE] [--independence-policy FILE]
                        [--revocation FILE] [--now STR] [--freshness-window N]
                        [--verifier FILE] [--verifier-contract FILE]

One invocation evaluates exactly one scenario bundle and writes exactly one
JSON result object to stdout. No case discovery is performed.

Operator-input files named on the command line MUST live inside the bundle and
be covered by its manifest (contract section 5.1: the bundle's own bytes). When
the manifest also declares them, the two MUST agree.

Exit codes (contract section 8.5):
  0  measured        - one result object, measurement_status MEASURED
  1  no result object - manifest missing/unparseable, identity unknown, file absent
  2  no result object - CLI usage error
  3  one result object - MEASUREMENT_INVALID or ERROR, level1 null
`;

function parseArgs(argv) {
  const flags = {
    bundle: null, bindings: null, "independence-policy": null, revocation: null,
    now: null, "freshness-window": null, verifier: null, "verifier-contract": null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") throw new UsageError("--help: nothing is evaluated");
    if (!a.startsWith("--")) throw new UsageError(`unexpected argument: ${a}`);
    const name = a.slice(2);
    if (!(name in flags)) throw new UsageError(`unknown option: ${a}`);
    if (i + 1 >= argv.length) throw new UsageError(`option ${a} requires a value`);
    if (flags[name] !== null) throw new UsageError(`option ${a} given more than once`);
    flags[name] = argv[++i];
  }
  if (flags.bundle === null) throw new UsageError("--bundle is required");
  return flags;
}

// A CLI-named operator-input file must be the bundle's own: inside the bundle
// directory and listed in the manifest.
const FLAG_FOR_KIND = {
  bindings: "--bindings",
  independence_policy: "--independence-policy",
  revocation: "--revocation",
};

function cliOperatorPath(bundleDir, manifest, kind, value) {
  const flag = FLAG_FOR_KIND[kind];
  const resolvedBundle = path.resolve(bundleDir);
  const resolved = path.resolve(value);
  const rel = path.relative(resolvedBundle, resolved);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new UsageError(`${flag}: operator input must live inside the bundle: ${value}`);
  }
  if (!manifest.files.has(rel)) {
    throw new UsageError(`${flag}: operator input is not covered by the bundle manifest: ${rel}`);
  }
  return rel;
}

// ---------------------------------------------------------------------------
// 8. Frozen-verifier invocation
// ---------------------------------------------------------------------------

function assertVerifierDigests(verifierPath, contractPath) {
  const record = {};
  record["verifier_py/class_verifier.py"] = {
    pinned: PINNED_DIGESTS["verifier_py/class_verifier.py"],
    observed: null,
    asserted: false,
    note: "other lane; never read or invoked by the Node evaluator (contract section 3)",
  };
  const checks = [
    ["verifier_node_r2/class_verifier.mjs", verifierPath],
    ["CLASS_VERIFIER_CONTRACT.md", contractPath],
  ];
  const failures = [];
  for (const [key, file] of checks) {
    let observed = null;
    try {
      observed = sha256Hex(fs.readFileSync(file));
    } catch (e) {
      failures.push(`${key}: unreadable at ${file}: ${e.message}`);
    }
    record[key] = { pinned: PINNED_DIGESTS[key], observed, asserted: observed === PINNED_DIGESTS[key] };
    if (observed !== null && observed !== PINNED_DIGESTS[key]) {
      failures.push(`${key}: digest mismatch (pinned ${PINNED_DIGESTS[key]}, observed ${observed})`);
    }
  }
  return { record, failures };
}

// The evaluator reads three members of the frozen verdict as semantic input:
// authenticated_failures, authenticated_withheld and observer_assessment. An
// absent member would read as "no failure" / "not unknown" and silently
// produce ACCEPT, so the frozen section 2 envelope shape is asserted rather
// than assumed. This checks shape only -- never a reason's meaning.
const VERDICT_ARRAYS = [
  "authenticated_failures", "authenticated_withheld", "authenticated_caveats",
  "witnessed_failures", "witnessed_withheld",
];
const VERDICT_CLASSES = ["AIREP-Core", "AIREP-Authenticated", "AIREP-Witnessed"];
const OBSERVER_ASSESSMENTS = ["same_executor", "independent", "unknown", "not_applicable"];

function verdictShapeViolation(verdict) {
  for (const k of VERDICT_ARRAYS) {
    if (!Array.isArray(verdict[k])) return `${k} is not an array`;
    if (!verdict[k].every((r) => typeof r === "string")) return `${k} holds a non-string reason`;
  }
  if (!VERDICT_CLASSES.includes(verdict.class)) return `illegal class ${JSON.stringify(verdict.class)}`;
  if (!OBSERVER_ASSESSMENTS.includes(verdict.observer_assessment)) {
    return `illegal observer_assessment ${JSON.stringify(verdict.observer_assessment)}`;
  }
  return null;
}

function runFrozenVerifier(verifierPath, requestPath, operatorArgs) {
  const args = [verifierPath, "--request", requestPath, ...operatorArgs];
  const proc = spawnSync(process.execPath, args, { encoding: "buffer", maxBuffer: 256 * 1024 * 1024 });
  if (proc.error) {
    throw new UnmeasurableError("ERROR", `frozen verifier not invocable: ${proc.error.message}`);
  }
  if (proc.status === null) {
    throw new UnmeasurableError("ERROR", `frozen verifier terminated by signal ${proc.signal}`);
  }
  return {
    exitCode: proc.status,
    stdout: proc.stdout ?? Buffer.alloc(0),
    // stderr is hashed for audit only. It is NEVER parsed, matched on, or
    // allowed to influence a predicate, verdict or status (section 8.3).
    stderrDigest: sha256Prefixed(proc.stderr ?? Buffer.alloc(0)),
  };
}

// ---------------------------------------------------------------------------
// 9. Reference resolution and the three predicates (section 6)
// ---------------------------------------------------------------------------

// v0.2 reference semantics: match on record_id, additionally on chain_id when
// the reference carries one. Zero matches is unresolved; more than one is
// ambiguous. Both fail closed; the evaluator never picks one.
export function resolveRef(ref, artifacts) {
  if (!isPlainObject(ref) || typeof ref.record_id !== "string") return { state: "unresolved", matches: 0 };
  const matches = artifacts.filter((a) => {
    if (a.value.record_id !== ref.record_id) return false;
    if (typeof ref.chain_id === "string" && a.value.chain_id !== ref.chain_id) return false;
    return true;
  });
  if (matches.length === 0) return { state: "unresolved", matches: 0 };
  if (matches.length > 1) return { state: "ambiguous", matches: matches.length };
  return { state: "resolved", matches: 1, target: matches[0] };
}

// R-A -- graph resolution. The four edges the contract enumerates.
export function predicateRA(byType, artifacts) {
  const edges = [
    ["control", "decision_ref"],
    ["execution", "decision_ref"],
    ["effect", "decision_ref"],
    ["effect", "execution_ref"],
  ];
  const failures = [];
  for (const [family, member] of edges) {
    const holder = byType.get(family);
    const r = resolveRef(holder.value[member], artifacts);
    if (r.state !== "resolved") failures.push(`${family}.${member}: ${r.state}`);
  }
  return { outcome: failures.length === 0 ? "PASS" : "FAIL", detail: failures };
}

// R-B -- authorized-vs-executed equality, compared as exact strings. Both are
// sha256_digest by schema, so no normalization, case folding or re-hashing.
export function predicateRB(byType) {
  const authorized = byType.get("control").value.authorized_action_digest;
  const executed = byType.get("execution").value.executed_action_digest;
  if (typeof authorized !== "string" || typeof executed !== "string") {
    return { outcome: "FAIL", detail: ["authorized_action_digest or executed_action_digest is not a string"] };
  }
  return authorized === executed
    ? { outcome: "PASS", detail: [] }
    : { outcome: "FAIL", detail: [`authorized ${authorized} != executed ${executed}`] };
}

// R-C -- independence, taken from the frozen verifier's observer_assessment for
// the Effect. The evaluator never re-derives independence: that is a frozen
// stage-8 property and a second definition of it would be unpinned.
export function predicateRC(byType, resultsByPath) {
  const effect = byType.get("effect");
  const wire = effect.value.observer_relationship;
  const verdict = resultsByPath.get(effect.bundlePath).verifierResult;
  if (verdict === null || !isPlainObject(verdict)) {
    return { outcome: "FAIL", detail: ["no frozen verdict for the Effect; observer_assessment unavailable"] };
  }
  const assessment = verdict.observer_assessment;
  if (wire === "independent" && assessment === "unknown") {
    return { outcome: "FAIL", detail: ["wire observer_relationship 'independent' with effective assessment 'unknown'"] };
  }
  return { outcome: "PASS", detail: [] };
}

// Level-1 mapping, in the pinned order (section 7). Step 1 precedes the rest
// because a bundle containing a cryptographically broken artifact has no
// meaningful reconciliation verdict; step 2 precedes step 3 because IOP-R-INDEP
// is built to satisfy R-A and R-B.
export function mapLevel1(hasRejectingArtifact, predicates) {
  if (hasRejectingArtifact) return "REJECT";
  if (predicates.R_C === "FAIL") return "INDEPENDENCE_NOT_ESTABLISHED";
  if (predicates.R_A === "FAIL" || predicates.R_B === "FAIL") return "RECONCILIATION_MISMATCH";
  return "ACCEPT";
}

// ---------------------------------------------------------------------------
// 10. Evaluation
// ---------------------------------------------------------------------------

function readBundleFile(bundleDir, rel) {
  return fs.readFileSync(path.join(bundleDir, rel));
}

function evaluateBundle(flags, ctx) {
  const bundleDir = flags.bundle;
  if (!fs.existsSync(bundleDir) || !fs.statSync(bundleDir).isDirectory()) {
    throw new PreflightError(`--bundle is not a directory: ${bundleDir}`);
  }
  const manifest = loadManifest(bundleDir);
  const scenarioId = manifest.scenarioId;
  // Bundle identity is established here; from this point every failure owes a
  // result object naming the scenario (section 8.5).
  ctx.scenarioId = scenarioId;

  // Layer 1 -- every shipped file exists, then every file is verified against
  // its manifest digest BEFORE anything is parsed (section 5).
  const bytes = new Map();
  for (const rel of manifest.files.keys()) {
    let buf;
    try {
      buf = readBundleFile(bundleDir, rel);
    } catch (e) {
      throw new PreflightError(`file listed in the manifest is absent or unreadable: ${rel} (${e.message})`);
    }
    bytes.set(rel, buf);
  }
  const digestFailures = [];
  for (const [rel, expected] of manifest.files.entries()) {
    const observed = sha256Hex(bytes.get(rel));
    if (observed !== expected) {
      digestFailures.push(`${rel}: manifest ${expected}, observed ${observed}`);
    }
  }
  if (digestFailures.length > 0) {
    throw new UnmeasurableError("ERROR", `manifest digest mismatch: ${digestFailures.join("; ")}`);
  }

  // Operator inputs: manifest-declared, CLI-named, or both in agreement.
  const opInputs = { ...manifest.operatorInputs };
  const cliMap = {
    bindings: flags.bindings,
    independence_policy: flags["independence-policy"],
    revocation: flags.revocation,
  };
  for (const [kind, value] of Object.entries(cliMap)) {
    if (value === null) continue;
    const rel = cliOperatorPath(bundleDir, manifest, kind, value);
    if (opInputs[kind] !== undefined && opInputs[kind] !== rel) {
      throw new UsageError(
        `${FLAG_FOR_KIND[kind]} names ${rel} but the manifest declares ${opInputs[kind]}`);
    }
    opInputs[kind] = rel;
  }
  const clock = { ...manifest.clock };
  if (flags.now !== null) {
    if (clock.now !== null && clock.now !== flags.now) {
      throw new UsageError(`--now conflicts with manifest.clock.now`);
    }
    clock.now = flags.now;
  }
  if (flags["freshness-window"] !== null) {
    if (clock.freshnessWindow !== null && clock.freshnessWindow !== flags["freshness-window"]) {
      throw new UsageError(`--freshness-window conflicts with manifest.clock.freshness_window_seconds`);
    }
    clock.freshnessWindow = flags["freshness-window"];
  }

  // Frozen-verifier digest assertion, before use (section 3).
  const verifierPath = flags.verifier ?? DEFAULT_VERIFIER;
  const contractPath = flags["verifier-contract"] ?? DEFAULT_VERIFIER_CONTRACT;
  const digests = assertVerifierDigests(verifierPath, contractPath);
  // Section 3 requires the asserted digests to be recorded in the output, so
  // every later failure path carries them too, not only the happy path.
  ctx.verifierDigests = digests.record;
  if (digests.failures.length > 0) {
    const err = new UnmeasurableError("ERROR",
      `frozen-verifier digest assertion failed: ${digests.failures.join("; ")}`);
    err.verifierDigests = digests.record;
    throw err;
  }

  // Parse the artifacts, the head_witness and the operator inputs.
  const parsed = new Map();
  const parseTargets = [
    ...manifest.artifacts,
    ...(manifest.headWitness === null ? [] : [manifest.headWitness]),
    ...Object.values(opInputs),
  ];
  for (const rel of parseTargets) {
    if (parsed.has(rel)) continue;
    const text = bytes.get(rel).toString("utf8");
    let value;
    try {
      value = JSON.parse(text);
    } catch (e) {
      throw new UnmeasurableError("ERROR", `bundle file is not parseable JSON: ${rel} (${e.message})`);
    }
    parsed.set(rel, { text, value });
  }

  // Numeric preflight, before any envelope is assembled (section 5.1).
  for (const rel of parseTargets) {
    if (!parsed.has(rel)) continue;
    let numbers;
    try {
      numbers = scanJsonNumbers(parsed.get(rel).text);
    } catch (e) {
      throw new UnmeasurableError("ERROR", `numeric preflight could not scan ${rel}: ${e.message}`);
    }
    for (const { pointer, token } of numbers) {
      const reason = checkNumberToken(token);
      if (reason !== null) {
        throw new UnmeasurableError("ERROR",
          `numeric preflight rejected ${rel} at JSON Pointer "${pointer}" (${token}): ${reason}`);
      }
    }
  }

  // Artifact set, ordered by UTF-8 byte order of record_id (section 8.4).
  const artifacts = manifest.artifacts.map((rel) => {
    const value = parsed.get(rel).value;
    if (!isPlainObject(value)) {
      throw new UnmeasurableError("ERROR", `artifact is not a JSON object: ${rel}`);
    }
    if (typeof value.record_id !== "string") {
      throw new UnmeasurableError("ERROR", `artifact has no usable record_id: ${rel}`);
    }
    return { bundlePath: rel, value };
  });
  artifacts.sort((a, b) => byteCompare(a.value.record_id, b.value.record_id));
  // The pinned run-identity invariant is the (chain_id, record_id) TUPLE
  // (frozen section 2 / ruling R-10), not record_id alone: one record_id in two
  // chains is legal, and a bare reference to it is simply ambiguous under the
  // section 5 resolution rule, which R-A already fails closed on.
  const tuples = artifacts.map((a) => jcs([a.value.chain_id ?? null, a.value.record_id]));
  if (new Set(tuples).size !== tuples.length) {
    throw new UnmeasurableError("ERROR", "bundle carries a duplicate (chain_id, record_id) tuple");
  }

  const headWitness = manifest.headWitness === null ? null : parsed.get(manifest.headWitness).value;

  const operatorArgs = [];
  if (opInputs.bindings !== undefined) operatorArgs.push("--bindings", path.join(bundleDir, opInputs.bindings));
  if (opInputs.independence_policy !== undefined) {
    operatorArgs.push("--independence-policy", path.join(bundleDir, opInputs.independence_policy));
  }
  if (opInputs.revocation !== undefined) operatorArgs.push("--revocation", path.join(bundleDir, opInputs.revocation));
  if (clock.now !== null) operatorArgs.push("--now", clock.now);
  if (clock.freshnessWindow !== null) operatorArgs.push("--freshness-window", clock.freshnessWindow);

  // Section 5.1: one closed §0 request envelope per artifact.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "airep-interop-node-"));
  const resultsByPath = new Map();
  try {
    for (const primary of artifacts) {
      const related = artifacts
        .filter((a) => a !== primary)
        .sort((a, b) => byteCompare(a.value.record_id, b.value.record_id))
        .map((a) => a.value);
      const envelope = { artifact: primary.value, related_artifacts: related };
      if (headWitness !== null) envelope.head_witness = headWitness;

      const envelopeBytes = Buffer.from(jcs(envelope), "utf8");
      const envelopeDigest = sha256Prefixed(envelopeBytes);
      const requestPath = path.join(tmpDir, `request-${resultsByPath.size}.json`);
      fs.writeFileSync(requestPath, envelopeBytes);

      const run = runFrozenVerifier(verifierPath, requestPath, operatorArgs);
      let verifierResult = null;
      if (run.exitCode === 0) {
        try {
          verifierResult = JSON.parse(run.stdout.toString("utf8"));
        } catch (e) {
          throw new UnmeasurableError("ERROR",
            `frozen verifier exited 0 but its stdout is not parseable JSON for ${primary.bundlePath}`);
        }
        if (!isPlainObject(verifierResult)) {
          throw new UnmeasurableError("ERROR",
            `frozen verifier exited 0 but did not emit a verdict object for ${primary.bundlePath}`);
        }
        const shape = verdictShapeViolation(verifierResult);
        if (shape !== null) {
          throw new UnmeasurableError("ERROR",
            `frozen verdict violates class-verifier contract section 2 for ${primary.bundlePath}: ${shape}`);
        }
      }
      resultsByPath.set(primary.bundlePath, {
        artifact: primary,
        envelopeDigest,
        exitCode: run.exitCode,
        verifierResult,
        stderrDigest: run.stderrDigest,
      });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // ---- artifacts[] entries (section 8.3), in record_id byte order ----------
  const artifactEntries = artifacts.map((a) => {
    const r = resultsByPath.get(a.bundlePath);
    const ref = { record_id: a.value.record_id };
    if (typeof a.value.chain_id === "string") ref.chain_id = a.value.chain_id;
    return {
      artifact_ref: ref,
      request_envelope_digest: r.envelopeDigest,
      verifier_exit_code: r.exitCode,
      verifier_result: r.verifierResult,
      verifier_stderr_digest: r.stderrDigest,
    };
  });

  // ---- withheld reasons, verbatim (section 8.2) ---------------------------
  const withheldReasons = [];
  for (const a of artifacts) {
    const verdict = resultsByPath.get(a.bundlePath).verifierResult;
    if (verdict === null) continue;
    for (const channel of ["authenticated_withheld", "witnessed_withheld"]) {
      const reasons = verdict[channel];
      if (Array.isArray(reasons) && reasons.length > 0) {
        const ref = { record_id: a.value.record_id };
        if (typeof a.value.chain_id === "string") ref.chain_id = a.value.chain_id;
        withheldReasons.push({ artifact_ref: ref, channel, reasons });
      }
    }
  }

  const base = {
    scenario_id: scenarioId,
    verifier_digests: digests.record,
    evaluator_version: EVALUATOR_VERSION,
    artifacts: artifactEntries,
    withheld_reasons: withheldReasons,
  };

  // ---- run-validity guard on frozen exit codes (section 7.2) --------------
  // Preflight-clean, in the part a single lane can observe: the manifest
  // verified, the numeric preflight passed, the envelope was built per §5.1
  // and the operator inputs are the bundle's own. Everything above throws
  // before this point otherwise. The contract's second half of that condition
  // -- "both lanes produced identical envelope bytes" -- is NOT observable
  // from inside one lane (ruling AD15-IR-4) and is therefore not evaluated
  // here; it stays with the aggregate harness. Recorded, not resolved.
  const preflightClean = true;
  for (const a of artifacts) {
    const r = resultsByPath.get(a.bundlePath);
    if (r.exitCode === 0) continue;
    if (r.exitCode === 1 && preflightClean && EXIT1_REJECT_SCENARIOS.has(scenarioId)) continue;
    return {
      ...base,
      measurement_status: "ERROR",
      level1: null,
      predicates: { R_A: "NOT_APPLICABLE", R_B: "NOT_APPLICABLE", R_C: "NOT_APPLICABLE" },
      _exit: 3,
      _diagnostic: `frozen verifier exited ${r.exitCode} for ${a.bundlePath}; scenario ${scenarioId} `
        + "does not qualify for the section 7.2 exit-1 REJECT reading",
    };
  }

  // ---- §7.1: authenticated_withheld is never a qualifying result ----------
  // Every one of the twelve scenarios expects each artifact that reaches a
  // verdict to reach AIREP-Authenticated (the corpus binding store resolves
  // all four producer identities by construction), so any non-empty
  // authenticated_withheld channel means the operator inputs or the harness
  // are wrong, not the artifact.
  const withheldAuth = withheldReasons.filter((w) => w.channel === "authenticated_withheld");
  if (withheldAuth.length > 0) {
    return {
      ...base,
      measurement_status: "MEASUREMENT_INVALID",
      level1: null,
      predicates: { R_A: "NOT_APPLICABLE", R_B: "NOT_APPLICABLE", R_C: "NOT_APPLICABLE" },
      _exit: 3,
      _diagnostic: "authenticated_withheld is non-empty; the tier could not be evaluated "
        + "(section 7.1) -- fix the operator inputs and re-run, do not score this scenario",
    };
  }

  // ---- predicate applicability (section 6.1) ------------------------------
  const byType = new Map();
  for (const a of artifacts) {
    const t = a.value.artifact_type;
    if (typeof t === "string" && ARTIFACT_TYPES.includes(t) && !byType.has(t)) byType.set(t, a);
  }
  let predicates;
  let raDetail = [];
  let rbDetail = [];
  let rcDetail = [];
  if (artifacts.length === 1) {
    // Single-artifact scenario: no bundle graph, no Control/Execution pair, no
    // observer relationship. Not run through the predicates at all.
    predicates = { R_A: "NOT_APPLICABLE", R_B: "NOT_APPLICABLE", R_C: "NOT_APPLICABLE" };
  } else if (artifacts.length === 4 && ARTIFACT_TYPES.every((t) => byType.has(t))) {
    const ra = predicateRA(byType, artifacts);
    const rb = predicateRB(byType);
    const rc = predicateRC(byType, resultsByPath);
    // All three are evaluated even when one has already failed: which
    // predicate fired is the measurement (section 6.1).
    predicates = { R_A: ra.outcome, R_B: rb.outcome, R_C: rc.outcome };
    raDetail = ra.detail; rbDetail = rb.detail; rcDetail = rc.detail;
  } else {
    return {
      ...base,
      measurement_status: "ERROR",
      level1: null,
      predicates: { R_A: "NOT_APPLICABLE", R_B: "NOT_APPLICABLE", R_C: "NOT_APPLICABLE" },
      _exit: 3,
      _diagnostic: `bundle carries ${artifacts.length} artifacts and does not match either pinned `
        + "shape (one artifact, or one each of decision/control/execution/effect); "
        + "predicate applicability is undeterminable",
    };
  }

  // ---- Level-1 mapping, in the pinned order (section 7) -------------------
  let level1;
  const rejecting = [];
  for (const a of artifacts) {
    const r = resultsByPath.get(a.bundlePath);
    if (r.exitCode === 1) {
      // Reached only through the §7.2 guard above: stage-0/1 artifact
      // invalidity, no class at all.
      rejecting.push(`${a.value.record_id}: no class at all (frozen exit 1)`);
      continue;
    }
    const fails = r.verifierResult?.authenticated_failures;
    if (Array.isArray(fails) && fails.length > 0) {
      rejecting.push(`${a.value.record_id}: authenticated_failures ${fails.join(",")}`);
    }
  }
  level1 = mapLevel1(rejecting.length > 0, predicates);

  return {
    ...base,
    measurement_status: "MEASURED",
    level1,
    predicates,
    _exit: 0,
    _diagnostic: [...rejecting, ...raDetail, ...rbDetail, ...rcDetail].join("; "),
  };
}

// ---------------------------------------------------------------------------
// 11. Entry point
// ---------------------------------------------------------------------------

function emit(result) {
  const { _exit, _diagnostic, ...body } = result;
  if (_diagnostic) process.stderr.write(_diagnostic + "\n");
  process.stdout.write(stableStringify(body) + "\n");
  return _exit;
}

export function main(argv) {
  let flags;
  try {
    flags = parseArgs(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n\n${USAGE}`);
      return 2;
    }
    throw e;
  }
  const ctx = { scenarioId: null, verifierDigests: null };
  try {
    const result = evaluateBundle(flags, ctx);
    return emit(result);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n\n${USAGE}`);
      return 2;
    }
    if (e instanceof PreflightError) {
      // Bundle identity was never established: silence on stdout (section 8.5).
      process.stderr.write(`bundle preflight failed: ${e.message}\n`);
      return 1;
    }
    if (e instanceof UnmeasurableError) {
      process.stderr.write(`${e.status}: ${e.message}\n`);
      return emit({
        scenario_id: ctx.scenarioId,
        measurement_status: e.status,
        level1: null,
        predicates: { R_A: "NOT_APPLICABLE", R_B: "NOT_APPLICABLE", R_C: "NOT_APPLICABLE" },
        artifacts: [],
        withheld_reasons: [],
        verifier_digests: e.verifierDigests ?? ctx.verifierDigests,
        evaluator_version: EVALUATOR_VERSION,
        _exit: 3,
        _diagnostic: "",
      });
    }
    throw e;
  }
}

const invokedDirectly = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) {
  process.exit(main(process.argv.slice(2)));
}
