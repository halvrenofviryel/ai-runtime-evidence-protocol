#!/usr/bin/env node
// AIREP v0.2 reference interop evaluator -- Node lane.
//
// Implements INTEROP_REFERENCE_EVALUATOR_CONTRACT.md (AD15-IR-2), post-erratum
// basis 930b9457db00c1d66e2d355f59a6cf5811d52d3a, sections 5-8.
//
// Bundle-level AD-03 reconciliation only: every per-artifact schema / hash /
// signature / class result is taken verbatim from the frozen Node class
// verifier, which is invoked as a subprocess and never imported, vendored,
// modified or re-implemented. Only the Node lane's verifier is ever invoked
// (section 3, lane-crossing prohibition); the peer lane's verifier is never
// read, never invoked, and its digest appears nowhere in this file or in the
// output (section 8.2.1).
//
// Explicitly NOT implemented, by ruling AD15-IR-4 (section 5.1): cross-lane
// envelope-digest comparison. A single invocation cannot observe the other
// lane's digest. This program emits only its own request_envelope_digest; the
// aggregate harness compares the pair.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// 0. Constants
// ---------------------------------------------------------------------------

const EVALUATOR_VERSION = "interop_eval_node/0.2.0";

// The registered twelve (section 8.1). A manifest whose scenario_id is not one
// of these carries "no usable scenario_id" and therefore establishes no bundle
// identity (section 8.5, exit 1).
const SCENARIOS = new Set([
  "IOP-P-DEC", "IOP-P-CTL", "IOP-P-EXE", "IOP-P-EFF",
  "IOP-B-DEC", "IOP-B-CTL", "IOP-B-EXE", "IOP-B-EFF",
  "IOP-R-CLEAN", "IOP-R-TOCTOU", "IOP-R-XREF", "IOP-R-INDEP",
]);

// Section 7.2: frozen `exit 1` may be read as Level-1 REJECT only for these
// scenarios -- the ones whose targeted predicate IS stage-0 / stage-1 artifact
// invalidity. Pinned by the contract by name; never inferred, never widened.
// IOP-B-EXE is deliberately absent: its target is stage 4, a completed
// Authenticated-tier FAILURE that exits 0.
const EXIT1_REJECT_SCENARIOS = new Set(["IOP-B-DEC", "IOP-B-CTL", "IOP-B-EFF"]);

const ARTIFACT_FAMILIES = ["control", "decision", "effect", "execution"];

// Closed role set, section 5. `clock` stays legal so a future run can carry
// one; the official W1 composition check below rejects it for this run.
const ROLES = new Set(["artifact", "bindings", "independence_policy", "revocation", "clock"]);
const REQUIRED_OPERATOR_ROLES = ["bindings", "independence_policy", "revocation"];
const FORBIDDEN_OPERATOR_ROLES = ["clock"];

// Frozen-verifier digests, section 3. Asserted before use and recorded in the
// output. The Python lane's verifier digest is NOT here: section 3 forbids this
// lane from reading it, and section 8.2.1 forbids it from appearing at all.
const PINNED_VERIFIER_DIGEST =
  "e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4";
const PINNED_VERIFIER_CONTRACT_DIGEST =
  "7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885";

const MAX_SAFE_INT = 9007199254740991n;
const HEX64 = /^[0-9a-f]{64}$/;
const MANIFEST_NAME = "manifest.json";

// NODE-IMP-1: fileURLToPath, never `new URL(import.meta.url).pathname`. The
// latter is percent-encoded, so a repository path containing a literal space
// (or `#`, or any non-ASCII character) silently mis-resolves both the default
// verifier location and the direct-invocation guard at the foot of this file.
// The observed consequence was exit 0 with empty stdout -- the one output the
// section 8.5 table cannot defend against.
const SELF_PATH = fileURLToPath(import.meta.url);
const HERE = path.dirname(SELF_PATH);
const DEFAULT_VERIFIER = path.join(
  HERE, "..", "..", "class-verification", "verifier_node_r2", "class_verifier.mjs");
const DEFAULT_VERIFIER_CONTRACT = path.join(
  HERE, "..", "..", "class-verification", "CLASS_VERIFIER_CONTRACT.md");

// ---------------------------------------------------------------------------
// 1. Failure kinds -- one per band of the section 8.5 exit/stdout table
// ---------------------------------------------------------------------------

// exit 2: CLI usage error. No result object; stdout stays empty.
class UsageError extends Error {}

// exit 1: bundle identity could not be established, and only that -- manifest
// absent, unparseable, or carrying no usable scenario_id from the registered
// twelve. No result object; stdout stays empty. There is no scenario to name.
class IdentityError extends Error {}

// exit 3: bundle identity WAS established but the scenario could not be
// measured. Exactly one result object, level1 null, predicates null,
// nonmeasurement populated.
//
// Section 8.2.2 closed reason registry. The third column of that table is the
// measurement_status each reason MUST carry, so the pairing is derived here
// rather than chosen at each raise site.
const REASON_STATUS = Object.freeze({
  "manifest-invalid": "ERROR",
  "manifest-digest-mismatch": "ERROR",
  "bundle-file-missing": "ERROR",
  "bundle-json-invalid": "ERROR",
  "bundle-shape-invalid": "ERROR",
  "numeric-preflight-violation": "ERROR",
  "verifier-digest-mismatch": "ERROR",
  "verifier-not-invocable": "ERROR",
  "verifier-run-invalid": "ERROR",
  "internal-error": "ERROR",
  // The only reason that is not ERROR: the measurement was attempted and could
  // not conclude, rather than never being reached.
  "authenticated-withheld": "MEASUREMENT_INVALID",
});

class NonMeasurement extends Error {
  constructor(reason, detail, jsonPointer = null) {
    super(`${reason}: ${detail}`);
    if (!Object.prototype.hasOwnProperty.call(REASON_STATUS, reason)) {
      throw new Error(`unregistered nonmeasurement reason: ${reason}`);
    }
    // section 8.2.2: json_pointer is REQUIRED for a numeric-preflight
    // violation and permitted for no other reason. The object is closed, so
    // both directions are enforced here and cannot drift at a raise site.
    const needsPointer = reason === "numeric-preflight-violation";
    if (needsPointer && typeof jsonPointer !== "string") {
      throw new Error(`${reason} requires a JSON Pointer`);
    }
    if (!needsPointer && jsonPointer !== null) {
      throw new Error(`${reason} must not carry a JSON Pointer`);
    }
    this.reason = reason;
    this.detail = detail;
    this.jsonPointer = jsonPointer;
    this.status = REASON_STATUS[reason];
  }

  toObject() {
    const o = { reason: this.reason, detail: this.detail };
    if (this.jsonPointer !== null) o.json_pointer = this.jsonPointer;
    return o;
  }
}

// ---------------------------------------------------------------------------
// 2. RFC 8785 (JCS) canonicalization
// ---------------------------------------------------------------------------
// A general-purpose serializer; no AIREP semantics and no frozen-verifier code.
// RFC 8785 3.2.3 sorts object members by UTF-16 code unit, which is exactly
// JavaScript's default Array.prototype.sort on strings. String escaping is
// JSON.stringify's (well-formed since ES2019), which is the escaping JCS
// mandates; numbers use the ES6 Number-to-String form.

export function jcs(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort()
      .map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  if (typeof v === "number" && !Number.isFinite(v)) {
    // Unreachable after the numeric preflight; kept fail-closed.
    throw new NonMeasurement("internal-error", "non-finite number reached canonicalization");
  }
  return JSON.stringify(v);
}

// Deterministic, human-readable rendering of the result object. Member order is
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
// Sections 5.1 and 8.4 order by UTF-8 BYTE order -- not by code point and not
// by UTF-16 code unit. It is the one order both runtimes implement identically.

export function byteCompare(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256Prefixed(buf) {
  return "sha256:" + sha256Hex(buf);
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// 4. Numeric preflight (section 5.1)
// ---------------------------------------------------------------------------
// The checks run on the SOURCE TOKEN, not on the parsed double: an integer
// beyond 2^53-1 is already destroyed by the time JSON.parse has returned it, so
// a post-parse check cannot see the defect it exists to catch.
//
// The bound is on the mathematical VALUE, not on JSON spelling -- 1e20 is
// integer-valued and is rejected even though it is written in exponential form
// (section 5.1, erratum correction 7).

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

  // Integer-valued numbers: absolute value <= 2^53-1. exp >= 0 after
  // normalization is exactly "the value is an integer", whatever the spelling.
  if (exact.exp >= 0) {
    let intValue = exact.mant;
    for (let i = 0; i < exact.exp; i++) intValue *= 10n;
    const abs = intValue < 0n ? -intValue : intValue;
    if (abs > MAX_SAFE_INT) {
      return "integer-valued number exceeds 2^53-1";
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
// its location, because section 8.2.2 makes the offending JSON Pointer a
// mandatory member of the nonmeasurement object.

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
// 6. Manifest (section 5, "Manifest encoding (normative, pinned)")
// ---------------------------------------------------------------------------
// The encoding is exact. Nothing below is inferred: the object is closed to
// three members, each files[] entry is closed to three members, sha256 is bare
// 64 lowercase hex, role comes from a closed set, files[] is sorted ascending
// by path in UTF-8 byte order, and the root manifest.json is excluded from it.

const MANIFEST_MEMBERS = ["files", "manifest_version", "scenario_id"];
const FILE_ENTRY_MEMBERS = ["path", "role", "sha256"];

function closedMemberViolation(obj, allowed) {
  const got = Object.keys(obj).sort();
  const want = [...allowed].sort();
  if (got.length !== want.length || got.some((k, idx) => k !== want[idx])) {
    return `members are ${JSON.stringify(got)}, the closed set is ${JSON.stringify(want)}`;
  }
  return null;
}

// Bundle-relative, normalized, no escape, no backslash, not the root manifest.
export function checkBundlePath(p) {
  if (typeof p !== "string" || p.length === 0) return "path must be a non-empty string";
  if (p.includes("\\")) return "path must not contain a backslash";
  if (p.includes("\0")) return "path must not contain a NUL";
  if (path.posix.isAbsolute(p) || path.win32.isAbsolute(p)) return "path must be bundle-relative";
  const segments = p.split("/");
  for (const s of segments) {
    if (s === "") return "path must not contain an empty segment";
    if (s === ".") return "path must be normalized (no '.' segment)";
    if (s === "..") return "path must not contain a '..' segment";
  }
  if (p === MANIFEST_NAME) {
    return `${MANIFEST_NAME} is excluded from files[] and must not be listed`;
  }
  return null;
}

// Reads and validates manifest.json. Distinguishes the two failure bands:
// an IdentityError (exit 1, no scenario to name) from a NonMeasurement
// (exit 3, identity established and the scenario is named).
export function loadManifest(bundleDir, onIdentity = null) {
  const manifestPath = path.join(bundleDir, MANIFEST_NAME);
  let text;
  try {
    text = fs.readFileSync(manifestPath, "utf8");
  } catch (e) {
    throw new IdentityError(`${MANIFEST_NAME} absent or unreadable at ${manifestPath}: ${e.message}`);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new IdentityError(`${MANIFEST_NAME} is not parseable as strict JSON: ${e.message}`);
  }
  if (!isPlainObject(doc)) {
    throw new IdentityError(`${MANIFEST_NAME} is not a JSON object; no scenario_id is obtainable`);
  }
  if (typeof doc.scenario_id !== "string" || !SCENARIOS.has(doc.scenario_id)) {
    throw new IdentityError(
      "manifest carries no usable scenario_id from the registered twelve; bundle identity unknown");
  }
  // ---- bundle identity is established from here on; every failure below owes
  // ---- a result object NAMING THIS SCENARIO (section 8.5). The caller is told
  // ---- immediately, so a manifest rule broken on the very next line still
  // ---- produces a named result rather than a nameless one.
  const scenarioId = doc.scenario_id;
  if (onIdentity !== null) onIdentity(scenarioId);

  const closure = closedMemberViolation(doc, MANIFEST_MEMBERS);
  if (closure !== null) {
    throw new NonMeasurement("manifest-invalid", `manifest object is not closed: ${closure}`);
  }
  if (doc.manifest_version !== "1") {
    throw new NonMeasurement("manifest-invalid",
      `manifest_version must be the string "1", got ${JSON.stringify(doc.manifest_version)}`);
  }
  if (!Array.isArray(doc.files)) {
    throw new NonMeasurement("manifest-invalid", "files must be an array");
  }

  const entries = [];
  const seen = new Set();
  let previous = null;
  for (let idx = 0; idx < doc.files.length; idx++) {
    const entry = doc.files[idx];
    if (!isPlainObject(entry)) {
      throw new NonMeasurement("manifest-invalid", `files[${idx}] is not an object`);
    }
    const entryClosure = closedMemberViolation(entry, FILE_ENTRY_MEMBERS);
    if (entryClosure !== null) {
      throw new NonMeasurement("manifest-invalid", `files[${idx}] is not closed: ${entryClosure}`);
    }
    const pathViolation = checkBundlePath(entry.path);
    if (pathViolation !== null) {
      throw new NonMeasurement("manifest-invalid",
        `files[${idx}].path ${JSON.stringify(entry.path)}: ${pathViolation}`);
    }
    if (typeof entry.role !== "string" || !ROLES.has(entry.role)) {
      throw new NonMeasurement("manifest-invalid",
        `files[${idx}].role ${JSON.stringify(entry.role)} is outside the closed role set`);
    }
    // Bare 64 lowercase hex, deliberately NOT the "sha256:..." wire form.
    if (typeof entry.sha256 !== "string" || !HEX64.test(entry.sha256)) {
      throw new NonMeasurement("manifest-invalid",
        `files[${idx}].sha256 must be exactly 64 lowercase hex characters with no prefix`);
    }
    if (seen.has(entry.path)) {
      throw new NonMeasurement("manifest-invalid", `files[] lists ${entry.path} more than once`);
    }
    if (previous !== null && byteCompare(previous, entry.path) >= 0) {
      throw new NonMeasurement("manifest-invalid",
        `files[] must be sorted ascending by path in UTF-8 byte order: ${previous} precedes ${entry.path}`);
    }
    seen.add(entry.path);
    previous = entry.path;
    entries.push({ path: entry.path, role: entry.role, sha256: entry.sha256 });
  }

  return { scenarioId, entries, manifestPath };
}

// Every regular file under the bundle, recursively, bundle-relative, with
// symlinks refused anywhere (section 5). readdirSync's Dirent types come from
// lstat, so a link is never followed to classify it.
export function walkBundle(bundleDir) {
  const found = [];
  const stack = [""];
  while (stack.length > 0) {
    const rel = stack.pop();
    const abs = rel === "" ? bundleDir : path.join(bundleDir, rel);
    let dirents;
    try {
      dirents = fs.readdirSync(abs, { withFileTypes: true });
    } catch (e) {
      throw new NonMeasurement("manifest-invalid",
        `bundle directory unreadable at ${rel === "" ? "." : rel}: ${e.message}`);
    }
    for (const d of dirents) {
      const childRel = rel === "" ? d.name : `${rel}/${d.name}`;
      if (d.isSymbolicLink()) {
        // Forbidden even when the target resolves inside the bundle: a digest
        // over a link's target is not a digest over the bundle's own bytes.
        throw new NonMeasurement("manifest-invalid",
          `symbolic links are forbidden anywhere under the bundle: ${childRel}`);
      }
      if (d.isDirectory()) { stack.push(childRel); continue; }
      if (d.isFile()) {
        // The root manifest.json is excluded from files[] by section 5 (it
        // cannot hash itself), so it is excluded from the disk side of the
        // closure check as well. A nested file of the same name is an ordinary
        // bundle file and IS listed.
        if (childRel !== MANIFEST_NAME) found.push(childRel);
        continue;
      }
      // Fail closed on anything that is neither a regular file, a directory nor
      // a symlink (fifo, socket, device). No official bundle can carry one, and
      // silently ignoring it would leave unhashed bytes inside the bundle.
      throw new NonMeasurement("manifest-invalid",
        `bundle carries a non-regular file: ${childRel}`);
    }
  }
  found.sort(byteCompare);
  return found;
}

// ---------------------------------------------------------------------------
// 7. CLI
// ---------------------------------------------------------------------------
// Section 8.5 pins exit 0 to "exactly one result object, MEASURED". A --help
// path printing usage to stdout and exiting 0 would contradict that, so usage
// text goes to stderr and --help is an exit-2 usage error like any other
// non-measuring invocation.

const USAGE = `interop_eval.mjs - AIREP v0.2 reference interop evaluator (Node lane)

  node interop_eval.mjs --bundle DIR
                        [--bindings FILE] [--independence-policy FILE]
                        [--revocation FILE]
                        [--verifier FILE] [--verifier-contract FILE]

One invocation evaluates exactly one scenario bundle and writes exactly one
JSON result object to stdout. No case discovery is performed.

Operator inputs are the bundle's own: they are identified by their manifest
role, never synthesized or filtered. The optional operator-input flags are
assertions -- each must name the bundle file already carrying that role, and a
disagreement is a usage error.

Exit codes (contract section 8.5):
  0  one result object  - measurement_status MEASURED, level1 populated
  1  no result object   - bundle identity could not be established
  2  no result object   - CLI usage error
  3  one result object  - MEASUREMENT_INVALID or ERROR, level1 and predicates null
`;

const FLAG_FOR_ROLE = {
  bindings: "--bindings",
  independence_policy: "--independence-policy",
  revocation: "--revocation",
};

export function parseArgs(argv) {
  const flags = {
    bundle: null, bindings: null, "independence-policy": null, revocation: null,
    verifier: null, "verifier-contract": null,
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

// ---------------------------------------------------------------------------
// 8. Frozen-verifier identity and invocation
// ---------------------------------------------------------------------------

// Section 8.2.1: exactly two entries, both recomputed here. The peer lane's
// verifier digest is absent by construction -- there is no constant for it in
// this file and no code path that could emit one.
function assertVerifierDigests(verifierPath, contractPath) {
  const observed = { class_verifier: null, class_verifier_contract: null };
  const failures = [];
  const checks = [
    ["class_verifier", verifierPath, PINNED_VERIFIER_DIGEST],
    ["class_verifier_contract", contractPath, PINNED_VERIFIER_CONTRACT_DIGEST],
  ];
  for (const [key, file, pinned] of checks) {
    let hex = null;
    try {
      hex = sha256Hex(fs.readFileSync(file));
    } catch (e) {
      failures.push(`${key}: unreadable at ${file}: ${e.message}`);
      continue;
    }
    observed[key] = "sha256:" + hex;
    if (hex !== pinned) {
      failures.push(`${key}: pinned sha256:${pinned}, observed sha256:${hex}`);
    }
  }
  return { observed, failures };
}

// The evaluator reads three members of the frozen verdict as semantic input:
// authenticated_failures, authenticated_withheld and observer_assessment. An
// absent member would read as "no failure" / "not unknown" and silently produce
// ACCEPT, so the frozen section 2 envelope shape is asserted rather than
// assumed. This checks SHAPE only -- never a reason's meaning.
const VERDICT_ARRAYS = [
  "authenticated_failures", "authenticated_withheld", "authenticated_caveats",
  "witnessed_failures", "witnessed_withheld",
];
const VERDICT_CLASSES = ["AIREP-Core", "AIREP-Authenticated", "AIREP-Witnessed"];
const OBSERVER_ASSESSMENTS = ["same_executor", "independent", "unknown", "not_applicable"];

export function verdictShapeViolation(verdict) {
  for (const k of VERDICT_ARRAYS) {
    if (!Array.isArray(verdict[k])) return `${k} is not an array`;
    if (!verdict[k].every((r) => typeof r === "string")) return `${k} holds a non-string reason`;
  }
  if (!VERDICT_CLASSES.includes(verdict.class)) {
    return `illegal class ${JSON.stringify(verdict.class)}`;
  }
  if (!OBSERVER_ASSESSMENTS.includes(verdict.observer_assessment)) {
    return `illegal observer_assessment ${JSON.stringify(verdict.observer_assessment)}`;
  }
  return null;
}

function runFrozenVerifier(verifierPath, requestPath, operatorArgs) {
  const args = [verifierPath, "--request", requestPath, ...operatorArgs];
  const proc = spawnSync(process.execPath, args, { encoding: "buffer", maxBuffer: 256 * 1024 * 1024 });
  if (proc.error) {
    throw new NonMeasurement("verifier-not-invocable",
      `frozen verifier could not be executed: ${proc.error.message}`);
  }
  if (proc.status === null) {
    throw new NonMeasurement("verifier-not-invocable",
      `frozen verifier terminated by signal ${proc.signal} with no exit code`);
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
  if (!isPlainObject(ref) || typeof ref.record_id !== "string") {
    return { state: "unresolved", matches: 0 };
  }
  const matches = artifacts.filter((a) => {
    if (a.value.record_id !== ref.record_id) return false;
    if (typeof ref.chain_id === "string" && a.value.chain_id !== ref.chain_id) return false;
    return true;
  });
  if (matches.length === 0) return { state: "unresolved", matches: 0 };
  if (matches.length > 1) return { state: "ambiguous", matches: matches.length };
  return { state: "resolved", matches: 1, target: matches[0] };
}

// R-A -- graph resolution: the four edges the contract enumerates, and nothing
// more. It deliberately does NOT check that a decision_ref resolves to an
// artifact of the Decision family (section 6, maintainer confirmation): that
// would be a stricter, unpinned predicate, and the section 5 bundle-shape rule
// already fixes family composition.
export function predicateRA(byFamily, artifacts) {
  const edges = [
    ["control", "decision_ref"],
    ["execution", "decision_ref"],
    ["effect", "decision_ref"],
    ["effect", "execution_ref"],
  ];
  const failures = [];
  for (const [family, member] of edges) {
    const holder = byFamily.get(family);
    const r = resolveRef(holder.value[member], artifacts);
    if (r.state !== "resolved") failures.push(`${family}.${member}: ${r.state}`);
  }
  return { outcome: failures.length === 0 ? "PASS" : "FAIL", detail: failures };
}

// R-B -- authorized-vs-executed equality, compared as exact strings. Both are
// sha256_digest by schema, so no normalization, case folding or re-hashing.
export function predicateRB(byFamily) {
  const authorized = byFamily.get("control").value.authorized_action_digest;
  const executed = byFamily.get("execution").value.executed_action_digest;
  if (typeof authorized !== "string" || typeof executed !== "string") {
    return {
      outcome: "FAIL",
      detail: ["authorized_action_digest or executed_action_digest is not a string"],
    };
  }
  return authorized === executed
    ? { outcome: "PASS", detail: [] }
    : { outcome: "FAIL", detail: [`authorized ${authorized} != executed ${executed}`] };
}

// R-C -- independence, taken from the frozen verifier's observer_assessment for
// the Effect. The evaluator never re-derives independence: that is a frozen
// stage-8 property and a second definition of it would be unpinned.
export function predicateRC(byFamily, resultsByPath) {
  const effect = byFamily.get("effect");
  const wire = effect.value.observer_relationship;
  const record = resultsByPath.get(effect.bundlePath);
  const verdict = record === undefined ? null : record.verifierResult;
  if (verdict === null || !isPlainObject(verdict)) {
    return {
      outcome: "FAIL",
      detail: ["no frozen verdict for the Effect; observer_assessment unavailable"],
    };
  }
  if (wire === "independent" && verdict.observer_assessment === "unknown") {
    return {
      outcome: "FAIL",
      detail: ["wire observer_relationship 'independent' with effective assessment 'unknown'"],
    };
  }
  return { outcome: "PASS", detail: [] };
}

// Level-1 mapping in the pinned order (section 7). Step 1 precedes the rest
// because a bundle containing a cryptographically broken artifact has no
// meaningful reconciliation verdict; step 2 precedes step 3 because
// IOP-R-INDEP is built to satisfy R-A and R-B.
export function mapLevel1(hasRejectingArtifact, predicates) {
  if (hasRejectingArtifact) return "REJECT";
  if (predicates.R_C === "FAIL") return "INDEPENDENCE_NOT_ESTABLISHED";
  if (predicates.R_A === "FAIL" || predicates.R_B === "FAIL") return "RECONCILIATION_MISMATCH";
  return "ACCEPT";
}

// ---------------------------------------------------------------------------
// 10. Evaluation
// ---------------------------------------------------------------------------

// Sorting and artifact_ref construction tolerate a missing record_id rather
// than erroring on it. A broken-per-family fixture targets one specific stage-0
// violation, and that violation may be an absent core member; refusing to
// evaluate such a bundle would score a genuine detection as this evaluator's
// own fault, which is precisely the inversion section 7.2 warns about. Absence
// is represented by absence: the member is simply omitted from artifact_ref.
function sortKey(a) {
  return typeof a.value.record_id === "string" ? a.value.record_id : "";
}

function compareArtifacts(a, b) {
  const c = byteCompare(sortKey(a), sortKey(b));
  return c !== 0 ? c : byteCompare(a.bundlePath, b.bundlePath);
}

function artifactRef(a) {
  const ref = {};
  if (typeof a.value.record_id === "string") ref.record_id = a.value.record_id;
  if (typeof a.value.chain_id === "string") ref.chain_id = a.value.chain_id;
  return ref;
}

function scenarioArtifactCount(scenarioId) {
  return scenarioId.startsWith("IOP-R-") ? 4 : 1;
}

// Full bundle preflight (section 8.3.1 step 1), in the pinned order: manifest,
// symlink and path rules, file presence, digests, JSON parseability, bundle
// shape, operator-input composition, numeric envelope, frozen-verifier digest
// assertions. NO frozen verifier is invoked until every one of these passes,
// so a failure here is a pre-invocation ERROR carrying artifacts: [].
function preflight(flags, ctx) {
  const bundleDir = flags.bundle;

  // ---- manifest -----------------------------------------------------------
  const manifest = loadManifest(bundleDir, (id) => { ctx.scenarioId = id; });

  // ---- symlink and path rules; disk/manifest closure both ways ------------
  const onDisk = walkBundle(bundleDir);
  const listed = new Set(manifest.entries.map((e) => e.path));
  for (const rel of onDisk) {
    if (!listed.has(rel)) {
      throw new NonMeasurement("manifest-invalid",
        `regular file present under the bundle but absent from files[]: ${rel}`);
    }
  }
  const onDiskSet = new Set(onDisk);
  for (const entry of manifest.entries) {
    if (!onDiskSet.has(entry.path)) {
      throw new NonMeasurement("bundle-file-missing",
        `files[] lists ${entry.path} but no such regular file is present under the bundle`);
    }
  }

  // ---- digests, before anything is parsed ---------------------------------
  const bytes = new Map();
  for (const entry of manifest.entries) {
    let buf;
    try {
      buf = fs.readFileSync(path.join(bundleDir, entry.path));
    } catch (e) {
      throw new NonMeasurement("bundle-file-missing",
        `${entry.path} could not be read: ${e.message}`);
    }
    const observed = sha256Hex(buf);
    if (observed !== entry.sha256) {
      throw new NonMeasurement("manifest-digest-mismatch",
        `${entry.path}: manifest ${entry.sha256}, observed ${observed}`);
    }
    bytes.set(entry.path, buf);
  }

  // ---- JSON parseability --------------------------------------------------
  const parsed = new Map();
  for (const entry of manifest.entries) {
    const text = bytes.get(entry.path).toString("utf8");
    let value;
    try {
      value = JSON.parse(text);
    } catch (e) {
      throw new NonMeasurement("bundle-json-invalid",
        `${entry.path} is not parseable JSON: ${e.message}`);
    }
    parsed.set(entry.path, { text, value });
  }

  // ---- bundle shape -------------------------------------------------------
  const artifactEntries = manifest.entries.filter((e) => e.role === "artifact");
  const wantArtifacts = scenarioArtifactCount(manifest.scenarioId);
  if (artifactEntries.length !== wantArtifacts) {
    throw new NonMeasurement("bundle-shape-invalid",
      `${manifest.scenarioId} requires exactly ${wantArtifacts} artifact-role file(s), `
      + `the manifest carries ${artifactEntries.length}`);
  }
  const artifacts = artifactEntries.map((e) => {
    const value = parsed.get(e.path).value;
    if (!isPlainObject(value)) {
      throw new NonMeasurement("bundle-shape-invalid", `artifact ${e.path} is not a JSON object`);
    }
    return { bundlePath: e.path, value };
  });
  artifacts.sort(compareArtifacts);

  let byFamily = null;
  if (wantArtifacts === 4) {
    byFamily = new Map();
    for (const a of artifacts) {
      const t = a.value.artifact_type;
      if (typeof t !== "string" || !ARTIFACT_FAMILIES.includes(t)) {
        throw new NonMeasurement("bundle-shape-invalid",
          `artifact ${a.bundlePath} carries no recognizable artifact_type; `
          + "family composition cannot be established");
      }
      if (byFamily.has(t)) {
        throw new NonMeasurement("bundle-shape-invalid",
          `${manifest.scenarioId} requires exactly one artifact of each family; `
          + `${t} occurs more than once`);
      }
      byFamily.set(t, a);
    }
    for (const family of ARTIFACT_FAMILIES) {
      if (!byFamily.has(family)) {
        throw new NonMeasurement("bundle-shape-invalid",
          `${manifest.scenarioId} requires exactly one ${family} artifact; none is present`);
      }
    }
  }

  // ---- operator-input composition, official W1 ----------------------------
  const byRole = new Map();
  for (const e of manifest.entries) {
    if (e.role === "artifact") continue;
    if (!byRole.has(e.role)) byRole.set(e.role, []);
    byRole.get(e.role).push(e.path);
  }
  for (const role of REQUIRED_OPERATOR_ROLES) {
    const got = byRole.get(role) ?? [];
    if (got.length !== 1) {
      throw new NonMeasurement("bundle-shape-invalid",
        `an official W1 bundle carries exactly one ${role} operator input, the manifest carries ${got.length}`);
    }
  }
  for (const role of FORBIDDEN_OPERATOR_ROLES) {
    const got = byRole.get(role) ?? [];
    if (got.length !== 0) {
      throw new NonMeasurement("bundle-shape-invalid",
        `no official W1 bundle carries a ${role} operator input; the manifest carries ${got.length}`);
    }
  }
  const operatorPaths = {};
  for (const role of REQUIRED_OPERATOR_ROLES) operatorPaths[role] = byRole.get(role)[0];

  // Operator-input flags are assertions about the bundle's own files, never a
  // way to substitute foreign bytes (section 5.1).
  const cli = {
    bindings: flags.bindings,
    independence_policy: flags["independence-policy"],
    revocation: flags.revocation,
  };
  for (const [role, value] of Object.entries(cli)) {
    if (value === null) continue;
    const declared = path.resolve(bundleDir, operatorPaths[role]);
    if (path.resolve(value) !== declared) {
      throw new UsageError(
        `${FLAG_FOR_ROLE[role]} names ${value}, but the bundle's ${role} input is ${operatorPaths[role]}`);
    }
  }

  // ---- numeric envelope, before any envelope is assembled -----------------
  // Every JSON number reachable in the assembled envelope and in the operator
  // inputs, at any depth (section 5.1).
  for (const entry of manifest.entries) {
    const { text } = parsed.get(entry.path);
    let numbers;
    try {
      numbers = scanJsonNumbers(text);
    } catch (e) {
      throw new NonMeasurement("bundle-json-invalid",
        `${entry.path} could not be re-scanned for numbers: ${e.message}`);
    }
    for (const { pointer, token } of numbers) {
      const reason = checkNumberToken(token);
      if (reason !== null) {
        throw new NonMeasurement("numeric-preflight-violation",
          `${entry.path} carries ${token}: ${reason}`, pointer);
      }
    }
  }

  // ---- frozen-verifier digest assertions ----------------------------------
  const verifierPath = flags.verifier ?? DEFAULT_VERIFIER;
  const contractPath = flags["verifier-contract"] ?? DEFAULT_VERIFIER_CONTRACT;
  const digests = assertVerifierDigests(verifierPath, contractPath);
  ctx.verifierDigests = digests.observed;
  if (digests.failures.length > 0) {
    throw new NonMeasurement("verifier-digest-mismatch",
      `frozen-verifier identity assertion failed: ${digests.failures.join("; ")}`);
  }

  return { manifest, artifacts, byFamily, operatorPaths, verifierPath, bundleDir };
}

function evaluateBundle(flags, ctx) {
  const pf = preflight(flags, ctx);
  const { manifest, artifacts, byFamily, operatorPaths, verifierPath, bundleDir } = pf;
  const scenarioId = manifest.scenarioId;

  // Operator inputs are passed through as the files the bundle ships, the same
  // bytes to every artifact (section 5.1).
  const operatorArgs = [
    "--bindings", path.join(bundleDir, operatorPaths.bindings),
    "--independence-policy", path.join(bundleDir, operatorPaths.independence_policy),
    "--revocation", path.join(bundleDir, operatorPaths.revocation),
  ];

  // ---- one closed section 0 request envelope per artifact -----------------
  // head_witness is never present: no official W1 bundle defines one, and the
  // closed manifest role set has no way to carry one (section 5).
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "airep-interop-node-"));
  const resultsByPath = new Map();
  try {
    for (const primary of artifacts) {
      const related = artifacts
        .filter((a) => a !== primary)
        .sort(compareArtifacts)
        .map((a) => a.value);
      const envelope = { artifact: primary.value, related_artifacts: related };
      const envelopeBytes = Buffer.from(jcs(envelope), "utf8");
      const envelopeDigest = sha256Prefixed(envelopeBytes);
      const requestPath = path.join(tmpDir, `request-${resultsByPath.size}.json`);
      fs.writeFileSync(requestPath, envelopeBytes);

      const run = runFrozenVerifier(verifierPath, requestPath, operatorArgs);

      // The invocation produced an exit code, so it is recordable. Recorded
      // before any interpretation, so a bundle abandoned partway still lists
      // exactly what was attempted (section 8.3.1 step 3).
      const record = {
        artifact: primary,
        envelopeDigest,
        exitCode: run.exitCode,
        verifierResult: null,
        stderrDigest: run.stderrDigest,
      };
      resultsByPath.set(primary.bundlePath, record);
      ctx.artifactEntries.push({
        artifact_ref: artifactRef(primary),
        request_envelope_digest: envelopeDigest,
        verifier_exit_code: run.exitCode,
        // null whenever the exit code is 1: no verdict exists (section 8.3).
        verifier_result: null,
        verifier_stderr_digest: run.stderrDigest,
      });
      const entry = ctx.artifactEntries[ctx.artifactEntries.length - 1];

      if (run.exitCode === 0) {
        let verdict;
        try {
          verdict = JSON.parse(run.stdout.toString("utf8"));
        } catch {
          throw new NonMeasurement("verifier-run-invalid",
            `frozen verifier exited 0 but its stdout is not parseable JSON for ${primary.bundlePath}`);
        }
        if (!isPlainObject(verdict)) {
          throw new NonMeasurement("verifier-run-invalid",
            `frozen verifier exited 0 but did not emit a verdict object for ${primary.bundlePath}`);
        }
        const shape = verdictShapeViolation(verdict);
        if (shape !== null) {
          throw new NonMeasurement("verifier-run-invalid",
            `frozen verdict violates class-verifier contract section 2 for ${primary.bundlePath}: ${shape}`);
        }
        record.verifierResult = verdict;
        entry.verifier_result = verdict;
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // ---- withheld reasons, verbatim (section 8.2) ---------------------------
  for (const a of artifacts) {
    const verdict = resultsByPath.get(a.bundlePath).verifierResult;
    if (verdict === null) continue;
    for (const channel of ["authenticated_withheld", "witnessed_withheld"]) {
      const reasons = verdict[channel];
      if (Array.isArray(reasons) && reasons.length > 0) {
        ctx.withheldReasons.push({ artifact_ref: artifactRef(a), channel, reasons });
      }
    }
  }

  // ---- section 7.2 causal guard on frozen exit codes ----------------------
  // Frozen exit 1 means run-invalid: no verdict was emitted. It may be read as
  // Level-1 REJECT only when the request was preflight-clean AND the scenario's
  // targeted predicate is stage-0 / stage-1 invalidity. Preflight-clean is
  // established by construction: every step of preflight() completed, the
  // envelope was built per section 5.1, and the operator inputs are the
  // bundle's own. Cross-lane envelope equality is NOT part of this condition
  // (AD15-IR-4) and is never evaluated here.
  for (const a of artifacts) {
    const r = resultsByPath.get(a.bundlePath);
    if (r.exitCode === 0) continue;
    if (r.exitCode === 1 && EXIT1_REJECT_SCENARIOS.has(scenarioId)) continue;
    throw new NonMeasurement("verifier-run-invalid",
      `frozen verifier exited ${r.exitCode} for ${a.bundlePath}; scenario ${scenarioId} does not `
      + "qualify for the section 7.2 exit-1 REJECT reading, so this is the evaluator's error, "
      + "not the artifact's");
  }

  // ---- section 7.1: authenticated_withheld is never a qualifying result ---
  // Every scenario in an official run expects each artifact to reach the
  // Authenticated tier evaluation -- the binding store resolves all four
  // producer identities by construction -- so a withheld channel means the
  // operator inputs or the harness are wrong, not the artifact. Withheld is the
  // absence of a measurement, and it is neither REJECT nor ACCEPT.
  const withheldAuth = ctx.withheldReasons.filter((w) => w.channel === "authenticated_withheld");
  if (withheldAuth.length > 0) {
    const named = withheldAuth
      .map((w) => `${w.artifact_ref.record_id ?? "(no record_id)"}: ${w.reasons.join(",")}`)
      .join("; ");
    throw new NonMeasurement("authenticated-withheld",
      `the Authenticated tier could not be evaluated -- ${named}; fix the operator inputs and `
      + "re-run rather than scoring this scenario");
  }

  // ---- predicate applicability (section 6.1) ------------------------------
  // The eight single-artifact scenarios have no bundle graph, no
  // Control/Execution pair and no observer relationship. They are not run
  // through the predicates at all; NOT_APPLICABLE records that we established
  // this by measuring it, and it is never aggregated as a pass.
  let predicates;
  const detail = [];
  if (byFamily === null) {
    predicates = { R_A: "NOT_APPLICABLE", R_B: "NOT_APPLICABLE", R_C: "NOT_APPLICABLE" };
  } else {
    // All three are evaluated even when one has already failed: WHICH predicate
    // fired is the measurement (section 6.1).
    const ra = predicateRA(byFamily, artifacts);
    const rb = predicateRB(byFamily);
    const rc = predicateRC(byFamily, resultsByPath);
    predicates = { R_A: ra.outcome, R_B: rb.outcome, R_C: rc.outcome };
    detail.push(...ra.detail, ...rb.detail, ...rc.detail);
  }

  // ---- Level-1 mapping, in the pinned order (section 7) -------------------
  const rejecting = [];
  for (const a of artifacts) {
    const r = resultsByPath.get(a.bundlePath);
    if (r.exitCode === 1) {
      // Reached only through the guard above: stage-0 / stage-1 artifact
      // invalidity, no class at all.
      rejecting.push(`${a.bundlePath}: no class at all (frozen exit 1)`);
      continue;
    }
    const fails = r.verifierResult === null ? null : r.verifierResult.authenticated_failures;
    if (Array.isArray(fails) && fails.length > 0) {
      // A completed verdict left at AIREP-Core with a populated
      // authenticated_failures channel IS a REJECT (section 7 step 1). A
      // withheld channel never reaches here -- section 7.1 stopped it.
      rejecting.push(`${a.bundlePath}: authenticated_failures ${fails.join(",")}`);
    }
  }
  const level1 = mapLevel1(rejecting.length > 0, predicates);

  // Section 8.3.1 step 4: in a MEASURED result artifacts[] length MUST equal
  // the bundle's artifact count from section 5.
  if (ctx.artifactEntries.length !== scenarioArtifactCount(scenarioId)) {
    throw new NonMeasurement("internal-error",
      `MEASURED result would carry ${ctx.artifactEntries.length} artifacts[] entries, `
      + `${scenarioArtifactCount(scenarioId)} expected`);
  }

  return {
    result: {
      scenario_id: scenarioId,
      measurement_status: "MEASURED",
      level1,
      predicates,
      nonmeasurement: null,
      artifacts: ctx.artifactEntries,
      withheld_reasons: ctx.withheldReasons,
      verifier_digests: ctx.verifierDigests,
      evaluator_version: EVALUATOR_VERSION,
    },
    diagnostic: [...rejecting, ...detail].join("; "),
  };
}

// ---------------------------------------------------------------------------
// 11. Output
// ---------------------------------------------------------------------------

// Whether this process has written a result object to stdout. The section 8.5
// contract is that exit 0 asserts a measured result while stdout carries it;
// the NODE-IMP-1 defect produced exit 0 with empty stdout, so the invariant is
// tracked explicitly and enforced at process exit rather than assumed.
let resultWritten = false;

// Synchronous, complete write. process.stdout.write is asynchronous on a pipe,
// so a subsequent process.exit() can truncate or drop it entirely -- another
// route to the exit-0-with-empty-stdout failure. fs.writeSync loops until every
// byte is out.
function writeStdoutSync(text) {
  const buf = Buffer.from(text, "utf8");
  let off = 0;
  while (off < buf.length) {
    try {
      off += fs.writeSync(1, buf, off, buf.length - off);
    } catch (e) {
      if (e.code === "EAGAIN") continue;
      throw e;
    }
  }
}

function emit(result, diagnostic, exitCode) {
  if (diagnostic) process.stderr.write(diagnostic + "\n");
  writeStdoutSync(stableStringify(result) + "\n");
  resultWritten = true;
  return exitCode;
}

// Exit-3 result object: identity established, scenario not measured. level1 and
// predicates are null -- not a triple of NOT_APPLICABLE, which would conflate
// "does not apply" with "never reached" (section 8.2.3).
function nonMeasuredResult(ctx, err) {
  return {
    scenario_id: ctx.scenarioId,
    measurement_status: err.status,
    level1: null,
    predicates: null,
    nonmeasurement: err.toObject(),
    // Pre-invocation failures carry an empty array, not entries with null or
    // placeholder fields (section 8.3.1 step 2); once invocation began, exactly
    // the invocations attempted (step 3).
    artifacts: ctx.artifactEntries,
    withheld_reasons: ctx.withheldReasons,
    verifier_digests: ctx.verifierDigests,
    evaluator_version: EVALUATOR_VERSION,
  };
}

// ---------------------------------------------------------------------------
// 12. Entry point
// ---------------------------------------------------------------------------

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

  const ctx = {
    scenarioId: null,
    verifierDigests: null,
    artifactEntries: [],
    withheldReasons: [],
  };

  try {
    const { result, diagnostic } = evaluateBundle(flags, ctx);
    return emit(result, diagnostic, 0);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n\n${USAGE}`);
      return 2;
    }
    if (e instanceof IdentityError) {
      // No scenario to name: silence on stdout, diagnostics on stderr.
      process.stderr.write(`bundle identity not established: ${e.message}\n`);
      return 1;
    }
    if (e instanceof NonMeasurement) {
      process.stderr.write(`${e.status} (${e.reason}): ${e.detail}\n`);
      return emit(nonMeasuredResult(ctx, e), "", 3);
    }
    // An unexpected fault. Once identity is established the harness is owed a
    // result object naming the scenario rather than a crash it has to infer
    // (section 8.2.2, internal-error). Before identity there is no scenario to
    // name, so the exit-1 band applies -- the dividing line is whether bundle
    // identity was established, and nothing else (section 8.5).
    const stack = e && e.stack ? e.stack : String(e);
    process.stderr.write(`unexpected evaluator fault: ${stack}\n`);
    if (ctx.scenarioId === null) return 1;
    const wrapped = new NonMeasurement("internal-error",
      `unexpected evaluator fault: ${e && e.message ? e.message : String(e)}`);
    return emit(nonMeasuredResult(ctx, wrapped), "", 3);
  }
}

// NODE-IMP-1. Direct-invocation detection, three independent ways, none of
// which can be defeated by percent-encoding:
//
//  1. pathToFileURL(argv[1]) vs import.meta.url -- both sides are produced by
//     Node's own URL machinery, so their escaping is symmetric by construction.
//     This is the test the original defect got backwards.
//  2. resolved path vs fileURLToPath(import.meta.url) -- decoded on both sides.
//  3. realpath of both -- catches a symlinked or otherwise differently spelled
//     entry point.
export function isDirectInvocation(entry = process.argv[1]) {
  if (typeof entry !== "string" || entry.length === 0) return false;
  try {
    if (pathToFileURL(entry).href === import.meta.url) return true;
  } catch { /* fall through to the path comparisons */ }
  try {
    if (path.resolve(entry) === path.resolve(SELF_PATH)) return true;
  } catch { /* fall through */ }
  try {
    if (fs.realpathSync(path.resolve(entry)) === fs.realpathSync(SELF_PATH)) return true;
  } catch { /* not resolvable; not direct */ }
  return false;
}

if (isDirectInvocation()) {
  // Last-resort invariant: exit 0 with empty stdout is unacceptable under every
  // condition, because exit 0 asserts a measured result while stdout carries
  // none -- the one output the section 8.5 table cannot defend against. If the
  // program is about to do that, it exits non-zero instead and says why.
  process.on("exit", (code) => {
    if (code === 0 && !resultWritten) {
      process.stderr.write(
        "internal invariant violated: exit 0 with no result object on stdout; "
        + "exiting 3 instead\n");
      process.exitCode = 3;
    }
  });
  // process.exitCode, not process.exit(): the latter can truncate pending
  // stdout on a pipe.
  process.exitCode = main(process.argv.slice(2));
}
