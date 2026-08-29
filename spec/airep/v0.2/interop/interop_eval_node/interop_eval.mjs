#!/usr/bin/env node
// AIREP v0.2 reference interop evaluator -- Node lane.
//
// Implements INTEROP_REFERENCE_EVALUATOR_CONTRACT.md (AD15-IR-2), canonical
// post-Erratum-4 basis cd7b634f46e1106aca8f228d9633150cbc111855, sections 5-8.
// The contract's own sha256 is recorded in README.md and deliberately not here:
// every 64-hex literal in this file is a frozen-verifier digest this lane
// asserts, and the self-test requires that set to be exactly two (section
// 8.2.1, peer-digest absence).
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

const EVALUATOR_VERSION = "interop_eval_node/0.2.3";

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

// exit 1: bundle identity could not be established, and only that. No result
// object; stdout stays empty. There is no scenario to name.
//
// Erratum 4 (E4-2) makes the boundary a DIRECT READ and enumerates it. Identity
// comes from reading the bytes of DIR/manifest.json directly -- never from
// enumerating the bundle first -- and every one of these five is identity not
// established:
//
//   1. the bundle root itself cannot be accessed;
//   2. DIR/manifest.json is not found;
//   3. it is found but cannot be opened or read;
//   4. its bytes do not parse as strict JSON;
//   5. no registered scenario_id can be obtained from it.
//
// A root manifest that cannot be read NEVER yields bundle-file-unreadable. That
// reason names a file listed in files[], from which the root manifest is
// deliberately excluded -- but more fundamentally a reason belongs to a result
// object, and here there is no scenario to name one after. Unreadable and
// absent are genuinely indistinguishable TO THE EVALUATOR at this point,
// because neither yields an identity.
class IdentityError extends Error {}

// exit 3: bundle identity WAS established but the scenario could not be
// measured. Exactly one result object, level1 null, predicates null,
// nonmeasurement populated.
//
// Section 8.2.2 closed reason registry. The third column of that table is the
// measurement_status each reason MUST carry, so the pairing is derived here
// rather than chosen at each raise site.
const REASON_STATUS = Object.freeze({
  // Erratum 2: manifest-invalid covers the WHOLE bundle-layout surface, now
  // enumerated normatively in section 8.2.2. No new reason code is added for
  // any member of that enumeration.
  "manifest-invalid": "ERROR",
  // Erratum 3 bounds the four filesystem reasons EXACTLY, so no condition
  // falls between them and none overlaps:
  //
  //   path absent, or a definite ENOENT on read      -> bundle-file-missing
  //   present, permitted regular file, read fails    -> bundle-file-unreadable
  //   bytes read but not parseable JSON              -> bundle-json-invalid
  //   bytes read but digest does not match           -> manifest-digest-mismatch
  //
  // Each says a different TRUE thing about the bundle. The candidate this lane
  // is remediating had no row for the second and reported it as the first,
  // which asserts something false: nothing was missing.
  "manifest-digest-mismatch": "ERROR",
  "bundle-file-missing": "ERROR",
  "bundle-file-unreadable": "ERROR",
  // Erratum 4 (E4-3). Enumeration failure is NOT a layout violation. Once a
  // usable manifest and scenario_id exist the evaluator traverses the bundle;
  // if that traversal cannot complete -- permission denied, an I/O error, any
  // other failure to enumerate a directory -- the reason is this one, and it is
  // deliberately NOT manifest-invalid. manifest-invalid says the layout is
  // WRONG; this says the layout could not be MEASURED. Saying "the layout
  // violates a rule" about a faulty medium is as false as saying "the file is
  // missing" was, which is the shape Erratum 3 closed one level down. This lane
  // recorded exactly that discomfort as open ambiguity 5 rather than inventing
  // a registry row; the erratum closed it with a dedicated row.
  //
  // The file-level distinctions are unaffected: enumeration succeeding but a
  // listed file being absent is still bundle-file-missing, and a listed regular
  // file whose bytes will not read is still bundle-file-unreadable.
  "bundle-directory-unreadable": "ERROR",
  "bundle-json-invalid": "ERROR",
  "bundle-shape-invalid": "ERROR",
  "numeric-preflight-violation": "ERROR",
  "verifier-digest-mismatch": "ERROR",
  // Erratum 2 narrowed these three, and the narrowing is the point: the first
  // says we could not start it, the second says the thing we started
  // misbehaved, the third says WE did. An external subprocess protocol failure
  // is never internal-error.
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
//
// NO MANIFEST DISCOVERY IS PERFORMED (Erratum 3). The manifest is exactly
// <bundle>/manifest.json and nothing else. There is no search, no fallback
// name, no walk looking for a manifest-shaped file, and adding one would be a
// contract violation rather than a convenience: if the root manifest is absent,
// bundle identity is not established, so the answer is exit 1 with empty
// stdout, never manifest-invalid -- that reason would require an identity this
// evaluator does not have. The single path.join below IS the whole lookup.
//
// THE IDENTITY BOUNDARY IS A DIRECT READ (Erratum 4, E4-2). The readFileSync
// below is the FIRST filesystem operation the evaluator performs on the bundle:
// nothing is enumerated, stat-ed or listed beforehand, and walkBundle() does
// not run until this function has returned a usable scenario_id. That ordering
// is what makes all five listed conditions collapse into one IdentityError
// band -- an inaccessible bundle root, an absent manifest and an unreadable
// manifest all surface here as the same failed read, and the contract says they
// are indistinguishable to the evaluator precisely because none of them yields
// an identity to name a reason against. Introducing a pre-read existence or
// enumeration check would split that band and produce a reason where the
// contract requires silence.
export function loadManifest(bundleDir, onIdentity = null) {
  const manifestPath = path.join(bundleDir, MANIFEST_NAME);
  let text;
  try {
    text = fs.readFileSync(manifestPath, "utf8");
  } catch (e) {
    // Conditions 1-3 of the E4-2 enumeration arrive here as one failed read:
    // an inaccessible bundle root (ENOTDIR, EACCES on the directory), an absent
    // manifest (ENOENT) and a present-but-unopenable manifest (EACCES, EIO).
    // They are deliberately NOT separated into distinct reasons -- there is no
    // scenario to name a reason against, and bundle-file-unreadable in
    // particular is wrong here because the root manifest is never a files[]
    // entry. The errno is carried on stderr for the operator, where it has no
    // semantics.
    throw new IdentityError(
      `${MANIFEST_NAME} could not be read at ${manifestPath}: ${e.message}`);
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
//
// Erratum 2 made the whole bundle-layout surface normatively manifest-invalid,
// so every raise below is bound to that enumeration rather than to this lane's
// own reading of it: a forbidden symlink; a regular file on disk that files[]
// does not list; a files[] entry whose target is not a permitted file kind; a
// FIFO, socket, device or other non-regular non-directory object; and the
// closure, sort, role, path and digest-encoding rules. Directories are
// containers only and are never files[] entries -- a directory under the bundle
// is normal and is simply descended.
//
// Erratum 4 (E4-3) removes ONE condition from that reading: a directory that
// cannot be ENUMERATED is bundle-directory-unreadable, not manifest-invalid.
// The walk below is reached only after identity is established, so every
// failure inside it owes a result object naming the scenario either way; what
// the erratum fixes is which true thing that object says.
//
// Erratum 3 REMOVED "a manifest with the wrong name or location" from that
// enumeration, and nothing here replaces it. The condition was unimplementable:
// naming it requires a scenario_id, and a bundle with no root manifest.json has
// none. Section 8.5 already routes it to exit 1. A wrongly-named file sitting
// BESIDE a valid root manifest needs no special rule either -- it is an
// unlisted regular file, caught by the closure check below, or a listed entry
// with an invalid role, caught in loadManifest. Neither is a new code path.
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
      // Erratum 4 (E4-3). Identity is already established -- loadManifest ran
      // first and read DIR/manifest.json DIRECTLY -- so what failed here is the
      // measurement of the layout, not the layout itself. bundle-file-missing
      // would be false (nothing is known to be absent) and manifest-invalid
      // would be false (no rule is known to be broken); only the enumeration
      // failed, and that now has its own registry row.
      throw new NonMeasurement("bundle-directory-unreadable",
        `bundle traversal could not enumerate ${rel === "" ? "the bundle root" : rel}: ${e.message}`);
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
      // Erratum 2 enumerates "a FIFO, socket, device or any other non-regular,
      // non-directory object under the bundle" as manifest-invalid. Fail closed
      // on all of them: no official bundle can carry one, and ignoring it would
      // leave unhashed bytes inside a bundle whose manifest claims to cover
      // every byte.
      throw new NonMeasurement("manifest-invalid",
        `bundle carries a non-regular, non-directory object: ${childRel}`);
    }
  }
  found.sort(byteCompare);
  return found;
}

// ---------------------------------------------------------------------------
// 7. CLI
// ---------------------------------------------------------------------------
// Section 8.5's exit table governs EVALUATION invocations. Erratum 3 pins
// --help as a CLI meta-action that is not one: it exits 0, may write
// human-readable help to stdout, produces no result JSON object, does not
// require --bundle, and the exit table does not apply to it. The frozen
// class-verifier contract carries the same carve-out for the same reason, and
// the frozen verifier of this lane implements it the same way.
//
// The candidate this lane is remediating resolved the contradiction the other
// way -- usage text to stderr, exit 2 -- because the pre-erratum contract made
// exit 0 unsatisfiable for a help screen. That resolution is superseded.
//
// Erratum 4 (E4-1) pins the width of that carve-out, because "exactly one flag
// wide" proved ambiguous: two isolated lanes read it differently and measurably
// diverged, one treating it as a statement about SPELLINGS and refusing -h, the
// other as a statement about the EXIT-0 LICENCE and accepting it. This lane was
// the one that accepted -h. The contract now says which:
//
//   * the meta-action is the SINGLE-TOKEN INVOCATION `--help`, and nothing else;
//   * `-h` is NOT an alias -- it is a CLI usage error: exit 2, no result object;
//   * `--help` alongside ANY other argument is not a meta-action either. Only
//     the lone help invocation is carved out;
//   * help text content and byte length are not a parity requirement. The two
//     lanes may print different help and nothing compares it.
//
// Every other CLI usage error remains exit 2 with empty stdout, and the "exit 0
// never has empty stdout" invariant still binds every evaluation invocation --
// see the process-exit guard at the foot of this file. That guard stays keyed
// on INVOCATION KIND rather than on stdout in general, so narrowing the help
// spelling here does not weaken what an EVALUATION exiting 0 must satisfy: it
// must still have written a result object, exactly as before Erratum 3.

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

Exit codes for an evaluation invocation (contract section 8.5):
  0  one result object  - measurement_status MEASURED, level1 populated
  1  no result object   - bundle identity could not be established
  2  no result object   - CLI usage error
  3  one result object  - MEASUREMENT_INVALID or ERROR, level1 and predicates null

--help, given alone as the ONLY argument, is a CLI meta-action rather than an
evaluation: it exits 0, prints this text, evaluates nothing, emits no result
object, and does not require --bundle. The exit table above does not apply to
it. -h is not an alias for it, and --help alongside any other argument is not
the meta-action; both are ordinary usage errors and exit 2.
`;

const FLAG_FOR_ROLE = {
  bindings: "--bindings",
  independence_policy: "--independence-policy",
  revocation: "--revocation",
};

function emptyFlags() {
  return {
    bundle: null, bindings: null, "independence-policy": null, revocation: null,
    verifier: null, "verifier-contract": null,
  };
}

// Returns { flags, help }.
//
// Erratum 4 (E4-1): the meta-action is ONE EXACT INVOCATION, not one concept.
// It is recognised before the option loop and only when argv is precisely the
// single token `--help`. Everything else -- `-h`, `--help --bundle DIR`,
// `--bundle DIR --help`, `--help junk`, `--help --help` -- falls through into
// the ordinary loop, where `--help` is simply not a known option and `-h` is
// simply not an option at all. Both therefore exit 2 with empty stdout, which
// is what the erratum requires, and neither needs a special case to do so.
//
// This is a narrowing of this lane's previous behaviour, which accepted `-h` as
// an alias and let `--help` anywhere in argv win. Only the --bundle requirement
// is lifted for the meta-action, because the contract says in terms that
// --help does not require it.
export function parseArgs(argv) {
  if (argv.length === 1 && argv[0] === "--help") {
    return { flags: emptyFlags(), help: true };
  }
  const flags = emptyFlags();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) throw new UsageError(`unexpected argument: ${a}`);
    const name = a.slice(2);
    if (!(name in flags)) throw new UsageError(`unknown option: ${a}`);
    if (i + 1 >= argv.length) throw new UsageError(`option ${a} requires a value`);
    if (flags[name] !== null) throw new UsageError(`option ${a} given more than once`);
    flags[name] = argv[++i];
  }
  if (flags.bundle === null) throw new UsageError("--bundle is required");
  return { flags, help: false };
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

// Erratum 2, PROCESS band. The two reasons are separated by ONE question: did
// the process start?
//
//  * verifier-not-invocable -- NARROWED: only a process that could not be
//    spawned or executed AT ALL.
//  * verifier-run-invalid -- the process started successfully but the
//    invocation did not produce a process/result shape the frozen contract
//    permits.
//
// spawnSync reports both bands through `error`, so `error` alone cannot
// discriminate them. `pid` can, and that was MEASURED on this runtime rather
// than assumed: a spawn that never happened returns pid 0 with error ENOENT,
// while a process that started and was then killed for exceeding maxBuffer
// (ENOBUFS) or for a timeout (ETIMEDOUT) carries a real pid. Those two started,
// so under Erratum 2 they are run-invalid, not not-invocable.
//
// internal-error is unreachable from here by construction: an external
// subprocess protocol failure is never this evaluator's own fault.
//
// Pure, and exported, so the self-test can drive it with the exact shapes
// spawnSync produces without having to defeat the frozen digest assertion in
// order to reach a misbehaving stub.
export function classifyProcessShape(proc) {
  const started = typeof proc.pid === "number" && proc.pid > 0;
  if (!started) {
    return {
      reason: "verifier-not-invocable",
      detail: "frozen verifier could not be spawned or executed at all: "
        + `${proc.error ? proc.error.message : "no process was created"}`,
    };
  }
  if (proc.error) {
    return {
      reason: "verifier-run-invalid",
      detail: `frozen verifier started (pid ${proc.pid}) but the invocation did not complete `
        + `normally: ${proc.error.message}`,
    };
  }
  if (proc.status === null) {
    // Started, then died on a signal: no exit code at all, which is not a
    // process shape the frozen contract permits.
    return {
      reason: "verifier-run-invalid",
      detail: `frozen verifier started (pid ${proc.pid}) and was terminated by signal `
        + `${proc.signal} with no exit code`,
    };
  }
  return null;
}

// Erratum 2, RESULT band for a frozen exit 0. Every rejection below is
// verifier-run-invalid: empty stdout, stdout that is not strict JSON, and a
// malformed, multiple or wrong-shape result instead of the single expected
// verdict object. Returns { verdict } on success, or { reason, detail }.
export function classifyVerdictStdout(stdoutText) {
  // Named explicitly rather than left to fall out of JSON.parse("") as a parser
  // message: a process claiming a completed verdict while emitting nothing is
  // the same failure NODE-IMP-1 records on this program's own output side.
  if (stdoutText.trim() === "") {
    return {
      reason: "verifier-run-invalid",
      detail: "frozen verifier exited 0 with empty stdout; exit 0 asserts a completed verdict "
        + "and none was emitted",
    };
  }
  let verdict;
  try {
    // Strict JSON. A malformed result, and multiple concatenated results, both
    // land here.
    verdict = JSON.parse(stdoutText);
  } catch {
    return {
      reason: "verifier-run-invalid",
      detail: "frozen verifier exited 0 but its stdout is not strict JSON",
    };
  }
  if (!isPlainObject(verdict)) {
    return {
      reason: "verifier-run-invalid",
      detail: "frozen verifier exited 0 but emitted a wrong-shape result rather than the "
        + "single expected verdict object",
    };
  }
  const shape = verdictShapeViolation(verdict);
  if (shape !== null) {
    return {
      reason: "verifier-run-invalid",
      detail: `frozen verdict violates class-verifier contract section 2: ${shape}`,
    };
  }
  return { verdict };
}

function runFrozenVerifier(verifierPath, requestPath, operatorArgs) {
  const args = [verifierPath, "--request", requestPath, ...operatorArgs];
  const proc = spawnSync(process.execPath, args, { encoding: "buffer", maxBuffer: 256 * 1024 * 1024 });
  const bad = classifyProcessShape(proc);
  if (bad !== null) throw new NonMeasurement(bad.reason, bad.detail);
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
//
// AD15-IR-7 (Erratum 4, E4-4) makes this the ONLY place duplicate semantic IDs
// are judged. There is no preflight gate on them, so a bundle carrying two
// artifacts with the same record_id reaches frozen stage evaluation intact and
// an actual reference into that pair lands on the "ambiguous" branch below --
// a reconciliation finding, not the evaluator's refusal to look.
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

// AD15-IR-5 + AD15-IR-6 -- the manifest path is the TOTAL ordering key.
//
// There is exactly ONE ordering function, and that is now the contract's
// position rather than this lane's convenience. AD15-IR-6 moved the last
// remaining record_id-keyed surface -- related_artifacts inside the section 5.1
// request envelope -- onto artifact_path, so every surface a harness needs an
// identity for uses the same key:
//
//  * result identity, and artifacts[] ordering  (sections 8.3, 8.3.1, 8.4);
//  * aggregate cross-lane comparison, (scenario_id, artifact_path);
//  * related_artifacts ordering inside the request envelope (section 5.1).
//
// The Erratum-2 candidate of this lane deliberately kept two comparators apart,
// on the reading that AD15-IR-5 had left section 5.1 alone, and sorted an
// artifact with no usable record_id under an empty key with a bundlePath
// tiebreak. AD15-IR-6 supersedes that resolution explicitly: it was one of two
// defensible readings, and neither was cross-lane safe, because a differing
// related_artifacts order changes request_envelope_digest -- exactly what
// aggregate duty 2 compares. The distinction this lane preserved is therefore
// COLLAPSED on purpose, not lost by accident, and compareByRecordId is gone
// rather than left unused.
//
// Why artifact_path is total where record_id was not: the manifest lists every
// file and files[] forbids a duplicate path, so artifact_path always exists and
// is unique. No tiebreak is needed or permitted, and the envelope is always
// defined -- including for an artifact carrying no record_id at all.
//
// record_id remains ONLY the AIREP semantic reference-resolution key. R-A is
// untouched; see resolveRef(), which is the sole remaining reader of it.
//
// An evaluator MUST NOT synthesize a record_id -- ever, for any reason. A
// missing record_id now reaches the frozen stage-0 evaluation it belongs to
// instead of being converted into this evaluator's own preflight failure.
function compareByPath(a, b) {
  return byteCompare(a.bundlePath, b.bundlePath);
}

// AD15-IR-5: an object when a usable record_id exists, null when it does not.
// "Usable" is the same test resolveRef() applies, so the file carries one
// definition of it rather than two. Absence is represented by absence; nothing
// is fabricated to fill the field.
function artifactRef(a) {
  if (typeof a.value.record_id !== "string") return null;
  const ref = { record_id: a.value.record_id };
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
    if (onDiskSet.has(entry.path)) continue;
    // Erratum 2 splits two failures that both merely look like "absent from the
    // walk", and the split is normative rather than inferred:
    //
    //  * a files[] entry whose target is NOT A PERMITTED FILE KIND is a
    //    bundle-layout violation -> manifest-invalid;
    //  * a files[] entry with nothing on disk at all -> bundle-file-missing.
    //
    // Directories are containers only and are never files[] entries, so a
    // directory named by files[] falls in the first band, not the second: it is
    // present, and it is the wrong kind. lstat, never stat, so a link is
    // classified rather than followed.
    let st = null;
    try {
      st = fs.lstatSync(path.join(bundleDir, entry.path));
    } catch { /* nothing at that path at all -- handled after this block */ }
    if (st !== null) {
      const kind = st.isDirectory() ? "a directory"
        : st.isSymbolicLink() ? "a symbolic link"
        : st.isFIFO() ? "a FIFO"
        : st.isSocket() ? "a socket"
        : st.isBlockDevice() ? "a block device"
        : st.isCharacterDevice() ? "a character device"
        : "an object that is not a regular file";
      throw new NonMeasurement("manifest-invalid",
        `files[] entry ${entry.path} names ${kind}; a files[] target must be a regular file, `
        + "and directories are containers only -- never files[] entries");
    }
    throw new NonMeasurement("bundle-file-missing",
      `files[] lists ${entry.path} but no such file is present under the bundle`);
  }

  // ---- digests, before anything is parsed ---------------------------------
  const bytes = new Map();
  for (const entry of manifest.entries) {
    let buf;
    try {
      buf = fs.readFileSync(path.join(bundleDir, entry.path));
    } catch (e) {
      // Erratum 3. The presence-and-kind sweep above already ran, so reaching
      // here at all means the path was present and a regular file a moment ago.
      // The two outcomes are still kept apart on the evidence rather than on
      // that assumption:
      //
      //  * a DEFINITE ENOENT -- the file was removed between the sweep and this
      //    read -- is genuinely missing, and bundle-file-missing is true;
      //  * anything else (EACCES, EIO, EISDIR, ELOOP, EMFILE, a short read on a
      //    faulty medium) is a file that is there and cannot be read.
      //
      // Reporting the second as "missing" would tell a reader the bundle is
      // incomplete when in fact the medium or the permissions are at fault.
      if (e && e.code === "ENOENT") {
        throw new NonMeasurement("bundle-file-missing",
          `files[] lists ${entry.path} but it is no longer present: ${e.message}`);
      }
      throw new NonMeasurement("bundle-file-unreadable",
        `${entry.path} is present but its bytes could not be read: ${e.message}`);
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
  // Ruling AD15-IR-7 (Erratum 4, E4-4): there is NO bundle-wide preflight gate
  // on duplicate record_id or duplicate (chain_id, record_id), and none may be
  // added here. artifact_path is each artifact's total harness identity
  // (AD15-IR-5, AD15-IR-6), so duplicated semantic IDs cannot make a bundle
  // unidentifiable. Artifacts carrying them still go to frozen stage
  // evaluation; if a real reference lookup then produces more than one match,
  // R-A and the frozen resolution semantics treat it as AMBIGUOUS and fail
  // closed -- see resolveRef(). A preflight gate would make that predicate
  // unreachable, converting a genuine reconciliation finding into this
  // evaluator's own refusal.
  //
  // Frozen R-10 is a different surface: it makes a duplicate
  // (chain_id, record_id) in the BATCH VERIFIER'S OWN emitted verdict set
  // run-invalid. This evaluator submits each artifact as a separate request, so
  // that batch invariant does not generalize into a bundle-wide semantic
  // preflight and must not be widened into one.
  //
  // The checks below are the section 5 SHAPE rules only -- artifact count and
  // family composition -- and neither reads record_id.
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
  // Result order (section 8.4). This is also the order invocations are
  // attempted in, so a bundle abandoned partway lists a byte-ordered prefix.
  artifacts.sort(compareByPath);

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
      // Section 5.1, as amended by AD15-IR-6: every OTHER artifact of this
      // bundle, in ascending UTF-8 byte order of its manifest-relative
      // artifact_path. artifact_path always exists and is unique, so the
      // envelope is a function of the bundle alone and is defined even when an
      // artifact carries no usable record_id -- which is the whole point of the
      // ruling. `artifacts` is already sorted by path, and Array.prototype.sort
      // is stable, so this re-sort is a restatement of the key rather than a
      // reliance on the incoming order.
      const related = artifacts
        .filter((a) => a !== primary)
        .sort(compareByPath)
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
        // Required, and the entry's identity (AD15-IR-5). Always present.
        artifact_path: primary.bundlePath,
        // Object, or null when no usable record_id exists (AD15-IR-5).
        artifact_ref: artifactRef(primary),
        request_envelope_digest: envelopeDigest,
        verifier_exit_code: run.exitCode,
        // null whenever the exit code is 1: no verdict exists (section 8.3).
        verifier_result: null,
        verifier_stderr_digest: run.stderrDigest,
      });
      const entry = ctx.artifactEntries[ctx.artifactEntries.length - 1];

      if (run.exitCode === 0) {
        const band = classifyVerdictStdout(run.stdout.toString("utf8"));
        if (band.reason !== undefined) {
          throw new NonMeasurement(band.reason, `${band.detail} (for ${primary.bundlePath})`);
        }
        record.verifierResult = band.verdict;
        entry.verifier_result = band.verdict;
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
        ctx.withheldReasons.push({
          // artifact_path is the identity (AD15-IR-5); artifact_ref may be null.
          artifact_path: a.bundlePath, artifact_ref: artifactRef(a), channel, reasons,
        });
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
    // Erratum 2 pins BOTH of the remaining shapes to verifier-run-invalid: a
    // non-qualifying exit 1, and exit 2 or any other exit the frozen contract
    // does not permit for this invocation. Neither is internal-error -- the
    // thing we invoked misbehaved, not us.
    throw new NonMeasurement("verifier-run-invalid",
      r.exitCode === 1
        ? `frozen verifier exited 1 for ${a.bundlePath}, but scenario ${scenarioId} does not `
          + "qualify for the section 7.2 exit-1 REJECT reading, so this is the evaluator's "
          + "error, not the artifact's"
        : `frozen verifier exited ${r.exitCode} for ${a.bundlePath}; the frozen contract permits `
          + "no such exit for this invocation");
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
      .map((w) => `${w.artifact_path}: ${w.reasons.join(",")}`)
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

// Whether ANY byte has reached stdout, and whether this invocation was the one
// CLI meta-action rather than an evaluation.
//
// Erratum 3 makes --help exit 0 with help text and no result object. The guard
// must accommodate that WITHOUT relaxing what it checks for an evaluation, so
// it is split by invocation kind rather than loosened for both:
//
//   evaluation   exiting 0 MUST have written a result object  (unchanged);
//   --help       exiting 0 MUST have written help to stdout.
//
// Keyed this way, an evaluation that exits 0 with no result object still trips
// the guard exactly as it did before Erratum 3 -- which is the NODE-IMP-1
// failure -- and "exit 0 never has empty stdout" holds on both paths.
let stdoutWritten = false;
let metaAction = false;

// Synchronous, complete write. process.stdout.write is asynchronous on a pipe,
// so a subsequent process.exit() can truncate or drop it entirely -- another
// route to the exit-0-with-empty-stdout failure. fs.writeSync loops until every
// byte is out.
export function writeStdoutSync(text) {
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
  if (buf.length > 0) stdoutWritten = true;
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
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n\n${USAGE}`);
      return 2;
    }
    throw e;
  }

  // Erratum 3, narrowed by Erratum 4 (E4-1): a CLI meta-action, reachable only
  // from the single-token invocation `--help`, taken before anything is
  // evaluated. Exit 0, help to stdout, no result object, no bundle touched. The
  // section 8.5 exit table does not apply here, and the official aggregate
  // harness never invokes this path. Written with the same synchronous
  // full-write used for a result object, so a help screen cannot be truncated
  // on a pipe either. Help CONTENT is not a cross-lane parity requirement, so
  // nothing downstream depends on these bytes.
  if (parsed.help) {
    metaAction = true;
    writeStdoutSync(USAGE);
    return 0;
  }
  const flags = parsed.flags;

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
    const satisfied = metaAction ? stdoutWritten : resultWritten;
    if (code === 0 && !satisfied) {
      process.stderr.write(
        `internal invariant violated: exit 0 with ${metaAction ? "empty stdout" : "no result object on stdout"}; `
        + "exiting 3 instead\n");
      process.exitCode = 3;
    }
  });
  // process.exitCode, not process.exit(): the latter can truncate pending
  // stdout on a pipe.
  process.exitCode = main(process.argv.slice(2));
}
