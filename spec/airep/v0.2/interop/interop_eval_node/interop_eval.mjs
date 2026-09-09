#!/usr/bin/env node
// AIREP v0.2 reference interop evaluator -- Node lane.
//
// Implements INTEROP_REFERENCE_EVALUATOR_CONTRACT.md (AD15-IR-2), canonical
// Erratum-7 round-three basis 51c14fe11ae7a94e9c55e30490a754bbe4ccf505,
// sections 5-8 inclusive of AD15-IR-12 through AD15-IR-20 and the section 8.7
// four-class normative surface.
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

const EVALUATOR_VERSION = "interop_eval_node/0.2.6";

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
  // Erratum 5 (E5-3). The last gap in the filesystem taxonomy, between the
  // listed-file cases Erratum 3 separated and the enumeration case Erratum 4
  // separated: an entry whose NAME was obtained but whose KIND could not be
  // determined. Calling that manifest-invalid asserts the layout is wrong when
  // that is precisely what could not be established, and
  // bundle-directory-unreadable does not fit either, because enumeration
  // SUCCEEDED. The full boundary, in order of what was actually learned:
  //
  //   name obtained, no-follow kind inspection cannot complete
  //                                            -> bundle-entry-uninspectable
  //   kind determined: symlink / forbidden non-regular object -> manifest-invalid
  //   kind determined: a directory that cannot be enumerated
  //                                            -> bundle-directory-unreadable
  //   kind determined: a regular file whose bytes cannot be read
  //                                            -> bundle-file-unreadable
  //
  // Each row says only what was actually learned, and stops there. Reporting a
  // layout violation when the layout could not be inspected is the same error
  // as reporting a missing file when the medium was merely unreadable.
  "bundle-entry-uninspectable": "ERROR",
  "bundle-json-invalid": "ERROR",
  "bundle-shape-invalid": "ERROR",
  "numeric-preflight-violation": "ERROR",
  "verifier-digest-mismatch": "ERROR",
  // Erratum 5 (E5-4). Section 8.2.1 required EXACTLY TWO self-recomputed
  // verifier_digests entries while the contract separately required a
  // frozen-identity assertion. When a frozen file cannot be READ those two
  // demands conflict: a digest that cannot be computed cannot be emitted, and
  // no implementer may fabricate one. This reason is the resolution -- it is
  // the ONLY result for which verifier_digests is null.
  //
  // It is deliberately distinct from verifier-digest-mismatch. Unreadable says
  // we could not learn what is there; mismatch says we learned exactly what is
  // there and it is not what was pinned. Collapsing them would lose the one
  // distinction a reader needs to tell a broken checkout from a tampered one.
  "frozen-identity-unreadable": "ERROR",
  // Erratum 2 narrowed these three, and the narrowing is the point: the first
  // says we could not start it, the second says the thing we started
  // misbehaved, the third says WE did. An external subprocess protocol failure
  // is never internal-error.
  "verifier-not-invocable": "ERROR",
  "verifier-run-invalid": "ERROR",
  "internal-error": "ERROR",
  // Ruling AD15-IR-14 (Erratum 7, E7-7). A supplied operator-input flag that
  // contradicts the manifest is a usage problem, but it is only DETECTABLE
  // after the manifest has been read -- that is, after identity is established.
  // Reporting it as a CLI usage error (exit 2, empty stdout) would contradict
  // AD15-IR-8's rule that an established identity is owed a result object, so
  // it is a registry reason at exit 3 instead.
  //
  // A CLI SYNTAX error -- unknown option, missing value, malformed argument --
  // stays exit 2 with empty stdout, because it is detectable before anything is
  // read. The dividing line is the same one section 8.5 draws everywhere: was
  // identity established when the fault became detectable.
  //
  // The candidate this lane is remediating raised UsageError here, i.e. exit 2.
  // That resolution is superseded.
  "operator-input-assertion-mismatch": "ERROR",
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
// 1a. Ruling AD15-IR-13 -- the canonical stage pipeline and total precedence
// ---------------------------------------------------------------------------
// Section 8.6 replaces the pairwise failure ordering earlier errata built up
// with a TOTAL one. Two properties carry it, and both are structural rather
// than a matter of care at each raise site:
//
//   1. A STAGE RUNS TO COMPLETION over the whole bundle before the next stage
//      begins, and the first stage that produces a failure determines the
//      reported reason. No later stage overrides an earlier one.
//   2. WITHIN a stage, precedence is by MECHANISM first, then by PATH, then --
//      only where the reason carries one -- by JSON POINTER.
//
// The barriers are the whole point. A bundle with one unreadable file and a
// DIFFERENT file's digest mismatch must report bundle-file-unreadable: every
// read completes (stage 6) before any digest is checked (stage 7). The
// superseded implementation of this lane read and hashed each file in ONE loop,
// so it reported whichever failure came first in manifest order -- a reading
// that satisfied the old "complete the whole bundle preflight first" and is now
// explicitly non-conforming. Stages 5 and 6 are separated for the same reason.
//
// The comparison key is three components plus a conditional fourth:
//
//   (stage_rank, reason_rank_within_stage, canonical_artifact_path
//    [, json_pointer -- for numeric-preflight-violation only])
//
// The fourth is conditional because a locator is NORMATIVE ONLY WHERE IT IS
// EMITTED, and section 8.2.2 permits json_pointer for exactly one reason. For
// every other reason two same-stage same-reason failures produce results that
// are identical on the section 8.7 parity surface, so which one is selected
// cannot be observed -- that is a stated exemption, not a fallback to discovery
// order.
//
// A PATHLESS whole-bundle violation uses the EMPTY BYTE STRING as its internal
// path key. A composition rule is violated by a SET of files, not by one, so
// the "sorted-first offending path" rule does not reach it; no real path is
// empty, so the empty key never collides. The internal key is not emitted.
export const STAGE = Object.freeze({
  CLI: 1,
  IDENTITY: 2,
  FROZEN_IDENTITY: 3,
  MANIFEST_STRUCTURE: 4,
  TRAVERSAL: 5,
  FILE_READS: 6,
  DIGESTS: 7,
  JSON_PARSE: 8,
  SHAPE: 9,
  NUMERIC: 10,
  INVOCATION: 11,
  WITHHELD: 12,
  VERDICT: 13,
});

// Each row of the section 8.6 table lists its reasons IN PRECEDENCE ORDER. A
// failure of an earlier-listed reason is reported over a later-listed one
// regardless of paths, so the rank is read from this table and never chosen at
// a raise site.
export const STAGE_REASON_ORDER = Object.freeze({
  [STAGE.FROZEN_IDENTITY]: ["frozen-identity-unreadable", "verifier-digest-mismatch"],
  [STAGE.MANIFEST_STRUCTURE]: ["manifest-invalid"],
  [STAGE.TRAVERSAL]: [
    "bundle-entry-uninspectable", "bundle-directory-unreadable",
    "manifest-invalid", "bundle-file-missing",
  ],
  // E8-2. The stage-6 row carries TWO reasons, in this order. Section 8.2.2's
  // listed-file boundary has always routed "a definite ENOENT on read" to
  // bundle-file-missing; the stage-6 row named only bundle-file-unreadable, and
  // the two collide when a file is present at stage 5 and gone before stage 6.
  // The two isolated lanes were MEASURED resolving that differently on a
  // Class-1 field. bundle-file-missing keeps the rank its stage-5 mechanism
  // gives it, so it OUTRANKS bundle-file-unreadable here too.
  [STAGE.FILE_READS]: ["bundle-file-missing", "bundle-file-unreadable"],
  [STAGE.DIGESTS]: ["manifest-digest-mismatch"],
  [STAGE.JSON_PARSE]: ["bundle-json-invalid"],
  [STAGE.SHAPE]: ["bundle-shape-invalid", "operator-input-assertion-mismatch"],
  [STAGE.NUMERIC]: ["numeric-preflight-violation"],
  [STAGE.INVOCATION]: ["verifier-not-invocable", "verifier-run-invalid"],
  [STAGE.WITHHELD]: ["authenticated-withheld"],
});

export function reasonRank(stage, reason) {
  const order = STAGE_REASON_ORDER[stage];
  if (order === undefined) throw new Error(`stage ${stage} declares no reason order`);
  const idx = order.indexOf(reason);
  if (idx < 0) throw new Error(`reason ${reason} is not declared for stage ${stage}`);
  return idx;
}

// One stage's worth of candidate failures. Every stage collects into a fresh
// instance and calls settle() at its barrier: nothing is thrown mid-stage, so a
// later-listed mechanism found early can never pre-empt an earlier-listed one
// found late.
//
// `pathKey` is the failure's canonical artifact path, or "" for a pathless
// whole-bundle violation. It is INTERNAL: it never reaches the result object.
class StageFailures {
  constructor(stage) {
    this.stage = stage;
    this.items = [];
  }

  add(reason, pathKey, detail, jsonPointer = null) {
    this.items.push({
      rank: reasonRank(this.stage, reason),
      pathKey: pathKey === null || pathKey === undefined ? "" : pathKey,
      reason, detail, jsonPointer,
    });
    return this;
  }

  get empty() { return this.items.length === 0; }

  // The stage barrier. Selects the minimum under the pinned comparison key and
  // raises it; the remaining candidates are discarded, which is exactly what
  // "the first stage that produces a failure determines the reported reason"
  // means one level down.
  settle() {
    if (this.items.length === 0) return;
    let best = this.items[0];
    for (const item of this.items.slice(1)) {
      if (compareStageFailures(item, best) < 0) best = item;
    }
    throw new NonMeasurement(best.reason, best.detail, best.jsonPointer);
  }
}

export function compareStageFailures(a, b) {
  if (a.rank !== b.rank) return a.rank < b.rank ? -1 : 1;
  const byPath = byteCompare(a.pathKey, b.pathKey);
  if (byPath !== 0) return byPath;
  // Level three, and only where the reason carries an EMITTED locator. Two
  // numbers in one artifact both outside the section 5.1 envelope share a
  // stage, a reason and a path, and numeric-preflight-violation carries a
  // normative json_pointer -- so without this the selection would be
  // observable and unpinned.
  //
  // BYTE order, not numeric order: /a/10 sorts before /a/9 because "1"
  // precedes "9" as a byte. That is deliberate. A rule that compared array
  // indices numerically would have to parse them, which invites the two lanes
  // to disagree about what is an index.
  const ap = a.jsonPointer;
  const bp = b.jsonPointer;
  if (typeof ap === "string" && typeof bp === "string") return byteCompare(ap, bp);
  if (typeof ap === "string") return -1;
  if (typeof bp === "string") return 1;
  return 0;
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
// 5. Ruling AD15-IR-20 -- the JSON byte domain, and the document scanner
// ---------------------------------------------------------------------------

// Section 5's byte rule, BEFORE any parse. The encoding of manifest.json and of
// every listed artifact and operator-input JSON file is constrained:
//
//   - UTF-8 only;
//   - no UTF-8 BOM;
//   - no UTF-16 or UTF-32 acceptance;
//   - decoding must be strict and lossless;
//   - malformed UTF-8 is rejected;
//   - replacement decoding with U+FFFD is forbidden;
//   - bytes are never repaired or transcoded into acceptance.
//
// A BOM is called out separately because it is the case a lenient runtime most
// often accepts silently: one lane strips it and parses, the other rejects, and
// the divergence is invisible until a corpus carries one. Node's default
// TextDecoder STRIPS a UTF-8 BOM and substitutes U+FFFD for malformed input --
// exactly the two repairs the ruling forbids -- so the decoder below is
// constructed with `fatal` and `ignoreBOM` and the BOM is then rejected
// explicitly rather than consumed.
//
// The UTF-16 and UTF-32 forms are detected by their byte order marks first,
// because that is what makes the rejection say the true thing. Without the
// sniff a UTF-16BE document would still be refused -- 0x00 is a legal UTF-8
// byte, so it decodes to a string full of NULs that JSON.parse then rejects --
// but it would be refused for the wrong stated cause. The BOM-less forms
// remain refused by one of the two paths; neither is ever accepted.
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function checkJsonByteDomain(buf) {
  if (buf.length >= 4
      && buf[0] === 0xFF && buf[1] === 0xFE && buf[2] === 0x00 && buf[3] === 0x00) {
    return "carries a UTF-32LE byte order mark; the JSON byte domain is UTF-8 only";
  }
  if (buf.length >= 4
      && buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0xFE && buf[3] === 0xFF) {
    return "carries a UTF-32BE byte order mark; the JSON byte domain is UTF-8 only";
  }
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    return "carries a UTF-16LE byte order mark; the JSON byte domain is UTF-8 only";
  }
  if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    return "carries a UTF-16BE byte order mark; the JSON byte domain is UTF-8 only";
  }
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    return "carries a UTF-8 byte order mark; a BOM is not stripped and not accepted";
  }
  try {
    STRICT_UTF8.decode(buf);
  } catch (e) {
    return `is not strictly decodable as UTF-8: ${e.message}`;
  }
  return null;
}

// Decodes bytes already accepted by checkJsonByteDomain. Kept separate so no
// call site can decode without having checked.
export function decodeAcceptedJsonBytes(buf) {
  return STRICT_UTF8.decode(buf);
}

// RFC 8785 requires its input's strings to be valid Unicode. Strict JSON admits
// an escape such as \ud800 with no pair, which does not encode to well-formed
// UTF-8, so such a document PARSES CLEANLY AND STILL HAS NO CANONICAL FORM.
// Section 5's stage-8 table assigns it: bundle-json-invalid, and NEVER repair
// by substituting U+FFFD or dropping the code unit.
export function hasUnpairedSurrogate(str) {
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      const next = i + 1 < str.length ? str.charCodeAt(i + 1) : -1;
      if (next >= 0xDC00 && next <= 0xDFFF) { i++; continue; }
      return true;
    }
    if (c >= 0xDC00 && c <= 0xDFFF) return true;
  }
  return false;
}

// The document has already been accepted by JSON.parse before this runs. The
// scanner re-walks the SOURCE TEXT to recover three things the parsed value can
// no longer answer:
//
//  1. each number's SOURCE SPELLING and RFC 6901 location -- an integer beyond
//     2^53-1 is already destroyed by the time JSON.parse returned it, and
//     section 8.2.2 makes the offending pointer a mandatory member;
//  2. DUPLICATE OBJECT MEMBER NAMES -- JSON.parse keeps the last occurrence, so
//     the decoded object shows one member and the defect is invisible;
//  3. UNPAIRED SURROGATES in any string, member names included.
//
// On (2), ruling AD15-IR-17 and E7-22 are the same rule at two layers, and both
// exist because relying on a runtime default is not a rule, it is a coincidence
// that two implementations currently agree. Two lanes could canonicalize
// {"k":1} and {"k":2} from the same bytes and emit DIFFERENT
// request_envelope_digest values WHILE BOTH REPORTED SUCCESS -- divergent
// evidence over identical input with no error raised. Detection happens WHILE
// PARSING, before any value is taken from the decoded object.

function pointerEscape(token) {
  return String(token).replace(/~/g, "~0").replace(/\//g, "~1");
}

export function scanJsonDocument(text) {
  const numbers = [];
  // { objectPointer, name } -- objectPointer "" is the top-level object, which
  // is the distinction AD15-IR-17 turns on.
  const duplicates = [];
  const surrogates = [];
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
          // Left as a raw code unit on purpose: a lone \ud800 must SURVIVE into
          // the scanned value so hasUnpairedSurrogate can see it. Repairing it
          // here is the failure mode the ruling forbids.
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
  function noteString(pointer, value) {
    if (hasUnpairedSurrogate(value)) surrogates.push(pointer);
  }
  function parseValue(pointer) {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; ws();
      if (text[i] === "}") { i++; return; }
      const seen = new Set();
      for (;;) {
        ws();
        const key = parseString();
        noteString(pointer + "/" + pointerEscape(key), key);
        if (seen.has(key)) duplicates.push({ objectPointer: pointer, name: key });
        seen.add(key);
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
    if (c === '"') { const v = parseString(); noteString(pointer, v); return; }
    if (c === "t") { literal("true"); return; }
    if (c === "f") { literal("false"); return; }
    if (c === "n") { literal("null"); return; }
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (m === null) fail("unexpected token");
    numbers.push({ pointer, token: m[0] });
    i += m[0].length;
  }

  parseValue("");
  ws();
  if (i !== n) fail("trailing content");
  return { numbers, duplicates, surrogates };
}

// Retained as the narrow view the numeric preflight and its regression tests
// use. It is a projection of the scan above, not a second walker.
export function scanJsonNumbers(text) {
  return scanJsonDocument(text).numbers;
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

// Ruling AD15-IR-19 -- the path grammar is LEXICAL and CLOSED.
//
// "Bundle-relative and normalized" named a property without saying how to test
// it, and "normalized" invites an evaluator to normalize a path INTO
// acceptance. The grammar is exact:
//
//   path    = segment *("/" segment)
//   segment = 1*(ALPHA / DIGIT / "." / "_" / "-")
//
// with all of the following also required: no segment equal to "." or "..";
// no leading slash; no trailing slash; no empty segment; no doubled slash; no
// backslash; no colon or drive prefix; no NUL or control character; no
// non-ASCII character; NO NORMALIZATION OR REPAIR.
//
//   A path is accepted only when its ORIGINAL JSON STRING already satisfies the
//   canonical grammar. An evaluator never normalizes a path into acceptance.
//
// The single character-class test carries most of the list by construction: a
// colon, a backslash, a NUL, a control character and every non-ASCII character
// -- an unpaired surrogate included -- are all outside the segment charset, so
// none of them needs a separate rule and none can be reached by a repair. The
// conditions that are NOT expressible as a charset (empty segment, "." / "..",
// leading and trailing and doubled slash) are tested explicitly below.
//
// A violation is manifest-invalid at STAGE 4: it is a property of the manifest
// document, testable before the filesystem is consulted.
//
// The superseded implementation used path.posix/path.win32 helpers and a
// "normalized" reading. Those are libraries that answer questions about paths;
// this is a lexical grammar over a JSON string, and the two are not the same
// test -- a helper that reports "a.json/" and "a.json" as the same path is
// answering the wrong question.
const PATH_SEGMENT = /^[A-Za-z0-9._-]+$/;

export function checkBundlePath(p) {
  if (typeof p !== "string") return "path must be a string";
  if (p.length === 0) return "path must not be empty";
  if (p.startsWith("/")) return "path must not have a leading slash";
  if (p.endsWith("/")) return "path must not have a trailing slash";
  if (p.includes("//")) return "path must not contain a doubled slash";
  for (const seg of p.split("/")) {
    if (seg.length === 0) return "path must not contain an empty segment";
    if (seg === ".") return 'path must not contain a "." segment';
    if (seg === "..") return 'path must not contain a ".." segment';
    if (!PATH_SEGMENT.test(seg)) {
      return `segment ${JSON.stringify(seg)} is outside the canonical grammar `
        + '1*(ALPHA / DIGIT / "." / "_" / "-")';
    }
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
//
// Erratum 5 (E5-4) SPLITS this function in two, and the split is the whole
// point of the pinned preflight order in section 8.2.1. Establishing identity
// and validating the manifest's STRUCTURE are now separate steps, because the
// frozen-identity read has to happen BETWEEN them:
//
//   1. readManifestIdentity() -- the section 5 direct read; identity or exit 1;
//   2. readFrozenIdentity()   -- immediately afterwards, before any other
//                                post-identity preflight;
//   3. validateManifestStructure() -- closure, sort, role, path, digest
//                                encoding; part of "the remaining preflight".
//
// Keeping structure inside the identity function would have put every manifest
// rule ahead of step 2, and section 8.2.1 requires that EVERY post-identity
// result carry a populated verifier_digests. A manifest-invalid result emitted
// before the frozen pair was read would have carried null instead -- which the
// contract reserves for frozen-identity-unreadable alone.
export function readManifestIdentity(bundleDir) {
  const manifestPath = path.join(bundleDir, MANIFEST_NAME);
  let buf;
  try {
    buf = fs.readFileSync(manifestPath);
  } catch (e) {    // Conditions 1-3 of the E4-2 enumeration arrive here as one failed read:
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

  // Ruling AD15-IR-20, MANIFEST SIDE. The byte domain is checked BEFORE any
  // parse, and the two files sit on opposite sides of the identity boundary:
  // a manifest whose bytes are outside the domain yields NO IDENTITY, so it is
  // exit 1 with empty stdout, while a listed file lands on bundle-json-invalid
  // at stage 8. Reporting a reason here would require an identity this
  // evaluator does not have.
  const byteViolation = checkJsonByteDomain(buf);
  if (byteViolation !== null) {
    throw new IdentityError(`${MANIFEST_NAME} ${byteViolation}`);
  }
  const text = decodeAcceptedJsonBytes(buf);

  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new IdentityError(`${MANIFEST_NAME} is not parseable as strict JSON: ${e.message}`);
  }
  if (!isPlainObject(doc)) {
    throw new IdentityError(`${MANIFEST_NAME} is not a JSON object; no scenario_id is obtainable`);
  }

  // Ruling AD15-IR-17 -- duplicate manifest member names, detected WHILE
  // PARSING and before any value is taken from the decoded object.
  //
  // RFC 8259 permits an object to repeat a member name and BOTH runtimes decode
  // such an object last-wins by default. This lane's superseded register
  // recorded that as "left as the library default deliberately" -- which the
  // ruling names as the same defect as relying on traversal order: it is not a
  // rule, it is a coincidence that two implementations currently agree. So the
  // decoded object above is NOT trusted to answer "was scenario_id repeated";
  // the scan below is.
  //
  // The NESTING DISTINCTION is the point:
  //
  //  * only a duplicate TOP-LEVEL scenario_id enters the exit-1 band -- no
  //    registered scenario_id is DETERMINISTICALLY obtainable, which is already
  //    the fifth condition of the section 5 direct-read identity boundary. It
  //    adds no new condition to that band;
  //  * a scenario_id duplicated inside files[] or any other NESTED object does
  //    NOT erase a valid top-level identity. It is manifest-invalid at stage 4;
  //  * ANY OTHER duplicated member is likewise manifest-invalid at stage 4.
  //
  // Reading a nested scenario_id as identity-destroying would let a member
  // buried in files[] suppress a result object the evaluator can perfectly well
  // produce -- exactly the exit-1/exit-3 confusion AD15-IR-8 exists to prevent.
  let scan;
  try {
    scan = scanJsonDocument(text);
  } catch (e) {
    // JSON.parse accepted it, so this walker disagreeing is a fault in the
    // walker, not in the manifest. There is still no identity to name, so the
    // exit-1 band applies rather than a fabricated reason.
    throw new IdentityError(
      `${MANIFEST_NAME} parsed but could not be re-scanned for duplicate members: ${e.message}`);
  }
  const topLevelDuplicates = scan.duplicates.filter((d) => d.objectPointer === "");
  if (topLevelDuplicates.some((d) => d.name === "scenario_id")) {
    throw new IdentityError(
      `${MANIFEST_NAME} repeats the top-level member "scenario_id"; no registered scenario_id `
      + "is deterministically obtainable, so bundle identity is not established -- the "
      + "runtime's last-wins default is not a rule and is not consulted");
  }

  if (typeof doc.scenario_id !== "string" || !SCENARIOS.has(doc.scenario_id)) {
    throw new IdentityError(
      "manifest carries no usable scenario_id from the registered twelve; bundle identity unknown");
  }
  // ---- bundle identity is ESTABLISHED, and by ruling AD15-IR-8 (Erratum 5,
  // ---- E5-1) that establishment is MONOTONIC: no later filesystem, traversal
  // ---- or preflight failure can retroactively unestablish it. Every failure
  // ---- from here on owes a result object NAMING THIS SCENARIO at exit 3
  // ---- (section 8.5), never the exit-1 silence band.
  //
  // `duplicates` is carried forward so stage 4 can report every remaining
  // duplicate -- nested scenario_id included -- against this scenario.
  return { doc, scenarioId: doc.scenario_id, manifestPath, duplicates: scan.duplicates };
}

// STAGE 4 -- manifest structure and closure (section 8.6).
//
// Reached only after identity is established AND the frozen identity pair has
// been read, so every failure below carries a populated verifier_digests.
//
// Stage 4 and stage 5 both produce manifest-invalid and the split is
// deliberate: stage 4 is MANIFEST-OBJECT closure -- rules the JSON document
// violates on its own terms (unknown members, sort, role, path syntax, digest
// encoding, duplicate members) -- while stage 5 is FILESYSTEM LAYOUT closure. A
// manifest that is malformed on its own terms is reported before the disk is
// consulted.
//
// Every candidate is COLLECTED and the stage barrier selects one. The
// superseded implementation threw at the first violation in manifest order,
// which is a reading of "the first failure" that depends on iteration order
// rather than on the pinned key.
export function validateManifestStructure(doc, duplicates = []) {
  const f = new StageFailures(STAGE.MANIFEST_STRUCTURE);

  // Ruling AD15-IR-17, the stage-4 half. A top-level duplicate scenario_id
  // never reaches here -- it was the exit-1 band. Everything else is here,
  // including a nested scenario_id, which does NOT erase a valid top-level
  // identity and therefore owes a result object.
  for (const d of duplicates) {
    if (d.objectPointer === "" && d.name === "scenario_id") continue;
    f.add("manifest-invalid", "",
      `manifest object at ${d.objectPointer === "" ? "the top level" : d.objectPointer} `
      + `repeats the member ${JSON.stringify(d.name)}; a repeated member name is not resolved `
      + "by the parser's first-wins or last-wins default");
  }

  const closure = closedMemberViolation(doc, MANIFEST_MEMBERS);
  if (closure !== null) {
    f.add("manifest-invalid", "", `manifest object is not closed: ${closure}`);
  }
  if (doc.manifest_version !== "1") {
    f.add("manifest-invalid", "",
      `manifest_version must be the string "1", got ${JSON.stringify(doc.manifest_version)}`);
  }
  if (!Array.isArray(doc.files)) {
    f.add("manifest-invalid", "", "files must be an array");
    f.settle();
    // settle() always throws when anything was added, so this is unreachable;
    // it is present so the function has no path that returns an entry list
    // built from a non-array.
    return [];
  }

  const entries = [];
  const seen = new Set();
  let previous = null;
  for (let idx = 0; idx < doc.files.length; idx++) {
    const entry = doc.files[idx];
    if (!isPlainObject(entry)) {
      f.add("manifest-invalid", "", `files[${idx}] is not an object`);
      continue;
    }
    // The entry's own path is its internal key when it has a usable one, and
    // the empty string otherwise. The key is never emitted -- manifest-invalid
    // carries no locator -- so where an entry has no usable path the selection
    // among same-stage failures is unobservable, which section 8.6 states as an
    // explicit exemption rather than leaving it to discovery order.
    const key = typeof entry.path === "string" ? entry.path : "";
    const entryClosure = closedMemberViolation(entry, FILE_ENTRY_MEMBERS);
    if (entryClosure !== null) {
      f.add("manifest-invalid", key, `files[${idx}] is not closed: ${entryClosure}`);
    }
    const pathViolation = checkBundlePath(entry.path);
    if (pathViolation !== null) {
      f.add("manifest-invalid", key,
        `files[${idx}].path ${JSON.stringify(entry.path)}: ${pathViolation}`);
    }
    if (typeof entry.role !== "string" || !ROLES.has(entry.role)) {
      f.add("manifest-invalid", key,
        `files[${idx}].role ${JSON.stringify(entry.role)} is outside the closed role set`);
    }
    // Bare 64 lowercase hex, deliberately NOT the "sha256:..." wire form.
    if (typeof entry.sha256 !== "string" || !HEX64.test(entry.sha256)) {
      f.add("manifest-invalid", key,
        `files[${idx}].sha256 must be exactly 64 lowercase hex characters with no prefix`);
    }
    if (typeof entry.path === "string") {
      if (seen.has(entry.path)) {
        f.add("manifest-invalid", key, `files[] lists ${entry.path} more than once`);
      }
      if (previous !== null && byteCompare(previous, entry.path) >= 0) {
        f.add("manifest-invalid", key,
          "files[] must be sorted ascending by path in UTF-8 byte order: "
          + `${previous} precedes ${entry.path}`);
      }
      seen.add(entry.path);
      previous = entry.path;
    }
    if (pathViolation === null && entryClosure === null) {
      entries.push({ path: entry.path, role: entry.role, sha256: entry.sha256 });
    }
  }

  f.settle();
  return entries;
}

// STAGE 5 -- canonical traversal, layout closure and listed-file presence.
//
// One stage, one barrier, four mechanisms in the pinned precedence order:
// bundle-entry-uninspectable, bundle-directory-unreadable, manifest-invalid,
// bundle-file-missing. Everything is COLLECTED and the barrier selects one, so
// an uninspectable entry found late still outranks a missing file found early.
//
// TRAVERSAL ORDER IS NEVER THE OPERATING SYSTEM'S. readdir order is unspecified
// and varies by filesystem, so a lane reporting the first failure in
// enumeration order is not deterministic. Every directory's entries are sorted
// before that directory is inspected or descended into.
//
// THE SORT KEY IS PLATFORM-NEUTRAL (E7-24). "Raw bytes" alone is a POSIX-shaped
// rule; the key is defined over what the API actually provides:
//
//   * lossless raw name bytes  -> those bytes, compared as unsigned bytes;
//   * a Unicode-native name    -> the UTF-8 encoding of the exact string
//                                 returned, with NO normalization;
//   * a name that cannot be represented losslessly, or that carries an unpaired
//     surrogate -> it cannot equal any manifest `path`, which is a JSON string,
//     so it is an UNLISTED ENTRY and a deterministic manifest-invalid here.
//
// This runtime is the first bullet: readdirSync with encoding "buffer" returns
// the name bytes the operating system supplied, and Buffer.compare is unsigned
// byte order. Buffer names are used for the lstat path too, so nothing is
// round-tripped through a string that could lose or normalize a byte.
//
// NFC/NFD conversion, case folding, locale-dependent mapping and any
// platform-specific name normalization are FORBIDDEN, here and anywhere else a
// name is compared. A normalizing key makes two byte-distinct entries collide
// on one platform and not on another -- the cross-platform determinism defect
// AD15-IR-9 exists to close, reintroduced one layer down.
//
// AD15-IR-9: for EVERY enumerated entry a separate NO-FOLLOW metadata lookup is
// performed. A type hint obtained during enumeration -- d_type, Dirent.isFile()
// and their equivalents -- is not kind evidence on its own: those APIs may
// answer from a value the directory read happened to carry, without performing
// any metadata lookup on the entry itself, and they can only answer that way on
// filesystems that populate it. So this walk does not request Dirents at all;
// it requests names and calls lstat itself.
const NAME_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function traverseBundle(bundleDir, manifestEntries) {
  const f = new StageFailures(STAGE.TRAVERSAL);
  const onDisk = [];
  const listed = new Set(manifestEntries.map((e) => e.path));
  const dirBuf = Buffer.from(bundleDir);
  const SEP = Buffer.from(path.sep);

  // Depth-first, but the ORDER within each directory is the sorted name key,
  // and the queue is processed in sorted order too, so the whole traversal is a
  // function of the bundle rather than of the medium.
  const queue = [{ rel: "", abs: dirBuf }];
  while (queue.length > 0) {
    const { rel, abs } = queue.shift();
    let names;
    try {
      names = fs.readdirSync(abs, { encoding: "buffer" });
    } catch (e) {
      // AD15-IR-8 / E4-3. Identity is already established -- readManifestIdentity
      // read DIR/manifest.json DIRECTLY -- so what failed here is the
      // MEASUREMENT of the layout, not the layout itself. bundle-file-missing
      // would be false (nothing is known to be absent) and manifest-invalid
      // would be false (no rule is known to be broken).
      f.add("bundle-directory-unreadable", rel,
        `bundle traversal could not enumerate ${rel === "" ? "the bundle root" : rel}: ${e.message}`);
      continue;
    }
    names.sort(Buffer.compare);
    for (const nameBuf of names) {
      const childAbs = Buffer.concat([abs, SEP, nameBuf]);
      let name = null;
      try {
        name = NAME_DECODER.decode(nameBuf);
        if (hasUnpairedSurrogate(name)) name = null;
      } catch { name = null; }
      const childRel = name === null ? null : (rel === "" ? name : `${rel}/${name}`);

      // lstat, never stat: a link must be CLASSIFIED, never followed. The kind
      // question is separate from the name question and can fail on its own.
      let st;
      try {
        st = fs.lstatSync(childAbs);
      } catch (e) {
        f.add("bundle-entry-uninspectable", childRel ?? "",
          `directory entry ${childRel ?? nameBuf.toString("latin1")} was enumerated, but its `
          + `filesystem kind could not be determined: ${e.message}`);
        continue;
      }
      if (childRel === null) {
        // A manifest `path` is a JSON string, so no entry whose name is not
        // losslessly representable can ever be listed in files[]. It is an
        // unlisted entry, reported by this stage's layout closure exactly as
        // any other unlisted entry is.
        f.add("manifest-invalid", "",
          "bundle carries a directory entry whose name is not representable as a "
          + "well-formed JSON string, so it cannot be listed in files[]");
        continue;
      }
      if (st.isSymbolicLink()) {
        // Forbidden even when the target resolves inside the bundle: a digest
        // over a link's target is not a digest over the bundle's own bytes.
        f.add("manifest-invalid", childRel,
          `symbolic links are forbidden anywhere under the bundle: ${childRel}`);
        continue;
      }
      if (st.isDirectory()) {
        queue.push({ rel: childRel, abs: childAbs });
        continue;
      }
      if (st.isFile()) {
        // The root manifest.json is excluded from files[] by section 5 (it
        // cannot hash itself), so it is excluded from the disk side of the
        // closure check as well. A NESTED file of the same name is an ordinary
        // bundle file and IS listed.
        if (childRel === MANIFEST_NAME) continue;
        onDisk.push(childRel);
        if (!listed.has(childRel)) {
          f.add("manifest-invalid", childRel,
            `regular file present under the bundle but absent from files[]: ${childRel}`);
        }
        continue;
      }
      // Erratum 2 enumerates "a FIFO, socket, device or any other non-regular,
      // non-directory object under the bundle" as manifest-invalid. Fail closed
      // on all of them: ignoring one would leave unhashed bytes inside a bundle
      // whose manifest claims to cover every byte.
      f.add("manifest-invalid", childRel,
        `bundle carries a non-regular, non-directory object: ${childRel}`);
    }
  }

  // Listed-file presence, in the same stage: the section 8.6 table places
  // bundle-file-missing at stage 5, after the layout mechanisms and before any
  // read is attempted.
  const onDiskSet = new Set(onDisk);
  for (const entry of manifestEntries) {
    if (onDiskSet.has(entry.path)) continue;
    // Two failures that both merely LOOK like "absent from the walk", split
    // normatively rather than by inference:
    //
    //  * a files[] entry whose target is NOT A PERMITTED FILE KIND is a
    //    bundle-layout violation -> manifest-invalid;
    //  * a files[] entry with nothing on disk at all -> bundle-file-missing.
    //
    // Directories are containers only and are never files[] entries, so a
    // directory named by files[] falls in the first band, not the second: it is
    // present, and it is the wrong kind.
    let st = null;
    try {
      st = fs.lstatSync(path.join(bundleDir, entry.path));
    } catch { /* nothing at that path at all */ }
    if (st !== null) {
      const kind = st.isDirectory() ? "a directory"
        : st.isSymbolicLink() ? "a symbolic link"
        : st.isFIFO() ? "a FIFO"
        : st.isSocket() ? "a socket"
        : st.isBlockDevice() ? "a block device"
        : st.isCharacterDevice() ? "a character device"
        : "an object that is not a regular file";
      f.add("manifest-invalid", entry.path,
        `files[] entry ${entry.path} names ${kind}; a files[] target must be a regular file, `
        + "and directories are containers only -- never files[] entries");
      continue;
    }
    f.add("bundle-file-missing", entry.path,
      `files[] lists ${entry.path} but no such file is present under the bundle`);
  }

  f.settle();
  onDisk.sort(byteCompare);
  return onDisk;
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

// Section 8.2.1, frozen-identity preflight, in the order Erratum 5 (E5-4)
// pinned. It runs as step 2 -- IMMEDIATELY after bundle identity, before any
// other post-identity preflight -- and it separates READ failure from MATCH
// failure, which the superseded implementation conflated:
//
//   3. if EITHER file cannot be read -> frozen-identity-unreadable,
//      verifier_digests NULL, artifacts [];
//   4. if both are read, the exact two-entry object is built from the
//      RECOMPUTED values;
//   5. if a recomputed value does not match its pin -> verifier-digest-mismatch,
//      and the ACTUAL recomputed two-entry object is RETAINED -- a reader needs
//      to see what was actually there, not what was expected.
//
// The old code returned a two-entry object with null members for an unreadable
// file and reported it as a MISMATCH. Both halves were wrong: it fabricated a
// placeholder digest for a file it never read, and it asserted a comparison it
// never performed. Absence is represented by absence.
//
// The peer lane's verifier digest is absent by construction -- there is no
// constant for it in this file and no code path that could emit one.
//
// `setDigests` receives the two-entry object the moment BOTH reads succeed, so
// a subsequent mismatch still carries the recomputed values into the result.
function readFrozenIdentity(verifierPath, contractPath, setDigests) {
  const checks = [
    ["class_verifier", verifierPath, PINNED_VERIFIER_DIGEST],
    ["class_verifier_contract", contractPath, PINNED_VERIFIER_CONTRACT_DIGEST],
  ];

  // ---- step 3: read both, or fail without inventing a digest --------------
  const hexes = {};
  const unreadable = [];
  for (const [key, file] of checks) {
    try {
      hexes[key] = sha256Hex(fs.readFileSync(file));
    } catch (e) {
      unreadable.push(`${key} at ${file}: ${e.message}`);
    }
  }
  if (unreadable.length > 0) {
    // verifier_digests stays null: setDigests is deliberately NOT called.
    throw new NonMeasurement("frozen-identity-unreadable",
      "this lane's own frozen identity could not be read, so its digest cannot be recomputed: "
      + unreadable.join("; "));
  }

  // ---- step 4: the exact two-entry object, from RECOMPUTED values ---------
  setDigests({
    class_verifier: "sha256:" + hexes.class_verifier,
    class_verifier_contract: "sha256:" + hexes.class_verifier_contract,
  });

  // ---- step 5: compare; the recomputed object is already retained ---------
  const mismatches = checks
    .filter(([key, , pinned]) => hexes[key] !== pinned)
    .map(([key, , pinned]) => `${key}: pinned sha256:${pinned}, observed sha256:${hexes[key]}`);
  if (mismatches.length > 0) {
    throw new NonMeasurement("verifier-digest-mismatch",
      `frozen-verifier identity assertion failed: ${mismatches.join("; ")}`);
  }
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
  // Ruling AD15-IR-18 -- THE GATE THIS CONTRACT ADDS.
  //
  // artifact_ref is a Class-1 cross-lane equality field (section 8.7) and an
  // open nested object cannot be one. The frozen class-verifier contract
  // enumerates artifact_ref without declaring that nested object CLOSED, so
  // without this obligation one evaluator could accept an extra member and copy
  // it verbatim while another rejected the verdict -- and the two would emit
  // different values for the same input while both reported success.
  //
  // The closure is enforced HERE, at the result-shape gate, so the Source-A
  // copy downstream is verbatim over a value ALREADY KNOWN to be closed. A
  // rejection is verifier-run-invalid, which section 8.2.2 defines as a shape
  // rejected by EITHER contract precisely so this case has a registry entry;
  // narrowing it to the frozen contract alone would have left it with none.
  //
  // E8-3 -- A BEHAVIOURAL CHANGE IN THIS LANE. The gate was previously CLOSED
  // but not REQUIRED or TYPED: an ABSENT artifact_ref, a NULL one, and one with
  // no record_id at all were all accepted and then silently converted to null on
  // the emitted entry. This lane read it that way and the peer lane did not --
  // on a Class-1 field.
  //
  // Whether an omitted artifact_ref is FROZEN-conforming is not settled by the
  // frozen text: frozen section 6's verdict-envelope shape gates do not include
  // artifact_ref presence, and common.schema.json constrains an artifact_ref
  // VALUE rather than making the member required. W1 requires it ON ITS OWN
  // AUTHORITY, because artifact_ref is a Class-1 cross-lane equality field and a
  // field two implementations must agree on cannot be optional. section 8.2.2
  // already defines verifier-run-invalid as a shape rejected by EITHER contract,
  // so a frozen-conforming verdict that W1 rejects has both a reason and a
  // defined outcome. There is no repair and no coercion.
  if (!("artifact_ref" in verdict)) {
    return "artifact_ref is absent; W1 requires it on every accepted verdict, because it is a "
      + "Class-1 cross-lane equality field and cannot be optional";
  }
  const ref = verdict.artifact_ref;
  if (ref === null || !isPlainObject(ref)) {
    return "artifact_ref is present but is not a JSON object";
  }
  for (const k of Object.keys(ref)) {
    if (k !== "record_id" && k !== "chain_id") {
      return `artifact_ref carries the member ${JSON.stringify(k)}; W1 closes that object `
        + "to record_id and chain_id";
    }
  }
  if (!("record_id" in ref)) return "artifact_ref.record_id is absent";
  if (typeof ref.record_id !== "string") {
    return "artifact_ref.record_id is present but is not a string";
  }
  if ("chain_id" in ref && typeof ref.chain_id !== "string") {
    return "artifact_ref.chain_id is present but is not a string";
  }
  return null;
}

// Ruling AD15-IR-18 -- the closed artifact_ref projection, ONE FUNCTION, TOTAL
// over every JSON value. It was described only as "the structured reference
// when a usable record_id exists", which left two lanes to invent the same
// object from the same artifact by luck.
//
//   1. If value is not a JSON object, return null.
//   2. If value.record_id is not a JSON string, return null.
//   3. Otherwise return an object containing exactly "record_id", and, only
//      when value.chain_id is a JSON string, "chain_id".
//   4. A missing or non-string chain_id is OMITTED, never represented as null.
//   5. Empty strings remain strings; no minLength rule is added that the frozen
//      schema does not have.
//   6. No coercion, Unicode normalization, case mapping, repair, synthesis or
//      stringification is permitted.
//
// Step 4 matters because an omitted member and a null member are different JSON
// values and therefore different RFC 8785 canonical bytes -- which is what
// harness duty 6 compares. Step 6 restates AD15-IR-5's absolute bar on
// synthesizing a record_id, extended to every form of quiet repair.
export function artifactRefFromArtifact(value) {
  if (!isPlainObject(value)) return null;
  if (typeof value.record_id !== "string") return null;
  const ref = { record_id: value.record_id };
  if (typeof value.chain_id === "string") ref.chain_id = value.chain_id;
  return ref;
}

// Ruling AD15-IR-15 -- THREE process outcomes, distinguished. The superseded
// two-way split (started / did not start) forced the middle row into the same
// shape as a spawn failure, which discards the evidence of a run that genuinely
// happened.
//
//   | what happened            | artifacts[] entry | exit_code | result | stderr |
//   | never started            | NONE              | n/a       | n/a    | n/a    |
//   | started, no normal exit  | PRESENT           | null      | null   | present|
//   | exited normally          | PRESENT           | integer   | verdict/null | present |
//
// A frozen verifier killed by a signal plainly STARTED, so it is
// verifier-run-invalid -- but there is no portable integer to put in
// verifier_exit_code. Runtimes disagree: one reports signal death as a negative
// return code, another reports no status at all plus a separate signal name. An
// entry demanding an integer "verbatim" would force this lane to fabricate a
// value or classify the run differently from its peer.
//
// NO SIGNAL NAME, SIGNAL NUMBER OR SYNTHESIZED EXIT CODE reaches any normative
// field. The signal is useful to a human, so it may appear in
// nonmeasurement.detail, which section 8.7 places in Class 4 (diagnostic-only,
// never compared). The prohibition is on letting a signal reach a field
// anything compares.
//
// spawnSync reports both the never-started and the abnormal bands through
// `error`, so `error` alone cannot discriminate them. `pid` can, and that was
// MEASURED on this runtime rather than assumed: a spawn that never happened
// returns pid 0 with error ENOENT, while a process that started and was then
// killed for exceeding maxBuffer (ENOBUFS) or for a timeout (ETIMEDOUT) carries
// a real pid. `status === null` is then exactly "started and did not exit
// normally".
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
      outcome: "never-started",
      reason: "verifier-not-invocable",
      detail: "frozen verifier could not be spawned or executed at all: "
        + `${proc.error ? proc.error.message : "no process was created"}`,
    };
  }
  if (proc.status === null || proc.status === undefined) {
    return {
      outcome: "abnormal-termination",
      reason: "verifier-run-invalid",
      detail: `frozen verifier started (pid ${proc.pid}) and did not exit normally`
        + `${proc.signal ? ` (terminated by ${proc.signal})` : ""}`
        + `${proc.error ? `: ${proc.error.message}` : ""}`
        + " -- there is no portable exit code, so verifier_exit_code and verifier_result "
        + "are both null and no value is synthesized",
    };
  }
  return { outcome: "exited-normally", reason: null, detail: null };
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

// Returns the classification rather than throwing it. AD15-IR-15 makes the
// abnormal-termination row ENTRY-BEARING, so the caller has to record an entry
// BEFORE it decides to abort -- which it cannot do if the failure has already
// unwound the stack.
function runFrozenVerifier(verifierPath, requestPath, operatorArgs) {
  const args = [verifierPath, "--request", requestPath, ...operatorArgs];
  const proc = spawnSync(process.execPath, args, { encoding: "buffer", maxBuffer: 256 * 1024 * 1024 });
  const shape = classifyProcessShape(proc);
  return {
    outcome: shape.outcome,
    reason: shape.reason,
    detail: shape.detail,
    // null for every outcome but "exited-normally"; never synthesized.
    exitCode: shape.outcome === "exited-normally" ? proc.status : null,
    stdout: proc.stdout ?? Buffer.alloc(0),
    // stderr is hashed for audit only. It is NEVER parsed, matched on, or
    // allowed to influence a predicate, verdict or status (section 8.3). An
    // abnormally terminated process still wrote whatever it wrote, so its
    // digest is over the bytes actually captured -- that is the evidence of a
    // run that genuinely happened.
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

// Section 7.1, as rewritten by Erratum 5 (E5-5): the rule is SCENARIO-
// INDEPENDENT.
//
// The superseded wording was "for any artifact the scenario expects to reach
// AIREP-Authenticated", which presumes a per-scenario expected-tier table NO
// EVALUATOR HAS, AND NONE SHOULD HAVE: consulting an expected-outcome oracle is
// exactly what a measuring instrument must not do. The replacement needs no
// table at all:
//
//   on the mandatory W1 surface, ANY emitted frozen-verifier verdict carrying a
//   non-empty authenticated_withheld channel makes the scenario
//   MEASUREMENT_INVALID, REGARDLESS OF SCENARIO ID.
//
// That is why this function takes ONLY the withheld channel records. It has no
// scenario_id parameter, no expected-tier table and no way to reach one -- the
// oracle is removed structurally, not merely left unused. Re-introducing the
// dependency would require changing this signature, which is the property the
// discrimination test in the self-test measures.
//
// The rule is sound on this surface because of how the mandatory twelve are
// built: operator inputs are complete by construction, no mandatory scenario
// targets Authenticated-withheld behaviour, stage-0/stage-1 invalid artifacts
// emit no verdict at all (section 7.2 handles those), and IOP-B-EXE targets a
// definitive authenticated_failures rather than a withheld channel. So a
// withheld channel here means the MEASUREMENT INFRASTRUCTURE or the operator
// inputs failed -- never a scenario's semantic outcome.
//
// It does NOT extend to witnessed_withheld: W1 carries no witness, so
// no-witness-supplied is an ordinary diagnostic surface, not a measurement
// failure. Hence the channel filter below is exact.
//
// Withheld is neither REJECT (nothing was refused) nor ACCEPT (nothing was
// established). Treating it as ACCEPT would let a corpus shipped with a broken
// binding store report twelve green results while measuring almost nothing.
export function authenticatedWithheldViolation(withheldReasons) {
  const withheldAuth = withheldReasons.filter((w) => w.channel === "authenticated_withheld");
  if (withheldAuth.length === 0) return null;
  // AD15-IR-16 entry shape: one entry per reason string, so the detail is
  // assembled from entries rather than from an array member that no longer
  // exists. detail is Class-4 diagnostic-only and is never compared.
  const named = withheldAuth
    .map((w) => `${w.artifact_path}: ${w.reason}`)
    .join("; ");
  return new NonMeasurement("authenticated-withheld",
    `the Authenticated tier could not be evaluated -- ${named}; fix the operator inputs and `
    + "re-run rather than scoring this scenario");
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

// The former local artifactRef() helper is GONE, not left unused. AD15-IR-18
// replaces it with one exported total function, artifactRefFromArtifact(), and
// two definitions of the same projection is exactly the divergence the ruling
// exists to close.

function scenarioArtifactCount(scenarioId) {
  return scenarioId.startsWith("IOP-R-") ? 4 : 1;
}

// The bundle preflight, as the canonical stage pipeline of section 8.6.
//
// A STAGE RUNS TO COMPLETION over the whole bundle before the next begins, and
// no implementation may interleave stages for efficiency in a way that changes
// which failure is reported. The barriers are load-bearing, not tidiness:
//
//   stage 5 | stage 6   one MISSING file plus a DIFFERENT file's digest
//                       mismatch reports bundle-file-missing;
//   stage 6 | stage 7   one UNREADABLE file plus a DIFFERENT file's digest
//                       mismatch reports bundle-file-unreadable -- every read
//                       completes before any digest is checked;
//   stage 8 | stage 10  a JCS-domain NUMBER such as 1e400 is stage-10
//                       numeric-preflight-violation WITH ITS POINTER, never
//                       stage-8 bundle-json-invalid (E7-21, E7-33).
//
// The superseded implementation of this lane read and hashed each file in ONE
// loop and parsed-and-number-scanned in another, so its reported reason
// depended on manifest order. That satisfied the old "complete the whole bundle
// preflight first" wording and is now explicitly non-conforming.
//
// NO frozen verifier is invoked until every stage below has passed, so a
// failure here is a pre-invocation ERROR carrying artifacts: [].
function preflight(flags, ctx) {
  const bundleDir = flags.bundle;

  // ---- STAGE 2: bundle identity, by the section 5 DIRECT READ ------------
  // The first filesystem operation performed on the bundle. Nothing is
  // enumerated, stat-ed or listed beforehand, which is what collapses the five
  // E4-2 conditions into one exit-1 band.
  const identity = readManifestIdentity(bundleDir);
  ctx.scenarioId = identity.scenarioId;

  // ---- STAGE 3: this lane's frozen identity, IMMEDIATELY afterwards ------
  // Section 8.2.1 pins this BEFORE any other post-identity preflight. Because
  // it runs here, every other post-identity result carries a populated
  // verifier_digests, and no placeholder is ever emitted.
  const verifierPath = flags.verifier ?? DEFAULT_VERIFIER;
  const contractPath = flags["verifier-contract"] ?? DEFAULT_VERIFIER_CONTRACT;
  readFrozenIdentity(verifierPath, contractPath, (d) => { ctx.verifierDigests = d; });

  // ---- STAGE 4: manifest structure and closure ---------------------------
  const manifestEntries = validateManifestStructure(identity.doc, identity.duplicates);
  const manifest = { scenarioId: identity.scenarioId, entries: manifestEntries };

  // ---- STAGE 5: canonical traversal, layout closure, listed-file presence -
  traverseBundle(bundleDir, manifest.entries);

  // ---- STAGE 6: ALL listed-file reads ------------------------------------
  // Every read completes before any digest is checked. Nothing else happens in
  // this stage -- not a digest, not a parse -- because that is the only thing
  // that makes the stage-6/stage-7 barrier observable.
  const bytes = new Map();
  {
    const f = new StageFailures(STAGE.FILE_READS);
    for (const entry of manifest.entries) {
      try {
        bytes.set(entry.path, fs.readFileSync(path.join(bundleDir, entry.path)));
      } catch (e) {
        // Stage 5 already established presence and kind, so reaching here means
        // the path was present and a regular file a moment ago. The two
        // outcomes are kept apart on the EVIDENCE rather than on that
        // assumption: a definite ENOENT is a file removed between the stages and
        // is genuinely missing; anything else (EACCES, EIO, EISDIR, ELOOP,
        // EMFILE, a short read on a faulty medium) is a file that is there and
        // cannot be read. Reporting the second as "missing" would tell a reader
        // the bundle is incomplete when the medium or the permissions are at
        // fault.
        //
        // E8-2 -- A BEHAVIOURAL CHANGE IN THIS LANE. The superseded code
        // reported the ENOENT case as bundle-file-unreadable, reasoning that
        // bundle-file-missing belonged to stage 5 and a closed stage must not be
        // reached backwards into. Section 8.2.2 had always said "path absent, OR
        // A DEFINITE ENOENT ON READ" is bundle-file-missing; the stage-6 row
        // failed to restate it, this lane followed the row, and the peer lane
        // followed the boundary -- a measured cross-lane divergence on a Class-1
        // field. The row is now correct: the reason is reported IN STAGE 6, at
        // stage 6's rank, but it is bundle-file-missing, which OUTRANKS
        // bundle-file-unreadable within that stage.
        f.add(
          e && e.code === "ENOENT" ? "bundle-file-missing" : "bundle-file-unreadable",
          entry.path,
          e && e.code === "ENOENT"
            ? `${entry.path} was present at traversal and gave a definite ENOENT on read, `
              + `so it is missing rather than unreadable: ${e.message}`
            : `${entry.path} is present but its bytes could not be read: ${e.message}`);
      }
    }
    f.settle();
  }

  // ---- STAGE 7: ALL digest checks ----------------------------------------
  {
    const f = new StageFailures(STAGE.DIGESTS);
    for (const entry of manifest.entries) {
      const observed = sha256Hex(bytes.get(entry.path));
      if (observed !== entry.sha256) {
        f.add("manifest-digest-mismatch", entry.path,
          `${entry.path}: manifest ${entry.sha256}, observed ${observed}`);
      }
    }
    f.settle();
  }

  // ---- STAGE 8: byte domain, JSON parse, and the TWO canonicalization rules
  // Section 5's table is the WHOLE of stage 8's canonicalizability question:
  // an unpaired surrogate, and a duplicate object member name. It is not
  // shorthand for "whatever RFC 8785 rejects" -- the numeric row is also a
  // canonicalization failure and stays at stage 10 so its json_pointer is not
  // lost.
  const parsed = new Map();
  {
    const f = new StageFailures(STAGE.JSON_PARSE);
    for (const entry of manifest.entries) {
      const buf = bytes.get(entry.path);
      // AD15-IR-20, LISTED-FILE side: a listed artifact or operator-input file
      // whose bytes are outside the domain is bundle-json-invalid here, where
      // the manifest's equivalent was exit 1. The two sit on opposite sides of
      // the identity boundary.
      const byteViolation = checkJsonByteDomain(buf);
      if (byteViolation !== null) {
        f.add("bundle-json-invalid", entry.path, `${entry.path} ${byteViolation}`);
        continue;
      }
      const text = decodeAcceptedJsonBytes(buf);
      let value;
      try {
        value = JSON.parse(text);
      } catch (e) {
        f.add("bundle-json-invalid", entry.path,
          `${entry.path} is not parseable JSON: ${e.message}`);
        continue;
      }
      let scan;
      try {
        scan = scanJsonDocument(text);
      } catch (e) {
        f.add("bundle-json-invalid", entry.path,
          `${entry.path} parsed but could not be re-scanned: ${e.message}`);
        continue;
      }
      // Rule 1 of the stage-8 table. A document can PARSE CLEANLY and still
      // have no canonical form; repair by substituting U+FFFD or dropping a
      // code unit is forbidden.
      if (scan.surrogates.length > 0) {
        f.add("bundle-json-invalid", entry.path,
          `${entry.path} carries an unpaired surrogate at ${scan.surrogates[0]}; RFC 8785 `
          + "requires valid Unicode strings, and the code unit is neither repaired nor dropped");
        continue;
      }
      // Rule 2. Left to the runtime, one lane raises, another silently
      // canonicalizes {"k":1} where a third canonicalizes {"k":2}, and the two
      // produce DIFFERENT request_envelope_digest values over the same file
      // while both report success. The digest would then attest to something
      // the file did not say.
      if (scan.duplicates.length > 0) {
        const d = scan.duplicates[0];
        f.add("bundle-json-invalid", entry.path,
          `${entry.path} repeats the member ${JSON.stringify(d.name)} in the object at `
          + `${d.objectPointer === "" ? "the document root" : d.objectPointer}; neither `
          + "first-wins nor last-wins is applied");
        continue;
      }
      parsed.set(entry.path, { text, value, numbers: scan.numbers });
    }
    f.settle();
  }

  // ---- STAGE 9: bundle and operator-input shape; operator assertions ------
  const shape = new StageFailures(STAGE.SHAPE);

  // Ruling AD15-IR-7: there is NO bundle-wide preflight gate on duplicate
  // record_id or duplicate (chain_id, record_id), and none may be added here.
  // artifact_path is each artifact's total harness identity, so duplicated
  // semantic IDs cannot make a bundle unidentifiable. Artifacts carrying them
  // still go to frozen stage evaluation; if a real reference lookup then
  // produces more than one match, R-A and the frozen resolution semantics treat
  // it as AMBIGUOUS and fail closed -- see resolveRef(). A preflight gate would
  // make that predicate unreachable, converting a genuine reconciliation
  // finding into this evaluator's own refusal.
  //
  // Frozen R-10 is a different surface: it makes a duplicate
  // (chain_id, record_id) in the BATCH VERIFIER'S OWN emitted verdict set
  // run-invalid. This evaluator submits each artifact as a separate request, so
  // that batch invariant does not generalize into a bundle-wide semantic
  // preflight and must not be widened into one.
  const artifactEntries = manifest.entries.filter((e) => e.role === "artifact");
  const wantArtifacts = scenarioArtifactCount(manifest.scenarioId);
  const artifacts = [];
  if (artifactEntries.length !== wantArtifacts) {
    // A composition rule is violated by the bundle as a WHOLE rather than by
    // any one file, so its internal path key is the empty byte string.
    shape.add("bundle-shape-invalid", "",
      `${manifest.scenarioId} requires exactly ${wantArtifacts} artifact-role file(s), `
      + `the manifest carries ${artifactEntries.length}`);
  } else {
    for (const e of artifactEntries) {
      const value = parsed.get(e.path).value;
      if (!isPlainObject(value)) {
        shape.add("bundle-shape-invalid", e.path, `artifact ${e.path} is not a JSON object`);
        continue;
      }
      artifacts.push({ bundlePath: e.path, value });
    }
  }
  // Result order (section 8.4), and by AD15-IR-12 the INVOCATION order too.
  artifacts.sort(compareByPath);

  let byFamily = null;
  if (wantArtifacts === 4 && artifacts.length === 4) {
    byFamily = new Map();
    for (const a of artifacts) {
      const t = a.value.artifact_type;
      if (typeof t !== "string" || !ARTIFACT_FAMILIES.includes(t)) {
        shape.add("bundle-shape-invalid", a.bundlePath,
          `artifact ${a.bundlePath} carries no recognizable artifact_type; `
          + "family composition cannot be established");
        continue;
      }
      if (byFamily.has(t)) {
        shape.add("bundle-shape-invalid", "",
          `${manifest.scenarioId} requires exactly one artifact of each family; `
          + `${t} occurs more than once`);
        continue;
      }
      byFamily.set(t, a);
    }
    for (const family of ARTIFACT_FAMILIES) {
      if (!byFamily.has(family)) {
        shape.add("bundle-shape-invalid", "",
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
      shape.add("bundle-shape-invalid", "",
        `an official W1 bundle carries exactly one ${role} operator input, `
        + `the manifest carries ${got.length}`);
    }
  }
  for (const role of FORBIDDEN_OPERATOR_ROLES) {
    const got = byRole.get(role) ?? [];
    if (got.length !== 0) {
      shape.add("bundle-shape-invalid", "",
        `no official W1 bundle carries a ${role} operator input; the manifest carries ${got.length}`);
    }
  }

  // Ruling AD15-IR-14. Operator-input flags are ASSERTIONS about the bundle's
  // own files, never a way to substitute foreign bytes (section 5.1). A
  // mismatch is detectable only AFTER the manifest has been read -- that is,
  // after identity is established -- so it is result-bearing at exit 3 rather
  // than the exit-2 usage band this lane previously used. A CLI SYNTAX error
  // stays exit 2, because it is detectable before anything is read.
  //
  // Same stage as composition, and ranked BELOW it: the worked case in section
  // 8.6 is exactly this pair, and the bundle's own composition is settled
  // before any assertion an operator makes ABOUT it.
  const cli = {
    bindings: flags.bindings,
    independence_policy: flags["independence-policy"],
    revocation: flags.revocation,
  };
  for (const role of REQUIRED_OPERATOR_ROLES) {
    const value = cli[role];
    if (value === null) continue;
    const declaredRel = (byRole.get(role) ?? [])[0];
    if (declaredRel === undefined) {
      shape.add("operator-input-assertion-mismatch", "",
        `${FLAG_FOR_ROLE[role]} names ${value}, but the manifest declares no ${role} input`);
      continue;
    }
    if (path.resolve(value) !== path.resolve(bundleDir, declaredRel)) {
      shape.add("operator-input-assertion-mismatch", declaredRel,
        `${FLAG_FOR_ROLE[role]} names ${value}, but the bundle's ${role} input is ${declaredRel}`);
    }
  }
  shape.settle();

  const operatorPaths = {};
  for (const role of REQUIRED_OPERATOR_ROLES) operatorPaths[role] = byRole.get(role)[0];

  // ---- STAGE 10: numeric preflight ---------------------------------------
  // Every JSON number reachable in the assembled envelope and in the operator
  // inputs, at any depth (section 5.1). The pointer is RFC 6901 against the
  // INDIVIDUAL FILE the violation is in, never the request envelope: the check
  // happens before any envelope exists, and the two bases give different
  // strings for the same violation, which would be a normative divergence
  // under section 8.7.
  {
    const f = new StageFailures(STAGE.NUMERIC);
    for (const entry of manifest.entries) {
      for (const { pointer, token } of parsed.get(entry.path).numbers) {
        const reason = checkNumberToken(token);
        if (reason !== null) {
          f.add("numeric-preflight-violation", entry.path,
            `${entry.path} carries ${token}: ${reason}`, pointer);
        }
      }
    }
    // Two numbers in ONE file both outside the envelope share a stage, a reason
    // and a path, and this reason carries an EMITTED json_pointer -- so the
    // selection IS observable and the third tie-break level decides it, in
    // ascending UTF-8 byte order of the pointer string.
    f.settle();
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

  // ---- STAGE 11: one closed section 0 request envelope per artifact -------
  //
  // Ruling AD15-IR-12 -- CANONICAL INVOCATION ORDER AND FATAL-RUN FAIL-FAST.
  // AD15-IR-11 pinned what a spawn failure contributes to artifacts[] but not
  // the two things that make the contribution observable: the order invocations
  // happen in, and whether the scenario continues after one fails. Adversarial
  // review found a four-artifact bundle failing at its SECOND artifact admitted
  // [A], [C, D] and [A, C, D] -- all three conforming. Both are pinned now:
  //
  //   ORDER: ascending UTF-8 byte order of artifact_path -- the same key
  //   AD15-IR-5 and AD15-IR-6 already use for identity and envelope ordering.
  //   `artifacts` was sorted by compareByPath in stage 9.
  //
  //   FAIL-FAST:
  //     verifier-not-invocable -- the current artifact contributes NO entry,
  //       earlier entries are retained, and the scenario ABORTS IMMEDIATELY;
  //     verifier-run-invalid -- a concrete process result exists, so the current
  //       artifact DOES contribute its entry, and the scenario ABORTS
  //       IMMEDIATELY;
  //     a clean exit-0 verdict never aborts, EVEN carrying a non-empty
  //       authenticated_withheld channel -- under AD15-IR-10 the remaining
  //       artifacts must still be evaluated for run validity before section 7.1
  //       is applied at all.
  //
  // The worked case is single-valued: a bundle [A, B, C, D] whose B cannot be
  // spawned yields artifacts[] = [A]. [C, D] and [A, C, D] are non-conforming.
  //
  // The superseded implementation of this lane invoked EVERY artifact and then
  // classified the exit codes in a separate loop afterwards, so a non-qualifying
  // exit 1 on B still ran C and D. Section 3's "for every artifact" is subject
  // to this abort: it states the invocation obligation, not a guarantee that
  // every artifact is reached on a failing bundle.
  //
  // head_witness is never present: no official W1 bundle defines one, and the
  // closed manifest role set has no way to carry one (section 5).
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "airep-interop-node-"));
  const resultsByPath = new Map();
  let fatal = null;
  try {
    for (const primary of artifacts) {
      // Section 5.1, as amended by AD15-IR-6: every OTHER artifact of this
      // bundle, in ascending UTF-8 byte order of its manifest-relative
      // artifact_path. artifact_path always exists and is unique, so the
      // envelope is a function of the bundle alone and is defined even when an
      // artifact carries no usable record_id -- which is the whole point of the
      // ruling.
      const related = artifacts
        .filter((a) => a !== primary)
        .sort(compareByPath)
        .map((a) => a.value);
      const envelope = { artifact: primary.value, related_artifacts: related };
      const envelopeBytes = Buffer.from(jcs(envelope), "utf8");
      const envelopeDigest = sha256Prefixed(envelopeBytes);
      const requestPath = path.join(tmpDir, `request-${resultsByPath.size}.json`);
      fs.writeFileSync(requestPath, envelopeBytes);

      // AD15-IR-18, and section 8.3.1's field-timing list: a PRELIMINARY
      // artifact_ref is known BEFORE invocation, derived from the artifact by
      // the projection. On the exit-0 path it is REPLACED by the accepted
      // verdict's closed artifact_ref; on every OTHER emitted entry the
      // preliminary value IS the emitted one -- Source B, which is defined by
      // EXCLUSION and is not a list of outcomes.
      const preliminaryRef = artifactRefFromArtifact(primary.value);

      const run = runFrozenVerifier(verifierPath, requestPath, operatorArgs);

      // AD15-IR-11 + AD15-IR-15, first row: the process NEVER STARTED, so
      // nothing was measured and no entry is invented. Entries for invocations
      // that completed earlier are retained, and the scenario aborts.
      if (run.outcome === "never-started") {
        fatal = new NonMeasurement(run.reason, `${run.detail} (for ${primary.bundlePath})`);
        break;
      }

      // Every remaining outcome produced a CONCRETE PROCESS RESULT, so it
      // contributes a full entry -- recorded BEFORE any interpretation, so a
      // bundle abandoned partway lists exactly what was attempted.
      const record = {
        artifact: primary,
        envelopeDigest,
        exitCode: run.exitCode,
        verifierResult: null,
        stderrDigest: run.stderrDigest,
      };
      resultsByPath.set(primary.bundlePath, record);
      const entry = {
        // Required, and the entry's identity (AD15-IR-5). Always present.
        artifact_path: primary.bundlePath,
        // Source B by default; replaced below only on the accepted exit-0 path.
        artifact_ref: preliminaryRef,
        request_envelope_digest: envelopeDigest,
        // AD15-IR-15: null for abnormal termination, the integer verbatim
        // otherwise. Never synthesized, and never a signal number.
        verifier_exit_code: run.exitCode,
        // null whenever no verdict exists -- exit 1, exit 2 and abnormal
        // termination all emit none (section 8.3).
        verifier_result: null,
        verifier_stderr_digest: run.stderrDigest,
      };
      ctx.artifactEntries.push(entry);

      // AD15-IR-15, middle row: started and did not exit normally. The entry
      // above is complete with two null measurements; the run is fatal.
      if (run.outcome === "abnormal-termination") {
        fatal = new NonMeasurement(run.reason, `${run.detail} (for ${primary.bundlePath})`);
        break;
      }

      if (run.exitCode === 0) {
        const band = classifyVerdictStdout(run.stdout.toString("utf8"));
        if (band.reason !== undefined) {
          // A shape rejected by EITHER contract -- the frozen one, or this
          // contract's own E8-3 artifact_ref gate. The entry stands; the
          // scenario aborts.
          //
          // E8-4, and it holds HERE BY CONSTRUCTION rather than by a decision
          // taken at this line: the entry was pushed above with
          // verifier_exit_code 0 (the process exited normally), verifier_result
          // null (nothing is written into it until a verdict is ACCEPTED), and
          // artifact_ref still the AD15-IR-18 Source-B preliminary projection
          // (the Source-A replacement is below this branch). The rejected bytes
          // are kept as diagnostic evidence only -- stdout that parses is not a
          // verdict until it has passed both contracts' shape rules, so it may
          // not enter the normative verifier_result. verifier_result is
          // Class-1, so the shape is pinned rather than left to two
          // implementations happening to agree.
          fatal = new NonMeasurement(band.reason, `${band.detail} (for ${primary.bundlePath})`);
          break;
        }
        record.verifierResult = band.verdict;
        entry.verifier_result = band.verdict;
        // AD15-IR-18, SOURCE A: the accepted exit-0 verdict. Copied VERBATIM
        // from verifier_result.artifact_ref, after the result-shape gate has
        // accepted it -- so the copy is over a value already known to be
        // PRESENT, an object, carrying a string record_id, and closed (E8-3).
        // There is no absent-member branch here any more: an absent, null or
        // untyped artifact_ref is verifier-run-invalid at the gate above, and
        // never reaches this line.
        entry.artifact_ref = band.verdict.artifact_ref;
        continue;
      }

      // Section 7.2 causal guard, applied INLINE so the abort is immediate.
      // Frozen exit 1 means run-invalid: no verdict was emitted. It may be read
      // as Level-1 REJECT only when the request was preflight-clean AND the
      // scenario's targeted predicate is stage-0/stage-1 invalidity.
      // Preflight-clean is established by construction: every stage of
      // preflight() completed, the envelope was built per section 5.1, and the
      // operator inputs are the bundle's own. Cross-lane envelope equality is
      // NOT part of this condition (AD15-IR-4) and is never evaluated here.
      //
      // A QUALIFYING exit 1 is NOT fatal: it is the artifact's own invalidity,
      // which the Level-1 mapping reads as REJECT, so the remaining artifacts
      // are still evaluated.
      if (run.exitCode === 1 && EXIT1_REJECT_SCENARIOS.has(scenarioId)) continue;
      fatal = new NonMeasurement("verifier-run-invalid",
        run.exitCode === 1
          ? `frozen verifier exited 1 for ${primary.bundlePath}, but scenario ${scenarioId} `
            + "does not qualify for the section 7.2 exit-1 REJECT reading, so this is the "
            + "evaluator's error, not the artifact's"
          : `frozen verifier exited ${run.exitCode} for ${primary.bundlePath}; the frozen `
            + "contract permits no such exit for this invocation");
      break;
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  // ---- withheld reasons, verbatim (AD15-IR-16 / E8-1) ---------------------
  // E8-1: on EVERY result-bearing path, withheld_reasons is the projection of
  // every accepted frozen-verifier verdict ACTUALLY RETAINED in artifacts[]
  // before termination. A fatal stage-11 result does not erase withheld
  // channels already observed. A malformed or GATE-REJECTED verifier output
  // contributes none, because it is not an accepted verdict -- which holds here
  // by construction: record.verifierResult is assigned ONLY on the accepted
  // exit-0 path, so a rejected shape leaves it null and the loop below skips it.
  // "[]" therefore means no withheld reason was observed among the accepted
  // verdicts actually obtained; it says nothing about invocations never reached.
  //
  // Collected BEFORE the fatal run is raised, deliberately. AD15-IR-10 orders
  // the reported measurement_status and reason -- the ERROR outcome wins over
  // the withheld tier -- but it says nothing about discarding a channel that
  // was actually observed. A verdict that WAS emitted and DID carry a withheld
  // channel is evidence of a run that genuinely happened, and dropping it is
  // the same mistake AD15-IR-15 forbids one row up when it insists an
  // abnormally terminated process still contributes its entry. section 8.2
  // makes this member unconditional; nothing in it is conditioned on the run
  // completing.
  //
  // The entry shape is PINNED, because section 8.7 makes this member normative
  // and an unpinned entry shape is two lanes emitting different objects for the
  // same withheld channel and calling it conformance. Exactly three members --
  // artifact_path, channel, reason -- and NOTHING ELSE. This lane's superseded
  // shape carried an artifact_ref member and an array-valued `reasons`; both
  // are gone. ONE ENTRY PER REASON STRING.
  //
  // `reason` is VERBATIM from the frozen verdict, never re-worded: a withheld
  // reason is the frozen verifier's output, and an evaluator that paraphrases
  // it has substituted its own text for a measurement.
  for (const a of artifacts) {
    const record = resultsByPath.get(a.bundlePath);
    const verdict = record === undefined ? null : record.verifierResult;
    if (verdict === null) continue;
    for (const channel of ["authenticated_withheld", "witnessed_withheld"]) {
      const reasons = verdict[channel];
      if (!Array.isArray(reasons)) continue;
      for (const reason of reasons) {
        ctx.withheldReasons.push({ artifact_path: a.bundlePath, channel, reason });
      }
    }
  }
  // Ordered by (artifact_path, channel, reason) in UTF-8 byte order.
  ctx.withheldReasons.sort((x, y) =>
    byteCompare(x.artifact_path, y.artifact_path)
    || byteCompare(x.channel, y.channel)
    || byteCompare(x.reason, y.reason));

  // ---- STAGE 12: section 7.1, AFTER stage 11 completes (AD15-IR-10) -------
  // The fatal run is raised HERE, before section 7.1 is consulted at all, which
  // is what makes the ordering structural rather than a matter of care: a
  // verifier that misbehaved AS A PROCESS cannot be trusted to have produced a
  // meaningful withheld channel either, so reporting MEASUREMENT_INVALID would
  // attribute the failure to the tier when it belongs to the run.
  if (fatal !== null) throw fatal;

  // Section 7.1 is evaluated ONLY after every artifact invocation has passed the
  // section 7.2 process- and result-shape guard.
  const withheld = authenticatedWithheldViolation(ctx.withheldReasons);
  if (withheld !== null) throw withheld;

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
// 10a. Section 8.7 -- the normative surface, as four classes
// ---------------------------------------------------------------------------
// Not every observable difference between two conforming evaluators is a
// defect. The earlier binary model was internally CONTRADICTORY: it called
// every artifacts[] field and all of verifier_digests normative, while
// verifier_stderr_digest and each lane's own class-verifier digest are EXPECTED
// to differ -- the two frozen verifiers are different programs -- so a lane
// obeying it literally would have failed a conforming peer. It also omitted
// scenario_id, so the scenario label itself was never compared.
//
//   Class 1 -- cross-lane equality: exit code and result-object shape,
//     scenario_id, measurement_status, level1, predicates,
//     nonmeasurement.reason, nonmeasurement.json_pointer, artifacts[]
//     membership and order, artifact_path, artifact_ref,
//     request_envelope_digest, verifier_exit_code, verifier_result,
//     withheld_reasons, verifier_digests.class_verifier_contract.
//   Class 2 -- lane-local assertion: verifier_digests.class_verifier equals
//     THIS lane's own pin; evaluator_version satisfies this lane's version rule
//     and section 8.4 repeat determinism; mandatory-block execution complete.
//   Class 3 -- audit-only: verifier_stderr_digest, required and equal to
//     SHA-256 over the exact captured stderr, NOT compared across lanes.
//   Class 4 -- diagnostic-only: nonmeasurement.detail, raw stderr, signal names
//     and numbers, stack traces, OS error prose, help text, timing.
//
// THE CLOSED MEMBER SETS. A result object carrying an unknown member at any
// closed level is INVALID -- it is not silently dropped from the projection.
// Excluding it would let a lane smuggle an uncompared field into a result that
// still passed the projection; the closed set exists to prevent exactly that.
export const RESULT_MEMBERS = Object.freeze([
  "artifacts", "evaluator_version", "level1", "measurement_status", "nonmeasurement",
  "predicates", "scenario_id", "verifier_digests", "withheld_reasons",
]);
export const ARTIFACT_ENTRY_MEMBERS = Object.freeze([
  "artifact_path", "artifact_ref", "request_envelope_digest",
  "verifier_exit_code", "verifier_result", "verifier_stderr_digest",
]);
export const NONMEASUREMENT_MEMBERS = Object.freeze(["detail", "json_pointer", "reason"]);
export const WITHHELD_ENTRY_MEMBERS = Object.freeze(["artifact_path", "channel", "reason"]);
export const VERIFIER_DIGEST_MEMBERS = Object.freeze(["class_verifier", "class_verifier_contract"]);
export const PREDICATE_MEMBERS = Object.freeze(["R_A", "R_B", "R_C"]);

function unknownMembers(obj, allowed) {
  return Object.keys(obj).filter((k) => !allowed.includes(k));
}

// Returns null when the result object is closed at every closed level, or a
// string naming the first violation. Fail-closed: the evaluator runs this over
// its OWN output before emitting, so a member added by a future edit becomes a
// loud internal-error rather than a quietly uncompared field.
export function resultShapeViolation(result) {
  if (!isPlainObject(result)) return "result is not a JSON object";
  const bad = unknownMembers(result, RESULT_MEMBERS);
  if (bad.length > 0) return `result carries unknown member(s) ${JSON.stringify(bad)}`;
  for (const k of RESULT_MEMBERS) {
    if (!Object.prototype.hasOwnProperty.call(result, k)) return `result omits ${k}`;
  }
  if (result.nonmeasurement !== null) {
    if (!isPlainObject(result.nonmeasurement)) return "nonmeasurement is neither null nor an object";
    const nb = unknownMembers(result.nonmeasurement, NONMEASUREMENT_MEMBERS);
    if (nb.length > 0) return `nonmeasurement carries unknown member(s) ${JSON.stringify(nb)}`;
  }
  if (result.predicates !== null) {
    if (!isPlainObject(result.predicates)) return "predicates is neither null nor an object";
    const pb = unknownMembers(result.predicates, PREDICATE_MEMBERS);
    if (pb.length > 0) return `predicates carries unknown member(s) ${JSON.stringify(pb)}`;
  }
  if (result.verifier_digests !== null) {
    if (!isPlainObject(result.verifier_digests)) {
      return "verifier_digests is neither null nor an object";
    }
    const vb = unknownMembers(result.verifier_digests, VERIFIER_DIGEST_MEMBERS);
    if (vb.length > 0) return `verifier_digests carries unknown member(s) ${JSON.stringify(vb)}`;
  }
  if (!Array.isArray(result.artifacts)) return "artifacts is not an array";
  for (const e of result.artifacts) {
    if (!isPlainObject(e)) return "an artifacts[] entry is not an object";
    const ab = unknownMembers(e, ARTIFACT_ENTRY_MEMBERS);
    if (ab.length > 0) return `an artifacts[] entry carries unknown member(s) ${JSON.stringify(ab)}`;
    for (const k of ARTIFACT_ENTRY_MEMBERS) {
      if (!Object.prototype.hasOwnProperty.call(e, k)) return `an artifacts[] entry omits ${k}`;
    }
    if (e.artifact_ref !== null) {
      if (!isPlainObject(e.artifact_ref)) return "artifact_ref is neither null nor an object";
      const rb = unknownMembers(e.artifact_ref, ["record_id", "chain_id"]);
      if (rb.length > 0) return `artifact_ref carries unknown member(s) ${JSON.stringify(rb)}`;
    }
  }
  if (!Array.isArray(result.withheld_reasons)) return "withheld_reasons is not an array";
  for (const w of result.withheld_reasons) {
    if (!isPlainObject(w)) return "a withheld_reasons entry is not an object";
    const wb = unknownMembers(w, WITHHELD_ENTRY_MEMBERS);
    if (wb.length > 0) {
      return `a withheld_reasons entry carries unknown member(s) ${JSON.stringify(wb)}`;
    }
    for (const k of WITHHELD_ENTRY_MEMBERS) {
      if (!Object.prototype.hasOwnProperty.call(w, k)) {
        return `a withheld_reasons entry omits ${k}`;
      }
    }
  }
  return null;
}

// The cross-lane normative projection: the result object with EXACTLY these
// removed, and everything else retained --
//
//   nonmeasurement.detail
//   evaluator_version
//   verifier_digests.class_verifier
//   artifacts[*].verifier_stderr_digest
//
// including verifier_digests.class_verifier_contract, which the two lanes MUST
// assert identically. Equality is equality of the CLOSED JSON VALUE,
// operationalized through its RFC 8785 canonical bytes, so that member order,
// whitespace and number spelling cannot make two equal values compare unequal
// nor two unequal values compare equal.
//
// Comparing a projection rather than listing fields inverts the failure mode of
// field-by-field duties: anything inside it is compared BY CONSTRUCTION, and
// anything a lane adds is an unknown member and therefore invalid rather than
// quietly uncompared. That is why resultShapeViolation() runs first.
export function normativeProjection(result) {
  const violation = resultShapeViolation(result);
  if (violation !== null) {
    throw new Error(`result is not projectable: ${violation}`);
  }
  const out = {};
  for (const k of RESULT_MEMBERS) {
    if (k === "evaluator_version") continue;
    out[k] = result[k];
  }
  if (result.nonmeasurement !== null) {
    const nm = {};
    for (const k of Object.keys(result.nonmeasurement)) {
      if (k === "detail") continue;
      nm[k] = result.nonmeasurement[k];
    }
    out.nonmeasurement = nm;
  }
  if (result.verifier_digests !== null) {
    const vd = {};
    for (const k of Object.keys(result.verifier_digests)) {
      if (k === "class_verifier") continue;
      vd[k] = result.verifier_digests[k];
    }
    out.verifier_digests = vd;
  }
  out.artifacts = result.artifacts.map((e) => {
    const copy = {};
    for (const k of Object.keys(e)) {
      if (k === "verifier_stderr_digest") continue;
      copy[k] = e[k];
    }
    return copy;
  });
  return out;
}

// The comparison the aggregate harness's duty 6 performs. A lane cannot run it
// against its peer -- section 4 forbids a lane from seeing the other tree -- so
// what it is used for HERE is the peer-safe half: that the model SEPARATES THE
// CLASSES on this lane's own result.
export function projectionBytes(result) {
  return jcs(normativeProjection(result));
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

// Section 8.7's closed member set is enforced on the way OUT, fail-closed. A
// result object carrying an unknown member at any closed level is INVALID
// rather than silently dropped from the projection, so an evaluator that never
// checked its own shape could smuggle an uncompared field past duty 6. The
// check is here, at the single write point, so no emission path can bypass it.
function emit(result, diagnostic, exitCode) {
  const violation = resultShapeViolation(result);
  if (violation !== null) {
    const e = new Error(`result object is not closed under section 8.7: ${violation}`);
    e.resultShapeViolation = true;
    throw e;
  }
  if (diagnostic) process.stderr.write(diagnostic + "\n");
  writeStdoutSync(stableStringify(result) + "\n");
  resultWritten = true;
  return exitCode;
}

// The one result object this program can always build correctly: every member
// of the closed set, with the two collections empty. It exists so that a
// shape violation in the ordinary path still produces a NAMED result object at
// exit 3 rather than a crash the harness has to infer -- and it cannot itself
// trip the gate, because it is assembled from the closed set by construction.
function minimalInternalErrorResult(scenarioId, detail) {
  return {
    scenario_id: scenarioId,
    measurement_status: "ERROR",
    level1: null,
    predicates: null,
    nonmeasurement: { reason: "internal-error", detail },
    artifacts: [],
    withheld_reasons: [],
    verifier_digests: null,
    evaluator_version: EVALUATOR_VERSION,
  };
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
      try {
        return emit(nonMeasuredResult(ctx, e), "", 3);
      } catch (shapeErr) {
        if (!shapeErr.resultShapeViolation) throw shapeErr;
        process.stderr.write(`${shapeErr.message}\n`);
        return emit(minimalInternalErrorResult(ctx.scenarioId, shapeErr.message), "", 3);
      }
    }
    if (e.resultShapeViolation) {
      // The MEASURED path built an unclosed result. Identity is established --
      // emit() is only ever reached after it is -- so the harness is owed a
      // result object naming the scenario, and internal-error is exactly the
      // registry row for an unexpected evaluator fault after identity.
      process.stderr.write(`${e.message}\n`);
      return emit(minimalInternalErrorResult(ctx.scenarioId, e.message), "", 3);
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
