#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// AIREP v0.2 WP-α01 integrity verifier (Node) — Stage-4 independently authored
// implementation.
//
// This program is an INTEGRITY VERIFIER (integrity-construction verifier): it verifies
// the hash / record-signature / head-witness construction frozen in
// `spec/airep/v0.2/INTEGRITY.md` against the Stage-4 corpus fixtures, and nothing more.
// It is NOT a conformance verifier — artifact schemas, profile validation, and
// conformance-class semantics are out of scope for this stage.
//
// Authoring basis (Stage-4 independence mandate, STAGE4_CONTRACT.md §3):
//   - normative construction: ../../INTEGRITY.md (frozen; read-only)
//   - reporting contract:     ../STAGE4_CONTRACT.md §1/§2/§2a, ../REASON_CODES.md,
//                             ../FIXTURES.md, ../corpus_manifest.json
//   - JCS canonicalization:   adapted from spec/airep/v0.1/conformance/verify.mjs
//                             `canonical()` (the only element reused from v0.1)
//   The other Stage-4 verifier (Python) — its source and its output — was not read,
//   imported, called, or shelled out to. Fixture `expected` members are never accessed:
//   they are deleted immediately after JSON.parse, before any evaluation.
//
// Behaviour (per the pinned evaluation precedence, STAGE4_CONTRACT.md §2a):
//   artifact path: version -> tag registry -> hash -> producer binding -> suite
//                  -> signature -> (optional wire-alg caveat)
//   witness path (fidelity-gate revision, 2026-08-22):
//                  head resolve -> head version -> claim structure -> head reconcile
//                  -> witnessed_at validity -> witness binding -> suite
//                  -> witness signature -> freshness -> (optional wire-alg caveat)
// A REJECT carries exactly ONE reason: the first decisive failure. Fail-closed
// everywhere: no alternate-tag, alternate-version, alternate-suite, or v0.1-fallback
// attempt of any kind (INTEGRITY §4.3, §5).
//
// Usage:  node integrity_verifier.mjs
//   Reads  ../corpus/*.json  and writes  ../results/results_node.json
//   (both resolved relative to this file, so the invocation directory is irrelevant).
//
// Exit code: 0 iff a normalized result was produced for every corpus fixture — the
// verdicts themselves are data, never exit codes. Nonzero only on harness failure
// (unreadable corpus, malformed fixture envelope, unwritable results file).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = path.join(HERE, "..", "corpus");
const RESULTS_DIR = path.join(HERE, "..", "results");
const RESULTS_FILE = path.join(RESULTS_DIR, "results_node.json");

// The only wire-format version this integrity verifier implements (INTEGRITY §1.1/§5).
const SUPPORTED_VERSION = "0.2";
// Closed tag-context registry for v0.2 (INTEGRITY §1.2) — case-sensitive, never folded.
const REGISTERED_CONTEXTS = new Set(["decision", "control", "execution", "effect"]);
// Closed suite registry this verifier implements (INTEGRITY §3.1).
const IMPLEMENTED_SUITES = new Set(["ed25519"]);
const LF = Buffer.from([0x0a]);

// ---------------------------------------------------------------------------------
// RFC 8785 (JCS) canonicalization — adapted from spec/airep/v0.1/conformance/verify.mjs
// `canonical()`. Sorted object keys (UTF-16 code-unit order, which is what
// Array.prototype.sort does for strings), no whitespace; ES6 JSON.stringify supplies
// the RFC 8785 string-escape and number serialization for the value classes used here.
// ---------------------------------------------------------------------------------
function jcs(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort()
      .map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  return JSON.stringify(v); // string / number / boolean
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Import a raw 32-byte Ed25519 public key (hex) by prefixing the fixed SPKI DER header.
function importEd25519PublicKey(hex) {
  const der = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(hex, "hex"),
  ]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

// Ed25519 (RFC 8032, pure, no pre-hash) over the raw preimage bytes. Any exception
// (malformed key hex, malformed signature hex) is a verification failure — fail-closed,
// never a distinct code (REASON_CODES: indistinguishable causes share one observable).
function ed25519Verify(pubKeyHex, preimage, sigHex) {
  try {
    if (typeof pubKeyHex !== "string" || typeof sigHex !== "string") return false;
    const key = importEd25519PublicKey(pubKeyHex);
    return crypto.verify(null, preimage, key, Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------
// Timestamp validation per INTEGRITY §4.2: exactly YYYY-MM-DDTHH:MM:SSZ, real
// Gregorian calendar date, hour 00-23 / minute 00-59 / second 00-59 (leap-second 60
// forbidden), no fractional seconds, literal Z only. Never Date-parsing leniency:
// every component is range-checked here, and the epoch value is computed by a pure
// civil-date day-count (days-from-civil algorithm) — NOT Date.UTC, whose legacy
// two-digit-year remapping silently maps years 0000-0099 to 1900-1999 and corrupts
// distances across the 0099/0100 boundary (fixture S9-1 crosses exactly that).
// Returns epoch seconds (number, proleptic Gregorian, may be negative) or null if invalid.
// ---------------------------------------------------------------------------------
const TS_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

function isLeapYear(y) {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

// Days since 1970-01-01 for a valid proleptic-Gregorian civil date (Hinnant's
// days_from_civil): pure integer arithmetic, no Date object, no year remapping.
function daysFromCivil(y, m, d) {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400; // [0, 399]
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1; // [0, 365]
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy; // [0, 146096]
  return era * 146097 + doe - 719468;
}

function validateTimestamp(s) {
  if (typeof s !== "string") return null;
  const m = TS_RE.exec(s);
  if (!m) return null;
  const [year, month, day, hour, minute, second] = m.slice(1).map((x) => Number(x));
  if (month < 1 || month > 12) return null;
  const daysInMonth = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > daysInMonth[month - 1]) return null;
  if (hour > 23 || minute > 59 || second > 59) return null; // second 60 (leap) forbidden
  return daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
}

// ---------------------------------------------------------------------------------
// Reason helpers — closed registry (REASON_CODES.md); dedupe + ASCII-ascending order.
// ---------------------------------------------------------------------------------
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const reject = (code) => ({ verdict: "REJECT", reasons: [code] });
const pass = (caveats) =>
  caveats.length
    ? { verdict: "PASS_WITH_CAVEAT", reasons: [...new Set(caveats)].sort() }
    : { verdict: "PASS", reasons: ["OK"] };

// The wire algorithm label is informative only and never selects behaviour
// (INTEGRITY §3.2, §4.3). Reporting rule: the caveat fires when the label names a
// suite other than the binding-derived one. The label is matched case-insensitively
// against the canonical lowercase suite-id — the conventional spelling "Ed25519"
// names the same suite as binding suite-id "ed25519" (FIXTURES.md positive controls
// carry it and are specified PASS ["OK"]); a label naming a DIFFERENT suite
// (e.g. "ECDSA-P256") disagrees and yields WIRE_ALG_IGNORED (STAGE4_CONTRACT §2.3).
// An absent label disagrees with nothing.
function wireAlgCaveats(wireAlg, bindingSuite) {
  if (wireAlg === undefined) return [];
  if (typeof wireAlg === "string" && wireAlg.toLowerCase() === bindingSuite) return [];
  return ["WIRE_ALG_IGNORED"];
}

// ---------------------------------------------------------------------------------
// Artifact path (STAGE4_CONTRACT §2a):
// version -> tag registry -> hash -> producer binding -> suite -> signature -> caveat
// ---------------------------------------------------------------------------------
function evaluateArtifactPath(inputs) {
  const art = isObj(inputs.artifact) ? inputs.artifact : {};

  // 1. version — declared airep_version absent, malformed, or unimplemented
  //    (includes a v0.1-style record presented as v0.2). No fallback.
  if (art.airep_version !== SUPPORTED_VERSION) return reject("UNSUPPORTED_VERSION");

  // 2. tag registry — the declared (airep_version, artifact_type) pair must map to a
  //    registered tag; case-sensitive, no nearest match (INTEGRITY §1.2).
  const context = art.artifact_type;
  if (typeof context !== "string" || !REGISTERED_CONTEXTS.has(context)) {
    return reject("UNREGISTERED_TAG");
  }

  // 3. hash — mechanical subtraction per INTEGRITY §2: logical copy, delete
  //    integrity.current and integrity.signature, retain everything else (the
  //    integrity object itself, integrity.previous included, stays).
  const body = structuredClone(art);
  if (isObj(body.integrity)) {
    delete body.integrity.current;
    delete body.integrity.signature;
  }
  const hashTag = `AIREP/${SUPPORTED_VERSION}/hash/${context}`;
  const hashPreimage = Buffer.concat([
    Buffer.from(hashTag, "ascii"), LF, Buffer.from(jcs(body), "utf8"),
  ]);
  const computed = "sha256:" + sha256Hex(hashPreimage);
  const wireCurrent = isObj(art.integrity) ? art.integrity.current : undefined;
  if (computed !== wireCurrent) return reject("HASH_MISMATCH");

  // 4. producer binding — the fixture-supplied verifier-accepted binding; the wire
  //    alg label is never a substitute (REASON_CODES: KEY_BINDING_UNAVAILABLE).
  const binding = inputs.producer_binding;
  if (!isObj(binding) || typeof binding.public_key_hex !== "string") {
    return reject("KEY_BINDING_UNAVAILABLE");
  }

  // 5. suite — from the binding only.
  if (!IMPLEMENTED_SUITES.has(binding.suite)) return reject("SUITE_UNSUPPORTED");

  // 6. signature — preimage per INTEGRITY §3: sig tag LF canonical-suite-id LF the
  //    full integrity.current string; the suite-id comes from the binding, so a
  //    signed-suite mismatch simply fails verification (A11b -> SIGNATURE_INVALID).
  const sigTag = `AIREP/${SUPPORTED_VERSION}/sig/${context}`;
  const sigPreimage = Buffer.concat([
    Buffer.from(sigTag, "ascii"), LF,
    Buffer.from(binding.suite, "ascii"), LF,
    Buffer.from(wireCurrent, "ascii"),
  ]);
  const sig = isObj(art.integrity) && isObj(art.integrity.signature)
    ? art.integrity.signature : {};
  if (!ed25519Verify(binding.public_key_hex, sigPreimage, sig.value)) {
    return reject("SIGNATURE_INVALID");
  }

  // 7. caveat — only on an otherwise-passing result.
  return pass(wireAlgCaveats(sig.alg, binding.suite));
}

// ---------------------------------------------------------------------------------
// Witness path (STAGE4_CONTRACT §2a, fidelity-gate revision 2026-08-22):
// head resolve -> head version -> claim structure -> head reconcile
// -> witnessed_at validity -> witness binding -> suite -> witness signature
// -> freshness -> caveat
// ---------------------------------------------------------------------------------
const CLAIM_MEMBERS = ["chain_id", "current", "length", "sequence", "witnessed_at"];
const CURRENT_RE = /^sha256:[0-9a-f]{64}$/;

// Closed five-member claim structure of INTEGRITY §4, with the pinned §4.2
// constraints on the four non-time members (witnessed_at time semantics are the
// separate WITNESS_TIME_INVALID step). Extra members are never silently ignored and
// never silently included in a rebuilt claim — the member set must be EXACTLY the
// closed five.
function claimStructureValid(claim) {
  if (!isObj(claim)) return false;
  const keys = Object.keys(claim).sort();
  if (keys.length !== CLAIM_MEMBERS.length ||
      !keys.every((k, i) => k === CLAIM_MEMBERS[i])) return false;
  if (typeof claim.chain_id !== "string") return false;
  if (!Number.isSafeInteger(claim.sequence) || claim.sequence < 0) return false;
  if (typeof claim.current !== "string" || !CURRENT_RE.test(claim.current)) return false;
  if (!Number.isSafeInteger(claim.length) || claim.length < 1) return false;
  return true;
}

function evaluateWitnessPath(inputs) {
  const w = isObj(inputs.witness) ? inputs.witness : {};
  const claim = isObj(w.claim) ? w.claim : {};

  // 1. head resolve — witness.head_ref names the key in inputs.head_artifacts.
  const heads = isObj(inputs.head_artifacts) ? inputs.head_artifacts : {};
  const headRef = w.head_ref;
  const head =
    typeof headRef === "string" && Object.prototype.hasOwnProperty.call(heads, headRef)
      ? heads[headRef] : undefined;
  if (!isObj(head)) return reject("WITNESS_HEAD_UNRESOLVED");

  // 2. head version — the resolved head's declared airep_version must be a version
  //    this integrity verifier implements: the closed registry is enforced on the
  //    witness path too. A head declaring 0.3 with a witness genuinely signed under
  //    0.3 tags is UNSUPPORTED_VERSION, never a cryptographic accept.
  if (head.airep_version !== SUPPORTED_VERSION) return reject("UNSUPPORTED_VERSION");

  // 3. claim structure — exactly the closed five members with their pinned non-time
  //    constraints (INTEGRITY §4/§4.2); structure fails before reconcile/signature.
  if (!claimStructureValid(claim)) return reject("WITNESS_CLAIM_INVALID");

  // 4. head reconcile — the claim's chain_id / sequence / current must equal the
  //    resolved head's own members (INTEGRITY §4.3). Strict identity, no coercion.
  const headCurrent = isObj(head.integrity) ? head.integrity.current : undefined;
  if (
    claim.chain_id !== head.chain_id ||
    claim.sequence !== head.sequence ||
    claim.current !== headCurrent
  ) {
    return reject("WITNESS_HEAD_MISMATCH");
  }

  // 5. witnessed_at validity — INTEGRITY §4.2 time semantics (format regex AND real
  //    calendar; leap-second 60 forbidden).
  const witnessedEpoch = validateTimestamp(claim.witnessed_at);
  if (witnessedEpoch === null) return reject("WITNESS_TIME_INVALID");

  // 6. witness binding — the trust-store entry for this witness identity is the only
  //    verifier-accepted binding; verifier-accepted requires explicit trusted: true
  //    (a missing or non-true trusted member fails closed — no default-trust).
  const store = isObj(inputs.witness_trust_store) ? inputs.witness_trust_store : {};
  const entry =
    typeof w.witness_id === "string" &&
    Object.prototype.hasOwnProperty.call(store, w.witness_id)
      ? store[w.witness_id] : undefined;
  if (!isObj(entry) || typeof entry.public_key_hex !== "string" || entry.trusted !== true) {
    return reject("KEY_BINDING_UNAVAILABLE");
  }

  // 7. suite — from the trust-store binding only.
  if (!IMPLEMENTED_SUITES.has(entry.suite)) return reject("SUITE_UNSUPPORTED");

  // 8. witness signature — tag version equals the referenced head's declared
  //    airep_version (INTEGRITY §4.3; no independent witness version, no search;
  //    step 2 already pinned it to an implemented version). The signature is
  //    verified over JCS of the PRESENTED claim object, which the structure step
  //    guarantees has exactly the closed five members.
  const witnessTag = `AIREP/${head.airep_version}/sig/head-witness`;
  const witnessPreimage = Buffer.concat([
    Buffer.from(witnessTag, "ascii"), LF,
    Buffer.from(entry.suite, "ascii"), LF,
    Buffer.from(jcs(claim), "utf8"),
  ]);
  const sig = isObj(w.signature) ? w.signature : {};
  if (!ed25519Verify(entry.public_key_hex, witnessPreimage, sig.value)) {
    return reject("WITNESS_SIGNATURE_INVALID");
  }

  // 9. freshness — ONLY the signed witnessed_at, against the fixture-supplied now and
  //    freshness_window_seconds (INTEGRITY §4.1; no system clock; unsigned freshness
  //    fields never enter this decision). A signed timestamp beyond the window in
  //    either direction — stale past or future — is WITNESS_STALE; a distance exactly
  //    equal to the window is fresh (boundary-equal, fixture S10-1).
  const nowEpoch = validateTimestamp(inputs.now);
  const windowSeconds = inputs.freshness_window_seconds;
  if (nowEpoch === null || typeof windowSeconds !== "number") {
    throw new Error("harness: fixture-supplied now/freshness_window_seconds invalid");
  }
  if (Math.abs(nowEpoch - witnessedEpoch) > windowSeconds) return reject("WITNESS_STALE");

  // 10. caveat — wire-carried witness algorithm label is informative only.
  return pass(wireAlgCaveats(sig.alg, entry.suite));
}

// ---------------------------------------------------------------------------------
// Harness: evaluate every corpus fixture, write the normalized results file.
// ---------------------------------------------------------------------------------
function evaluateFixture(fixture) {
  const inputs = isObj(fixture.inputs) ? fixture.inputs : {};
  // Fixture kind rule (FIXTURES.md / corpus_manifest.json): inputs.witness present
  // => witness-path fixture; otherwise artifact-path fixture.
  const outcome =
    inputs.witness !== undefined
      ? evaluateWitnessPath(inputs)
      : evaluateArtifactPath(inputs);
  return {
    fixture_id: fixture.fixture_id,
    verdict: outcome.verdict,
    reasons: outcome.reasons,
  };
}

function main() {
  const files = fs.readdirSync(CORPUS_DIR).filter((f) => f.endsWith(".json")).sort();
  if (files.length === 0) throw new Error("harness: empty corpus directory");

  const results = {};
  for (const file of files) {
    const fixture = JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, file), "utf8"));
    // Independence hygiene: the fixture's expected outcome is removed before any
    // evaluation — this program never reads it.
    delete fixture.expected;
    if (typeof fixture.fixture_id !== "string" || fixture.fixture_id === "") {
      throw new Error(`harness: fixture without fixture_id: ${file}`);
    }
    if (Object.prototype.hasOwnProperty.call(results, fixture.fixture_id)) {
      throw new Error(`harness: duplicate fixture_id: ${fixture.fixture_id}`);
    }
    results[fixture.fixture_id] = evaluateFixture(fixture);
  }

  // Results file: {"results": {...}}, keys sorted recursively (jcs sorts every object
  // level; arrays keep their — already ASCII-sorted — order), trailing newline, no
  // metadata: byte-deterministic across runs.
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  fs.writeFileSync(RESULTS_FILE, jcs({ results }) + "\n", "utf8");

  // Exit 0 iff a normalized result exists for every corpus fixture. Verdicts are data.
  if (Object.keys(results).length !== files.length) {
    throw new Error("harness: result count does not match corpus fixture count");
  }
  process.exit(0);
}

main();
