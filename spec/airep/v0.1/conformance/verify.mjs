#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// AIREP v0.1 verifier — a SECOND, independent implementation (Node, zero dependencies).
//
// Its purpose is interop: it re-derives integrity.current from scratch and MUST reach the
// byte-identical SHA-256 the Python reference (conformance/verify.py) computed. Two
// independent implementations agreeing on the hash is what makes AIREP an interchange
// format rather than a single-tool artifact.
//
// Per SPEC §6/§8, for each record it checks, independently of the Python reference:
//   - structure: the required top-level members are present, the top level is closed
//     (additionalProperties:false — a stray vendor key is rejected, not ignored), and the
//     directive.verb / evidence[].type values are inside their closed enums;
//   - neutrality (§8.2): deleting `profiles` leaves only core members;
//   - integrity: integrity.current = SHA-256 over the canonical form with current+signature
//     removed and previous retained;
//   - chain: each previous links to the prior current and decision_index increments (a
//     standalone decision_index-0 record must point at the all-zero genesis previous);
//   - signature: if a public key is given, the Ed25519 signature over current verifies.
// This hand-codes core.schema.json's fixed shape rather than running a general Draft-2020-12
// engine; it is kept in lockstep with the schema verify.py validates against, and the two are
// tested to reach the same verdict on the example vectors and on the adversarial cases in
// conformance/README.md. verify.py (full jsonschema) remains the authority for exhaustive
// schema validation; this verifier exists to prove the format is checkable on a second,
// dependency-free stack.
//
// Usage:  node verify.mjs <record.json | chain.jsonl> [--pubkey <hex | path-to-key-file>] [--class]
//
// --class reports the highest AIREP conformance class satisfied: Core, Verified, or (by default)
// TRUSTED_NOT_IMPLEMENTED. **By default Trusted is never reported** — its four prerequisites
// (witness-signature verification, witness-key distinctness, freshness recency, revocation) are
// unevaluated, and an unenforced prerequisite can never be reported as satisfied. **Trusted is
// reachable only in the opt-in STRICT mode (WP-10):** pass --trust-store + --freshness-window +
// --revocation-source and the four gates run for real; a record earns Trusted iff every one passes,
// else the ceiling is Verified with the specific reason named. Any input missing → the gates cannot
// run → TRUSTED_NOT_IMPLEMENTED (never a silent Trusted). See CONFORMANCE_CLASSES.md §AIREP-Trusted
// (strict mode). v1: one independent trusted witness, local JSON inputs, timestamp freshness window.
//
// A witness-less `Verified` record whose own profiles.key_trust.revocation.revoked is true is still
// `Verified` (revocation is a Trusted gate, not a Verified requirement) but carries
// verified_withheld=producer-key-revoked on its line — a self-declared revoked signing key is never
// rendered as a clean Verified. verified_withheld= names caveats on a Verified record;
// trusted_withheld= names why Trusted was withheld.
//
// Exit code reflects RECORD VALIDITY ONLY, never the class: 0 when every record passed every
// check this verifier ran, 1 when a record failed or the input could not be read, 2 on usage
// error (--help exits 0 without verifying). A TRUSTED_NOT_IMPLEMENTED record exits 0 because it
// is a valid record — exit 0 is NOT a statement that any particular class was reached. This
// verifier runs NO profile-schema validation, so its exit 0 is a weaker statement than
// verify.py's. Requires Node >= 16 (raw Ed25519 keys).
//
// PROFILE DIMENSION IS NOT_MEASURED HERE, AND SAYS SO. Because no profile schema is validated,
// a record carrying a `profiles` block is NOT reported as a clean pass over that block: every
// such record is annotated `profile_not_measured=<names>` on its line and the CLASS summary
// names it. verify.py (full jsonschema) is the authority that DOES validate `profiles.<name>`
// against `profiles/<name>.schema.json`, so for a record whose profile block VIOLATES its schema
// the two verifiers diverge BY DESIGN — verify.py exits 1 (INVALID), this verifier's core checks
// still pass and it exits 0. The annotation is what stops that exit 0 from reading as "the
// profile was validated and passed". It is NOT_MEASURED, not PASS. (Kept in lockstep with
// verify.py's PROFILE_VALIDATORS; matching verify.py's exit code would mean duplicating its
// Draft-2020-12 profile engine, which this second stack deliberately does not do.)
//
// Canonicalization: sorted object keys, no whitespace, UTF-8 — RFC 8785-equivalent for the
// float-free / simple-decimal, ASCII-key records here (JS Number->String == the ES6 form JCS
// mandates, and Python json.dumps matches it for these values, so both impls agree).

import crypto from "node:crypto";
import fs from "node:fs";

const GENESIS = "sha256:" + "0".repeat(64);
const REQUIRED = ["airep_version", "subject", "input", "claim", "output",
  "evidence", "directive", "scope", "integrity"];
// The core is closed at the top level (core.schema.json additionalProperties:false):
// the only members allowed are the 9 required ones plus the optional `profiles` extension.
const ALLOWED_TOP = new Set([...REQUIRED, "profiles"]);
// Closed enums the core schema fixes (SPEC §3.1). A presence check misses these; a real
// verifier must reject out-of-enum values so it agrees with the Python reference.
const VERBS = new Set(["release", "block", "defer", "redact", "escalate_to_human", "kill"]);
const EV_TYPES = new Set(["retrieval", "tool_call", "memory", "policy",
  "human_approval", "external_url", "eval", "other"]);
const HASH_RE = /^sha256:[0-9a-f]{64}$/;

const isArr = Array.isArray;
const isObj = (v) => v !== null && typeof v === "object" && !isArr(v);
const isStr = (v) => typeof v === "string";
const isBool = (v) => typeof v === "boolean";
const isInt = (v) => typeof v === "number" && Number.isInteger(v);
const isStrArr = (v) => isArr(v) && v.every(isStr);

// Schema check encoding the fixed shape of core.schema.json — the closed top level
// (additionalProperties:false), every required member at the top level AND inside each core
// sub-object, the value types the schema fixes, the closed directive.verb / evidence[].type
// enums, the `const` members, and the integrity hash pattern. verify.py runs the same schema
// through the full Draft-2020-12 engine (jsonschema); this hand-coded check is kept in lockstep
// with it so the two verifiers reach the same verdict, not only the same hash. (Neither verifier
// enforces JSON Schema `format`, e.g. date-time — verify.py is constructed without a format
// checker — so they agree there too.)
function schemaCheck(rec) {
  const bad = [];
  if (!isObj(rec)) return ["not-object"];
  for (const k of REQUIRED) if (!(k in rec)) bad.push("missing:" + k);
  for (const k of Object.keys(rec)) if (!ALLOWED_TOP.has(k)) bad.push("extra-top:" + k);
  if ("airep_version" in rec && rec.airep_version !== "0.1") bad.push("airep_version:" + rec.airep_version);

  // Require an object member to be an object holding the given [key, predicate, tag] subfields.
  const reqObj = (name, val, fields) => {
    if (val === undefined) return; // absence already reported as missing:<name>
    if (!isObj(val)) { bad.push(`${name}:not-object`); return; }
    for (const [k, pred, tag] of fields) {
      if (!(k in val)) bad.push(`${name}.${k}:missing`);
      else if (pred && !pred(val[k])) bad.push(`${name}.${k}:${tag}`);
    }
  };

  reqObj("subject", rec.subject, [
    ["runtime", isStr, "type"], ["producer", isStr, "type"],
    ["decision_index", (v) => isInt(v) && v >= 0, "type"], ["timestamp_utc", isStr, "type"]]);
  reqObj("input", rec.input, [["input_ref", isStr, "type"], ["governance_state", isObj, "type"]]);
  reqObj("claim", rec.claim, [
    ["assertion", isStr, "type"], ["basis", (v) => isStrArr(v) && v.length >= 1, "type"]]);
  reqObj("output", rec.output, [["result_ref", isStr, "type"]]);
  reqObj("directive", rec.directive, [
    ["verb", (v) => VERBS.has(v), "enum"], ["policy_basis", isStrArr, "type"]]);
  reqObj("scope", rec.scope, [["covers", isStrArr, "type"], ["does_not_cover", isStrArr, "type"]]);
  reqObj("integrity", rec.integrity, [
    ["previous", (v) => isStr(v) && HASH_RE.test(v), "format"],
    ["current", (v) => isStr(v) && HASH_RE.test(v), "format"],
    ["canonical_json", (v) => v === true, "const"], ["signature", isObj, "type"]]);
  if (isObj(rec.integrity) && isObj(rec.integrity.signature)) {
    reqObj("integrity.signature", rec.integrity.signature, [
      ["alg", isStr, "type"], ["value", isStr, "type"]]);
  }
  if ("evidence" in rec) {
    if (!isArr(rec.evidence)) bad.push("evidence:not-array");
    else rec.evidence.forEach((e, i) => {
      if (!isObj(e)) { bad.push(`evidence[${i}]:not-object`); return; }
      if (!("type" in e)) bad.push(`evidence[${i}].type:missing`);
      else if (!EV_TYPES.has(e.type)) bad.push(`evidence[${i}].type:${e.type}`);
      if (!("ref" in e)) bad.push(`evidence[${i}].ref:missing`);
      else if (!isStr(e.ref)) bad.push(`evidence[${i}].ref:type`);
      if (!("resolvable" in e)) bad.push(`evidence[${i}].resolvable:missing`);
      else if (!isBool(e.resolvable)) bad.push(`evidence[${i}].resolvable:type`);
    });
  }
  return bad;
}

// The profile-schema dimension this verifier does NOT measure. verify.py validates each
// `profiles.<name>` against `profiles/<name>.schema.json`; this stack runs no such engine, so
// every profile block present is reported NOT_MEASURED by name — never silently passed. Returns
// the sorted profile names carried by the record.
function profilesNotMeasured(rec) {
  if (!isObj(rec) || !isObj(rec.profiles)) return [];
  return Object.keys(rec.profiles).sort();
}

// Neutrality (SPEC §8.2): delete `profiles` and the record must still be a valid core record.
// With the closed top level that means every remaining member is one of the 9 core members —
// so a profile can never smuggle a field into the core.
function neutralityCheck(rec) {
  if (rec === null || typeof rec !== "object") return [];
  for (const k of Object.keys(rec)) {
    if (k !== "profiles" && !REQUIRED.includes(k)) return ["neutrality:" + k];
  }
  return [];
}

function canonical(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort()
      .map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  }
  return JSON.stringify(v); // string / number / boolean
}

function recompute(rec) {
  const integ = { ...rec.integrity };
  delete integ.current;
  delete integ.signature;
  const body = { ...rec, integrity: integ };
  return "sha256:" + crypto.createHash("sha256").update(canonical(body), "utf8").digest("hex");
}

function loadPub(s) {
  if (!s) return null;
  let hex = s;
  if (fs.existsSync(s)) {
    const lines = fs.readFileSync(s, "utf8").split("\n")
      .map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    hex = lines[lines.length - 1] || "";
  }
  // Wrap a raw 32-byte Ed25519 public key into SPKI DER (fixed 12-byte prefix).
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function verifySig(integ, pub) {
  if (!pub) return null;
  try {
    return crypto.verify(null, Buffer.from(integ.current, "utf8"), pub,
      Buffer.from(integ.signature.value, "hex"));
  } catch {
    return false;
  }
}

function loadRecords(file) {
  const text = fs.readFileSync(file, "utf8");
  if (file.endsWith(".jsonl")) {
    return text.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  }
  const obj = JSON.parse(text);
  return Array.isArray(obj) ? obj : [obj];
}

// --- conformance classes (CONFORMANCE_CLASSES.md) — kept in lockstep with verify.py ----------
const REAL_ALGS = new Set(["ed25519", "ecdsa", "rsa", "rsa-pss", "hmac-sha256"]);
// TRUSTED_NOT_IMPLEMENTED sits at Verified's rank on purpose: it is NOT a class above Verified.
// It is Verified plus a NAMED statement that the Trusted prerequisites were never evaluated.
const CLASS_RANK = { INVALID: 0, Core: 1, Verified: 2, TRUSTED_NOT_IMPLEMENTED: 2, Trusted: 3 };

// The AIREP-Trusted prerequisites (CONFORMANCE_CLASSES.md §AIREP-Trusted) this verifier does NOT
// evaluate. A prerequisite that is not enforced can never be reported as satisfied, so while this
// list is non-empty the top class is UNREACHABLE — presence of witness material downgrades to
// TRUSTED_NOT_IMPLEMENTED rather than granting Trusted. Implementing a check means removing its
// entry AND adding the real check; removing an entry alone re-opens the hole.
const TRUSTED_GATES_NOT_IMPLEMENTED = [
  "witness-signature-not-verified",     // req 1: chain_witness.witness.value is never re-verified
  "witness-key-distinctness-unproven",  // req 1: a witness_id string is not a key
  "freshness-recency-not-evaluated",    // req 2: presence is checked, recency/nonce-challenge is not
  "revocation-not-honored",             // req 3: no revocation source is consulted
];

// Cross-runtime-stable predicates. Python and JavaScript disagree on the truthiness of `{}` and `[]`
// (falsy in Python, truthy in JS), so every presence test on the Trusted path is expressed as an
// explicit type + non-emptiness check that both languages evaluate identically.
const nonemptyStr = (v) => typeof v === "string" && v !== "";
const nonemptyObj = (v) => isObj(v) && Object.keys(v).length > 0;

function evidenceAnchored(rec) {
  for (const e of rec.evidence || []) {
    if (e && e.resolvable === false && !e.content_hash) return false;
  }
  return true;
}
function keyTrustBound(rec) {
  const kt = (rec.profiles || {}).key_trust;
  return isObj(kt) && ["key_id", "algorithm", "public_key"].every((k) => k in kt);
}
// WP-09: the record's own key_trust declares its signing key revoked. Self-declared, definitively
// checkable, needs NO external revocation source (that source is the undefined Trusted-tier policy).
// A revoked signing key undermines the authorship a Verified record asserts, so it is named — never
// a silent Verified — but the class stays Verified (CONFORMANCE_CLASSES.md §Verified does not gate
// on revocation; that is a Trusted gate). Kept in lockstep with verify.py::_producer_key_revoked.
function producerKeyRevoked(rec) {
  const rev = ((rec.profiles || {}).key_trust || {}).revocation;
  return isObj(rev) && rev.revoked === true;
}
// Witness material is PRESENT. Presence is not verification: this says a chain_witness block
// exists and is populated, NOT that the witness signature is valid, that the witness key is
// independent of the producer, or that the anchor is fresh. Necessary for Trusted, never sufficient.
function witnessPresent(rec) {
  const prof = rec.profiles || {};
  const cw = prof.chain_witness || prof.freshness_witness;
  if (!isObj(cw)) return false; // no head witness on this record → at most Verified
  const head = cw.head || {};
  if (!isObj(head)) return false;
  // Type-EXPLICIT, never truthiness: `witness: {}` is falsy in Python but truthy in JavaScript, so
  // a truthiness test made the two verifiers report different classes for identical bytes. Presence
  // predicates on the Trusted path must be decided by type + non-emptiness, which both languages
  // agree on. Kept in lockstep with verify.py::_witness_present.
  return Boolean(nonemptyStr(cw.chain_id) && nonemptyStr(head.current) && nonemptyObj(cw.witness));
}
// Trusted prerequisites that ARE structurally checkable and DEFINITIVELY fail on this record.
// Cheap structural reads, not cryptography: passing them earns nothing (the gates in
// TRUSTED_GATES_NOT_IMPLEMENTED still never ran); failing one is decisive.
function trustedStructuralFailures(rec) {
  const prof = rec.profiles || {};
  const cw = prof.chain_witness || prof.freshness_witness || {};
  const kt = prof.key_trust || {};
  const bad = [];
  // req 1 (necessary, not sufficient): a "witness" naming the producer's own key is theater —
  // chain_witness.schema.json: witness_id "MUST be distinct from the producer". Distinct ids do
  // NOT prove distinct keys, so passing this leaves witness-key-distinctness-unproven standing.
  const wid = isObj(cw.witness) ? cw.witness.witness_id : undefined;
  // Compared as strings only: an id is a string, and `{} == {}` is True in Python but
  // `{} === {}` is False in JS, so a loose comparison would diverge across the two verifiers.
  if (nonemptyStr(wid) && wid === kt.key_id) bad.push("witness-not-independent");
  // req 2: a freshness anchor must be PRESENT (timestamp, nonce, or challenge response), and be a
  // non-empty string — truthiness alone diverges across runtimes on {} / [].
  const fr = isObj(cw.freshness) ? cw.freshness : {};
  if (!["witness_timestamp_utc", "nonce", "challenge_response"].some((k) => nonemptyStr(fr[k]))) {
    bad.push("no-freshness-anchor");
  }
  // req 3: key_trust must CARRY revocation state, and a revoked key is untrusted.
  const rev = kt.revocation;
  if (!isObj(rev) || !("revoked" in rev)) bad.push("no-revocation-state");
  else if (rev.revoked === true) bad.push("producer-key-revoked");
  return bad;
}
// ---- WP-10 strict-Trusted: the four Trusted gates, run ONLY with operator-supplied inputs -------
// Default mode leaves these four gates unevaluated (TRUSTED_NOT_IMPLEMENTED). In strict mode the
// operator supplies --trust-store + --freshness-window + --revocation-source and the gates run for
// real; a record earns Trusted iff every one passes, else the ceiling is Verified with the specific
// failure named. Kept byte-for-byte in lockstep with verify.py. v1 scope: exactly ONE independent
// trusted witness (no N-of-M quorum), local JSON inputs (no transparency-log / no online CRL), a
// timestamp freshness window (no nonce/challenge). See docs WP10_STRICT_TRUSTED_DESIGN.
function parseIso(s) {
  if (!nonemptyStr(s)) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t; // epoch millis
}
function producerPubkeyHex(kt) {
  const pk = kt.public_key;
  if (isObj(pk) && nonemptyStr(pk.value)) return pk.value.trim().toLowerCase();
  if (nonemptyStr(pk)) return pk.trim().toLowerCase();
  return null;
}
function verifyWitnessSig(cw, wit, wpubHex) {
  // Re-verify chain_witness.witness.value over the canonical head claim, under the witness key
  // RESOLVED FROM THE TRUST STORE. Claim shape is byte-identical to verify.py / the fixtures:
  // {chain_id, decision_index, current, length}. canonical() matches verify.py's jcs for these.
  const head = cw.head || {};
  const claim = { chain_id: cw.chain_id, decision_index: head.decision_index,
                  current: head.current, length: head.length };
  try {
    const pub = loadPub(wpubHex);
    return crypto.verify(null, Buffer.from(canonical(claim), "utf8"), pub,
      Buffer.from(String((wit || {}).value || ""), "hex"));
  } catch {
    return false;
  }
}
function keyRevoked(revocation, keyId, relevantTime) {
  // Revoked iff the external source lists the key AND the record was signed at/after revoked_at
  // (CONFORMANCE_CLASSES.md §Trusted req 3). Missing revoked_at / unknown signing time → treated
  // conservatively as revoked, never a silent pass. Kept in lockstep with verify.py::_key_revoked.
  if (!isObj(revocation) || !nonemptyStr(keyId)) return false;
  const entry = revocation[keyId];
  if (!isObj(entry)) return false;
  const ra = parseIso(entry.revoked_at);
  if (ra === null || relevantTime === null) return true;
  return relevantTime >= ra;
}
function strictTrustedFailures(rec, strict) {
  const prof = rec.profiles || {};
  const cw = prof.chain_witness || prof.freshness_witness || {};
  const kt = prof.key_trust || {};
  const wit = isObj(cw.witness) ? cw.witness : {};
  const bad = [];
  const { trustStore, revocation, window, now } = strict;

  // gate 1+ (key resolution / trust / independence): resolve the witness key from the store by
  // witness_id and decide independence on the RESOLVED PUBLIC KEYS, never on id strings.
  const wid = wit.witness_id;
  const entry = nonemptyStr(wid) ? trustStore[wid] : undefined;
  let wpub = null;
  if (!isObj(entry) || !nonemptyStr(entry.public_key_hex)) {
    bad.push("witness-unknown");
  } else {
    wpub = entry.public_key_hex.trim().toLowerCase();
    if (entry.trusted !== true) bad.push("witness-untrusted");
    const ppub = producerPubkeyHex(kt);
    if (ppub !== null && wpub === ppub) bad.push("witness-not-independent");
  }

  // gate: witness signature verifies under the resolved key
  if (wpub !== null && verifyWitnessSig(cw, wit, wpub) !== true) bad.push("witness-signature-invalid");

  // gate: freshness recency within the operator's window (deterministic against --now)
  const fr = isObj(cw.freshness) ? cw.freshness : {};
  const wts = parseIso(fr.witness_timestamp_utc);
  if (wts === null) bad.push("no-freshness-anchor");
  else if (wts > now) bad.push("freshness-in-future");
  else if ((now - wts) / 1000 > window) bad.push("freshness-stale");

  // gate: revocation, consulted for BOTH the producer key and the witness key
  const recTs = parseIso((rec.subject || {}).timestamp_utc);
  if (keyRevoked(revocation, kt.key_id, recTs)) bad.push("producer-key-revoked");
  if (keyRevoked(revocation, wid, wts)) bad.push("witness-key-revoked");
  return bad;
}

// Returns [class, withheldReasons]. AIREP-Trusted is FAIL-CLOSED: granted only when every
// normative prerequisite is actually enforced and passes. Without operator trust inputs (default
// mode) the Trusted-tier gates cannot run, so the top class is withheld and named. With them
// (strict mode: `strict` is a context object) the four gates run for real.
function classify(rec, sigOk, strict) {
  const alg = String((((rec.integrity || {}).signature) || {}).alg || "").toLowerCase();
  const verified = sigOk === true && REAL_ALGS.has(alg) && evidenceAnchored(rec) && keyTrustBound(rec);
  if (!verified) return ["Core", []];
  if (!witnessPresent(rec)) return ["Verified", []]; // no Trusted claim is being made at all
  const structural = trustedStructuralFailures(rec);
  if (structural.length) return ["Verified", structural]; // a prerequisite demonstrably fails
  if (!strict) {
    // Witness material is present and structurally coherent, but with no operator trust inputs the
    // four gates cannot run. Never grant on presence.
    return ["TRUSTED_NOT_IMPLEMENTED", [...TRUSTED_GATES_NOT_IMPLEMENTED]];
  }
  // STRICT MODE: the four gates run for real against the operator's trust inputs.
  const gateFailures = strictTrustedFailures(rec, strict);
  if (gateFailures.length) return ["Verified", gateFailures];
  return ["Trusted", []]; // every gate ran and passed
}

// Assemble the strict-Trusted context, or [null, note]. Strict engages ONLY when all three inputs
// are present; a partial set falls back to default with a printed note, never a silent Trusted.
function buildStrict(args) {
  const val = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const tsPath = val("--trust-store");
  const windowRaw = val("--freshness-window");
  const revPath = val("--revocation-source");
  const nowRaw = val("--now");
  const supplied = [Boolean(tsPath), windowRaw !== undefined, Boolean(revPath)];
  if (!supplied.some(Boolean)) return [null, null];
  if (!supplied.every(Boolean)) {
    return [null, "strict-Trusted needs all three of --trust-store, --freshness-window, " +
                  "--revocation-source; falling back to default (Trusted withheld)"];
  }
  const now = nowRaw ? parseIso(nowRaw) : Date.now();
  if (now === null) return [null, `--now is not a valid ISO-8601 timestamp: ${nowRaw} (Trusted withheld)`];
  return [{
    trustStore: JSON.parse(fs.readFileSync(tsPath, "utf8")),
    revocation: JSON.parse(fs.readFileSync(revPath, "utf8")),
    window: Number(windowRaw),
    now,
  }, null];
}

const USAGE = `Verify an AIREP record or chain (Node reference verifier)

Usage:
  node verify.mjs <record.json | chain.jsonl> [--pubkey <hex | path-to-key-file>] [--class]
                  [--trust-store <p> --freshness-window <s> --revocation-source <p> [--now <iso>]]

  --pubkey  Ed25519 public key (hex) or a path to a key file; enables signature re-verification
  --class   report the highest AIREP conformance class satisfied: Core | Verified |
            TRUSTED_NOT_IMPLEMENTED (default), or Trusted in strict mode. By default Trusted is
            withheld: its four prerequisites (witness signature, witness-key distinctness, freshness
            recency, revocation) are unevaluated, and an unenforced prerequisite is never reported
            as satisfied. Withheld classes name them as trusted_withheld=...
  strict-Trusted (WP-10): pass ALL of --trust-store, --freshness-window, --revocation-source (and
            optionally --now for deterministic freshness) to run the four gates for real. Trusted iff
            all pass, else Verified + named reason. v1: one independent trusted witness, local JSON.
            --trust-store        {witness_id: {public_key_hex, trusted}}
            --freshness-window   max seconds between the witness timestamp and --now
            --revocation-source  {key_id: {revoked_at, reason}} — producer AND witness keys
            --now                ISO-8601 evaluation time (default: system clock)

Exit code: 0 when every record passed every check this verifier ran, 1 when a record failed or the
input could not be read, 2 on usage error. It reflects record validity ONLY — it never encodes which
class was reached, so exit 0 must not be read as "Trusted". This verifier runs NO profile-schema
validation, so its exit 0 is a weaker statement than verify.py's. See CONFORMANCE_CLASSES.md.`;

function main() {
  const args = process.argv.slice(2);
  const file = args[0];
  if (!file || args.includes("--help") || args.includes("-h")) {
    console.log(USAGE);
    process.exit(file ? 0 : 2);
  }
  const pi = args.indexOf("--pubkey");
  const pub = loadPub(pi >= 0 ? args[pi + 1] : "");
  const showClass = args.includes("--class");
  const [strict, strictNote] = buildStrict(args);
  const records = loadRecords(file);
  // An empty input is not a vacuously perfect chain. Zero records means zero checks ran, and the
  // unmeasured case must never inherit a class — reporting the top class here would be the purest
  // form of the fail-open bug this classifier exists to prevent. (Kept in lockstep with verify.py.)
  if (records.length === 0) {
    console.log(`AIREP verify (node): ${file}  (0 record(s))`);
    console.log("  FAIL(no-records)  an AIREP input MUST contain at least one record");
    console.log("RESULT: 1 input FAILED");
    if (showClass) console.log("CLASS: INVALID");
    process.exit(1);
  }
  const isChain = records.length > 1;
  let fails = 0;
  let anyProfiles = false;
  let prev = GENESIS;
  // Starts UNSET, not at the top class: the ceiling is earned by the records, never inherited from
  // an initial value. A chain is only as strong as its weakest record.
  let chainClass = null;
  console.log(`AIREP verify (node): ${file}  (${records.length} record(s)${isChain ? " — chain" : ""})`);
  if (strictNote) console.log(`  NOTE  ${strictNote}`);
  if (strict) {
    console.log(`  strict-Trusted mode: now=${new Date(strict.now).toISOString()} `
      + `freshness_window=${Math.trunc(strict.window)}s`);
  }
  records.forEach((rec, i) => {
    const bad = [];
    bad.push(...schemaCheck(rec));
    bad.push(...neutralityCheck(rec));
    const integ = rec.integrity || {};
    if (recompute(rec) !== integ.current) bad.push("hash");
    if (isChain) {
      if (integ.previous !== prev) bad.push("chain-link");
      if ((rec.subject || {}).decision_index !== i) bad.push("index");
    } else if ((rec.subject || {}).decision_index === 0 && integ.previous !== GENESIS) {
      // A standalone genesis record (decision_index 0) must point at the all-zero previous.
      bad.push("genesis-previous");
    }
    const sig = verifySig(integ, pub);
    if (sig === false) bad.push("signature");
    prev = integ.current;
    const sigstr = sig === true ? "sig=ok" : sig === false ? "sig=FAIL" : "sig=skip";
    let cls = null, withheld = [];
    if (showClass) [cls, withheld] = bad.length ? ["INVALID", []] : classify(rec, sig, strict);
    if (cls !== null && (chainClass === null || CLASS_RANK[cls] < CLASS_RANK[chainClass])) chainClass = cls;
    let clspart = showClass ? `  class=${cls}` : "";
    // Never downgrade silently: say which Trusted prerequisite was unmet or unevaluated.
    if (withheld.length) clspart += `  trusted_withheld=${withheld.join(",")}`;
    // WP-09: a witness-less Verified record whose own key_trust declares the key revoked must not
    // read as a clean Verified. Name the self-declared caveat; the class stays Verified per contract.
    // (Witness-present revoked records already name producer-key-revoked via trustedStructuralFailures.)
    if (showClass && cls === "Verified" && !witnessPresent(rec) && producerKeyRevoked(rec)) {
      clspart += "  verified_withheld=producer-key-revoked";
    }
    // Never render an unmeasured dimension as a clean pass: name any profile block present,
    // whose schema this verifier did not validate (verify.py is the authority — see header).
    const profNM = profilesNotMeasured(rec);
    if (profNM.length) { anyProfiles = true; clspart += `  profile_not_measured=${profNM.join(",")}`; }
    console.log(`  [${i}] ${bad.length ? "FAIL(" + bad.join(",") + ")" : "PASS"}  ${sigstr}${clspart}  ${String(integ.current).slice(0, 23)}...`);
    if (bad.length) fails++;
  });
  console.log(`RESULT: ${fails ? fails + " record(s) FAILED" : "all records OK"}`);
  if (showClass) {
    const pubNote = !pub && !fails ? "  (pass --pubkey to assess Verified)" : "";
    // A class earned here never certifies the profile blocks: this verifier did not schema-validate
    // them. Say so on the summary so the class is not read as "profile validated" (see verify.py).
    const profNote = anyProfiles ? "  (profiles present — NOT schema-validated by this verifier; run verify.py)" : "";
    console.log(`CLASS: ${fails ? "INVALID" : (chainClass || "INVALID")}${pubNote}${profNote}`);
  }
  process.exit(fails ? 1 : 0);
}

main();
