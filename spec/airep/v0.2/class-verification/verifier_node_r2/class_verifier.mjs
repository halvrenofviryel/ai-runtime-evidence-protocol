#!/usr/bin/env node
// AIREP v0.2 class verifier (Node implementation).
//
// Implements CLASS_VERIFIER_CONTRACT.md sections 0-6 against the frozen
// INTEGRITY.md constructions and the accepted CONFORMANCE_CLASS_DESIGN.md
// semantics. Nothing here re-designs a frozen construction: the hash preimage,
// the record-signature preimage and the head-witness preimage are assembled
// literally as the frozen text spells them.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Ajv2020 } from "./node_modules/ajv/dist/2020.js";

// ---------------------------------------------------------------------------
// 0. Constants
// ---------------------------------------------------------------------------

const ARTIFACT_TYPES = ["decision", "control", "execution", "effect"];
const SUITE_REGISTRY = new Set(["ed25519"]);          // INTEGRITY 3.1 (closed)
const NAMESPACED_ID = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const SIG_HEX = /^[0-9a-f]{128}$/;
const PUBKEY_HEX = /^[0-9a-f]{64}$/;
const WITNESSED_AT = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;
const NOW_PATTERN = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$/;

// Committed repository layout: this file sits at
// <root>/v0.2/class-verification/verifier_node_r2/class_verifier.mjs and the
// accepted schemas at <root>/v0.2/schemas/ -- hence "../../schemas". Any other
// layout (e.g. a review snapshot) supplies --schema-dir.
const DEFAULT_SCHEMA_DIR = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "..", "schemas");
let schemaDir = DEFAULT_SCHEMA_DIR;

// Closed reason registry (contract section 5). tier: authenticated|witnessed.
const REASONS = {
  "producer-binding-missing":            ["authenticated", "withheld"],
  "producer-binding-not-trusted":        ["authenticated", "failure"],
  "producer-binding-malformed":          ["authenticated", "withheld"],
  "producer-suite-unsupported":          ["authenticated", "withheld"],
  "producer-revocation-state-missing":   ["authenticated", "withheld"],
  "producer-revocation-state-malformed": ["authenticated", "withheld"],
  "producer-binding-revoked":            ["authenticated", "failure"],
  "producer-signature-invalid":          ["authenticated", "failure"],
  "producer-key-self-revoked":           ["authenticated", "caveat"],
  "wire-alg-mismatch":                   ["authenticated", "caveat"],
  "no-witness-supplied":                 ["witnessed", "withheld"],
  "witness-binding-missing":             ["witnessed", "withheld"],
  "witness-binding-not-trusted":         ["witnessed", "failure"],
  "witness-binding-malformed":           ["witnessed", "withheld"],
  "witness-suite-unsupported":           ["witnessed", "withheld"],
  "witness-revocation-state-missing":    ["witnessed", "withheld"],
  "witness-revocation-state-malformed":  ["witnessed", "withheld"],
  "independence-policy-missing":         ["witnessed", "withheld"],
  "independence-policy-malformed":       ["witnessed", "withheld"],
  "independence-relation-absent":        ["witnessed", "withheld"],
  "freshness-inputs-missing":            ["witnessed", "withheld"],
  "witness-binding-revoked":             ["witnessed", "failure"],
  "witness-head-unresolved":             ["witnessed", "failure"],
  "witness-head-mismatch":               ["witnessed", "failure"],
  "witness-claim-invalid":               ["witnessed", "failure"],
  "witness-identity-not-distinct":       ["witnessed", "failure"],
  "witness-key-not-distinct":            ["witnessed", "failure"],
  "independence-explicitly-denied":      ["witnessed", "failure"],
  "witness-signature-invalid":           ["witnessed", "failure"],
  "witness-time-invalid":                ["witnessed", "failure"],
  "witness-freshness-outside-window":    ["witnessed", "failure"],
};

// ---------------------------------------------------------------------------
// 1. Errors: exit-code carriers (contract 6.4)
// ---------------------------------------------------------------------------

class UsageError extends Error {}      // exit 2
class InvalidRunError extends Error {} // exit 1

// ---------------------------------------------------------------------------
// 2. RFC 8785 (JCS) canonicalization
// ---------------------------------------------------------------------------
// Reused, per mandate, from the pre-existing v0.1 reference verifier's
// canonicalization logic. Object keys sort by UTF-16 code units (JS default
// sort == RFC 8785 3.2.3); strings are serialized by JSON.stringify, whose
// escaping (well-formed since ES2019) is the JCS escaping; numbers use the
// ES6 Number-to-String form JCS mandates.

function jcs(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort()
      .map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  if (typeof v === "number" && !Number.isFinite(v)) {
    throw new InvalidRunError("non-finite number cannot be canonicalized");
  }
  return JSON.stringify(v);
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function deepCopy(v) {
  return JSON.parse(JSON.stringify(v));
}

// ---------------------------------------------------------------------------
// 2b. Numeric source lexemes (errata E-1)
// ---------------------------------------------------------------------------
// INTEGRITY 4.2's "no sign, no fraction, no exponent" constrains the SOURCE
// SPELLING of the witness claim's `sequence` / `length`, but JSON.parse erases
// it ("1e0", "1.0", "-0" all become a number) and this runtime's reviver has no
// source access. So the request text is scanned once into a shadow tree that
// mirrors the document's containers and member names while replacing every
// number token with { lexeme: "<raw token text>" } and every other scalar with
// null. The input has already parsed, so the scanner assumes well-formed JSON.

const NUMBER_TOKEN = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?/;
const INTEGER_LEXEME = /^(0|[1-9][0-9]*)$/;   // the frozen lexical rule

function jsonShadow(text) {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const str = () => {
    const start = i++;                                  // consume the opening quote
    for (;;) {
      const c = text[i];
      if (c === "\\") { i += 2; continue; }
      i++;
      if (c === '"') break;
    }
    return JSON.parse(text.slice(start, i));            // member names keep escape semantics
  };
  const value = () => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; ws();
      const o = {};
      if (text[i] === "}") { i++; return o; }
      for (;;) {
        ws();
        const k = str();
        ws(); i++;                                      // consume ':'
        o[k] = value();
        ws();
        if (text[i] === ",") { i++; continue; }
        i++;                                            // consume '}'
        return o;
      }
    }
    if (c === "[") {
      i++; ws();
      const a = [];
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(value());
        ws();
        if (text[i] === ",") { i++; continue; }
        i++;                                            // consume ']'
        return a;
      }
    }
    if (c === '"') { str(); return null; }
    const m = NUMBER_TOKEN.exec(text.slice(i));
    if (m) { i += m[0].length; return { lexeme: m[0] }; }
    i += text.startsWith("true", i) ? 4 : text.startsWith("false", i) ? 5 : 4;   // true|false|null
    return null;
  };
  return value();
}

// The two lexemes stage 6 needs, or null when the document has no such token.
function claimNumericLexemes(shadow) {
  const claim = isPlainObject(shadow) && isPlainObject(shadow.head_witness)
    ? shadow.head_witness.claim : null;
  const lex = (k) => (isPlainObject(claim) && isPlainObject(claim[k])
    && typeof claim[k].lexeme === "string" ? claim[k].lexeme : null);
  return { sequence: lex("sequence"), length: lex("length") };
}

// ---------------------------------------------------------------------------
// 3. Frozen constructions (INTEGRITY 2, 3, 4)
// ---------------------------------------------------------------------------

const LF = Buffer.from([0x0a]);

// INTEGRITY 2 - hash preimage = tag-bytes LF jcs-bytes, over the artifact with
// integrity.current and integrity.signature deleted and everything else kept.
function hashPreimage(artifact) {
  const body = deepCopy(artifact);
  delete body.integrity.current;
  delete body.integrity.signature;
  const tag = `AIREP/${artifact.airep_version}/hash/${artifact.artifact_type}`;
  return Buffer.concat([Buffer.from(tag, "ascii"), LF, Buffer.from(jcs(body), "utf8")]);
}

function recomputeCurrent(artifact) {
  return "sha256:" + crypto.createHash("sha256").update(hashPreimage(artifact)).digest("hex");
}

// INTEGRITY 3 - sig_preimage = sig-tag-bytes LF suite-id-bytes LF current-bytes.
// suite-id comes ONLY from the verifier-accepted binding (INTEGRITY 3.2).
function recordSignaturePreimage(artifact, suiteId) {
  const tag = `AIREP/${artifact.airep_version}/sig/${artifact.artifact_type}`;
  return Buffer.concat([
    Buffer.from(tag, "ascii"), LF,
    Buffer.from(suiteId, "ascii"), LF,
    Buffer.from(artifact.integrity.current, "ascii"),
  ]);
}

// INTEGRITY 4 - witness_preimage = "AIREP/<version>/sig/head-witness" LF
// suite-id-bytes LF jcs-claim-bytes. <version> is the referenced head
// artifact's airep_version (INTEGRITY 4.3); no search, ever.
function headWitnessPreimage(headVersion, suiteId, claim) {
  const tag = `AIREP/${headVersion}/sig/head-witness`;
  return Buffer.concat([
    Buffer.from(tag, "ascii"), LF,
    Buffer.from(suiteId, "ascii"), LF,
    Buffer.from(jcs(claim), "utf8"),
  ]);
}

function ed25519PublicKey(hex) {
  // raw 32-byte key -> SPKI DER (fixed 12-byte Ed25519 prefix)
  const der = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(hex, "hex"),
  ]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function verifyEd25519(preimage, sigHex, pubHex) {
  if (typeof sigHex !== "string" || !SIG_HEX.test(sigHex)) return false;
  try {
    return crypto.verify(null, preimage, ed25519PublicKey(pubHex), Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 4. Proleptic-Gregorian integer date arithmetic (no Date.UTC: it remaps 0-99)
// ---------------------------------------------------------------------------

function isLeap(y) {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

function daysInMonth(y, m) {
  const d = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
  return m === 2 && isLeap(y) ? 29 : d;
}

// Howard Hinnant's days_from_civil, proleptic Gregorian, integer only.
function daysFromCivil(y, m, d) {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;                                  // [0, 399]
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function calendarValid(y, m, d, hh, mm, ss) {
  if (m < 1 || m > 12) return false;
  if (d < 1 || d > daysInMonth(y, m)) return false;
  if (hh > 23 || mm > 59 || ss > 59) return false;             // leap second 60 rejected
  return true;
}

// Returns { sec: BigInt, nano: BigInt } seconds since 1970-01-01T00:00:00Z.
function civilToInstant(y, m, d, hh, mm, ss, nanoStr) {
  const days = BigInt(daysFromCivil(y, m, d));
  const sec = days * 86400n + BigInt(hh) * 3600n + BigInt(mm) * 60n + BigInt(ss);
  const frac = nanoStr ? BigInt(nanoStr.padEnd(9, "0")) : 0n;
  return { sec, nano: frac };
}

// --now / clock `now`: pattern + Gregorian validity. Returns instant or null.
function parseNow(s) {
  if (typeof s !== "string") return null;
  const m = NOW_PATTERN.exec(s);
  if (!m) return null;
  const [, Y, Mo, D, H, Mi, S, F] = m;
  const y = +Y, mo = +Mo, d = +D, hh = +H, mi = +Mi, ss = +S;
  if (!calendarValid(y, mo, d, hh, mi, ss)) return null;
  return civilToInstant(y, mo, d, hh, mi, ss, F);
}

// witnessed_at: exactly YYYY-MM-DDTHH:MM:SSZ, Gregorian-valid (INTEGRITY 4.2).
function parseWitnessedAt(s) {
  if (typeof s !== "string") return null;
  const m = WITNESSED_AT.exec(s);
  if (!m) return null;
  const [, Y, Mo, D, H, Mi, S] = m;
  const y = +Y, mo = +Mo, d = +D, hh = +H, mi = +Mi, ss = +S;
  if (!calendarValid(y, mo, d, hh, mi, ss)) return null;
  return civilToInstant(y, mo, d, hh, mi, ss, null);
}

// Freshness predicate: abs(now - witnessed_at) <= window, boundary-equal fresh.
function withinWindow(nowInstant, wInstant, windowSeconds) {
  const NS = 1000000000n;
  const a = nowInstant.sec * NS + nowInstant.nano;
  const b = wInstant.sec * NS + wInstant.nano;
  let diff = a - b;
  if (diff < 0n) diff = -diff;
  return diff <= BigInt(windowSeconds) * NS;
}

// ---------------------------------------------------------------------------
// 5. Stage 0: accepted family schema validation
// ---------------------------------------------------------------------------

let validators = null;

function schemaValidators() {
  if (validators) return validators;
  const ajv = new Ajv2020({ strict: false, allErrors: false, validateFormats: false });
  const files = ["common", "decision", "control", "execution", "effect"];
  const schemas = {};
  for (const f of files) {
    let text;
    try {
      text = fs.readFileSync(path.join(schemaDir, `${f}.schema.json`), "utf8");
    } catch {
      // A schema directory that does not resolve is a config error, not a class
      // result (contract 6.4 exit 2, as for the malformed clock inputs).
      throw new UsageError(`accepted schema not readable under --schema-dir: ${schemaDir}`);
    }
    schemas[f] = JSON.parse(text);
  }
  ajv.addSchema(schemas.common);
  validators = {};
  for (const t of ARTIFACT_TYPES) {
    validators[t] = ajv.compile(schemas[t]);
  }
  return validators;
}

function schemaValid(artifact) {
  if (!isPlainObject(artifact)) return false;
  const t = artifact.artifact_type;
  if (typeof t !== "string" || !ARTIFACT_TYPES.includes(t)) return false;
  if (artifact.airep_version !== "0.2") return false;
  return schemaValidators()[t](artifact) === true;
}

// ---------------------------------------------------------------------------
// 6. Operator inputs (contract 1)
// ---------------------------------------------------------------------------

function readJsonFile(file, what) {
  let bytes;
  try {
    bytes = fs.readFileSync(file);
  } catch (e) {
    throw new InvalidRunError(`${what} file could not be read: ${file}`);
  }
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (e) {
    throw new InvalidRunError(`${what} file could not be parsed as JSON: ${file}`);
  }
  const digest = "sha256:" + crypto.createHash("sha256").update(bytes).digest("hex");
  return { value, digest, text: bytes.toString("utf8") };
}

function onlyKeys(obj, allowed) {
  return Object.keys(obj).every((k) => allowed.includes(k));
}

// --- 1.1 binding store -----------------------------------------------------

function loadBindingStore(value) {
  const store = { wellFormed: false, bindings: {}, producer: {}, witness: {} };
  if (!isPlainObject(value)) return store;
  if (!onlyKeys(value, ["bindings", "producer_bindings", "witness_bindings"])) return store;
  const b = value.bindings, p = value.producer_bindings, w = value.witness_bindings;
  // E-4: the section-1 container members are REQUIRED, not defaulted to empty.
  if (!isPlainObject(b) || !isPlainObject(p) || !isPlainObject(w)) return store;
  for (const map of [p, w]) {
    for (const k of Object.keys(map)) if (typeof map[k] !== "string") return store;
  }
  store.wellFormed = true;
  store.bindings = b;
  store.producer = p;
  store.witness = w;
  return store;
}

// Returns { status, binding_id, binding }.
// status: "ok" | "missing" | "not_trusted" | "malformed" | "suite_unsupported"
function resolveBinding(store, role, wireId) {
  if (store === null) return { status: "missing" };
  if (!store.wellFormed) return { status: "malformed" };
  if (typeof wireId !== "string") return { status: "missing" };
  const map = role === "producer" ? store.producer : store.witness;
  if (!Object.prototype.hasOwnProperty.call(map, wireId)) return { status: "missing" };
  const bindingId = map[wireId];
  if (!NAMESPACED_ID.test(bindingId)) return { status: "malformed", binding_id: bindingId };
  if (!Object.prototype.hasOwnProperty.call(store.bindings, bindingId)) {
    return { status: "malformed", binding_id: bindingId };
  }
  const entry = store.bindings[bindingId];
  const mal = { status: "malformed", binding_id: bindingId };
  if (!isPlainObject(entry)) return mal;
  if (!onlyKeys(entry, ["subject_identity", "role", "public_key_hex", "suite", "trusted"])) return mal;
  if (typeof entry.subject_identity !== "string" || !NAMESPACED_ID.test(entry.subject_identity)) return mal;
  if (entry.role !== role) return mal;
  if (typeof entry.public_key_hex !== "string" || !PUBKEY_HEX.test(entry.public_key_hex)) return mal;
  if (typeof entry.suite !== "string") return mal;
  if (!Object.prototype.hasOwnProperty.call(entry, "trusted")) return mal;   // absent => malformed
  if (entry.trusted !== true) return { status: "not_trusted", binding_id: bindingId, binding: entry };
  if (!SUITE_REGISTRY.has(entry.suite)) {
    return { status: "suite_unsupported", binding_id: bindingId, binding: entry };
  }
  return { status: "ok", binding_id: bindingId, binding: entry };
}

// --- 1.3 revocation snapshot ----------------------------------------------

function loadRevocation(value) {
  const snap = { wellFormed: false, bindings: {} };
  if (!isPlainObject(value)) return snap;
  if (!onlyKeys(value, ["snapshot_id", "bindings"])) return snap;
  if (typeof value.snapshot_id !== "string" || !NAMESPACED_ID.test(value.snapshot_id)) return snap;
  if (!isPlainObject(value.bindings)) return snap;          // E-4: required member
  snap.wellFormed = true;
  snap.bindings = value.bindings;
  return snap;
}

// "missing" | "malformed" | "active" | "revoked"
function revocationState(snapshot, bindingId) {
  if (snapshot === null) return "missing";
  if (!snapshot.wellFormed) return "malformed";
  if (!Object.prototype.hasOwnProperty.call(snapshot.bindings, bindingId)) return "missing";
  const e = snapshot.bindings[bindingId];
  if (!isPlainObject(e) || !onlyKeys(e, ["state"])) return "malformed";
  if (e.state === "active" || e.state === "revoked") return e.state;
  return "malformed";
}

// --- 1.2 independence policy ----------------------------------------------

function loadIndependence(value) {
  const pol = { wellFormed: false, independent: [], nonIndependent: [] };
  if (!isPlainObject(value)) return pol;
  if (!onlyKeys(value, ["independent_pairs", "non_independent_pairs"])) return pol;
  const parse = (arr) => {
    if (!Array.isArray(arr)) return null;                   // E-4: required member
    const out = [];
    for (const p of arr) {
      if (!isPlainObject(p) || !onlyKeys(p, ["a", "b"])) return null;
      if (typeof p.a !== "string" || typeof p.b !== "string") return null;
      if (!NAMESPACED_ID.test(p.a) || !NAMESPACED_ID.test(p.b)) return null;
      out.push([p.a, p.b]);
    }
    return out;
  };
  const ind = parse(value.independent_pairs);
  const non = parse(value.non_independent_pairs);
  if (ind === null || non === null) return pol;
  pol.wellFormed = true;
  pol.independent = ind;
  pol.nonIndependent = non;
  return pol;
}

function pairListed(list, x, y) {
  return list.some(([a, b]) => (a === x && b === y) || (a === y && b === x));
}

// "independent" | "denied" | "absent" | "malformed"
function policyRelation(policy, x, y) {
  if (!policy.wellFormed) return "malformed";
  const ind = pairListed(policy.independent, x, y);
  const non = pairListed(policy.nonIndependent, x, y);
  if (ind && non) return "malformed";        // listed in both => malformed policy
  if (non) return "denied";
  if (ind) return "independent";
  return "absent";
}

// ---------------------------------------------------------------------------
// 7. Contract section 0: evaluation request envelope + reference resolution
// ---------------------------------------------------------------------------

const CLAIM_MEMBERS = ["chain_id", "sequence", "current", "length", "witnessed_at"];

function loadRequest(value, text) {
  if (!isPlainObject(value)) throw new InvalidRunError("request is not a JSON object");
  if (!onlyKeys(value, ["artifact", "related_artifacts", "head_witness"])) {
    throw new InvalidRunError("request envelope carries an unknown member (closed envelope)");
  }
  if (!isPlainObject(value.artifact)) throw new InvalidRunError("request.artifact missing or not an object");
  const related = value.related_artifacts === undefined ? [] : value.related_artifacts;
  if (!Array.isArray(related) || !related.every(isPlainObject)) {
    throw new InvalidRunError("request.related_artifacts must be an array of objects");
  }
  let hw = null;
  if (value.head_witness !== undefined) {
    const h = value.head_witness;
    if (!isPlainObject(h)) throw new InvalidRunError("request.head_witness is not an object");
    if (!onlyKeys(h, ["head_ref", "witness_id", "claim", "signature"])) {
      throw new InvalidRunError("head_witness carries an unknown member (closed envelope)");
    }
    for (const k of ["head_ref", "witness_id", "claim", "signature"]) {
      if (!Object.prototype.hasOwnProperty.call(h, k)) {
        throw new InvalidRunError(`head_witness is missing ${k}`);
      }
    }
    // E-4 as narrowed by section 9 R-4: the section-0 nested closure is limited
    // to head_ref and signature; an unknown member in either makes the RUN
    // invalid. R-1 WITHDREW `claim` from that closure -- the claim is the frozen
    // INTEGRITY 4.2 evidence object and is evaluated on its own semantic path
    // (stage 6a), so a claim defect is never run-invalid.
    if (isPlainObject(h.head_ref) && !onlyKeys(h.head_ref, ["record_id", "chain_id"])) {
      throw new InvalidRunError("head_witness.head_ref carries an unknown member (closed envelope)");
    }
    if (!isPlainObject(h.signature)) throw new InvalidRunError("head_witness.signature is not an object");
    if (!onlyKeys(h.signature, ["alg", "value"])) {
      throw new InvalidRunError("head_witness.signature carries an unknown member (closed envelope)");
    }
    hw = h;
  }
  // E-1: the claim's numeric source lexemes, recovered from the request text.
  const claimLexemes = claimNumericLexemes(typeof text === "string" ? jsonShadow(text) : null);
  return { artifact: value.artifact, related, head_witness: hw, claimLexemes };
}

// v0.2 reference semantics: match record_id, additionally chain_id when carried.
// Returns { status: "ok"|"unresolved", artifact }.
function resolveRef(ref, pool) {
  if (!isPlainObject(ref) || typeof ref.record_id !== "string") return { status: "unresolved" };
  if (ref.chain_id !== undefined && typeof ref.chain_id !== "string") return { status: "unresolved" };
  const matches = pool.filter((a) => {
    if (a.record_id !== ref.record_id) return false;
    if (ref.chain_id !== undefined && a.chain_id !== ref.chain_id) return false;
    return true;
  });
  if (matches.length !== 1) return { status: "unresolved" };   // zero or ambiguous: fail closed
  return { status: "ok", artifact: matches[0] };
}

// ---------------------------------------------------------------------------
// 8. The producer (Authenticated) tier for any artifact - stages 0..5
// ---------------------------------------------------------------------------

function evaluateProducerTier(artifact, policy) {
  const failures = [];
  const withheld = [];
  const caveats = [];
  const res = resolveBinding(policy.bindings, "producer", artifact?.subject?.producer);

  let bindingAccepted = false;
  switch (res.status) {
    case "ok": bindingAccepted = true; break;
    case "missing": withheld.push("producer-binding-missing"); break;
    case "malformed": withheld.push("producer-binding-malformed"); break;
    case "suite_unsupported": withheld.push("producer-suite-unsupported"); break;
    case "not_trusted": failures.push("producer-binding-not-trusted"); break;
  }

  // Stage 3 - prerequisite: producer binding accepted.
  let state = null;
  if (bindingAccepted) {
    state = revocationState(policy.revocation, res.binding_id);
    if (state === "missing") withheld.push("producer-revocation-state-missing");
    else if (state === "malformed") withheld.push("producer-revocation-state-malformed");
    else if (state === "revoked") failures.push("producer-binding-revoked");
  }

  // Stage 4 - prerequisite: binding accepted and not revoked.
  let sigOk = null;
  if (bindingAccepted && state !== "revoked") {
    const preimage = recordSignaturePreimage(artifact, res.binding.suite);
    sigOk = verifyEd25519(preimage, artifact.integrity.signature.value, res.binding.public_key_hex);
    if (!sigOk) failures.push("producer-signature-invalid");
  }

  const authenticated = failures.length === 0 && withheld.length === 0;

  // Stage 5 - caveats surface only on an EARNED Authenticated result.
  if (authenticated) {
    const kt = artifact.profiles && artifact.profiles["airep.key-trust"];
    if (isPlainObject(kt) && isPlainObject(kt.revocation) && kt.revocation.revoked === true) {
      caveats.push("producer-key-self-revoked");
    }
    const wireAlg = artifact.integrity.signature.alg;
    if (typeof wireAlg === "string" && wireAlg.toLowerCase() !== res.binding.suite.toLowerCase()) {
      caveats.push("wire-alg-mismatch");
    }
  }

  return {
    failures, withheld, caveats, authenticated,
    bindingAccepted,
    bindingId: res.binding_id ?? null,
    binding: res.binding ?? null,
  };
}

// Full "Authenticated in its own right" check for a referenced artifact
// (contract section 0, observer path).
function authenticatesInOwnRight(artifact, policy) {
  if (!schemaValid(artifact)) return { ok: false };
  if (recomputeCurrent(artifact) !== artifact.integrity.current) return { ok: false };
  const tier = evaluateProducerTier(artifact, policy);
  return { ok: tier.authenticated, bindingId: tier.bindingId, binding: tier.binding };
}

// ---------------------------------------------------------------------------
// 9. Three-condition independence gate (design section 3 / contract 1.2)
// ---------------------------------------------------------------------------
// Returns a list of reasons using the supplied reason names; empty == independent.
function independenceGate(aBindingId, aBinding, bBindingId, bBinding, policy, names) {
  const out = [];
  if (aBinding.subject_identity === bBinding.subject_identity) out.push(names.identity);
  if (aBinding.public_key_hex === bBinding.public_key_hex) out.push(names.key);
  const rel = policyRelation(policy.independence, aBindingId, bBindingId);
  if (rel === "malformed") out.push(names.policyMalformed);
  else if (rel === "denied") out.push(names.denied);
  else if (rel === "absent") out.push(names.absent);
  return out;
}

// ---------------------------------------------------------------------------
// 10. Head-witness claim structural validation (frozen INTEGRITY 4.2)
// ---------------------------------------------------------------------------

function claimStructurallyValid(claim, lexemes) {
  if (!isPlainObject(claim)) return false;
  const keys = Object.keys(claim);
  if (keys.length !== CLAIM_MEMBERS.length) return false;        // closed: exactly five
  for (const m of CLAIM_MEMBERS) if (!Object.prototype.hasOwnProperty.call(claim, m)) return false;
  if (typeof claim.chain_id !== "string") return false;
  if (typeof claim.sequence !== "number" || !Number.isSafeInteger(claim.sequence) || claim.sequence < 0) return false;
  if (typeof claim.current !== "string" || !SHA256_DIGEST.test(claim.current)) return false;
  if (typeof claim.length !== "number" || !Number.isSafeInteger(claim.length) || claim.length < 1) return false;
  if (typeof claim.witnessed_at !== "string") return false;      // value semantics: stage 6, below
  // E-1: the numeric members carry a LEXICAL rule; the parsed value is not
  // sufficient, so the source spelling must itself be a bare decimal integer.
  if (!INTEGER_LEXEME.test(lexemes.sequence ?? "")) return false;
  if (!INTEGER_LEXEME.test(lexemes.length ?? "")) return false;
  return true;
}

// ---------------------------------------------------------------------------
// 11. The evaluation (contract section 3 stage order + section 4 dependencies)
// ---------------------------------------------------------------------------

function evaluate(request, policy) {
  const artifact = request.artifact;

  // Stage 0 - accepted family schema validation.
  if (!schemaValid(artifact)) {
    throw new InvalidRunError("stage 0: artifact fails accepted family schema validation");
  }
  // Stage 1 - Core: frozen hash recomputation under the declared (version, type).
  if (recomputeCurrent(artifact) !== artifact.integrity.current) {
    throw new InvalidRunError("stage 1: integrity.current does not match the frozen hash recomputation");
  }

  // Stages 2-5 - Authenticated tier.
  const prod = evaluateProducerTier(artifact, policy);
  const authFailures = [...prod.failures];
  const authWithheld = [...prod.withheld];
  const authCaveats = [...prod.caveats];

  const witFailures = [];
  const witWithheld = [];

  // ---- Stage 6: 6a claim validity -> 6b head -> 6c witnessed_at validity ---
  // Section 9 R-2: these are dependent sub-steps of one witness-head gate, not
  // independent gates. A failing sub-step reports its reason ALONE and the
  // later sub-steps do not run. Stage 6 is clean only when all three pass.
  const hw = request.head_witness;
  let stage6Clean = false;
  if (hw === null) {
    witWithheld.push("no-witness-supplied");
  } else if (!claimStructurallyValid(hw.claim, request.claimLexemes)) {
    // 6a - claim structural + lexical validity (closed five-member set, member
    // types, E-1 source-token rule). Reported alone; section 4 then suppresses
    // stages 7-10 as well.
    witFailures.push("witness-claim-invalid");
  } else {
    // 6b - head resolution, must-be-primary, reconciliation. Reported alone.
    const pool = [artifact, ...request.related];
    const resolved = resolveRef(hw.head_ref, pool);
    let headOk = false;
    if (resolved.status !== "ok") {
      witFailures.push("witness-head-unresolved");
    } else if (resolved.artifact !== artifact) {
      // A valid witness over some OTHER artifact never confers Witnessed here.
      witFailures.push("witness-head-mismatch");
    } else {
      const c = hw.claim;
      // R-5: a claim that resolves to the primary but does not reconcile is
      // witness-head-mismatch, the same reason as resolving elsewhere.
      const reconciles = c.chain_id === artifact.chain_id
        && c.sequence === artifact.sequence
        && c.current === artifact.integrity.current;
      if (!reconciles) witFailures.push("witness-head-mismatch");
      else headOk = true;
    }
    // 6c - witnessed_at format + Gregorian validity (E-2, sequenced by R-2).
    // Clock inputs play no part here; stage 10 computes recency only.
    if (headOk) {
      if (parseWitnessedAt(hw.claim.witnessed_at) === null) {
        witFailures.push("witness-time-invalid");
      } else {
        stage6Clean = true;
      }
    }
  }

  // ---- Stage 7: witness binding resolution + revocation --------------------
  let witRes = { status: "missing" };
  let witBindingAccepted = false;
  let stage7Clean = false;
  if (stage6Clean) {
    witRes = resolveBinding(policy.bindings, "witness", hw.witness_id);
    switch (witRes.status) {
      case "ok": witBindingAccepted = true; break;
      case "missing": witWithheld.push("witness-binding-missing"); break;
      case "malformed": witWithheld.push("witness-binding-malformed"); break;
      case "suite_unsupported": witWithheld.push("witness-suite-unsupported"); break;
      case "not_trusted": witFailures.push("witness-binding-not-trusted"); break;
    }
    if (witBindingAccepted) {
      const st = revocationState(policy.revocation, witRes.binding_id);
      if (st === "missing") witWithheld.push("witness-revocation-state-missing");
      else if (st === "malformed") witWithheld.push("witness-revocation-state-malformed");
      else if (st === "revoked") witFailures.push("witness-binding-revoked");
      else stage7Clean = true;
    }
  }

  // ---- Stage 8: independence (three conditions) ---------------------------
  // Prerequisites: producer binding accepted AND stage 7 clean AND policy present.
  if (prod.bindingAccepted && stage7Clean) {
    if (policy.independence === null) {
      witWithheld.push("independence-policy-missing");
    } else {
      const reasons = independenceGate(
        prod.bindingId, prod.binding, witRes.binding_id, witRes.binding, policy,
        {
          identity: "witness-identity-not-distinct",
          key: "witness-key-not-distinct",
          denied: "independence-explicitly-denied",
          absent: "independence-relation-absent",
          policyMalformed: "independence-policy-malformed",
        });
      for (const r of reasons) {
        if (REASONS[r][1] === "failure") witFailures.push(r); else witWithheld.push(r);
      }
    }
  }

  // ---- Stage 9: witness signature ----------------------------------------
  if (stage7Clean) {
    const preimage = headWitnessPreimage(artifact.airep_version, witRes.binding.suite, hw.claim);
    const ok = verifyEd25519(preimage, hw.signature.value, witRes.binding.public_key_hex);
    if (!ok) witFailures.push("witness-signature-invalid");
  }

  // ---- Stage 10: freshness ------------------------------------------------
  if (stage6Clean) {
    if (policy.now === null || policy.freshnessWindow === null) {
      witWithheld.push("freshness-inputs-missing");
    } else {
      // stage6Clean implies witnessed_at already parsed (E-2): recency only here.
      const w = parseWitnessedAt(hw.claim.witnessed_at);
      if (!withinWindow(policy.nowInstant, w, policy.freshnessWindow)) {
        witFailures.push("witness-freshness-outside-window");
      }
    }
  }

  // ---- Stage 11: class ----------------------------------------------------
  const authenticated = authFailures.length === 0 && authWithheld.length === 0;
  const witnessedClean = witFailures.length === 0 && witWithheld.length === 0;
  let klass = "AIREP-Core";
  if (authenticated) klass = witnessedClean ? "AIREP-Witnessed" : "AIREP-Authenticated";

  // ---- Observer assessment (Effect artifacts) -----------------------------
  const observer = observerAssessment(artifact, request, policy, prod, authenticated);

  return {
    artifact_ref: { chain_id: artifact.chain_id, record_id: artifact.record_id },
    class: klass,
    authenticated_failures: sortedSet(authFailures),
    authenticated_withheld: sortedSet(authWithheld),
    authenticated_caveats: sortedSet(authCaveats),
    witnessed_failures: sortedSet(witFailures),
    witnessed_withheld: sortedSet(witWithheld),
    observer_assessment: observer,
    evidence: {
      now: policy.now,
      freshness_window_seconds: policy.freshnessWindow,
      bindings_digest: policy.digests.bindings,
      independence_policy_digest: policy.digests.independence,
      revocation_digest: policy.digests.revocation,
    },
  };
}

// Contract section 3 / design section 7: `independent` on the wire is accepted only
// under the same three-condition gate; otherwise the effective value is `unknown`
// and the artifact's class does not drop for it.
function observerAssessment(artifact, request, policy, prod, authenticated) {
  if (artifact.artifact_type !== "effect") return "not_applicable";
  const declared = artifact.observer_relationship;
  if (declared !== "independent") return declared;              // same_executor | unknown
  if (!authenticated || !prod.bindingAccepted) return "unknown";
  const resolved = resolveRef(artifact.execution_ref, [artifact, ...request.related]);
  if (resolved.status !== "ok") return "unknown";
  const exec = authenticatesInOwnRight(resolved.artifact, policy);
  if (!exec.ok) return "unknown";
  if (policy.independence === null) return "unknown";
  const reasons = independenceGate(prod.bindingId, prod.binding, exec.bindingId, exec.binding, policy,
    { identity: "i", key: "k", denied: "d", absent: "a", policyMalformed: "m" });
  return reasons.length === 0 ? "independent" : "unknown";
}

function sortedSet(list) {
  return [...new Set(list)].sort();   // registry is ASCII: default sort == ASCII ascending
}

// ---------------------------------------------------------------------------
// 12. Deterministic output serialization
// ---------------------------------------------------------------------------

// Unsigned lexicographic order over each string's UTF-8 bytes; no normalization.
// (JS default string comparison is UTF-16 code-unit order and is NOT this.)
function utf8Compare(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function stableStringify(v, indent = 1, depth = 0) {
  const pad = (n) => " ".repeat(indent * n);
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) {
    if (v.length === 0) return "[]";
    const items = v.map((x) => pad(depth + 1) + stableStringify(x, indent, depth + 1));
    return "[\n" + items.join(",\n") + "\n" + pad(depth) + "]";
  }
  const keys = Object.keys(v).sort();
  if (keys.length === 0) return "{}";
  const items = keys.map((k) => pad(depth + 1) + JSON.stringify(k) + ": " + stableStringify(v[k], indent, depth + 1));
  return "{\n" + items.join(",\n") + "\n" + pad(depth) + "}";
}

// ---------------------------------------------------------------------------
// 13. CLI
// ---------------------------------------------------------------------------

const HELP = `class_verifier.mjs - AIREP v0.2 class verifier

Single case:
  node class_verifier.mjs --request FILE [--bindings FILE] [--independence-policy FILE]
                          [--revocation FILE] [--now STR] [--freshness-window N]

Batch:
  node class_verifier.mjs --corpus DIR --out FILE

  --schema-dir DIR   accepted v0.2 schema directory
                     (default: ../../schemas, relative to this file)

Exit codes: 0 evaluation completed; 1 unparseable input or stage-0/1 artifact
invalidity (no verdict producible); 2 CLI usage/config error.
`;

function parseArgs(argv) {
  const flags = {
    request: null, bindings: null, "independence-policy": null, revocation: null,
    now: null, "freshness-window": null, corpus: null, out: null, "schema-dir": null,
  };
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { help = true; continue; }
    if (!a.startsWith("--")) throw new UsageError(`unexpected argument: ${a}`);
    const name = a.slice(2);
    if (!(name in flags)) throw new UsageError(`unknown option: ${a}`);
    if (i + 1 >= argv.length) throw new UsageError(`option ${a} requires a value`);
    if (flags[name] !== null) throw new UsageError(`option ${a} given more than once`);
    flags[name] = argv[++i];
  }
  return { flags, help };
}

// Assemble the policy bundle shared by every stage.
function buildPolicy({ bindingsFile, independenceFile, revocationFile, now, freshnessWindow }) {
  const digests = { bindings: null, independence: null, revocation: null };
  let bindings = null, independence = null, revocation = null;

  if (bindingsFile !== null) {
    const r = readJsonFile(bindingsFile, "bindings");
    digests.bindings = r.digest;
    bindings = loadBindingStore(r.value);
  }
  if (independenceFile !== null) {
    const r = readJsonFile(independenceFile, "independence policy");
    digests.independence = r.digest;
    independence = loadIndependence(r.value);
  }
  if (revocationFile !== null) {
    const r = readJsonFile(revocationFile, "revocation");
    digests.revocation = r.digest;
    revocation = loadRevocation(r.value);
  }

  let nowInstant = null;
  if (now !== null && now !== undefined) {
    nowInstant = parseNow(now);
    if (nowInstant === null) throw new UsageError(`--now is present but malformed: ${now}`);
  }
  let window = null;
  if (freshnessWindow !== null && freshnessWindow !== undefined) {
    if (typeof freshnessWindow === "string") {
      if (!/^[0-9]+$/.test(freshnessWindow)) {
        throw new UsageError(`--freshness-window is present but malformed: ${freshnessWindow}`);
      }
      window = Number(freshnessWindow);
    } else if (typeof freshnessWindow === "number" && Number.isSafeInteger(freshnessWindow) && freshnessWindow >= 0) {
      window = freshnessWindow;
    } else {
      throw new UsageError(`freshness window is present but malformed: ${String(freshnessWindow)}`);
    }
    if (!Number.isSafeInteger(window) || window < 0) {
      throw new UsageError(`freshness window is present but malformed: ${String(freshnessWindow)}`);
    }
  }

  return {
    bindings, independence, revocation, digests,
    now: nowInstant === null ? null : now,
    nowInstant,
    freshnessWindow: window,
  };
}

function runSingle(flags) {
  if (flags.request === null) throw new UsageError("--request is required");
  const policy = buildPolicy({
    bindingsFile: flags.bindings,
    independenceFile: flags["independence-policy"],
    revocationFile: flags.revocation,
    now: flags.now,
    freshnessWindow: flags["freshness-window"],
  });
  const req = readJsonFile(flags.request, "request");
  const request = loadRequest(req.value, req.text);
  const verdict = evaluate(request, policy);
  process.stdout.write(stableStringify(verdict) + "\n");
  return 0;
}

function runBatch(flags) {
  const dir = flags.corpus;
  if (flags.out === null) throw new UsageError("--corpus requires --out");
  const indexPath = path.join(dir, "case_index.json");
  const index = readJsonFile(indexPath, "case index").value;
  if (!Array.isArray(index)) throw new InvalidRunError("case_index.json is not an array");

  const verdicts = [];
  for (const entry of index) {
    const files = entry.files || {};
    const resolve = (k) => (files[k] === undefined ? null : path.join(dir, files[k]));

    let now = null, window = null;
    const clockPath = resolve("clock");
    if (clockPath !== null) {
      const clock = readJsonFile(clockPath, "clock").value;
      if (!isPlainObject(clock) || !onlyKeys(clock, ["now", "freshness_window_seconds"])) {
        throw new UsageError(`clock input is present but malformed: ${clockPath}`);
      }
      now = clock.now === undefined ? null : clock.now;
      window = clock.freshness_window_seconds === undefined ? null : clock.freshness_window_seconds;
      if (now !== null && typeof now !== "string") {
        throw new UsageError(`clock 'now' is present but malformed: ${clockPath}`);
      }
    }

    const policy = buildPolicy({
      bindingsFile: resolve("bindings"),
      independenceFile: resolve("independence"),
      revocationFile: resolve("revocation"),
      now, freshnessWindow: window,
    });
    const reqPath = resolve("request");
    if (reqPath === null) throw new InvalidRunError(`case ${entry.case_id} supplies no request file`);
    // A genuinely invalid run propagates to main() and is reported as invalid
    // (contract 6.4, exit 1). No per-case swallowing, no case-specific path.
    const reqFile = readJsonFile(reqPath, "request");
    const request = loadRequest(reqFile.value, reqFile.text);
    verdicts.push(evaluate(request, policy));
  }

  verdicts.sort((x, y) => {
    const c = utf8Compare(x.artifact_ref.chain_id, y.artifact_ref.chain_id);
    return c !== 0 ? c : utf8Compare(x.artifact_ref.record_id, y.artifact_ref.record_id);
  });

  fs.writeFileSync(flags.out, stableStringify({ verdicts }) + "\n");
  return 0;
}

function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`usage error: ${e.message}\n`);
    return 2;
  }
  if (parsed.help) {
    process.stdout.write(HELP);
    return 0;
  }
  const { flags } = parsed;
  if (flags["schema-dir"] !== null) schemaDir = flags["schema-dir"];
  try {
    if (flags.corpus !== null) {
      if (flags.request !== null) throw new UsageError("--corpus and --request are mutually exclusive");
      return runBatch(flags);
    }
    return runSingle(flags);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n`);
      return 2;
    }
    if (e instanceof InvalidRunError) {
      process.stderr.write(`invalid: ${e.message}\n`);
      return 1;
    }
    throw e;
  }
}

process.exit(main());
