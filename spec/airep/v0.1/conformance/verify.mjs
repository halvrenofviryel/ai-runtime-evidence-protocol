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
// Usage:  node verify.mjs <record.json | chain.jsonl> [--pubkey <hex | path-to-key-file>]
// Exit 0 if every record passes, 1 otherwise. Requires Node >= 16 (raw Ed25519 keys).
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

function main() {
  const args = process.argv.slice(2);
  const file = args[0];
  const pi = args.indexOf("--pubkey");
  const pub = loadPub(pi >= 0 ? args[pi + 1] : "");
  const records = loadRecords(file);
  const isChain = records.length > 1;
  let fails = 0;
  let prev = GENESIS;
  console.log(`AIREP verify (node): ${file}  (${records.length} record(s)${isChain ? " — chain" : ""})`);
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
    console.log(`  [${i}] ${bad.length ? "FAIL(" + bad.join(",") + ")" : "PASS"}  ${sigstr}  ${String(integ.current).slice(0, 23)}...`);
    if (bad.length) fails++;
  });
  console.log(`RESULT: ${fails ? fails + " record(s) FAILED" : "all records OK"}`);
  process.exit(fails ? 1 : 0);
}

main();
