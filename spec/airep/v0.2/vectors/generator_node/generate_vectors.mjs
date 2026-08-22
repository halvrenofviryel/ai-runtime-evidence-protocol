#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// AIREP v0.2 WP-α01 Stage-3B — Node fixed-vector generator (independent implementation).
//
// Inputs (the ONLY ones, per the Stage-3 independence discipline):
//   - ../../INTEGRITY.md  (normative construction — restated in comments below, §-referenced)
//   - ../VECTOR_PLAN.md   (vector set, keys, output contract)
//   - ../INPUTS.json      (shared semantic inputs)
// The JCS canonicalization core is reused from the pre-existing v0.1 conformance verifier
// (spec/airep/v0.1/conformance/verify.mjs), as VECTOR_PLAN permits: in JavaScript,
// Object.keys().sort() sorts property names by UTF-16 code units (RFC 8785 §3.2.3) and
// JSON.stringify natively emits the ES6 number serialization (RFC 8785 §3.2.2.3) and the
// RFC 8785 string escaping (control chars as \n, \t, ... / lowercase \uXXXX; non-ASCII literal).
//
// Output: ../out/node_vectors.json — deterministic (recursively sorted keys, trailing newline,
// no timestamps / environment / generator metadata). Two runs are byte-identical.
//
// Usage: node spec/airep/v0.2/vectors/generator_node/generate_vectors.mjs

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const INPUTS_PATH = path.join(HERE, "..", "INPUTS.json");
const OUT_DIR = path.join(HERE, "..", "out");
const OUT_PATH = path.join(OUT_DIR, "node_vectors.json");

const LF = Buffer.from([0x0a]); // the single separator byte (INTEGRITY §2 rule 3, §3, §4)
const SUITE_ID = "ed25519"; // sole registered suite (INTEGRITY §3.1)

// ---- Closed tag registry (INTEGRITY §1.2, §5) -----------------------------------------------
// Tag selection is a pure function of the artifact's own declared (airep_version, artifact_type);
// anything outside the closed registry fails closed — never a nearest match.
const REGISTRY_VERSION = "0.2";
const ARTIFACT_TYPES = new Set(["decision", "control", "execution", "effect"]);

function requireRegistered(version, type) {
  if (version !== REGISTRY_VERSION || !ARTIFACT_TYPES.has(type)) {
    throw new Error(`unregistered tag pair (fail closed): version=${version} type=${type}`);
  }
}
function hashTag(version, type) {
  requireRegistered(version, type);
  return `AIREP/${version}/hash/${type}`;
}
function sigTag(version, type) {
  requireRegistered(version, type);
  return `AIREP/${version}/sig/${type}`;
}
// Witness tag version MUST equal the referenced head artifact's airep_version (INTEGRITY §4.3);
// for v0.2 the registry holds exactly AIREP/0.2/sig/head-witness — any other version is
// unregistered here and fails closed.
function witnessTag(headVersion) {
  if (headVersion !== REGISTRY_VERSION) {
    throw new Error(`unregistered head-witness tag version (fail closed): ${headVersion}`);
  }
  return `AIREP/${headVersion}/sig/head-witness`;
}

// ---- RFC 8785 (JCS) canonicalization -------------------------------------------------------
// Reused from spec/airep/v0.1/conformance/verify.mjs (canonical()).
function canonical(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort()
      .map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  }
  return JSON.stringify(v); // string / number / boolean
}
const jcsBytes = (v) => Buffer.from(canonical(v), "utf8");

// ---- Ed25519 keys (VECTOR_PLAN: published TEST seeds — never production) --------------------
const PRODUCER_SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const WITNESS_SEED_HEX = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
// Raw 32-byte seed -> PKCS#8 DER by prefixing the fixed header.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function keyFromSeed(seedHex) {
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) throw new Error("seed must be exactly 32 bytes");
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const jwk = crypto.createPublicKey(priv).export({ format: "jwk" });
  const raw = Buffer.from(jwk.x, "base64url"); // raw 32-byte Ed25519 public key
  if (raw.length !== 32) throw new Error("unexpected raw public key length");
  return { priv, pubHex: raw.toString("hex") };
}

// Pure Ed25519 (RFC 8032), no pre-hash, over the raw preimage bytes (INTEGRITY §3.1).
const sign = (preimage, key) => crypto.sign(null, preimage, key.priv);

const hex = (buf) => buf.toString("hex"); // Node hex output is lowercase
const asciiBytes = (s) => Buffer.from(s, "ascii");

// ---- Claim member validation (INTEGRITY §4.2) — fail closed on malformed inputs -------------
const CURRENT_RE = /^sha256:[0-9a-f]{64}$/;
const WITNESSED_AT_RE = /^\d{4}-\d{2}-\d{2}T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;
const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 - 1

function validateClaim(claim) {
  if (typeof claim.chain_id !== "string") throw new Error("claim.chain_id must be a string");
  if (!Number.isInteger(claim.sequence) || claim.sequence < 0 || claim.sequence > MAX_SAFE) {
    throw new Error("claim.sequence must be a non-negative safe integer");
  }
  if (!CURRENT_RE.test(claim.current)) throw new Error("claim.current malformed");
  if (!Number.isInteger(claim.length) || claim.length < 1 || claim.length > MAX_SAFE) {
    throw new Error("claim.length must be a positive safe integer");
  }
  if (!WITNESSED_AT_RE.test(claim.witnessed_at)) throw new Error("claim.witnessed_at malformed");
  // Reject invalid Gregorian calendar dates (e.g. February 30); leap-second 60 already
  // excluded by the regex above.
  const t = Date.parse(claim.witnessed_at);
  if (Number.isNaN(t) || new Date(t).toISOString() !== claim.witnessed_at.replace("Z", ".000Z")) {
    throw new Error("claim.witnessed_at is not a valid Gregorian UTC datetime");
  }
}

// ---- Deterministic output serialization -----------------------------------------------------
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v !== null && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}

// ---- Main -----------------------------------------------------------------------------------
function main() {
  const inputs = JSON.parse(fs.readFileSync(INPUTS_PATH, "utf8"));
  const producer = keyFromSeed(PRODUCER_SEED_HEX);
  const witness = keyFromSeed(WITNESS_SEED_HEX);

  const vectors = {};
  // Computed facts about each artifact vector, for witness-claim assembly.
  const heads = {}; // id -> { current, chain_id, airep_version }

  // V1–V4: hash + record signature per INTEGRITY §§1–3, §5.
  for (const [id, artifact] of Object.entries(inputs.artifacts)) {
    const ht = hashTag(artifact.airep_version, artifact.artifact_type);
    const st = sigTag(artifact.airep_version, artifact.artifact_type);

    // §2: hash over a logical copy with integrity.current and integrity.signature removed and
    // every other member retained. The shared bodies already omit both; the deletes below are
    // the mechanical subtraction (no-ops here) — nothing is added, removed, or defaulted.
    const body = structuredClone(artifact);
    if (body.integrity !== null && typeof body.integrity === "object") {
      delete body.integrity.current;
      delete body.integrity.signature;
    }
    const jb = jcsBytes(body);

    // §2: hash_preimage = tag-bytes LF jcs-bytes; current = "sha256:" + lowercase hex SHA-256.
    const hashPreimage = Buffer.concat([asciiBytes(ht), LF, jb]);
    const current = "sha256:" + crypto.createHash("sha256").update(hashPreimage).digest("hex");

    // §3: sig_preimage = sig-tag LF suite-id LF current-string; signed directly (no pre-hash).
    const sigPreimage = Buffer.concat([
      asciiBytes(st), LF, asciiBytes(SUITE_ID), LF, asciiBytes(current),
    ]);
    const signature = sign(sigPreimage, producer);

    vectors[id] = {
      hash_tag_hex: hex(asciiBytes(ht)),
      sig_tag_hex: hex(asciiBytes(st)),
      jcs_body_hex: hex(jb),
      hash_preimage_hex: hex(hashPreimage),
      current,
      suite_id_hex: hex(asciiBytes(SUITE_ID)),
      sig_preimage_hex: hex(sigPreimage),
      signature_hex: hex(signature),
      producer_pubkey_hex: producer.pubHex,
    };
    heads[id] = {
      current,
      chain_id: artifact.chain_id,
      airep_version: artifact.airep_version,
    };
  }

  // W1–W2: head-witness signatures per INTEGRITY §4.
  for (const [id, wc] of Object.entries(inputs.witness_claims)) {
    const head = heads[wc.head];
    if (!head) throw new Error(`witness ${id} references unknown head ${wc.head}`);

    // §4.3: witness tag version = the referenced head artifact's airep_version.
    const wt = witnessTag(head.airep_version);

    // §4: the closed five-member claim. chain_id = the head body's chain_id (same JSON string
    // value, no Unicode normalization — RFC 8785 alone determines its canonical bytes);
    // current = the COMPUTED integrity.current of the head vector; sequence / length /
    // witnessed_at verbatim from INPUTS.json.
    const claim = {
      chain_id: head.chain_id,
      sequence: wc.sequence,
      current: head.current,
      length: wc.length,
      witnessed_at: wc.witnessed_at,
    };
    validateClaim(claim);
    const jc = jcsBytes(claim);

    // §4: witness_preimage = head-witness tag LF suite-id LF jcs-claim.
    const witnessPreimage = Buffer.concat([
      asciiBytes(wt), LF, asciiBytes(SUITE_ID), LF, jc,
    ]);
    const witnessSignature = sign(witnessPreimage, witness);

    vectors[id] = {
      head: wc.head,
      witness_tag_hex: hex(asciiBytes(wt)),
      suite_id_hex: hex(asciiBytes(SUITE_ID)),
      jcs_claim_hex: hex(jc),
      witness_preimage_hex: hex(witnessPreimage),
      witness_signature_hex: hex(witnessSignature),
      witness_pubkey_hex: witness.pubHex,
    };
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(sortDeep({ vectors }), null, 2) + "\n", "utf8");
  console.log(`wrote ${Object.keys(vectors).length} vectors -> ${OUT_PATH}`);
}

main();
