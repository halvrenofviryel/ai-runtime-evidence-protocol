#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * AIREP v0.1 — an independent PRODUCER in TypeScript (zero dependencies; node:crypto only).
 *
 * Why this exists: AIREP ships two independent *verifiers* (Python + Node) that agree byte-for-byte.
 * Verifiers are readers. This is a *writer* on a third, independent stack — it emits a signed,
 * hash-chained AIREP chain that BOTH reference verifiers accept byte-for-byte. A format whose records
 * can be produced outside its author's Python runtime, and still validate, is an interchange format
 * rather than one tool's serialization. (Author-written: a second language/stack, same author — a
 * bridge toward, not a substitute for, a truly third-party producer; see ../../spec/airep/v0.1/STATUS.md.)
 *
 *   tsc airep_producer.ts && node airep_producer.js > /tmp/ts_chain.jsonl
 *   python3 ../../spec/airep/v0.1/conformance/verify.py  /tmp/ts_chain.jsonl --pubkey <pubkey>
 *   node     ../../spec/airep/v0.1/conformance/verify.mjs /tmp/ts_chain.jsonl --pubkey <pubkey>
 */
import { createHash, createPrivateKey, sign as edSign, KeyObject } from "node:crypto";

const GENESIS = "sha256:" + "0".repeat(64);

// RFC 8785 (JCS) canonical form. This is byte-identical to the reference verify.mjs canonicalizer,
// which agrees byte-for-byte with the Python jcs.py over a value battery (conformance/test_jcs.py):
// recursive key sort + native ES6 JSON.stringify (the number form JCS mandates) + no whitespace.
// Records here carry only strings and integers (no floats), so JSON.stringify == JCS exactly.
function canonical(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
  }
  return JSON.stringify(v); // string | number | boolean
}

function sha256(text: string): string {
  return "sha256:" + createHash("sha256").update(text, "utf8").digest("hex");
}

// The published THROWAWAY test seed (TEST ONLY — never use for any real signing identity). It derives
// the published examples/test_public_key.txt, so a chain signed here verifies under that public key.
const TEST_SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
function testPrivateKey(): KeyObject {
  // PKCS8 DER for an Ed25519 private key = fixed 16-byte prefix + the 32-byte seed.
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(TEST_SEED_HEX, "hex"),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

interface Evidence { type: string; ref: string; resolvable: boolean; content_hash?: string }
interface Decision {
  verb: "release" | "block" | "defer" | "redact" | "escalate_to_human" | "kill";
  assertion: string;
  basis: string[];
  evidence: Evidence[];
  covers: string[];
  doesNotCover: string[];
}

interface AirepRecord {
  airep_version: "0.1";
  subject: { runtime: string; producer: string; decision_index: number; timestamp_utc: string };
  input: { input_ref: string; governance_state: Record<string, unknown> };
  claim: { assertion: string; basis: string[] };
  output: { result_ref: string; redacted?: boolean };
  evidence: Evidence[];
  directive: { verb: string; policy_basis: string[] };
  scope: { covers: string[]; does_not_cover: string[] };
  integrity: { previous: string; canonical_json: true; current?: string; signature?: { alg: string; value: string } };
}

function buildRecord(d: Decision, index: number, previous: string, priv: KeyObject): AirepRecord {
  const rec: AirepRecord = {
    airep_version: "0.1",
    subject: {
      runtime: "ts-reference-producer",
      producer: "airep-producer-ts/0.1",
      decision_index: index,
      timestamp_utc: "2026-05-31T00:00:00Z",
    },
    input: { input_ref: sha256(`input-${index}`), governance_state: { policy_version: "p1" } },
    claim: { assertion: d.assertion, basis: d.basis },
    output: { result_ref: sha256(`output-${index}`), redacted: d.verb === "redact" },
    evidence: d.evidence,
    directive: { verb: d.verb, policy_basis: d.basis },
    scope: { covers: d.covers, does_not_cover: d.doesNotCover },
    // hash is computed with integrity = {previous, canonical_json} (current + signature absent),
    // exactly the body the verifiers recompute (current + signature removed, previous retained).
    integrity: { previous, canonical_json: true },
  };
  const current = sha256(canonical(rec));
  rec.integrity.current = current;
  const value = edSign(null, Buffer.from(current, "utf8"), priv).toString("hex");
  rec.integrity.signature = { alg: "Ed25519", value };
  return rec;
}

const DECISIONS: Decision[] = [
  {
    verb: "release", assertion: "answer released after the safety and ethics gates passed",
    basis: ["safety_gate", "ethics_gate"],
    evidence: [{ type: "policy", ref: "policy://safety/v1", content_hash: sha256("safety/v1"), resolvable: true }],
    covers: ["the safety and ethics gates fired and passed"],
    doesNotCover: ["whether the answer is factually correct", "reasoning faithfulness not attested"],
  },
  {
    verb: "block", assertion: "output blocked by the ethics gate",
    basis: ["ethics_gate"],
    evidence: [{ type: "policy", ref: "policy://ethics/v2", content_hash: sha256("ethics/v2"), resolvable: true }],
    covers: ["the ethics gate fired and blocked the output"],
    doesNotCover: ["whether a human would have blocked it", "factual correctness not assessed"],
  },
  {
    verb: "escalate_to_human", assertion: "handed to a human reviewer after a low-confidence signal",
    basis: ["hitl_queue"],
    evidence: [{ type: "human_approval", ref: "hitl://ticket/42", resolvable: false, content_hash: sha256("ticket/42") }],
    covers: ["the decision was queued for human review"],
    doesNotCover: ["the human's eventual verdict", "factual correctness not assessed"],
  },
];

function main(): void {
  const priv = testPrivateKey();
  let previous = GENESIS;
  const lines: string[] = [];
  DECISIONS.forEach((d, i) => {
    const rec = buildRecord(d, i, previous, priv);
    lines.push(JSON.stringify(rec));
    previous = rec.integrity.current as string;
  });
  process.stdout.write(lines.join("\n") + "\n");
}

main();
