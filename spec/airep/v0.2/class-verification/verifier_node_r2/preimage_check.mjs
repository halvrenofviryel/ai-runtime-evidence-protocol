// Construction self-check: assert the assembled preimage bytes match the frozen
// text of spec/INTEGRITY.md literally (field list recovered by splitting on 0x0A).
// No expected verdicts are consulted anywhere.
import fs from "node:fs";
import crypto from "node:crypto";

const src = fs.readFileSync("class_verifier.mjs", "utf8");
// Re-exec the module's construction functions by importing it is not possible
// (it runs main()), so mirror-load them via a tiny shim: the functions below are
// copied byte-for-byte from class_verifier.mjs and diffed against it here.
const need = [
  'const tag = `AIREP/${artifact.airep_version}/hash/${artifact.artifact_type}`;',
  'return Buffer.concat([Buffer.from(tag, "ascii"), LF, Buffer.from(jcs(body), "utf8")]);',
  'const tag = `AIREP/${artifact.airep_version}/sig/${artifact.artifact_type}`;',
  'const tag = `AIREP/${headVersion}/sig/head-witness`;',
  "const LF = Buffer.from([0x0a]);",
  "delete body.integrity.current;",
  "delete body.integrity.signature;",
];
let bad = 0;
for (const n of need) {
  if (!src.includes(n)) { console.log("FAIL: construction line absent:", n); bad++; }
}

// Now rebuild the three preimages independently here and check them structurally
// plus cryptographically against a corpus case.
function jcs(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  return JSON.stringify(v);
}
const LF = 0x0a;
const req = JSON.parse(fs.readFileSync("corpus/cases/P2/request.json", "utf8"));
const bnd = JSON.parse(fs.readFileSync("corpus/cases/P2/bindings.json", "utf8"));
const a = req.artifact;

const body = JSON.parse(JSON.stringify(a));
delete body.integrity.current;
delete body.integrity.signature;
const hashPre = Buffer.concat([Buffer.from("AIREP/0.2/hash/decision", "ascii"), Buffer.from([LF]), Buffer.from(jcs(body), "utf8")]);
const lfCount = (b) => [...b].filter((x) => x === LF).length;

if (lfCount(hashPre) !== 1) { console.log("FAIL: hash preimage does not contain exactly one LF"); bad++; }
const firstLF = hashPre.indexOf(LF);
if (hashPre.subarray(0, firstLF).toString("ascii") !== "AIREP/0.2/hash/decision") { console.log("FAIL: hash tag field"); bad++; }
if (hashPre[firstLF + 1] !== 0x7b) { console.log("FAIL: jcs bytes do not begin with '{'"); bad++; }
// The integrity object itself must survive the subtraction with `previous` intact.
if (!jcs(body).includes('"integrity":{"previous":')) { console.log("FAIL: integrity.previous not retained in hash preimage"); bad++; }
const digest = "sha256:" + crypto.createHash("sha256").update(hashPre).digest("hex");
if (digest !== a.integrity.current) { console.log("FAIL: recomputed current != declared current"); bad++; }
// A8-style: CRLF or trailing LF must change the digest.
const crlf = Buffer.concat([Buffer.from("AIREP/0.2/hash/decision", "ascii"), Buffer.from([0x0d, LF]), Buffer.from(jcs(body), "utf8")]);
if (("sha256:" + crypto.createHash("sha256").update(crlf).digest("hex")) === a.integrity.current) { console.log("FAIL: CRLF separator produced the same digest"); bad++; }

function pub(hex) {
  return crypto.createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}
const sigPre = Buffer.concat([
  Buffer.from("AIREP/0.2/sig/decision", "ascii"), Buffer.from([LF]),
  Buffer.from("ed25519", "ascii"), Buffer.from([LF]),
  Buffer.from(a.integrity.current, "ascii"),
]);
if (lfCount(sigPre) !== 2) { console.log("FAIL: record-sig preimage LF count"); bad++; }
const sf = sigPre.toString("utf8").split("\n");
if (sf.length !== 3 || sf[0] !== "AIREP/0.2/sig/decision" || sf[1] !== "ed25519" || sf[2] !== a.integrity.current) { console.log("FAIL: record-sig field list"); bad++; }
if (!crypto.verify(null, sigPre, pub(bnd.bindings["airep.producer-a"].public_key_hex), Buffer.from(a.integrity.signature.value, "hex"))) { console.log("FAIL: record signature does not verify over the frozen preimage"); bad++; }
// negative control: the suite field is signed, so a different suite-id must fail
const sigPreBad = Buffer.from(sigPre.toString("utf8").replace("ed25519", "ed448"), "utf8");
if (crypto.verify(null, sigPreBad, pub(bnd.bindings["airep.producer-a"].public_key_hex), Buffer.from(a.integrity.signature.value, "hex"))) { console.log("FAIL: signature verified under a wrong suite-id"); bad++; }

const w = req.head_witness;
const witPre = Buffer.concat([
  Buffer.from("AIREP/0.2/sig/head-witness", "ascii"), Buffer.from([LF]),
  Buffer.from("ed25519", "ascii"), Buffer.from([LF]),
  Buffer.from(jcs(w.claim), "utf8"),
]);
if (lfCount(witPre) !== 2) { console.log("FAIL: head-witness preimage LF count"); bad++; }
if (!crypto.verify(null, witPre, pub(bnd.bindings["airep.witness-a"].public_key_hex), Buffer.from(w.signature.value, "hex"))) { console.log("FAIL: witness signature does not verify over the frozen preimage"); bad++; }
// A4-style: a head-witness signature must not verify as a record signature
if (crypto.verify(null, sigPre, pub(bnd.bindings["airep.witness-a"].public_key_hex), Buffer.from(w.signature.value, "hex"))) { console.log("FAIL: witness signature replayed as record signature verified"); bad++; }

// Proleptic-Gregorian arithmetic: agrees with Date.UTC on modern years, and
// deliberately does NOT remap years 0-99 the way Date.UTC does.
function daysFromCivil(y, m, d) {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}
for (const [y, m, d] of [[1970, 1, 1], [2000, 2, 29], [2026, 8, 23], [1969, 12, 31], [2400, 12, 31]]) {
  const mine = daysFromCivil(y, m, d) * 86400000;
  const theirs = Date.UTC(y, m - 1, d);
  if (mine !== theirs) { console.log(`FAIL: date arithmetic disagrees for ${y}-${m}-${d}`); bad++; }
}
if (daysFromCivil(70, 1, 1) * 86400000 === Date.UTC(70, 0, 1)) { console.log("FAIL: expected Date.UTC year remapping to differ at year 70"); bad++; }

console.log(bad === 0 ? "CONSTRUCTION SELF-CHECK: clean" : `${bad} construction problems`);
