// Exit-code semantics check (contract 6.4). Builds throwaway inputs inside the
// working directory only. No expected verdicts consulted.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const TMP = "tmp_exitcheck";
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

const P2 = "corpus/cases/P2";
const base = ["--bindings", `${P2}/bindings.json`, "--independence-policy", `${P2}/independence.json`,
  "--revocation", `${P2}/revocation.json`, "--now", "2026-08-23T12:00:00Z", "--freshness-window", "3600"];

// Section 9 portability note: the committed default schema directory is
// ../../schemas, so this review snapshot passes --schema-dir explicitly.
const SCHEMAS = ["--schema-dir", "spec/schemas"];

function run(args) {
  const r = spawnSync(process.execPath, ["class_verifier.mjs", ...SCHEMAS, ...args], { encoding: "utf8" });
  return r.status;
}

// Same, without the snapshot's --schema-dir prefix, for the cases that set it.
function runBare(args) {
  const r = spawnSync(process.execPath, ["class_verifier.mjs", ...args], { encoding: "utf8" });
  return r.status;
}

// exit 1 fixtures
const req = JSON.parse(fs.readFileSync(`${P2}/request.json`, "utf8"));
const mutated = JSON.parse(JSON.stringify(req));
mutated.artifact.integrity.current = "sha256:" + "0".repeat(64);
fs.writeFileSync(path.join(TMP, "hash_mismatch.json"), JSON.stringify(mutated));
const schemaBad = JSON.parse(JSON.stringify(req));
delete schemaBad.artifact.claim;
fs.writeFileSync(path.join(TMP, "schema_bad.json"), JSON.stringify(schemaBad));
fs.writeFileSync(path.join(TMP, "not_json.json"), "{ this is not json");
fs.writeFileSync(path.join(TMP, "bad_bindings.json"), "{ nope");

// Errata E-4: unknown members in the section-0 envelope's nested objects are a
// run-invalid result (exit 1), not a class reason.
const P2WIT = "corpus/cases/P2";
for (const [name, mutate] of [
  ["claim", (r) => { r.head_witness.claim.note = "x"; }],
  ["head_ref", (r) => { r.head_witness.head_ref.note = "x"; }],
  ["signature", (r) => { r.head_witness.signature.note = "x"; }],
]) {
  const r = JSON.parse(fs.readFileSync(`${P2WIT}/request.json`, "utf8"));
  mutate(r);
  fs.writeFileSync(path.join(TMP, `unknown_${name}.json`), JSON.stringify(r));
}

const cases = [
  ["--help", ["--help"], 0],
  ["clean single case", ["--request", `${P2}/request.json`, ...base], 0],
  ["no operator inputs at all", ["--request", `${P2}/request.json`], 0],
  ["unparseable request", ["--request", `${TMP}/not_json.json`, ...base], 1],
  ["unparseable operator file", ["--request", `${P2}/request.json`, "--bindings", `${TMP}/bad_bindings.json`], 1],
  ["stage-1 hash mismatch", ["--request", `${TMP}/hash_mismatch.json`, ...base], 1],
  ["stage-0 schema invalid", ["--request", `${TMP}/schema_bad.json`, ...base], 1],
  ["missing --request", [...base], 2],
  ["unknown option", ["--request", `${P2}/request.json`, "--bogus", "x"], 2],
  ["option without value", ["--request"], 2],
  ["malformed --now (not a datetime)", ["--request", `${P2}/request.json`, "--now", "yesterday", "--freshness-window", "60"], 2],
  ["malformed --now (Feb 30)", ["--request", `${P2}/request.json`, "--now", "2026-02-30T00:00:00Z", "--freshness-window", "60"], 2],
  ["malformed --now (no Z)", ["--request", `${P2}/request.json`, "--now", "2026-08-23T12:00:00", "--freshness-window", "60"], 2],
  ["malformed --freshness-window (non-integer)", ["--request", `${P2}/request.json`, "--now", "2026-08-23T12:00:00Z", "--freshness-window", "1.5"], 2],
  ["malformed --freshness-window (negative)", ["--request", `${P2}/request.json`, "--now", "2026-08-23T12:00:00Z", "--freshness-window", "-1"], 2],
  ["--corpus without --out", ["--corpus", "corpus"], 2],
  ["unknown member in head_witness.claim", ["--request", `${TMP}/unknown_claim.json`, ...base], 1],
  ["unknown member in head_witness.head_ref", ["--request", `${TMP}/unknown_head_ref.json`, ...base], 1],
  ["unknown member in head_witness.signature", ["--request", `${TMP}/unknown_signature.json`, ...base], 1],
];

let bad = 0;
// Section 9 portability note: an unresolvable --schema-dir is a config error.
{
  const got = runBare(["--request", `${P2}/request.json`, "--schema-dir", `${TMP}/nope`]);
  if (got !== 2) { console.log(`FAIL: unresolvable --schema-dir: expected exit 2, got ${got}`); bad++; }
  else console.log("  ok  exit 2  unresolvable --schema-dir");
}
for (const [name, args, want] of cases) {
  const got = run(args);
  if (got !== want) { console.log(`FAIL: ${name}: expected exit ${want}, got ${got}`); bad++; }
  else console.log(`  ok  exit ${got}  ${name}`);
}
fs.rmSync(TMP, { recursive: true, force: true });
console.log(bad === 0 ? "EXIT-CODE SELF-CHECK: clean" : `${bad} exit-code problems`);
