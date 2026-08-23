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

function run(args) {
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
];

let bad = 0;
for (const [name, args, want] of cases) {
  const got = run(args);
  if (got !== want) { console.log(`FAIL: ${name}: expected exit ${want}, got ${got}`); bad++; }
  else console.log(`  ok  exit ${got}  ${name}`);
}
fs.rmSync(TMP, { recursive: true, force: true });
console.log(bad === 0 ? "EXIT-CODE SELF-CHECK: clean" : `${bad} exit-code problems`);
