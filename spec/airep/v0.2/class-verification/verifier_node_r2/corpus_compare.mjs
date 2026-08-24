// Corpus regression harness: runs the verifier once per corpus case in
// single-case mode and compares the seven expected.json members. This script is
// NOT a probe -- it is the section 7 regression check the round is required to
// report, and it is the only place an expected.json is read.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const DIR = "../corpus";
const index = JSON.parse(fs.readFileSync(path.join(DIR, "case_index.json"), "utf8"));
const MEMBERS = ["class", "observer_assessment", "authenticated_failures", "authenticated_withheld",
  "authenticated_caveats", "witnessed_failures", "witnessed_withheld"];

let aborted = 0, mismatching = 0, clean = 0;
for (const entry of index) {
  const f = entry.files || {};
  const args = ["class_verifier.mjs", "--schema-dir", "../../schemas",
    "--request", path.join(DIR, f.request)];
  for (const [flag, key] of [["--bindings", "bindings"], ["--independence-policy", "independence"],
    ["--revocation", "revocation"]]) {
    if (f[key] !== undefined) args.push(flag, path.join(DIR, f[key]));
  }
  if (f.clock !== undefined) {
    const c = JSON.parse(fs.readFileSync(path.join(DIR, f.clock), "utf8"));
    if (c.now !== undefined && c.now !== null) args.push("--now", String(c.now));
    if (c.freshness_window_seconds !== undefined && c.freshness_window_seconds !== null) {
      args.push("--freshness-window", String(c.freshness_window_seconds));
    }
  }
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  if (r.status !== 0) { aborted++; console.log(`${entry.case_id}: exit ${r.status} :: ${r.stderr.trim()}`); continue; }
  const got = JSON.parse(r.stdout);
  const want = JSON.parse(fs.readFileSync(path.join(DIR, "cases", entry.case_id, "expected.json"), "utf8"));
  const diffs = MEMBERS.filter((m) => JSON.stringify(got[m]) !== JSON.stringify(want[m]))
    .map((m) => `${m}: got ${JSON.stringify(got[m])} want ${JSON.stringify(want[m])}`);
  if (diffs.length) { mismatching++; console.log(`${entry.case_id}: ` + diffs.join(" | ")); }
  else clean++;
}
console.log(`cases=${index.length} aborted=${aborted} mismatching=${mismatching} clean=${clean}`);
process.exit(aborted === 0 && mismatching === 0 ? 0 : 1);
