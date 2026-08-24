// Negative control for exitcode_check.mjs's own failure propagation.
//
// A check script that prints "FAIL" and still exits 0 is worse than no check at all:
// it looks green to any CI gate reading only the exit status. exitcode_check.mjs had
// exactly that defect. This self-test proves the fix actually works, rather than
// asserting it from the presence of a line of source.
//
// Two measurements, both required:
//   POSITIVE  the unmodified script exits 0 and prints "clean";
//   NEGATIVE  a copy with ONE expectation deliberately falsified prints a failure
//             AND exits 1.
//
// The negative half is the point. Without it, "we added process.exit(...)" would be a
// claim about source text; with it, bad > 0 => exit 1 is a measured behaviour.
//
// The copy is mutated in a temporary directory and deleted afterwards; exitcode_check.mjs
// itself is never modified.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TARGET = path.join(HERE, "exitcode_check.mjs");
const TMP = path.join(HERE, "tmp_exitcode_selftest");

let bad = 0;
const ok = (m) => console.log("  ok    " + m);
const fail = (m) => { bad++; console.log("FAIL: " + m); };

function run(script, cwd) {
  const r = spawnSync(process.execPath, [script], { cwd, encoding: "utf8" });
  return { exit: r.status, out: (r.stdout || "") + (r.stderr || "") };
}

fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

// ---- POSITIVE: unmodified script is clean and exits 0 ----------------------
const pos = run(TARGET, HERE);
if (pos.exit === 0) ok("unmodified exitcode_check.mjs exits 0");
else fail(`unmodified exitcode_check.mjs exited ${pos.exit}, expected 0`);
if (/EXIT-CODE SELF-CHECK: clean/.test(pos.out)) ok("unmodified exitcode_check.mjs prints clean");
else fail("unmodified exitcode_check.mjs did not print its clean marker");

// ---- NEGATIVE: falsify one expectation; it must print a failure AND exit 1 --
const src = fs.readFileSync(TARGET, "utf8");
// `--help` is pinned to exit 0 by contract 6.4; expecting 99 must therefore fail.
const needle = '"--help"], 0';
if (!src.includes(needle)) {
  fail(`could not locate the --help expectation (${needle}) to falsify; ` +
       "the self-test cannot prove failure propagation and must not report success");
} else {
  const broken = path.join(TMP, "broken_check.mjs");
  fs.writeFileSync(broken, src.replace(needle, '"--help"], 99'));
  const neg = run(broken, HERE);
  if (/FAIL|exit-code problems/.test(neg.out)) ok("falsified copy reports a failure in its output");
  else fail("falsified copy did not report any failure -- the mutation was not effective, " +
            "so the exit-code result below proves nothing");
  if (neg.exit === 1) ok("falsified copy exits 1 -- failure DOES reach the process exit status");
  else fail(`falsified copy exited ${neg.exit}, expected 1 -- failure does NOT reach the ` +
            "process exit status, so no CI gate may rely on this script's exit code");
}

fs.rmSync(TMP, { recursive: true, force: true });
console.log(bad === 0
  ? "EXIT-CODE PROPAGATION SELF-TEST: clean (positive and negative control both measured)"
  : `${bad} exit-code propagation problems`);
process.exit(bad === 0 ? 0 : 1);
