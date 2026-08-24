// Errata self-check (CLASS_VERIFIER_CONTRACT.md section 9). Asserts only the
// outcomes section 9 itself pins in normative text; builds every input inside
// the working directory. No fixture expected values are read, no pass rate.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const TMP = "tmp_erratacheck";
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

const SCHEMAS = ["--schema-dir", "spec/schemas"];
let bad = 0;
const say = (m) => { bad++; console.log("FAIL:", m); };

function run(args) {
  const r = spawnSync(process.execPath, ["class_verifier.mjs", ...SCHEMAS, ...args], { encoding: "utf8" });
  return { status: r.status, verdict: r.status === 0 ? JSON.parse(r.stdout) : null };
}
const has = (a, x) => Array.isArray(a) && a.includes(x);

// P2 is a clean Decision with a clean, fresh, independent witness: every gate
// runs, so a single mutation isolates exactly one errata rule.
const P2 = "corpus/cases/P2";
const P2TEXT = fs.readFileSync(`${P2}/request.json`, "utf8");
const CLOCK = ["--now", "2026-08-23T12:00:00Z", "--freshness-window", "3600"];
const opInputs = (dir = P2) => ["--bindings", `${dir}/bindings.json`,
  "--independence-policy", `${dir}/independence.json`, "--revocation", `${dir}/revocation.json`];

function writeText(name, text) {
  const f = path.join(TMP, name);
  fs.writeFileSync(f, text);
  return f;
}
function writeJson(name, value) {
  return writeText(name, JSON.stringify(value, null, 1));
}

// --- E-1: the numeric members carry a LEXICAL rule -------------------------
// "-0" / "1e0" parse to the same numbers as "0" / "1" AND canonicalize (RFC
// 8785) to the same bytes, so the claim still reconciles and the genuine
// witness signature still verifies. Only the source spelling is wrong. The
// substitution is confined to the head_witness slice: the artifact carries a
// `sequence` member of its own earlier in the same document.
const HW_AT = P2TEXT.indexOf('"head_witness"');
if (HW_AT < 0) say("E-1: P2 request carries no head_witness (probe cannot run)");

function respellClaim(name, from, to) {
  const head = P2TEXT.slice(0, HW_AT), tail = P2TEXT.slice(HW_AT);
  if (tail.indexOf(from) < 0) { say(`E-1 ${name}: token ${from} absent from the claim`); return null; }
  const text = head + tail.replace(from, to);
  // The probe is only meaningful if nothing but the spelling changed.
  if (JSON.stringify(JSON.parse(text)) !== JSON.stringify(JSON.parse(P2TEXT))) {
    say(`E-1 ${name}: respelling changed the parsed document`);
    return null;
  }
  return writeText(`e1_${name}.json`, text);
}

for (const [name, from, to] of [["sequence", '"sequence": 0', '"sequence": -0'],
                                ["length", '"length": 1', '"length": 1e0'],
                                ["fraction", '"length": 1', '"length": 1.0']]) {
  const f = respellClaim(name, from, to);
  if (f === null) continue;
  const { status, verdict } = run(["--request", f, ...opInputs(), ...CLOCK]);
  if (status !== 0) { say(`E-1 ${name}: expected a verdict, got exit ${status}`); continue; }
  if (!has(verdict.witnessed_failures, "witness-claim-invalid")) {
    say(`E-1 ${name}: a non-conforming numeric lexeme did not yield witness-claim-invalid: `
      + JSON.stringify(verdict.witnessed_failures));
  }
  // Stage 6 failed, so the section-4 dependency rule suppresses stages 7-10.
  if (verdict.witnessed_failures.length !== 1 || verdict.witnessed_withheld.length !== 0) {
    say(`E-1 ${name}: stage 6 failure did not suppress stages 7-10`);
  }
}

// Control: the untouched request must not raise the lexical reason.
{
  const { status, verdict } = run(["--request", `${P2}/request.json`, ...opInputs(), ...CLOCK]);
  if (status !== 0) say(`E-1 control: exit ${status}`);
  else if (has(verdict.witnessed_failures, "witness-claim-invalid")) {
    say("E-1 control: a conforming decimal lexeme was rejected");
  }
}

// --- E-2: witnessed_at validity is stage 6, clock-independent --------------
for (const [name, stamp] of [["calendar", "2026-02-30T11:30:00Z"], ["leap-second", "2026-08-23T11:30:60Z"],
                             ["fractional", "2026-08-23T11:30:00.5Z"], ["offset", "2026-08-23T11:30:00+00:00"]]) {
  const f = writeText(`e2_${name}.json`, P2TEXT.replace('"2026-08-23T11:30:00Z"', JSON.stringify(stamp)));
  // NO clock inputs supplied: section 9 pins witness-time-invalid regardless.
  const { status, verdict } = run(["--request", f, ...opInputs()]);
  if (status !== 0) { say(`E-2 ${name}: expected a verdict, got exit ${status}`); continue; }
  if (!has(verdict.witnessed_failures, "witness-time-invalid")) {
    say(`E-2 ${name}: no witness-time-invalid without a clock: ${JSON.stringify(verdict.witnessed_failures)}`);
  }
  if (has(verdict.witnessed_withheld, "freshness-inputs-missing")) {
    say(`E-2 ${name}: reported freshness-inputs-missing for an invalid witnessed_at`);
  }
  // With the clock supplied the answer must be the same reason, still not freshness.
  const withClock = run(["--request", f, ...opInputs(), ...CLOCK]);
  if (withClock.status !== 0) { say(`E-2 ${name}: exit ${withClock.status} with clock`); continue; }
  if (!has(withClock.verdict.witnessed_failures, "witness-time-invalid")
      || has(withClock.verdict.witnessed_failures, "witness-freshness-outside-window")) {
    say(`E-2 ${name}: clock inputs changed the structural verdict`);
  }
}

// --- E-3: a wire `independent` is never effective below Authenticated ------
{
  const OB = "corpus/cases/OB1";
  const rev = JSON.parse(fs.readFileSync(`${OB}/revocation.json`, "utf8"));
  delete rev.bindings["airep.producer-a"];            // the PRIMARY's binding only
  const f = writeJson("e3_revocation.json", rev);
  const { status, verdict } = run(["--request", `${OB}/request.json`, "--bindings", `${OB}/bindings.json`,
    "--independence-policy", `${OB}/independence.json`, "--revocation", f, ...CLOCK]);
  if (status !== 0) say(`E-3: expected a verdict, got exit ${status}`);
  else {
    if (verdict.class !== "AIREP-Core") say(`E-3: primary should not be Authenticated, class=${verdict.class}`);
    if (verdict.observer_assessment !== "unknown") {
      say(`E-3: wire 'independent' survived a non-Authenticated primary: ${verdict.observer_assessment}`);
    }
  }
  // Control: with the snapshot intact the same case must not be forced to unknown
  // by this check itself.
  const ctl = run(["--request", `${OB}/request.json`, "--bindings", `${OB}/bindings.json`,
    "--independence-policy", `${OB}/independence.json`, "--revocation", `${OB}/revocation.json`, ...CLOCK]);
  if (ctl.status !== 0) say(`E-3 control: exit ${ctl.status}`);
  else if (ctl.verdict.class !== "AIREP-Authenticated") say("E-3 control: primary is not Authenticated");
}

// --- E-4: section-1 container members are required, not defaulted ----------
{
  const pol = JSON.parse(fs.readFileSync(`${P2}/independence.json`, "utf8"));
  delete pol.non_independent_pairs;
  const f = writeJson("e4_policy.json", pol);
  const { status, verdict } = run(["--request", `${P2}/request.json`, "--bindings", `${P2}/bindings.json`,
    "--independence-policy", f, "--revocation", `${P2}/revocation.json`, ...CLOCK]);
  if (status !== 0) say(`E-4 policy: expected a verdict, got exit ${status}`);
  else if (!has(verdict.witnessed_withheld, "independence-policy-malformed")) {
    say("E-4 policy: a missing container member was treated as an empty list: "
      + JSON.stringify(verdict.witnessed_withheld));
  }
}
{
  const bnd = JSON.parse(fs.readFileSync(`${P2}/bindings.json`, "utf8"));
  delete bnd.witness_bindings;
  const f = writeJson("e4_bindings.json", bnd);
  const { status, verdict } = run(["--request", `${P2}/request.json`, "--bindings", f,
    "--independence-policy", `${P2}/independence.json`, "--revocation", `${P2}/revocation.json`, ...CLOCK]);
  if (status !== 0) say(`E-4 bindings: expected a verdict, got exit ${status}`);
  else if (!has(verdict.authenticated_withheld, "producer-binding-malformed")) {
    say("E-4 bindings: a missing container member was tolerated: "
      + JSON.stringify(verdict.authenticated_withheld));
  }
}
{
  const rev = JSON.parse(fs.readFileSync(`${P2}/revocation.json`, "utf8"));
  delete rev.bindings;
  const f = writeJson("e4_revocation.json", rev);
  const { status, verdict } = run(["--request", `${P2}/request.json`, "--bindings", `${P2}/bindings.json`,
    "--independence-policy", `${P2}/independence.json`, "--revocation", f, ...CLOCK]);
  if (status !== 0) say(`E-4 revocation: expected a verdict, got exit ${status}`);
  else if (!has(verdict.authenticated_withheld, "producer-revocation-state-malformed")) {
    say("E-4 revocation: a missing container member was tolerated: "
      + JSON.stringify(verdict.authenticated_withheld));
  }
}
{
  // Unknown member at the binding store's top level (named explicitly in E-4).
  const bnd = JSON.parse(fs.readFileSync(`${P2}/bindings.json`, "utf8"));
  bnd.extra_map = {};
  const f = writeJson("e4_bindings_unknown.json", bnd);
  const { status, verdict } = run(["--request", `${P2}/request.json`, "--bindings", f,
    "--independence-policy", `${P2}/independence.json`, "--revocation", `${P2}/revocation.json`, ...CLOCK]);
  if (status !== 0) say(`E-4 store-unknown: expected a verdict, got exit ${status}`);
  else if (!has(verdict.authenticated_withheld, "producer-binding-malformed")) {
    say("E-4 store-unknown: an unknown top-level member was tolerated");
  }
}

// --- E-6: CONFIRMED behaviour - a missing revocation state is not "revoked",
// so the producer signature gate still runs diagnostically.
{
  const rev = JSON.parse(fs.readFileSync(`${P2}/revocation.json`, "utf8"));
  delete rev.bindings["airep.producer-a"];
  const f = writeJson("e6_revocation.json", rev);
  const good = run(["--request", `${P2}/request.json`, "--bindings", `${P2}/bindings.json`,
    "--independence-policy", `${P2}/independence.json`, "--revocation", f, ...CLOCK]);
  const req = JSON.parse(P2TEXT);
  req.artifact.integrity.signature.value = "0".repeat(128);
  const badSig = writeJson("e6_badsig_request.json", req);
  const broken = run(["--request", badSig, "--bindings", `${P2}/bindings.json`,
    "--independence-policy", `${P2}/independence.json`, "--revocation", f, ...CLOCK]);
  if (good.status !== 0 || broken.status !== 0) say("E-6: expected verdicts");
  else {
    if (!has(good.verdict.authenticated_withheld, "producer-revocation-state-missing")) {
      say("E-6: missing revocation state not reported");
    }
    if (has(good.verdict.authenticated_failures, "producer-signature-invalid")) {
      say("E-6: a valid signature was reported invalid");
    }
    if (!has(broken.verdict.authenticated_failures, "producer-signature-invalid")) {
      say("E-6: the signature gate did not run under a missing revocation state");
    }
  }
}

fs.rmSync(TMP, { recursive: true, force: true });
console.log(bad === 0 ? "ERRATA SELF-CHECK: clean" : `${bad} errata problems`);
