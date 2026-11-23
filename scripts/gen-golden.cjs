#!/usr/bin/env node
// Generates testdata/golden/{findings,ledger}.json.gz: documents plus the exact error lists the upstream
// validators (pinned skill commit, see skills/security-audit/UPSTREAM.json) return for them. The Go port must
// reproduce every list. Seeds are the documents the upstream test files validate; mutants add breadth.
//
// usage: node scripts/gen-golden.cjs <skills/security-audit dir>
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const { spawnSync } = require("node:child_process");

const upstream = path.resolve(process.argv[2] || "skills/security-audit");
const outDir = path.resolve(__dirname, "../testdata/golden");
fs.mkdirSync(outDir, { recursive: true });
const findingsMod = require(path.join(upstream, "validate-findings.cjs"));
const ledgerMod = require(path.join(upstream, "validate-coverage-ledger.cjs"));
const schema = JSON.parse(fs.readFileSync(path.join(upstream, "report-schema.json"), "utf8"));

// Seeds: run the upstream tests with the recorder preloaded.
function record(kind, testFile) {
  const out = path.join(require("node:os").tmpdir(), `golden-${kind}-${process.pid}.json`);
  const r = spawnSync(process.execPath, ["--require", path.join(__dirname, "golden-recorder.cjs"), path.join(upstream, testFile)], { env: { ...process.env, GOLDEN_OUT: out }, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`upstream tests failed: ${r.stdout}\n${r.stderr}`);
  const recs = JSON.parse(fs.readFileSync(out, "utf8"));
  fs.unlinkSync(out);
  return recs.map((x) => x.input);
}

let seed = 0x9e3779b9;
function rnd() { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed / 4294967296; }
const pick = (a) => a[Math.floor(rnd() * a.length)];

function paths(v, p = [], out = []) {
  out.push(p);
  if (Array.isArray(v)) v.forEach((x, i) => paths(x, [...p, i], out));
  else if (v && typeof v === "object") for (const k of Object.keys(v)) paths(v[k], [...p, k], out);
  return out;
}
function getAt(v, p) { return p.reduce((a, k) => a[k], v); }
const SCALARS = [null, 0, -1, 1, 1.5, 1e999 > 0 ? 7 : 7, true, false, "", " ", " x", "x ", "x\u0000y", "x​y", "​", "a\ud800b", "../x", "/abs", "a//b", "con", "aux.txt", "a:b", "a\\b", "~x", "Ünï/ç", "é", "x".repeat(300), "src/a b.c", "src/a.c", "entrypoint", "sink", "propagation", "confirmed", "needs_validation", "rejected", "planned", "covered", "candidate", "blocked", "deferred", "agent-1", "agents/agent-1/artifacts/x.txt"];
function mutate(doc) {
  const d = JSON.parse(JSON.stringify(doc));
  const ps = paths(d).filter((p) => p.length > 0);
  if (ps.length === 0) return d;
  const p = pick(ps);
  const parent = getAt(d, p.slice(0, -1));
  const key = p[p.length - 1];
  const cur = parent[key];
  const op = Math.floor(rnd() * 8);
  if (op === 0) { if (Array.isArray(parent)) parent.splice(key, 1); else delete parent[key]; }
  else if (op === 1) parent[key] = pick(SCALARS);
  else if (op === 2 && Array.isArray(cur)) { cur.push(cur.length ? JSON.parse(JSON.stringify(cur[0])) : "x"); }
  else if (op === 3 && cur && typeof cur === "object" && !Array.isArray(cur)) cur[pick(["extra", "root_cause", "severity", "blockers", "claimed_root_cause", "lifecycle", "reason"])] = pick(SCALARS);
  else if (op === 4 && Array.isArray(cur)) cur.length = 0;
  else if (op === 5 && Array.isArray(parent) && parent.length > 1) { const i = Math.floor(rnd() * parent.length); const j = Math.floor(rnd() * parent.length); [parent[i], parent[j]] = [parent[j], parent[i]]; }
  else if (op === 6 && typeof cur === "string") parent[key] = cur + pick(["​", " ", "\u0085", "\ud800", "x"]);
  else parent[key] = pick(SCALARS);
  return d;
}

function build(kind, seeds, run) {
  const cases = new Map();
  const add = (text) => {
    if (cases.has(text)) return;
    let errors;
    try { errors = [...run(JSON.parse(text))]; } catch (e) { return; }
    cases.set(text, errors);
  };
  seeds.forEach(add);
  const valid = seeds.filter((s) => { try { return run(JSON.parse(s)).length === 0; } catch { return false; } });
  for (const s of seeds) {
    const n = valid.includes(s) ? 150 : 8;
    for (let i = 0; i < n; i++) {
      let d = JSON.parse(s);
      const steps = 1 + Math.floor(rnd() * 2);
      for (let k = 0; k < steps; k++) d = mutate(d);
      add(JSON.stringify(d));
    }
  }
  const list = [...cases].map(([input, errors]) => ({ input, errors }));
  fs.writeFileSync(path.join(outDir, `${kind}.json.gz`), zlib.gzipSync(JSON.stringify(list)));
  console.log(kind, list.length, "cases,", list.filter((c) => c.errors.length === 0).length, "valid");
}

build("findings", record("findings", "validate-findings.test.cjs"), (d) => findingsMod.validateDocument(d, schema));
build("ledger", record("ledger", "validate-coverage-ledger.test.cjs"), (d) => ledgerMod.validateDocument(d));
