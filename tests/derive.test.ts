import assert from "node:assert/strict";
import { test } from "node:test";
import { buildGrid, elapsedMinutes, formatWhen, phaseStates, sortFindings, unitTotals, defaultRun, surplusRuns } from "../frontend-src/lib/derive";
import type { FindingRow, LedgerUnit, RunRow } from "../frontend-src/types";

const unit = (id: string, surface: string, cls: string, status: LedgerUnit["status"], extra: Partial<LedgerUnit> = {}): LedgerUnit => ({
  coverage_id: id, canonical_refs: { surface: `src/${surface}#x`, boundary: "b", subsystem: "s", attack_class: `A.md#${cls}` },
  surface, boundary: "b", subsystem: "s", attack_class: cls, starting_paths: [], wave: 1, status, agent_id: null,
  reviewed_paths: [], local_checks: [], result_fingerprints: [], unresolved: [], ...extra,
});

test("phase bar: earlier phases done, current phase now, a complete run is all done", () => {
  assert.deepEqual(phaseStates({ phase: "hunt", status: "in_progress" }), ["done", "now", "todo", "todo", "todo", "todo"]);
  assert.deepEqual(phaseStates({ phase: "validate", status: "incomplete" }), ["done", "done", "now", "todo", "todo", "todo"]);
  assert.deepEqual(phaseStates({ phase: "report", status: "complete" }), Array(6).fill("done"));
});

test("unit totals ignore not_applicable and out_of_scope; blocked and candidate count as concluded", () => {
  const t = unitTotals({ covered: 29, candidate: 6, blocked: 3, deferred: 4, not_applicable: 9, out_of_scope: 2 });
  assert.deepEqual(t, { total: 42, concluded: 38, pending: 4, deferred: 4 });
});

test("coverage grid: surfaces by attack classes, the most urgent unit stands for a shared cell", () => {
  const grid = buildGrid([
    unit("1", "api", "access", "covered"),
    unit("2", "api", "access", "candidate", { boundary: "other" }),
    unit("3", "api", "authn", "blocked"),
    unit("4", "web", "authn", "planned"),
  ]);
  assert.deepEqual(grid.rows.map((r) => r.label), ["api", "web"]);
  assert.deepEqual(grid.rows.map((r) => r.ref), ["src/api", "src/web"]);
  assert.deepEqual(grid.cols.map((c) => c.label), ["access", "authn"]);
  assert.equal(grid.cell(0, 0).unit?.status, "candidate");
  assert.equal(grid.cell(0, 0).units.length, 2);
  assert.equal(grid.cell(1, 0).unit, null);
  assert.equal(grid.cell(1, 1).unit?.status, "planned");
});

const row = (title: string, verdict: FindingRow["verdict"], severity?: FindingRow["severity"]): FindingRow => ({ fingerprint: title, verdict, title, file: "f.go", line: 1, severity });

test("findings sort: confirmed by severity, then needs_validation, then rejected", () => {
  const sorted = sortFindings([row("r", "rejected"), row("n", "needs_validation"), row("m", "confirmed", "medium"), row("c", "confirmed", "critical")]);
  assert.deepEqual(sorted.map((f) => f.title), ["c", "m", "n", "r"]);
});

test("elapsed time uses now only while running", () => {
  const base = { created_at: "2026-11-23T00:00:00Z", updated_at: "2026-11-23T00:30:00Z", completed_at: "2026-11-23T00:20:00Z" };
  const now = Date.parse("2026-11-23T01:00:00Z");
  assert.equal(elapsedMinutes({ ...base, status: "in_progress" }, now), 60);
  assert.equal(elapsedMinutes({ ...base, status: "complete" }, now), 20);
  assert.equal(elapsedMinutes({ ...base, completed_at: "", status: "incomplete" }, now), 30);
});

test("formatWhen: today shows the time, other days the date", () => {
  const now = new Date(2026, 10, 23, 15, 0).getTime();
  assert.equal(formatWhen(new Date(2026, 10, 23, 9, 5).toISOString(), now), "今天 09:05");
  assert.equal(formatWhen(new Date(2026, 10, 20, 9, 5).toISOString(), now), "11-20");
  assert.equal(formatWhen("nope", now), "");
});

test("default run is the one in progress, else the newest", () => {
  const r = (id: string, status: RunRow["status"]) => ({ run_id: id, status }) as RunRow;
  assert.equal(defaultRun([r("a", "complete"), r("b", "in_progress")])?.run_id, "b");
  assert.equal(defaultRun([r("a", "complete"), r("b", "complete")])?.run_id, "a");
  assert.equal(defaultRun([]), undefined);
});

test("retention lists the finished runs beyond the newest N, oldest first, and never a running one", () => {
  const r = (id: string, at: string, status: RunRow["status"]) => ({ run_id: id, created_at: at, status }) as RunRow;
  const runs = [r("r5", "2026-11-05", "in_progress"), r("r4", "2026-11-04", "complete"), r("r3", "2026-11-03", "incomplete"), r("r2", "2026-11-02", "complete"), r("r1", "2026-11-01", "complete")];
  assert.deepEqual(surplusRuns(runs, 3).map((x) => x.run_id), ["r1", "r2"]);
  assert.deepEqual(surplusRuns(runs, 1).map((x) => x.run_id), ["r1", "r2", "r3", "r4"]);
  assert.deepEqual(surplusRuns(runs, 0), []);
  assert.deepEqual(surplusRuns(runs, 10), []);
  // A running run that is old stays, even beyond the kept set.
  assert.deepEqual(surplusRuns([r("a", "2026-11-03", "complete"), r("b", "2026-11-02", "in_progress"), r("c", "2026-11-01", "complete")], 1).map((x) => x.run_id), ["c"]);
});
