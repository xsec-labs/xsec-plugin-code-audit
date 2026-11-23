import type { AgentEvent, Coverage, FindingRow, LedgerUnit, Phase, RunRow, Severity, UnitStatus, Verdict } from "../types";

export const PHASES: { id: Phase; label: string }[] = [
  { id: "recon", label: "侦察" },
  { id: "hunt", label: "狩猎" },
  { id: "validate", label: "候选验证" },
  { id: "output", label: "结构化输出" },
  { id: "verify", label: "独立复核" },
  { id: "report", label: "报告" },
];

export type PhaseState = "done" | "now" | "todo";

/** Phase bar state: all done once the run is complete, a stalled (incomplete) run keeps its last phase as current. */
export function phaseStates(run: Pick<RunRow, "phase" | "status">): PhaseState[] {
  const index = Math.max(0, PHASES.findIndex((p) => p.id === run.phase));
  return PHASES.map((_, i) => {
    if (run.status === "complete") return "done";
    if (i < index) return "done";
    return i === index ? "now" : "todo";
  });
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];
export const SEVERITY_LABEL: Record<Severity, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", informational: "提示" };
export const SEVERITY_GLYPH: Record<Severity, string> = { critical: "危", high: "高", medium: "中", low: "低", informational: "示" };
export const VERDICT_LABEL: Record<Verdict, string> = { confirmed: "已确认", needs_validation: "待验证", rejected: "已排除" };
export const UNIT_LABEL: Record<UnitStatus, string> = {
  planned: "排队", in_progress: "审计中", covered: "已覆盖", candidate: "有候选", blocked: "受阻",
  deferred: "延后", not_applicable: "不适用", out_of_scope: "范围外",
};
export const RUN_STATUS_LABEL = { in_progress: "进行中", complete: "已完成", incomplete: "未完成" } as const;
export const ROLE_LABEL: Record<string, string> = {
  recon: "侦察", hunter: "狩猎", critic: "覆盖评审", verifier: "验证", record_verifier: "复核",
};
export const CONDITION_LABEL: Record<string, string> = {
  authentication_level: "认证", authorization_role: "权限", user_interaction: "用户操作", system_configuration: "配置",
  network_routing: "网络", environmental_dependency: "环境", data_state: "数据", timing_dependency: "时序", third_party_dependency: "第三方",
};
export const STEP_LABEL = { entrypoint: "入口", propagation: "传递", sink: "落点" } as const;
export const FIX_LABEL = { proposed: "已提出修复", fixed: "已修复", still_present: "仍存在", cannot_determine: "无法判断" } as const;

export function severityRank(sev: Severity | undefined): number {
  const i = sev ? SEVERITY_ORDER.indexOf(sev) : -1;
  return i < 0 ? SEVERITY_ORDER.length : i;
}

const VERDICT_RANK: Record<Verdict, number> = { confirmed: 0, needs_validation: 1, rejected: 2 };

/** Default list order: confirmed first, then by severity, then needs_validation and rejected; ties by title. */
export function sortFindings(rows: FindingRow[]): FindingRow[] {
  return [...rows].sort((a, b) =>
    VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict]
    || severityRank(a.severity) - severityRank(b.severity)
    || a.title.localeCompare(b.title, "zh"));
}

export function matchesQuery(row: FindingRow, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [row.title, row.file, row.fingerprint].some((s) => s.toLowerCase().includes(q));
}

/** Units that count toward progress: everything except units that do not apply or are outside the scope. */
export function unitTotals(byStatus: Coverage["by_status"]) {
  const n = (s: UnitStatus) => byStatus[s] ?? 0;
  const total = n("planned") + n("in_progress") + n("covered") + n("candidate") + n("blocked") + n("deferred");
  const concluded = n("covered") + n("candidate") + n("blocked");
  return { total, concluded, pending: total - concluded, deferred: n("deferred") };
}

export function shortCommit(run: Pick<RunRow, "source_ref">): string {
  return (run.source_ref.commit ?? "").slice(0, 7);
}

export function runNumber(runId: string): string {
  const m = /run-(\d+)$/.exec(runId);
  return m ? m[1]! : runId;
}

export function scopeLabel(run: Pick<RunRow, "scope">): string {
  const s = run.scope;
  if (s.mode === "paths") return "指定路径";
  if (s.mode === "diff") return `代码变更 ${s.base ?? "?"}..${s.head ?? "HEAD"}`;
  return "整个仓库";
}

export function elapsedMinutes(run: Pick<RunRow, "created_at" | "updated_at" | "completed_at" | "status">, now: number): number {
  const start = Date.parse(run.created_at);
  if (Number.isNaN(start)) return 0;
  const endText = run.status === "in_progress" ? "" : run.completed_at || run.updated_at;
  const end = endText ? Date.parse(endText) : now;
  return Math.max(0, Math.round(((Number.isNaN(end) ? now : end) - start) / 60_000));
}

export function formatElapsed(minutes: number): string {
  if (minutes < 1) return "不到 1 分钟";
  if (minutes < 60) return `${minutes} 分钟`;
  return `${Math.floor(minutes / 60)} 小时 ${minutes % 60} 分钟`;
}

/** "今天 14:20", "11-20", or "2025-11-20" for another year. */
export function formatWhen(iso: string, now = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const d = new Date(t);
  const today = new Date(now);
  const hhmm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  if (d.toDateString() === today.toDateString()) return `今天 ${hhmm}`;
  const md = `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  return d.getFullYear() === today.getFullYear() ? md : `${d.getFullYear()}-${md}`;
}

/** Finished sub-agent count and the failed ones, for the "另有 N 个已完成" line. */
export function agentSummary(events: AgentEvent[]) {
  let returned = 0;
  let failed = 0;
  for (const e of events) {
    if (e.event === "returned") returned++;
    else if (e.event === "failed") failed++;
  }
  return { returned, failed };
}

export function runningAction(e: AgentEvent): string {
  if (e.summary) return e.summary;
  const role = ROLE_LABEL[e.role] ?? e.role;
  return e.unit_ids?.length ? `${role} · ${e.unit_ids.length} 个单元` : role;
}

/** Which run follows from `runs`: the in-progress run if any, else the newest. */
export function defaultRun(runs: RunRow[]): RunRow | undefined {
  return runs.find((r) => r.status === "in_progress") ?? runs[0];
}

/**
 * Finished runs beyond the newest `keep` (0 keeps all), oldest first. A run still in progress is never listed, and the
 * newest `keep` are counted among all runs, so a running run does not push a finished one out of the kept set.
 */
export function surplusRuns(runs: RunRow[], keep: number): RunRow[] {
  if (keep <= 0) return [];
  const newestFirst = [...runs].sort((a, b) => (a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : 0));
  return newestFirst.slice(keep).filter((r) => r.status !== "in_progress").reverse();
}

export function priorRunsOf(runs: RunRow[], repo: string, runId: string): RunRow[] {
  return runs.filter((r) => r.repo === repo && r.run_id !== runId);
}

// ---- coverage grid ----

export type GridCell = { unit: LedgerUnit | null; units: LedgerUnit[] };
export type Grid = { rows: { key: string; label: string; ref: string }[]; cols: { key: string; label: string }[]; cell(row: number, col: number): GridCell };

const STATUS_PRIORITY: UnitStatus[] = ["candidate", "blocked", "in_progress", "planned", "deferred", "covered", "out_of_scope", "not_applicable"];

/** The unit that stands for a cell with several units: the one that most needs attention. */
function representative(units: LedgerUnit[]): LedgerUnit {
  return [...units].sort((a, b) => STATUS_PRIORITY.indexOf(a.status) - STATUS_PRIORITY.indexOf(b.status))[0]!;
}

function refPath(ref: string): string {
  const i = ref.indexOf("#");
  return i > 0 ? ref.slice(0, i) : ref;
}

/** Entries (surface) by attack class; units sharing both, with different boundaries, collapse to the most urgent one. */
export function buildGrid(units: LedgerUnit[]): Grid {
  const rows: Grid["rows"] = [];
  const cols: Grid["cols"] = [];
  const rowIndex = new Map<string, number>();
  const colIndex = new Map<string, number>();
  const cells = new Map<string, LedgerUnit[]>();
  for (const u of units) {
    const rk = u.canonical_refs?.surface ?? u.surface;
    const ck = u.canonical_refs?.attack_class ?? u.attack_class;
    if (!rowIndex.has(rk)) { rowIndex.set(rk, rows.length); rows.push({ key: rk, label: u.surface, ref: refPath(rk) }); }
    if (!colIndex.has(ck)) { colIndex.set(ck, cols.length); cols.push({ key: ck, label: u.attack_class }); }
    const k = `${rowIndex.get(rk)}:${colIndex.get(ck)}`;
    const bucket = cells.get(k);
    if (bucket) bucket.push(u); else cells.set(k, [u]);
  }
  return {
    rows, cols,
    cell(r, c) {
      const bucket = cells.get(`${r}:${c}`);
      return bucket ? { unit: representative(bucket), units: bucket } : { unit: null, units: [] };
    },
  };
}

export function findingsForUnit(unit: LedgerUnit, rows: FindingRow[]): FindingRow[] {
  const wanted = new Set(unit.result_fingerprints);
  return rows.filter((r) => wanted.has(r.fingerprint));
}

/** Ledger units whose result_fingerprints name this finding: who found and who checked it. */
export function unitsForFinding(fingerprint: string, units: LedgerUnit[]): LedgerUnit[] {
  return units.filter((u) => u.result_fingerprints.includes(fingerprint));
}
