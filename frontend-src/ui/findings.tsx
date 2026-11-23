import { useMemo, useState } from "preact/hooks";
import type { Session } from "./session";
import type { FindingRow, Verdict } from "../types";
import { matchesQuery, priorRunsOf, runNumber, severityRank, sortFindings, unitTotals, VERDICT_LABEL } from "../lib/derive";
import { findingReference } from "../lib/request";
import { exportRun } from "../lib/api";
import { copySync } from "../lib/host";
import { Empty } from "./common";
import { FindingRowItem } from "./progress";
import { Icon } from "./icons";
import type { ExportFormat } from "../types";

type Chip = "all" | Verdict;
type Sort = "severity" | "title" | "location";

const SORTS: { id: Sort; label: string }[] = [
  { id: "severity", label: "按严重程度" },
  { id: "title", label: "按标题" },
  { id: "location", label: "按文件" },
];

export function applyFilters(rows: FindingRow[], chip: Chip, query: string, sort: Sort): FindingRow[] {
  const filtered = rows.filter((r) => (chip === "all" || r.verdict === chip) && matchesQuery(r, query));
  if (sort === "title") return filtered.sort((a, b) => a.title.localeCompare(b.title, "zh"));
  if (sort === "location") return filtered.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  return sortFindings(filtered);
}

export function isNewInRun(row: FindingRow, runId: string, hasPrior: boolean): boolean {
  return hasPrior && row.state?.first_seen_run === runId;
}

export const EXPORTS: { id: ExportFormat; label: string }[] = [
  { id: "sarif", label: "SARIF" },
  { id: "json", label: "JSON" },
  { id: "csv", label: "CSV" },
  { id: "markdown", label: "Markdown" },
];

export function ExportMenu({ s, runId, inline }: { s: Session; runId: string; inline?: boolean }) {
  const [open, setOpen] = useState(!!inline);
  const [withNeeds, setWithNeeds] = useState(false);
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [done, setDone] = useState<{ path: string; records: number; format: string } | null>(null);
  async function run(format: ExportFormat) {
    setBusy(format);
    try {
      const out = await exportRun(s.host, runId, format, withNeeds);
      setDone({ ...out, format });
    } catch (error) {
      s.notify(error instanceof Error ? error.message : "导出失败", "err");
    } finally { setBusy(null); }
  }
  return (
    <div class={inline ? "exportinline" : "menuwrap"}>
      {inline ? null : <button type="button" class="btn" aria-expanded={open} onClick={() => { setOpen(!open); setDone(null); }}><Icon name="download" />导出</button>}
      {open ? (
        <div class={inline ? "menu-body" : "menu"} role={inline ? undefined : "dialog"} aria-label="导出">
          <div class="menu-row">
            {EXPORTS.map((e) => (
              <button type="button" key={e.id} class="btn sm" disabled={busy !== null} onClick={() => void run(e.id)}>{busy === e.id ? "导出中…" : e.label}</button>
            ))}
          </div>
          <label class="check"><input type="checkbox" checked={withNeeds} onChange={(ev) => setWithNeeds((ev.currentTarget as HTMLInputElement).checked)} />包含待验证项</label>
          {done ? (
            <div class="exported">
              <span class="muted small">已导出 {done.records} 条（{done.format}）</span>
              <span class="mono path">{done.path}</span>
              <button type="button" class="btn sm" onClick={() => { const ok = copySync(done.path); s.notify(ok ? "路径已复制" : "无法复制路径", ok ? "ok" : "err"); }}><Icon name="copy" />复制路径</button>
            </div>
          ) : <span class="muted small">只导出已确认的发现。文件写在本机审计数据目录。</span>}
        </div>
      ) : null}
    </div>
  );
}

export function FindingsView({ s }: { s: Session }) {
  const [chip, setChip] = useState<Chip>("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<Sort>("severity");
  const run = s.run;
  const counts = useMemo(() => {
    const c = { all: s.findings.length, confirmed: 0, needs_validation: 0, rejected: 0 };
    for (const f of s.findings) c[f.verdict]++;
    return c;
  }, [s.findings]);
  if (!run) return null;
  const rows = applyFilters(s.findings, chip, query, sort);
  const hasPrior = priorRunsOf(s.runs, run.repo, run.run_id).length > 0;
  const newCount = s.findings.filter((f) => isNewInRun(f, run.run_id, hasPrior)).length;
  const { total, concluded, deferred } = unitTotals(run.counts.unit_status);
  return (
    <div class="col">
      <div class="bar">
        <label class="inp grow"><Icon name="search" /><input type="search" placeholder="搜索标题、文件或指纹" value={query} onInput={(e) => setQuery((e.currentTarget as HTMLInputElement).value)} aria-label="搜索发现" /></label>
        <label class="inp sel"><select value={sort} onChange={(e) => setSort((e.currentTarget as HTMLSelectElement).value as Sort)} aria-label="排序">{SORTS.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}</select><Icon name="chevronDown" /></label>
      </div>
      <div class="chips">
        {(["all", "confirmed", "needs_validation", "rejected"] as Chip[]).map((c) => (
          <button type="button" key={c} class={`chip${chip === c ? " on" : ""}`} aria-pressed={chip === c} onClick={() => setChip(c)}>
            {c === "all" ? "全部" : VERDICT_LABEL[c]}<span>{counts[c]}</span>
          </button>
        ))}
        <span class="grow" />
        <span class="muted small">第 {runNumber(run.run_id)} 次运行{hasPrior ? ` · 新增 ${newCount}` : ""}</span>
      </div>
      <div class="list scroll">
        {rows.length ? rows.map((f) => (
          <FindingRowItem key={f.fingerprint} row={f} isNew={isNewInRun(f, run.run_id, hasPrior)} onOpen={() => s.openFinding(f.fingerprint)}
            onRef={s.readOnly ? undefined : () => void s.send(findingReference(run.run_id, f), "已把发现引用放进对话输入框")} />
        )) : <Empty title={s.findings.length ? "没有符合条件的发现" : "这次运行还没有发现"}>{s.findings.length ? "换个筛选或搜索词试试。" : run.status === "in_progress" ? "审计进行中，发现写入后会出现在这里。" : "没有发现并不等于没有问题，可以看覆盖面了解审了哪些地方。"}</Empty>}
      </div>
      <div class="foot">
        <span class="muted small grow">覆盖 {concluded} / {total} 个单元{deferred ? ` · ${deferred} 个延后` : ""}</span>
        <ExportMenu s={s} runId={run.run_id} />
      </div>
    </div>
  );
}
