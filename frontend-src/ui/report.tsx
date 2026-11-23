import { useState } from "preact/hooks";
import type { Session } from "./session";
import type { ReportName, RunRow, Severity } from "../types";
import {
  RUN_STATUS_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, formatWhen, priorRunsOf, runNumber, scopeLabel, shortCommit, unitTotals,
} from "../lib/derive";
import { continueRequest, profileLabel } from "../lib/request";
import { deleteRun } from "../lib/api";
import { ConfirmButton } from "./common";
import { DOC_TITLES } from "./docview";
import { ExportMenu } from "./findings";

const DOCS: ReportName[] = ["REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md", "architecture.md"];
const SEV_COLOR: Record<Severity, string> = { critical: "var(--sev-c)", high: "var(--sev-h-bar)", medium: "var(--sev-m-t)", low: "var(--sev-l-t)", informational: "var(--muted)" };

function SeverityBar({ counts }: { counts: RunRow["counts"]["severity"] }) {
  const items = SEVERITY_ORDER.map((sv) => ({ sv, n: counts[sv] ?? 0 }));
  const total = items.reduce((a, x) => a + x.n, 0);
  return (
    <div>
      {total ? (
        <div class="sevbar" role="img" aria-label={items.map((x) => `${SEVERITY_LABEL[x.sv]} ${x.n}`).join("，")}>
          {items.filter((x) => x.n).map((x) => <i key={x.sv} style={{ flexGrow: x.n, background: SEV_COLOR[x.sv] }} />)}
        </div>
      ) : <div class="sevbar empty" />}
      <div class="legend">{items.filter((x) => x.sv !== "informational" || x.n).map((x) => <span key={x.sv} class="muted">{SEVERITY_LABEL[x.sv]} {x.n}</span>)}</div>
    </div>
  );
}

function HistoryRow({ s, row, current }: { s: Session; row: RunRow; current: boolean }) {
  const commit = shortCommit(row);
  const bits = [commit, row.counts.confirmed ? `已确认 ${row.counts.confirmed}` : "", row.counts.needs_validation ? `待验证 ${row.counts.needs_validation}` : "", `用了 ${row.agent_calls} 次调用`].filter(Boolean);
  if (row.status === "incomplete") bits.push(row.incomplete_reason ? `未完成：${row.incomplete_reason}` : "未完成");
  else if (row.status === "in_progress") bits.push("进行中");
  return (
    <div class={`hist${current ? " cur" : ""}`}>
      <button type="button" class="histbody" onClick={() => s.selectRun(row.run_id)} aria-current={current ? "true" : undefined}>
        <span class="tag">#{runNumber(row.run_id)}</span>
        <span class="t">{profileLabel(row.profile)}档 · {scopeLabel(row)}</span>
        <span class="r muted num">{formatWhen(row.created_at, s.now)}</span>
        <span class="s muted">{bits.join(" · ")}</span>
      </button>
      {!s.readOnly && row.status !== "in_progress" ? (
        <ConfirmButton label="删除" confirmLabel="确认删除" onConfirm={() => {
          deleteRun(s.host, row.run_id).then(() => { s.notify("已删除这次运行"); s.reload(); }, (e) => s.notify(e instanceof Error ? e.message : "删除失败", "err"));
        }} />
      ) : null}
    </div>
  );
}

export function ReportView({ s }: { s: Session }) {
  const run = s.run;
  const [showAll, setShowAll] = useState(false);
  if (!run) return null;
  const { total, concluded, deferred } = unitTotals(run.counts.unit_status);
  const pct = total ? Math.round((concluded / total) * 100) : 0;
  const files = s.detail?.files ?? {};
  const hasFile = (name: ReportName) => files[name] === true;
  const repoRuns = s.runs.filter((r) => r.repo === run.repo);
  const history = showAll ? s.runs : repoRuns;
  const hasPrior = priorRunsOf(s.runs, run.repo, run.run_id).length > 0;
  return (
    <div class="col">
      <div class="scroll">
        <section class="sec">
          <div class="reporthead">
            <h2 class="grow ell">{run.repo.replace(/-[0-9a-f]{6,}$/, "")} 安全审计报告</h2>
            <span class={`pill ${run.status === "complete" ? "ok" : run.status === "incomplete" ? "warn" : "info"}`}>{RUN_STATUS_LABEL[run.status]}</span>
          </div>
          <div class="stats">
            <div class="stat"><b>{run.counts.confirmed}</b><span>已确认</span></div>
            <div class="stat"><b>{run.counts.needs_validation}</b><span>待验证</span></div>
            <div class="stat"><b>{run.counts.rejected}</b><span>已排除</span></div>
            <div class="stat"><b>{pct}%</b><span>单元已有结论</span></div>
          </div>
          <SeverityBar counts={run.counts.severity} />
        </section>
        <section class="sec">
          <h3 class="sec-t">文档</h3>
          {DOCS.map((name) => (
            <div class="docrow" key={name}>
              <b class="grow">{DOC_TITLES[name]}</b>
              <span class="mono muted small">{name}</span>
              <button type="button" class="btn sm" disabled={!hasFile(name)} title={hasFile(name) ? "" : "这次运行还没有生成"} onClick={() => s.openDoc(name)}>打开</button>
            </div>
          ))}
          {run.status === "in_progress" ? <p class="muted small">三份报告在运行结束、生成报告后才有。</p> : null}
        </section>
        <section class="sec">
          <h3 class="sec-t">导出</h3>
          <ExportMenu s={s} runId={run.run_id} inline />
        </section>
        <section class="sec nopad-b">
          <div class="histhead"><h3 class="sec-t grow">历史运行</h3>
            {s.runs.length > repoRuns.length ? <button type="button" class="btn sm ghost" onClick={() => setShowAll(!showAll)}>{showAll ? "只看这个仓库" : "显示全部仓库"}</button> : null}
          </div>
          {history.map((r) => <HistoryRow key={r.run_id} s={s} row={r} current={r.run_id === run.run_id} />)}
        </section>
      </div>
      <div class="foot">
        <span class="muted small grow">{deferred ? `还有 ${deferred} 个延后单元没审` : hasPrior ? "新运行会沿用这次的结论" : "再审一轮只补没覆盖的部分"}</span>
        {!s.readOnly ? <button type="button" class="btn" onClick={() => void s.send(continueRequest(run.run_id, run.target), "已把“再审一轮”请求放进对话输入框")}>在此基础上再审一轮</button> : null}
      </div>
    </div>
  );
}
