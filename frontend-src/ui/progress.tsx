import type { Session } from "./session";
import type { FindingRow, RunDetail, RunRow } from "../types";
import {
  PHASES, RUN_STATUS_LABEL, ROLE_LABEL, agentSummary, elapsedMinutes, formatElapsed, phaseStates, runningAction, scopeLabel,
  shortCommit, sortFindings, unitTotals,
} from "../lib/derive";
import { profileLabel } from "../lib/request";
import { SevBadge, VerdictPill } from "./common";
import { Icon } from "./icons";

export function RunHeader({ run, now }: { run: RunRow; now: number }) {
  const commit = shortCommit(run);
  const minutes = elapsedMinutes(run, now);
  return (
    <div class="runhead">
      <b class="repo">{run.repo.replace(/-[0-9a-f]{6,}$/, "")}</b>
      {commit ? <span class="tag">{commit}{run.source_ref.dirty ? " +改动" : ""}</span> : null}
      <span class="tag">{profileLabel(run.profile)}档</span>
      <span class="tag">{scopeLabel(run)}</span>
      <span class="grow" />
      <span class="muted num">{run.status === "in_progress" ? `已用 ${formatElapsed(minutes)}` : `${RUN_STATUS_LABEL[run.status]} · 用时 ${formatElapsed(minutes)}`}</span>
    </div>
  );
}

function PhaseBar({ run }: { run: RunRow }) {
  const states = phaseStates(run);
  return (
    <ol class="phases" aria-label="审计阶段">
      {PHASES.map((p, i) => (
        <li key={p.id} class={`ph ${states[i]}`} aria-current={states[i] === "now" ? "step" : undefined}>
          <i />
          <span>{i + 1} {p.label}</span>
        </li>
      ))}
    </ol>
  );
}

function Stats({ run }: { run: RunRow }) {
  const { total, concluded } = unitTotals(run.counts.unit_status);
  const candidates = run.counts.unit_status.candidate ?? 0;
  return (
    <div class="stats">
      <div class="stat"><b>{concluded}<small> / {total}</small></b><span>覆盖单元</span></div>
      <div class="stat"><b>{candidates}</b><span>候选单元</span></div>
      <div class="stat"><b>{run.counts.confirmed}</b><span>已确认</span></div>
      <div class="stat"><b>{run.agent_calls}{run.budget ? <small> / {run.budget}</small> : null}</b><span>Agent 调用{run.budget ? "预算" : ""}</span></div>
    </div>
  );
}

function Running({ detail, run }: { detail: RunDetail; run: RunRow }) {
  const running = detail.agents_running;
  const sum = agentSummary(detail.agent_events);
  const queued = run.counts.unit_status.planned ?? 0;
  if (run.status !== "in_progress" && !running.length) return null;
  return (
    <section class="sec">
      <h3 class="sec-t">{running.length ? `正在运行 · ${running.length} 个子 Agent` : "暂时没有运行中的子 Agent"}</h3>
      {running.map((a) => (
        <div class="agent" key={a.agent_id}>
          <span class="tag">{a.agent_id}</span>
          <span class="grow ell" title={runningAction(a)}>{runningAction(a)}</span>
          <span class={`pill ${a.role === "verifier" || a.role === "record_verifier" ? "warn" : "info"}`}><i class="dot" />{ROLE_LABEL[a.role] ?? a.role}中</span>
        </div>
      ))}
      {sum.returned || sum.failed || queued ? (
        <p class="muted small">
          {[sum.returned ? `已完成 ${sum.returned} 个` : "", sum.failed ? `失败 ${sum.failed} 个` : "", queued ? `${queued} 个单元排队` : ""].filter(Boolean).join("，")}
        </p>
      ) : null}
    </section>
  );
}

export function FindingRowItem({ row, onOpen, onRef, isNew, rail }: {
  row: FindingRow; onOpen(): void; onRef?(): void; isNew?: boolean; rail?: boolean;
}) {
  const fixed = row.state?.fix_status === "fixed";
  const excluded = row.state?.user_decision === "excluded_by_user";
  const dim = row.verdict === "rejected" || excluded;
  return (
    <div class={`row${dim ? " dim" : ""}${onRef ? " hasref" : ""}`}>
      <SevBadge severity={row.severity} verdict={row.verdict} />
      <button type="button" class="rowbody" onClick={onOpen}>
        <span class="t">{row.title}</span>
        <span class="s">{row.file ? `${row.file}${row.line ? `:${row.line}` : ""}` : row.fingerprint}</span>
      </button>
      <span class="r">
        {isNew ? <span class="pill info">新增</span> : null}
        {fixed ? <span class="pill ok">已修复</span> : null}
        {!rail && !isNew && !fixed ? <VerdictPill verdict={row.verdict} /> : null}
        {excluded ? <span class="pill">你已排除</span> : null}
        {onRef ? <button type="button" class="btn sm ghost refbtn" onClick={onRef} title="把这条发现引用到对话"><Icon name="at" />引用</button> : null}
      </span>
    </div>
  );
}

export function ProgressView({ s }: { s: Session }) {
  const { run, detail } = s;
  if (!run) return null;
  const latest = sortFindings(s.findings).filter((f) => f.verdict !== "rejected").slice(0, 5);
  const incomplete = run.status === "incomplete";
  return (
    <div class="scroll">
      <section class="sec">
        <RunHeader run={run} now={s.now} />
        <PhaseBar run={run} />
      </section>
      {incomplete ? (
        <div class="sec warnline"><Icon name="alert" /><span>未完成：{run.incomplete_reason || "没有给出原因"}</span></div>
      ) : null}
      <section class="sec"><Stats run={run} /></section>
      {detail ? <Running detail={detail} run={run} /> : null}
      <section class="sec nopad-b">
        <h3 class="sec-t">最新结果</h3>
        {latest.length ? latest.map((f) => (
          <FindingRowItem key={f.fingerprint} row={f} onOpen={() => s.openFinding(f.fingerprint)} />
        )) : <p class="muted">{run.status === "in_progress" ? "还没有结果，狩猎阶段产生候选后会出现在这里。" : "这次运行没有产生发现。"}</p>}
        {s.findings.length > latest.length ? (
          <button type="button" class="btn ghost more" onClick={() => s.go("findings")}>查看全部 {s.findings.length} 条发现<Icon name="chevronRight" /></button>
        ) : null}
      </section>
    </div>
  );
}

