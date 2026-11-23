import { useEffect, useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import type { Session } from "./session";
import type { ExtStep, FindingDetail, FindingRecord, FindingRow, FixStatus, LedgerUnit, Severity, TraceStep, UserDecision } from "../types";
import { getFinding, setFindingState, errorLines, AuditError } from "../lib/api";
import {
  CONDITION_LABEL, FIX_LABEL, SEVERITY_LABEL, STEP_LABEL, unitsForFinding,
} from "../lib/derive";
import { findingReference, fixRequest } from "../lib/request";
import { Empty, ErrorNote, SevBadge, VerdictPill } from "./common";
import { Icon } from "./icons";

const SEV_CLASS: Record<Severity, string> = { critical: "c", high: "h", medium: "m", low: "l", informational: "x" };

function SevTag({ severity }: { severity: Severity }) {
  return <span class={`sev ${SEV_CLASS[severity]}`} title={SEVERITY_LABEL[severity]}>{SEVERITY_LABEL[severity].slice(0, 1)}</span>;
}

export function CodeBlock({ step, line }: { step: ExtStep | undefined; line: number }) {
  if (!step || !step.snippet.lines.length) return null;
  const { start_line: start, lines, truncated } = step.snippet;
  return (
    <pre class="code" aria-label={`${step.file} 第 ${line} 行附近`}>
      {lines.map((text, i) => (
        <div key={i} class={start + i === line ? "hl" : ""}><b>{start + i}</b>{text || " "}</div>
      ))}
      {truncated ? <div><b>…</b>（片段已截断）</div> : null}
    </pre>
  );
}

function Place({ file, line }: { file: string; line: number }) {
  return <span class="tag" title={`${file}:${line}`}>{file}:{line}</span>;
}

function stepOf(ext: FindingDetail["ext"], role: "trace" | "evidence", index: number): ExtStep | undefined {
  return ext?.steps?.find((x) => x.role === role && x.index === index);
}

function Flow({ title, steps, ext }: { title: string; steps: TraceStep[]; ext: FindingDetail["ext"] }) {
  if (!steps.length) return null;
  return (
    <section class="blk">
      <h3 class="sec-t">{title}</h3>
      {steps.map((t, i) => (
        <div class="step" key={i}>
          <div class="rail"><em>{i + 1}</em>{i < steps.length - 1 ? <u /> : null}</div>
          <div class="body">
            <div class="hd"><b>{STEP_LABEL[t.kind] ?? t.kind}</b><Place file={t.file} line={t.line} /><span class="muted">{t.description}</span></div>
            <CodeBlock step={stepOf(ext, "trace", i)} line={t.line} />
          </div>
        </div>
      ))}
    </section>
  );
}

function Evidence({ record, ext }: { record: FindingRecord; ext: FindingDetail["ext"] }) {
  if (!record.evidence.length) return null;
  return (
    <section class="blk">
      <h3 class="sec-t">证据</h3>
      {record.evidence.map((e, i) => (
        <div class="evi" key={i}>
          <div class="hd"><Place file={e.file} line={e.line} /><span class="muted">{e.description}</span></div>
          <CodeBlock step={stepOf(ext, "evidence", i)} line={e.line} />
        </div>
      ))}
    </section>
  );
}

function Text({ title, children }: { title: string; children: ComponentChildren }) {
  return <section class="blk"><h3 class="sec-t">{title}</h3><p class="body-text">{children}</p></section>;
}

function Remediation({ record }: { record: FindingRecord }) {
  const r = record.remediation;
  if (!r) return null;
  return (
    <section class="blk">
      <h3 class="sec-t">修复建议</h3>
      <p class="body-text">{r.strategy}</p>
      {(r.code_changes ?? []).map((c, i) => (
        <div key={i}>
          <div class="hd"><span class="tag">{c.file_name}</span></div>
          <pre class="code">{c.fixed_code.split("\n").map((l, j) => <div key={j} class="add"><b>+</b>{l || " "}</div>)}</pre>
        </div>
      ))}
    </section>
  );
}

function Reproduction({ record }: { record: FindingRecord }) {
  const e = record.execution;
  if (!e) return null;
  return (
    <section class="blk">
      <h3 class="sec-t">复现步骤</h3>
      <p class="body-text muted">{e.attacker_perspective}</p>
      <ol class="steps">{e.instructions.map((t, i) => <li key={i}>{t}</li>)}</ol>
      {e.payloads.length ? <pre class="code plain">{e.payloads.join("\n")}</pre> : null}
      <p class="body-text"><b>预期现象：</b>{e.observed_result}</p>
    </section>
  );
}

function Blockers({ record }: { record: FindingRecord }) {
  if (!record.blockers?.length) return null;
  return (
    <>
      <section class="blk">
        <h3 class="sec-t">卡在哪里</h3>
        <ul class="bul">{record.blockers.map((b, i) => <li key={i}>{b}</li>)}</ul>
      </section>
      {record.validation_plan ? (
        <section class="blk">
          <h3 class="sec-t">怎么验证</h3>
          <dl class="kv">
            {record.validation_plan.local ? <><dt>本地</dt><dd>{record.validation_plan.local}</dd></> : null}
            {record.validation_plan.deployment ? <><dt>部署侧</dt><dd>{record.validation_plan.deployment}</dd></> : null}
          </dl>
        </section>
      ) : null}
    </>
  );
}

function SeverityBox({ record }: { record: FindingRecord }) {
  const sv = record.severity;
  if (!sv) return <section class="blk"><h3 class="sec-t">严重程度</h3><p class="muted">待验证的问题不评级，确认后才有严重程度。</p></section>;
  return (
    <section class="blk">
      <h3 class="sec-t">严重程度</h3>
      <dl class="kv">
        <dt>可能性</dt><dd><b>{SEVERITY_LABEL[sv.likelihood.score as Severity] ?? sv.likelihood.score}</b> <span class="muted">{sv.likelihood.reason}</span></dd>
        <dt>影响</dt><dd><b>{SEVERITY_LABEL[sv.impact.score as Severity] ?? sv.impact.score}</b> <span class="muted">{sv.impact.reason}</span></dd>
        <dt>综合</dt><dd><SevTag severity={sv.overall_severity} /></dd>
        {record.confidence ? <><dt>置信度</dt><dd><b>{{ high: "高", medium: "中", low: "低" }[record.confidence.score] ?? record.confidence.score}</b> <span class="muted">{record.confidence.reason}</span></dd></> : null}
      </dl>
    </section>
  );
}

function Conditions({ record }: { record: FindingRecord }) {
  if (!record.conditions?.length) return null;
  return (
    <section class="blk">
      <h3 class="sec-t">成立条件</h3>
      <dl class="kv">{record.conditions.map((c, i) => <><dt key={`k${i}`}>{CONDITION_LABEL[c.kind] ?? c.kind}</dt><dd key={`v${i}`}>{c.description}</dd></>)}</dl>
    </section>
  );
}

function Verification({ fingerprint, units }: { fingerprint: string; units: LedgerUnit[] }) {
  const mine = unitsForFinding(fingerprint, units);
  if (!mine.length) return null;
  return (
    <section class="blk">
      <h3 class="sec-t">验证记录</h3>
      {mine.map((u) => (
        <div class="vlog" key={u.coverage_id}>
          <div class="hd">{u.agent_id ? <span class="tag">{u.agent_id}</span> : null}<span>第 {u.wave} 轮 · {u.surface} × {u.attack_class}</span></div>
          {u.local_checks.slice(0, 4).map((c, i) => (
            <p class="muted small" key={i}><span class="tag">{c.agent_id}</span> {c.invariant}：{c.result}</p>
          ))}
        </div>
      ))}
    </section>
  );
}

const FIX_OPTIONS: { id: FixStatus | "none"; label: string }[] = [
  { id: "none", label: "未修复" },
  { id: "proposed", label: FIX_LABEL.proposed },
  { id: "fixed", label: FIX_LABEL.fixed },
  { id: "still_present", label: FIX_LABEL.still_present },
  { id: "cannot_determine", label: FIX_LABEL.cannot_determine },
];

function StateBox({ s, runId, row, detail, onState }: { s: Session; runId: string; row: FindingRow; detail: FindingDetail; onState(state: FindingDetail["state"]): void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const st = detail.state;
  const verdict = detail.record.verdict;
  async function patch(p: Parameters<typeof setFindingState>[3]) {
    setBusy(true);
    setError(null);
    try {
      onState(await setFindingState(s.host, runId, row.fingerprint, p));
      s.reload();
    } catch (e) { setError(e); } finally { setBusy(false); }
  }
  const decision = st?.user_decision;
  return (
    <>
      {verdict === "confirmed" ? (
        <section class="blk">
          <h3 class="sec-t">修复状态</h3>
          <div class="fixrow">
            <label class="inp sel"><select value={st?.fix_status ?? "none"} disabled={busy || s.readOnly} aria-label="修复状态"
              onChange={(e) => void patch({ fix_status: (e.currentTarget as HTMLSelectElement).value as FixStatus | "none" })}>
              {FIX_OPTIONS.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
            </select><Icon name="chevronDown" /></label>
            {s.readOnly ? null : (
              st?.fix_status === "proposed" || st?.fix_status === "still_present"
                ? <button type="button" class="btn sm" onClick={() => void s.send(fixRequest(runId, row, "verify"), "已把“验证修复”请求放进对话输入框")}>验证修复</button>
                : null
            )}
          </div>
          {st?.fix_note ? <p class="muted small">{st.fix_note}</p> : null}
        </section>
      ) : (
        <section class="blk">
          <h3 class="sec-t">你的结论</h3>
          <div class="decide">
            {!s.readOnly && verdict === "needs_validation" ? (
              <button type="button" class="btn" onClick={() => void s.send(fixRequest(runId, row, "recheck"), "已把“再研判”请求放进对话输入框")}>让 Agent 再研判</button>
            ) : null}
            <button type="button" class="btn" aria-pressed={decision === "confirmed_by_user"} disabled={busy || s.readOnly}
              onClick={() => void patch({ user_decision: decision === "confirmed_by_user" ? "none" : ("confirmed_by_user" as UserDecision) })}>
              {decision === "confirmed_by_user" ? "已标记：我确认成立" : "我已确认成立"}
            </button>
            <button type="button" class="btn" aria-pressed={decision === "excluded_by_user"} disabled={busy || s.readOnly}
              onClick={() => void patch({ user_decision: decision === "excluded_by_user" ? "none" : ("excluded_by_user" as UserDecision) })}>
              {decision === "excluded_by_user" ? "已标记：已有防护，排除" : "已有防护，排除"}
            </button>
          </div>
          {decision ? <p class="muted small">你的结论只记在这条发现上，不会改动 Agent 的验证结论，之后的运行也会带着它。</p> : null}
        </section>
      )}
      {error ? <ErrorNote message={error instanceof Error ? error.message : "保存失败"} lines={errorLines(error)} /> : null}
    </>
  );
}

export function DetailBody({ s, row, runId }: { s: Session; row: FindingRow; runId: string }) {
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    let live = true;
    setDetail(null);
    setError(null);
    getFinding(s.host, runId, row.fingerprint).then((d) => { if (live) setDetail(d); }, (e) => { if (live) setError(e); });
    return () => { live = false; };
  }, [s.host, runId, row.fingerprint]);
  if (error) return <div class="pad"><ErrorNote message={error instanceof AuditError ? error.message : "读取发现失败"} /></div>;
  if (!detail) return <div class="pad muted">正在读取…</div>;
  const r = detail.record;
  const cwe = detail.ext?.cwe ?? [];
  const wide = s.wide;
  const rootCause = r.root_cause ?? r.claimed_root_cause;
  const main = (
    <div class="detmain">
      <div class="dethead">
        <SevBadge severity={row.severity} verdict={r.verdict} />
        <VerdictPill verdict={r.verdict} extra={r.verdict === "needs_validation" ? "不评级" : undefined} />
        {cwe.map((c) => <span class="tag" key={c}>{c}</span>)}
        <span class="grow" />
        {!s.readOnly ? <button type="button" class="btn sm" onClick={() => void s.send(findingReference(runId, row), "已把发现引用放进对话输入框")}><Icon name="at" />引用到对话</button> : null}
        {!s.readOnly && r.verdict === "confirmed" ? <button type="button" class="btn sm pri" onClick={() => void s.send(fixRequest(runId, row, "propose"), "已把“生成修复”请求放进对话输入框")}>生成修复</button> : null}
      </div>
      <h2>{r.title}</h2>
      <p class="body-text muted">{r.description}</p>
      {r.verdict === "rejected" && r.reason ? <Text title="排除理由">{r.reason}</Text> : null}
      {rootCause ? <Text title={r.verdict === "confirmed" ? "根因" : "疑似根因"}>{rootCause}</Text> : null}
      {r.intended_behavior ? <Text title="应有行为">{r.intended_behavior}</Text> : null}
      <Blockers record={r} />
      <Flow title={r.verdict === "confirmed" ? "数据流" : "已确认的源码路径"} steps={r.trace} ext={detail.ext} />
      <Evidence record={r} ext={detail.ext} />
      <Remediation record={r} />
      <Reproduction record={r} />
    </div>
  );
  const side = (
    <div class="detside">
      <SeverityBox record={r} />
      <Conditions record={r} />
      <Verification fingerprint={row.fingerprint} units={s.coverage?.units ?? []} />
      <StateBox s={s} runId={runId} row={row} detail={detail} onState={(state) => setDetail({ ...detail, state })} />
      <div class="muted small foot-id"><span class="mono">{row.fingerprint}</span></div>
    </div>
  );
  return <div class={`detbody${wide ? " wide" : ""}`}>{main}{side}</div>;
}

export function DetailView({ s, fingerprint, onBack, onSelect, rows }: {
  s: Session; fingerprint: string; onBack(): void; onSelect(fp: string): void; rows: FindingRow[];
}) {
  const index = rows.findIndex((r) => r.fingerprint === fingerprint);
  const row = rows[index];
  const run = s.run;
  if (!run) return null;
  if (!row) {
    return (
      <div class="col">
        <div class="detbar"><button type="button" class="ib" onClick={onBack} aria-label="返回"><Icon name="chevronLeft" /></button><b>发现详情</b></div>
        <Empty title="没有找到这条发现">它可能属于另一次运行，或已被删除。</Empty>
      </div>
    );
  }
  const prev = rows[index - 1];
  const next = rows[index + 1];
  return (
    <div class="col">
      <div class="detbar">
        <button type="button" class="ib" onClick={onBack} aria-label="返回列表"><Icon name="chevronLeft" /></button>
        <b>发现详情</b><span class="muted num">{index + 1} / {rows.length}</span>
        <span class="grow" />
        <button type="button" class="ib" disabled={!prev} onClick={() => prev && onSelect(prev.fingerprint)} aria-label="上一条"><Icon name="chevronUp" /></button>
        <button type="button" class="ib" disabled={!next} onClick={() => next && onSelect(next.fingerprint)} aria-label="下一条"><Icon name="chevronDown" /></button>
      </div>
      <div class="scroll"><DetailBody s={s} row={row} runId={run.run_id} /></div>
    </div>
  );
}

