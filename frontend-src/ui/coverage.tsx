import { useState } from "preact/hooks";
import type { Session } from "./session";
import type { LedgerUnit, UnitStatus } from "../types";
import { UNIT_LABEL, buildGrid, findingsForUnit, unitTotals } from "../lib/derive";
import { unitRequest } from "../lib/request";
import { profileLabel } from "../lib/request";
import { Empty, Meter, SevBadge } from "./common";

const CELL: Record<UnitStatus, string> = {
  covered: "cov", candidate: "cand", in_progress: "run", blocked: "blk", planned: "", deferred: "", not_applicable: "na", out_of_scope: "na",
};
const LEGEND: UnitStatus[] = ["covered", "candidate", "in_progress", "blocked", "planned", "deferred", "not_applicable"];

function UnitDetail({ s, unit }: { s: Session; unit: LedgerUnit }) {
  const run = s.run!;
  const outputs = findingsForUnit(unit, s.findings);
  const paths = unit.reviewed_paths.length ? unit.reviewed_paths : unit.starting_paths;
  return (
    <section class="sec unit">
      <div class="unithead">
        <h3>{unit.surface} × {unit.attack_class}</h3>
        <span class={`pill ${unit.status === "covered" ? "ok" : unit.status === "candidate" || unit.status === "blocked" ? "warn" : ""}`}>{UNIT_LABEL[unit.status]}</span>
        <span class="grow" />
        {!s.readOnly && run.status !== "in_progress" ? (
          <button type="button" class="btn sm" onClick={() => void s.send(unitRequest(run.run_id, unit), "已把“重新审这个单元”请求放进对话输入框")}>重新审这个单元</button>
        ) : null}
      </div>
      <dl class="kv">
        <dt>信任边界</dt><dd>{unit.boundary} <span class="tag">{unit.canonical_refs.boundary}</span></dd>
        <dt>子系统</dt><dd>{unit.subsystem}</dd>
        <dt>负责 Agent</dt><dd>{unit.agent_id ? <><span class="tag">{unit.agent_id}</span> 第 {unit.wave} 轮</> : <span class="muted">还没有分配</span>}</dd>
        <dt>{unit.reviewed_paths.length ? "已读路径" : "起点路径"}</dt>
        <dd class="mono">{paths.slice(0, 3).join("，")}{paths.length > 3 ? ` 等 ${paths.length} 个` : ""}{paths.length === 0 ? <span class="muted">—</span> : null}</dd>
        {unit.local_checks.length ? <><dt>做过的检查</dt><dd>{unit.local_checks.slice(0, 3).map((c, i) => <div key={i}>{c.invariant}：<span class="muted">{c.result}</span></div>)}{unit.local_checks.length > 3 ? <span class="muted">等 {unit.local_checks.length} 项</span> : null}</dd></> : null}
        {outputs.length ? <><dt>产出</dt><dd>{outputs.map((f) => <button type="button" class="link" key={f.fingerprint} onClick={() => s.openFinding(f.fingerprint)}>{f.title} <SevBadge severity={f.severity} verdict={f.verdict} /></button>)}</dd></> : null}
        {unit.unresolved.length ? <><dt>未决</dt><dd>{unit.unresolved.join("；")}</dd></> : null}
      </dl>
    </section>
  );
}

export function CoverageView({ s }: { s: Session }) {
  const [picked, setPicked] = useState<string | null>(null);
  const run = s.run;
  const cov = s.coverage;
  if (!run) return null;
  if (!cov) return <div class="pad muted">正在读取覆盖台账…</div>;
  if (!cov.units.length) return <Empty title="还没有覆盖台账">侦察阶段结束后，Agent 会把入口、信任边界和攻击类别画成覆盖单元，出现在这里。</Empty>;
  const { total, concluded } = unitTotals(cov.by_status);
  const grid = buildGrid(cov.units);
  const unit = picked ? cov.units.find((u) => u.coverage_id === picked) : undefined;
  const maxWave = cov.units.reduce((m, u) => Math.max(m, u.wave), 1);
  return (
    <div class="scroll">
      <section class="sec">
        <div class="bignum"><b>{concluded}</b><span class="muted"> / {total} 个单元已有结论</span><span class="grow" /><span class="muted small">{profileLabel(run.profile)}档 · {maxWave} 轮</span></div>
        <Meter value={concluded} max={total} />
        <div class="legend">
          {LEGEND.filter((st) => (cov.by_status[st] ?? 0) > 0).map((st) => (
            <span key={st}><i class={`cell ${CELL[st]}`} />{UNIT_LABEL[st]} {cov.by_status[st]}</span>
          ))}
        </div>
      </section>
      <section class="sec gridwrap">
        <table class="grid" aria-label="入口 × 攻击类别">
          <thead>
            <tr><th scope="col" class="corner">入口 × 攻击类别</th>{grid.cols.map((c) => <th scope="col" key={c.key} title={c.label}><span>{c.label}</span></th>)}</tr>
          </thead>
          <tbody>
            {grid.rows.map((r, ri) => (
              <tr key={r.key}>
                <th scope="row"><span class="ell">{r.label}</span><span class="tag ell">{r.ref}</span></th>
                {grid.cols.map((c, ci) => {
                  const cell = grid.cell(ri, ci);
                  if (!cell.unit) return <td key={c.key}><i class="cell na" aria-label="无单元" /></td>;
                  const u = cell.unit;
                  return (
                    <td key={c.key}>
                      <button type="button" class={`cell ${CELL[u.status]}${picked === u.coverage_id ? " sel" : ""}`} aria-label={`${r.label} × ${c.label}：${UNIT_LABEL[u.status]}`}
                        aria-pressed={picked === u.coverage_id} onClick={() => setPicked(picked === u.coverage_id ? null : u.coverage_id)} />
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      {unit ? <UnitDetail s={s} unit={unit} /> : <p class="muted pad small">点一个格子看谁审的、读了哪些文件、做了什么检查。</p>}
    </div>
  );
}
