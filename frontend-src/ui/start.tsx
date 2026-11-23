import { useEffect, useState } from "preact/hooks";
import type { Session } from "./session";
import type { Profile, Scope } from "../types";
import { PROFILES, parsePathList } from "../lib/settings";
import { FOCUS_AREAS, startRequest, type StartForm } from "../lib/request";
import { pickDirectory } from "../lib/host";
import { Segmented, Switch } from "./common";
import { Icon } from "./icons";

const SCOPES: { id: Scope["mode"]; label: string }[] = [
  { id: "repo", label: "整个仓库" },
  { id: "paths", label: "指定路径" },
  { id: "diff", label: "代码变更" },
];

export function StartView({ s, onStarted }: { s: Session; onStarted(): void }) {
  const recent = [...new Set(s.runs.map((r) => r.target))].slice(0, 4);
  const [form, setForm] = useState<StartForm>(() => ({
    target: recent[0] ?? "",
    scope: "repo",
    paths: [],
    base: "",
    head: "HEAD",
    profile: s.settings.profile,
    budget: s.settings.budget,
    focus: [],
    continuePrior: true,
  }));
  const [pathsText, setPathsText] = useState("");
  const [allFocus, setAllFocus] = useState(false);
  const set = (patch: Partial<StartForm>) => setForm((f) => ({ ...f, ...patch }));
  // The settings page may load after this view mounts; fill the defaults once when they arrive and the user has not touched them.
  useEffect(() => { setForm((f) => ({ ...f, profile: s.settings.profile, budget: s.settings.budget })); }, [s.settings.profile, s.settings.budget]);

  const target = form.target.trim();
  const hasPrior = s.runs.some((r) => (target ? r.target === target : true));
  const profile = PROFILES.find((p) => p.id === form.profile)!;
  const full: StartForm = { ...form, paths: parsePathList(pathsText) };
  const problem =
    form.scope === "paths" && full.paths.length === 0 ? "填写要审的路径"
    : form.scope === "diff" && !form.base.trim() ? "填写对比的起点（提交或分支）"
    : target && !/^(\/|[A-Za-z]:[\\/])/.test(target) ? "目录需要是绝对路径"
    : "";
  const visibleFocus = allFocus ? FOCUS_AREAS : FOCUS_AREAS.slice(0, 5);

  async function choose() {
    const result = await pickDirectory(s.host, "选择要审计的目录");
    if (result.kind === "picked") set({ target: result.path });
    else if (result.kind === "unsupported") s.notify(result.reason ? `不能打开目录选择：${result.reason}` : "这个版本的 Desktop 还不能选择目录，请直接填写路径", "err");
  }

  async function start() {
    const text = startRequest(full, s.settings, hasPrior);
    const result = await s.send(text, "已把审计请求放进对话输入框，发送后 Agent 就会开始");
    if (result === "sent") onStarted();
  }

  return (
    <div class="col">
      <div class="scroll pad form">
        <div class="field">
          <label class="label" for="ca-target">审计目标</label>
          <div class="inp val"><Icon name="folder" /><input id="ca-target" class="mono" value={form.target} placeholder="留空则审计当前会话的项目目录" onInput={(e) => set({ target: (e.currentTarget as HTMLInputElement).value })} spellcheck={false} /><button type="button" class="btn sm ghost" onClick={() => void choose()} disabled={s.readOnly}>选择…</button></div>
          {recent.length > 1 ? (
            <div class="chips tight">{recent.map((t) => <button type="button" key={t} class={`chip${t === form.target ? " on" : ""}`} onClick={() => set({ target: t })}>{t.split(/[\\/]/).filter(Boolean).slice(-2).join("/")}</button>)}</div>
          ) : null}
        </div>
        <div class="field">
          <span class="label">范围</span>
          <Segmented label="范围" value={form.scope} options={SCOPES} onChange={(scope) => set({ scope })} />
          {form.scope === "paths" ? <textarea class="inp area mono" rows={3} placeholder="每行一个仓库内的相对路径，例如 internal/store" value={pathsText} onInput={(e) => setPathsText((e.currentTarget as HTMLTextAreaElement).value)} /> : null}
          {form.scope === "diff" ? (
            <div class="two">
              <div class="inp val"><input class="mono" value={form.base} placeholder="起点（提交或分支）" onInput={(e) => set({ base: (e.currentTarget as HTMLInputElement).value })} spellcheck={false} aria-label="起点" /></div>
              <div class="inp val"><input class="mono" value={form.head} placeholder="终点，默认 HEAD" onInput={(e) => set({ head: (e.currentTarget as HTMLInputElement).value })} spellcheck={false} aria-label="终点" /></div>
            </div>
          ) : null}
        </div>
        <div class="field">
          <span class="label">审计档位</span>
          <div class="opts" role="radiogroup" aria-label="审计档位">
            {PROFILES.map((p) => (
              <button type="button" role="radio" aria-checked={p.id === form.profile} key={p.id} class={`opt${p.id === form.profile ? " on" : ""}`}
                onClick={() => set({ profile: p.id as Profile, budget: p.defaultBudget })}>
                <b>{p.label}</b><span>{p.summary}</span><span>{p.calls}</span>
              </button>
            ))}
          </div>
        </div>
        <div class="field">
          <span class="label">重点方向 <span class="muted">侦察后自动选择，可在这里先指定</span></span>
          <div class="chips tight">
            <button type="button" class={`chip${form.focus.length === 0 ? " on" : ""}`} onClick={() => set({ focus: [] })}>自动</button>
            {visibleFocus.map((f) => (
              <button type="button" key={f.id} class={`chip${form.focus.includes(f.id) ? " on" : ""}`} aria-pressed={form.focus.includes(f.id)}
                onClick={() => set({ focus: form.focus.includes(f.id) ? form.focus.filter((x) => x !== f.id) : [...form.focus, f.id] })}>{f.label}</button>
            ))}
            {!allFocus ? <button type="button" class="chip" onClick={() => setAllFocus(true)}>+{FOCUS_AREAS.length - visibleFocus.length}</button> : null}
          </div>
        </div>
        <div class="field half">
          <label class="label" for="ca-budget">调用预算上限</label>
          <div class="inp val"><input id="ca-budget" type="number" min={1} max={1000} value={form.budget} onInput={(e) => { const n = Number((e.currentTarget as HTMLInputElement).value); if (Number.isFinite(n) && n > 0) set({ budget: Math.min(1000, Math.round(n)) }); }} /><span class="muted nowrap">次 Agent 调用</span></div>
        </div>
        <div class="switches">
          <label class="swrow"><Switch label="沿用上次运行的结论" on={form.continuePrior && hasPrior} disabled={!hasPrior} onChange={(v) => set({ continuePrior: v })} /><span>沿用上次运行的结论，只补未覆盖和有改动的部分{hasPrior ? "" : <span class="muted"> 还没有上次的运行</span>}</span></label>
          <label class="swrow"><Switch label="在沙箱里运行目标代码" on={false} disabled onChange={() => undefined} /><span>允许在沙箱里运行目标代码做验证 <span class="muted">第一版只读源码</span></span></label>
        </div>
      </div>
      <div class="foot">
        <span class="muted small grow">{problem || `预计 ${profile.calls.replace("约 ", "")}，不运行目标代码`}</span>
        <button type="button" class="btn pri" disabled={s.readOnly || !!problem} onClick={() => void start()}><Icon name="play" />开始审计</button>
      </div>
    </div>
  );
}
