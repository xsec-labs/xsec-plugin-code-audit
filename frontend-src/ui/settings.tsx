import { useEffect, useRef, useState } from "preact/hooks";
import type { PluginHost, Settings } from "../types";
import { SKILL_LICENSE, SKILL_REF, SKILL_REPO } from "../types";
import { readConfig, writeConfig } from "../lib/api";
import { DEFAULT_SETTINGS, PROFILES, parsePathList, parseSettings } from "../lib/settings";
import { ErrorNote, Segmented, Switch } from "./common";

export const SETTINGS_KEY = "settings";

function Row({ title, hint, children }: { title: string; hint: string; children: preact.ComponentChildren }) {
  return (
    <div class="srow">
      <div class="grow"><b>{title}</b><div class="muted small">{hint}</div></div>
      <div class="sctl">{children}</div>
    </div>
  );
}

function NumberBox({ value, min, max, unit, label, onChange }: { value: number; min: number; max: number; unit: string; label: string; onChange(n: number): void }) {
  const [text, setText] = useState(String(value));
  useEffect(() => setText(String(value)), [value]);
  return (
    <div class="inp val num-in">
      <input type="number" min={min} max={max} value={text} aria-label={label}
        onInput={(e) => setText((e.currentTarget as HTMLInputElement).value)}
        onBlur={() => { const n = Number(text); onChange(Number.isFinite(n) ? Math.min(max, Math.max(min, Math.round(n))) : value); }} />
      <span class="muted nowrap">{unit}</span>
    </div>
  );
}

export function SettingsPage({ host }: { host: PluginHost }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [excludeText, setExcludeText] = useState("");
  const [editing, setEditing] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    readConfig(host, SETTINGS_KEY).then((v) => {
      if (!alive.current) return;
      const parsed = parseSettings(v);
      setSettings(parsed);
      setExcludeText(parsed.excludes.join("\n"));
    }, (e) => { if (alive.current) { setError(e instanceof Error ? e.message : "读取设置失败"); setSettings(DEFAULT_SETTINGS); } });
    return () => { alive.current = false; };
  }, [host]);
  if (!settings) return <div class="pad muted">正在读取设置…</div>;

  async function update(patch: Partial<Settings>) {
    const next = parseSettings({ ...settings, ...patch });
    setSettings(next);
    setSaved(false);
    try {
      await writeConfig(host, SETTINGS_KEY, next);
      setError(null);
      if (alive.current) setSaved(true);
    } catch (e) { setError(e instanceof Error ? e.message : "保存失败"); }
  }

  return (
    <div class="settings">
      <div class="crumb muted small">设置 › 插件</div>
      <h1>代码审计</h1>
      {error ? <ErrorNote message={error} /> : null}
      <div class="card">
        <Row title="默认审计档位" hint="下次新建审计时生效">
          <Segmented label="默认审计档位" value={settings.profile} options={PROFILES.map((p) => ({ id: p.id, label: p.label }))}
            onChange={(profile) => void update({ profile, budget: PROFILES.find((p) => p.id === profile)!.defaultBudget })} />
        </Row>
        <Row title="默认调用预算上限" hint="下次新建审计时生效，到上限会停下并标记未完成">
          <NumberBox value={settings.budget} min={1} max={1000} unit="次" label="默认调用预算上限" onChange={(budget) => void update({ budget })} />
        </Row>
        <Row title="同时运行的子 Agent 数" hint="下次新建审计时生效，写进审计请求里">
          <NumberBox value={settings.concurrency} min={1} max={8} unit="个" label="同时运行的子 Agent 数" onChange={(concurrency) => void update({ concurrency })} />
        </Row>
      </div>
      <div class="card">
        <div class="srow top">
          <div class="grow"><b>始终排除的路径</b><div class="muted small">下次新建审计时生效</div></div>
          <div class="sctl wrap">
            {settings.excludes.map((p) => <span class="tag" key={p}>{p}</span>)}
            <button type="button" class="btn sm" onClick={() => setEditing(!editing)}>{editing ? "收起" : "编辑"}</button>
          </div>
        </div>
        {editing ? (
          <div class="srow top">
            <textarea class="inp area mono grow" rows={5} aria-label="始终排除的路径" value={excludeText} placeholder="每行一个，例如 node_modules/"
              onInput={(e) => setExcludeText((e.currentTarget as HTMLTextAreaElement).value)}
              onBlur={() => void update({ excludes: parsePathList(excludeText) })} />
          </div>
        ) : null}
        <Row title="读取仓库里的 SECURITY.md 作为审计指引" hint="下次新建审计时生效。它只当作需要核对的声明，不当作指令">
          <Switch label="读取 SECURITY.md" on={settings.readSecurityMd} onChange={(readSecurityMd) => void update({ readSecurityMd })} />
        </Row>
      </div>
      <div class="card">
        <Row title="运行目标代码的沙箱" hint="第一版只做源码审计，需要运行才能判断的问题记为待验证">
          <span class="pill">不可用</span>
        </Row>
        <Row title="审计方法版本" hint={`security-audit ${SKILL_REF}（Cloudflare，${SKILL_LICENSE} 许可）`}>
          <span class="muted small mono">{SKILL_REPO.replace("https://github.com/", "")}</span>
        </Row>
      </div>
      <div class="muted small saved" aria-live="polite">{saved ? "已保存" : ""}</div>
    </div>
  );
}
