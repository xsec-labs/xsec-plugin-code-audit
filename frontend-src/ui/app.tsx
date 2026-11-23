import { useCallback, useEffect, useMemo, useRef, useState } from "preact/hooks";
import type { Coverage, FindingRow, PluginContext, PluginHost, ReportName, RunDetail, RunRow, Settings } from "../types";
import { getCoverage, getRun, listFindings, listRuns, readConfig, AuditError } from "../lib/api";
import { defaultRun, sortFindings } from "../lib/derive";
import { toConversation } from "../lib/host";
import { DEFAULT_SETTINGS, parseSettings } from "../lib/settings";
import type { Session, View } from "./session";
import { Empty, ErrorNote, Toast, useToast } from "./common";
import { Icon } from "./icons";
import { ProgressView } from "./progress";
import { FindingsView } from "./findings";
import { DetailBody, DetailView } from "./detail";
import { FindingRowItem } from "./progress";
import { CoverageView } from "./coverage";
import { ReportView } from "./report";
import { DocView } from "./docview";
import { StartView } from "./start";
import { SettingsPage, SETTINGS_KEY } from "./settings";

const FAST_POLL_MS = 2000;
const IDLE_POLL_MS = 15000;
const WIDE_PX = 880;

export function stampOf(run: RunRow | undefined): string {
  return run ? [run.updated_at, run.status, run.phase, run.agent_calls, run.agents_running, run.counts.confirmed, run.counts.needs_validation, run.counts.rejected].join("|") : "";
}

/** Poll only while something is running (or an audit was just requested) and the panel can be seen. */
export function pollDelay(runs: RunRow[], watching: boolean): number {
  return watching || runs.some((r) => r.status === "in_progress") ? FAST_POLL_MS : IDLE_POLL_MS;
}

function useWide(ref: { current: HTMLElement | null }): boolean {
  const [wide, setWide] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const apply = () => setWide(el.clientWidth >= WIDE_PX);
    apply();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(apply);
    observer.observe(el);
    return () => observer.disconnect();
  }, [ref]);
  return wide;
}

const TABS: { id: Exclude<View, "start">; label: string }[] = [
  { id: "progress", label: "进度" },
  { id: "findings", label: "发现" },
  { id: "coverage", label: "覆盖面" },
  { id: "report", label: "报告" },
];

export function WorkspaceApp({ host, context, visible }: { host: PluginHost; context: Extract<PluginContext, { kind: "workspace-tool" }>; visible: boolean }) {
  const rootRef = useRef<HTMLDivElement | null>(null);
  const wide = useWide(rootRef);
  const [toast, notify] = useToast();
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [runs, setRuns] = useState<RunRow[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [view, setView] = useState<View>("progress");
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [doc, setDoc] = useState<ReportName | null>(null);
  const [detail, setDetail] = useState<RunDetail | undefined>();
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [coverage, setCoverage] = useState<Coverage | undefined>();
  const [tick, setTick] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [watching, setWatching] = useState<{ until: number; known: Set<string> } | null>(null);
  const readOnly = context.workspace.mode === "observe";
  const watchingRef = useRef(watching);
  watchingRef.current = watching;

  const run = useMemo(() => runs?.find((r) => r.run_id === runId) ?? (runs ? defaultRun(runs) : undefined), [runs, runId]);
  const stamp = stampOf(run);
  const needsCoverage = view === "coverage" || fingerprint !== null;

  // Settings (defaults for the Start page).
  useEffect(() => {
    let live = true;
    readConfig(host, SETTINGS_KEY).then((v) => { if (live) setSettings(parseSettings(v)); }, () => undefined);
    return () => { live = false; };
  }, [host]);

  // Runs list: the heartbeat of the panel.
  useEffect(() => {
    if (!visible) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      let next: RunRow[] | null = null;
      try {
        next = await listRuns(host);
        if (!live) return;
        setRuns(next);
        setLoadError(null);
      } catch (e) {
        if (!live) return;
        setLoadError(e);
      }
      if (!live) return;
      setNow(Date.now());
      const w = watchingRef.current;
      timer = setTimeout(() => void load(), pollDelay(next ?? [], !!w && w.until > Date.now()));
    };
    void load();
    return () => { live = false; if (timer) clearTimeout(timer); };
  }, [host, visible, tick]);

  // A run created after the user asked for an audit becomes the selected one.
  useEffect(() => {
    if (!watching || !runs) return;
    const fresh = runs.find((r) => !watching.known.has(r.run_id));
    if (fresh) { setRunId(fresh.run_id); setView("progress"); setWatching(null); }
    else if (watching.until < Date.now()) setWatching(null);
  }, [runs, watching]);

  // First load: with no runs the panel opens on the Start page.
  const firstRuns = useRef(true);
  useEffect(() => {
    if (runs && firstRuns.current) {
      firstRuns.current = false;
      if (runs.length === 0) setView("start");
    }
  }, [runs]);

  const currentRunId = run?.run_id;
  useEffect(() => {
    if (!currentRunId) { setDetail(undefined); setFindings([]); setCoverage(undefined); return; }
    let live = true;
    getRun(host, currentRunId).then((d) => { if (live) setDetail(d); }, () => undefined);
    listFindings(host, currentRunId).then((f) => { if (live) setFindings(sortFindings(f)); }, () => undefined);
    return () => { live = false; };
  }, [host, currentRunId, stamp, tick]);

  useEffect(() => {
    if (!currentRunId || !needsCoverage) return;
    let live = true;
    getCoverage(host, currentRunId).then((c) => { if (live) setCoverage(c); }, () => undefined);
    return () => { live = false; };
  }, [host, currentRunId, needsCoverage, stamp, tick]);

  // Another run has another coverage ledger.
  useEffect(() => { setCoverage(undefined); }, [currentRunId]);

  const send = useCallback(async (text: string, done?: string) => {
    const result = await toConversation(host, text);
    if (result === "sent") notify(done ?? "已放进对话输入框");
    else if (result === "copied") notify("没法直接放进输入框，已复制到剪贴板，粘贴到对话里发送", "ok");
    else notify("无法复制，请在审计请求里手动选取", "err");
    return result;
  }, [host, notify]);

  const session: Session = {
    host, settings, readOnly, wide, runs: runs ?? [], run, detail, findings, coverage, now, notify, send,
    reload: () => setTick((t) => t + 1),
    selectRun: (id) => { setRunId(id); setFingerprint(null); setDoc(null); setView("progress"); },
    go: (v) => { setView(v); setFingerprint(null); setDoc(null); },
    openFinding: (fp) => { setFingerprint(fp); setDoc(null); },
    openDoc: (name) => { setDoc(name); setFingerprint(null); },
  };

  const startWatching = () => { setWatching({ until: Date.now() + 120_000, known: new Set((runs ?? []).map((r) => r.run_id)) }); setView("progress"); };

  let body;
  if (runs === null && loadError) {
    body = <div class="pad"><ErrorNote message={loadError instanceof AuditError ? loadError.message : loadError instanceof Error ? `代码审计服务暂不可用：${loadError.message}` : "代码审计服务暂不可用"} onRetry={() => setTick((t) => t + 1)} /></div>;
  } else if (runs === null) {
    body = <div class="pad muted">正在读取…</div>;
  } else if (view === "start" || !run) {
    body = <StartView s={session} onStarted={startWatching} />;
  } else if (doc) {
    body = <DocView s={session} name={doc} onBack={() => setDoc(null)} />;
  } else if (fingerprint && !wide) {
    body = <DetailView s={session} fingerprint={fingerprint} rows={findings} onBack={() => setFingerprint(null)} onSelect={setFingerprint} />;
  } else if (view === "progress") body = <ProgressView s={session} />;
  else if (view === "findings") body = <FindingsView s={session} />;
  else if (view === "coverage") body = <CoverageView s={session} />;
  else body = <ReportView s={session} />;

  // Wide: a finding opens as list | detail columns instead of replacing the panel.
  if (runs && run && view !== "start" && !doc && fingerprint && wide) {
    const row = findings.find((f) => f.fingerprint === fingerprint);
    body = (
      <div class="wide-detail">
        <div class="rail col">
          <div class="bar"><b>{findings.length} 条发现</b><span class="grow" /><button type="button" class="ib" aria-label="关闭详情" onClick={() => setFingerprint(null)}><Icon name="x" /></button></div>
          <div class="scroll">
            {findings.map((f) => (
              <div class={f.fingerprint === fingerprint ? "railsel" : ""} key={f.fingerprint}>
                <FindingRowItem row={f} rail onOpen={() => setFingerprint(f.fingerprint)} />
              </div>
            ))}
          </div>
        </div>
        <div class="scroll grow">{row ? <DetailBody s={session} row={row} runId={run.run_id} /> : <Empty title="没有找到这条发现" />}</div>
      </div>
    );
  }

  const inDetail = !!fingerprint || !!doc;
  return (
    <div class={`ca panel${wide ? " is-wide" : ""}`} ref={rootRef}>
      <header class="bar head">
        <Icon name="shield" /><b class="title">代码审计</b>
        {runs && run && runs.length > 1 && view !== "start" ? (
          <label class="inp sel runpick"><select value={run.run_id} onChange={(e) => session.selectRun((e.currentTarget as HTMLSelectElement).value)} aria-label="选择运行">
            {runs.map((r) => <option key={r.run_id} value={r.run_id}>{r.repo.replace(/-[0-9a-f]{6,}$/, "")} #{/(\d+)$/.exec(r.run_id)?.[1]}</option>)}
          </select><Icon name="chevronDown" /></label>
        ) : null}
        <span class="grow" />
        {runs && run && view !== "start" ? (
          <nav class="seg" aria-label="视图">
            {TABS.map((t) => (
              <button type="button" key={t.id} aria-pressed={!inDetail ? view === t.id : (t.id === "findings" && !!fingerprint) || (t.id === "report" && !!doc)} onClick={() => session.go(t.id)}>
                {t.label}{t.id === "findings" && findings.length ? ` ${findings.length}` : ""}
              </button>
            ))}
          </nav>
        ) : null}
        {runs && (run ? view !== "start" : false) ? (
          <button type="button" class="ib" aria-label="新建审计" title="新建审计" onClick={() => session.go("start")}><Icon name="plus" /></button>
        ) : null}
        {runs && run && view === "start" ? <button type="button" class="btn sm ghost" onClick={() => session.go("progress")}>历史运行 {runs.length}</button> : null}
      </header>
      {loadError && runs ? <div class="bar"><ErrorNote message="刷新失败，显示的是上一次的数据" onRetry={() => setTick((t) => t + 1)} /></div> : null}
      <div class="content">{body}</div>
      <Toast toast={toast} />
    </div>
  );
}

export function SettingsApp({ host }: { host: PluginHost }) {
  return <div class="ca page"><SettingsPage host={host} /></div>;
}
