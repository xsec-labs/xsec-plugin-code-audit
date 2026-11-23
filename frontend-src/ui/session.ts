import type { Coverage, FindingRow, PluginHost, ReportName, RunDetail, RunRow, Settings } from "../types";

export type View = "progress" | "findings" | "coverage" | "report" | "start";

/** What every panel view needs; assembled once in App and passed down. */
export type Session = {
  host: PluginHost;
  settings: Settings;
  readOnly: boolean;
  wide: boolean;
  runs: RunRow[];
  run: RunRow | undefined;
  detail: RunDetail | undefined;
  findings: FindingRow[];
  coverage: Coverage | undefined;
  now: number;
  notify(text: string, tone?: "ok" | "err"): void;
  /** Send a request to the conversation. When the host cannot take it, the panel opens the request text to copy by hand. */
  send(text: string, doneText?: string): Promise<"sent" | "manual">;
  reload(): void;
  selectRun(runId: string): void;
  go(view: View): void;
  openFinding(fingerprint: string): void;
  openDoc(name: ReportName): void;
};
