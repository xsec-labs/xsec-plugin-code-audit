import type {
  Coverage, ExportFormat, FindingDetail, FindingRow, FindingState, FixStatus, PluginHost, ReportName, RunDetail, RunRow, UserDecision,
} from "../types";

/** A sidecar failure: `isError` result, `{ok:false,error,details}` payload, or a host refusal. */
export class AuditError extends Error {
  readonly details: unknown;
  constructor(message: string, details?: unknown) {
    super(message);
    this.name = "AuditError";
    this.details = details;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validator messages the sidecar attaches to a refused write, for display under the error. */
export function errorLines(error: unknown): string[] {
  if (!(error instanceof AuditError) || !isObject(error.details)) return [];
  const errors = error.details.errors;
  return Array.isArray(errors) ? errors.filter((line): line is string => typeof line === "string").slice(0, 8) : [];
}

/** Unwrap an MCP CallToolResult into the sidecar's JSON object (structuredContent first, then the first text part). */
export function unwrap(raw: unknown): Record<string, unknown> {
  if (!isObject(raw)) throw new AuditError("代码审计服务返回了无法识别的结果");
  const content = Array.isArray(raw.content) ? raw.content : [];
  let text = "";
  for (const part of content) {
    if (isObject(part) && part.type === "text" && typeof part.text === "string") { text = part.text; break; }
  }
  let payload: unknown = isObject(raw.structuredContent) ? raw.structuredContent : undefined;
  if (payload === undefined && text) {
    try { payload = JSON.parse(text); } catch { payload = undefined; }
  }
  if (raw.isError === true || (isObject(payload) && payload.ok === false)) {
    const message = isObject(payload) && typeof payload.error === "string" ? payload.error : text || "代码审计服务返回错误";
    throw new AuditError(message, isObject(payload) ? payload.details : undefined);
  }
  if (!isObject(payload)) throw new AuditError("代码审计服务没有返回数据");
  return payload;
}

async function call(host: PluginHost, method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
  return unwrap(await host.request(`xsec.code-audit.${method}`, params));
}

function list<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

export async function listRuns(host: PluginHost, limit = 100): Promise<RunRow[]> {
  return list<RunRow>((await call(host, "runs.list", { limit })).runs);
}

export async function getRun(host: PluginHost, runId: string): Promise<RunDetail> {
  const out = await call(host, "run.get", { run_id: runId, include_agents: true });
  return out as unknown as RunDetail;
}

/** The whole ledger, paged: the sidecar returns at most 1000 units per call. */
export async function getCoverage(host: PluginHost, runId: string): Promise<Coverage> {
  const units: Coverage["units"] = [];
  let first: Record<string, unknown> | undefined;
  for (let offset = 0; offset < 10_000; offset += 1000) {
    const out = await call(host, "coverage.get", { run_id: runId, limit: 1000, offset });
    first ??= out;
    const page = list<Coverage["units"][number]>(out.units);
    units.push(...page);
    if (page.length < 1000 || units.length >= Number(out.matching ?? 0)) break;
  }
  return { total: Number(first?.total ?? 0), by_status: (first?.by_status ?? {}) as Coverage["by_status"], units };
}

export async function listFindings(host: PluginHost, runId: string): Promise<FindingRow[]> {
  const rows: FindingRow[] = [];
  for (let offset = 0; offset < 10_000; offset += 500) {
    const out = await call(host, "findings.list", { run_id: runId, limit: 500, offset });
    const page = list<FindingRow>(out.findings);
    rows.push(...page);
    if (page.length < 500 || rows.length >= Number(out.total ?? 0)) break;
  }
  return rows;
}

export async function getFinding(host: PluginHost, runId: string, fingerprint: string): Promise<FindingDetail> {
  const out = await call(host, "finding.get", { run_id: runId, fingerprint });
  return { record: out.record as FindingDetail["record"], ext: (out.ext ?? null) as FindingDetail["ext"], state: (out.state ?? null) as FindingDetail["state"] };
}

export async function readReport(host: PluginHost, runId: string, name: ReportName): Promise<{ markdown: string; truncated: boolean }> {
  const out = await call(host, "report.read", { run_id: runId, name });
  return { markdown: String(out.markdown ?? ""), truncated: out.truncated === true };
}

export type StatePatch = { fix_status?: FixStatus | "none"; fix_note?: string; user_decision?: UserDecision | "none"; user_note?: string };

export async function setFindingState(host: PluginHost, runId: string, fingerprint: string, patch: StatePatch): Promise<FindingState> {
  const out = await call(host, "finding.state.set", { run_id: runId, fingerprint, ...patch });
  return (out.state ?? {}) as FindingState;
}

export async function exportRun(host: PluginHost, runId: string, format: ExportFormat, includeNeedsValidation: boolean): Promise<{ path: string; records: number }> {
  const out = await call(host, "export", { run_id: runId, format, include_needs_validation: includeNeedsValidation });
  return { path: String(out.path ?? ""), records: Number(out.records ?? 0) };
}

export async function deleteRun(host: PluginHost, runId: string): Promise<void> {
  await call(host, "run.delete", { run_id: runId });
}

// ---- plugin settings (host-owned plugin config) ----

export async function readConfig(host: PluginHost, key: string): Promise<unknown> {
  const out = await host.request("xsec.plugin.config.get", { key });
  return isObject(out) ? out.value : undefined;
}

export async function writeConfig(host: PluginHost, key: string, value: unknown): Promise<void> {
  await host.request("xsec.plugin.config.set", { key, value });
}
