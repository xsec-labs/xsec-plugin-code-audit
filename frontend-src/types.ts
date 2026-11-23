declare const __SKILL_REF__: string;
declare const __SKILL_REPO__: string;
declare const __SKILL_LICENSE__: string;
export const SKILL_REF = __SKILL_REF__;
export const SKILL_REPO = __SKILL_REPO__;
export const SKILL_LICENSE = __SKILL_LICENSE__;

export type Disposable = { dispose(): void };

export type PluginHost = {
  apiVersion: number;
  readonly context?: { readonly kind?: unknown } | null;
  request(method: string, params: unknown): Promise<unknown>;
  onContext(listener: (context: unknown) => void): Disposable;
  onTheme(listener: (theme: Record<string, string>) => void): Disposable;
  onData(stream: string, listener: (payload: ArrayBuffer) => void): Disposable;
};

export type WorkspaceToolContext = {
  kind: "workspace-tool";
  visible: boolean;
  workspace: { mode: "interactive" | "observe"; dock: "side" | "bottom"; canAddComposerReference: boolean };
};
export type SettingsContext = { kind: "settings-page" };
export type PluginContext = WorkspaceToolContext | SettingsContext;

// ---- sidecar data (docs/tool-contract.md) ----

export type Profile = "quick" | "standard" | "deep";
export type Phase = "recon" | "hunt" | "validate" | "output" | "verify" | "report";
export type RunStatus = "in_progress" | "complete" | "incomplete";
export type Verdict = "confirmed" | "needs_validation" | "rejected";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type FixStatus = "proposed" | "fixed" | "still_present" | "cannot_determine";
export type UserDecision = "confirmed_by_user" | "excluded_by_user";
export type UnitStatus = "planned" | "not_applicable" | "out_of_scope" | "in_progress" | "covered" | "candidate" | "blocked" | "deferred";

export type Scope = { mode: "repo" | "paths" | "diff"; paths?: string[]; base?: string; head?: string };

export type Counts = {
  confirmed: number;
  needs_validation: number;
  rejected: number;
  severity: Partial<Record<Severity, number>>;
  units: number;
  unit_status: Partial<Record<UnitStatus, number>>;
};

export type RunRow = {
  run_id: string;
  repo: string;
  target: string;
  profile: Profile;
  scope: Scope;
  status: RunStatus;
  incomplete_reason: string;
  phase: Phase;
  budget: number | null;
  source_ref: { commit?: string; dirty?: boolean };
  created_at: string;
  updated_at: string;
  completed_at: string;
  counts: Counts;
  agent_calls: number;
  agents_running: number;
};

export type AgentEvent = {
  at: string;
  event: "dispatched" | "returned" | "failed";
  agent_id: string;
  role: string;
  phase?: string;
  unit_ids?: string[];
  summary?: string;
};

export type RunDetail = {
  run: RunRow & { focus: string[]; notes?: string[] };
  files: Record<string, boolean>;
  output_dir: string;
  agent_calls: number;
  agents_running: AgentEvent[];
  agent_events: AgentEvent[];
};

export type LocalCheck = { agent_id: string; reviewed_paths: string[]; invariant: string; method: string; result: string };

export type LedgerUnit = {
  coverage_id: string;
  canonical_refs: { surface: string; boundary: string; subsystem: string; attack_class: string };
  surface: string;
  boundary: string;
  subsystem: string;
  attack_class: string;
  starting_paths: string[];
  prior_status?: string;
  wave: number;
  status: UnitStatus;
  agent_id: string | null;
  reviewed_paths: string[];
  local_checks: LocalCheck[];
  result_fingerprints: string[];
  unresolved: string[];
};

export type Coverage = { total: number; by_status: Partial<Record<UnitStatus, number>>; units: LedgerUnit[] };

export type FindingState = {
  fix_status?: FixStatus;
  fix_note?: string;
  user_decision?: UserDecision;
  user_note?: string;
  vuln_id?: string;
  first_seen_run?: string;
  last_seen_run?: string;
};

export type FindingRow = {
  fingerprint: string;
  verdict: Verdict;
  title: string;
  file: string;
  line: number;
  severity?: Severity;
  likelihood?: Severity;
  impact?: Severity;
  confidence?: string;
  state?: FindingState;
};

export type TraceStep = { kind: "entrypoint" | "propagation" | "sink"; file: string; line: number; scope: string; description: string };
export type EvidenceItem = { file: string; line: number; description: string };
export type Condition = { kind: string; description: string };
export type Scored = { score: string; reason: string };

export type FindingRecord = {
  verdict: Verdict;
  fingerprint: string;
  title: string;
  description: string;
  root_cause?: string;
  claimed_root_cause?: string;
  intended_behavior?: string;
  trace: TraceStep[];
  evidence: EvidenceItem[];
  conditions?: Condition[];
  execution?: { attacker_perspective: string; payloads: string[]; instructions: string[]; observed_result: string };
  remediation?: { strategy: string; code_changes?: { file_name: string; fixed_code: string }[] };
  severity?: { likelihood: Scored; impact: Scored; overall_severity: Severity };
  confidence?: Scored;
  blockers?: string[];
  validation_plan?: { local?: string; deployment?: string };
  reason?: string;
};

export type ExtStep = {
  role: "trace" | "evidence";
  index: number;
  file: string;
  line: number;
  snippet: { start_line: number; lines: string[]; truncated?: boolean };
};

export type FindingDetail = {
  record: FindingRecord;
  ext: { steps: ExtStep[]; cwe?: string[]; tags?: string[] } | null;
  state: FindingState | null;
};

export type ExportFormat = "sarif" | "csv" | "markdown" | "json";
export type ReportName = "REPORT.md" | "FINDINGS-DETAIL.md" | "NEEDS-VALIDATION.md" | "architecture.md";

export type Settings = {
  profile: Profile;
  budget: number;
  concurrency: number;
  excludes: string[];
  readSecurityMd: boolean;
};
