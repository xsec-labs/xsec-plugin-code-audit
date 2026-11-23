# Code Audit sidecar: tool contract (v0.1.0)

`bin/code-audit-mcp` speaks MCP (2024-11-05, 2025-03-26, 2025-06-18) over stdio. Every result is a JSON object, also
returned as `structuredContent`. A failure sets `isError` and has `{"ok": false, "error": "...", "details": {...}}`.
Tools only read and write files under `PLUGIN_DATA`; none runs target code, and each finishes in milliseconds (the host
cuts a plugin call at 20 s). Arguments are strict: an unknown key is an error.

## Environment

| Variable | Meaning |
| --- | --- |
| `PLUGIN_DATA` | required; data root |
| `XSEC_PLUGIN_HOST_RPC_ENDPOINT` | loopback host RPC; when set, each call's `_meta["com.xsec.desktop/contextHandle"]` is traded for `{projectId, role}` with method `xsec.code-audit.context` (`params: {tool}`); a host without the method puts everything in project `default`. Unset: project `local`. |

## Layout

```text
PLUGIN_DATA/runs/<project>/<repo>/run-<N>/
  run-metadata.json  architecture.md  coverage-ledger.json  findings.json   (names match the Cloudflare skill)
  findings.ext.json  agents.json                                            (xSec additions)
  REPORT.md  FINDINGS-DETAIL.md  NEEDS-VALIDATION.md  exports/
PLUGIN_DATA/projects/<project>/state.json   per finding "<repo>:<fingerprint>": fix status, user decision, vuln id,
                                            first/last seen run (outlives runs)
```

`run_id` is `<repo>/run-<N>`; `<repo>` is the target's base name plus a short hash of its path (or the `repo` argument).

## Tools

`P` = parent only (refused for a sub-agent identity), `R` = read only (also offered to sub-agents).

| Tool | | Arguments | Result |
| --- | --- | --- | --- |
| `code_audit_run_start` | P | `target` (abs dir), `profile` quick/standard/deep, `scope` {mode repo/paths/diff, paths, base, head}, `budget`, `focus[]`, `source_ref` {commit, dirty}, `repo`, `companions[]` | `run_id`, `output_dir`, `prior_runs[]` (status, counts, has_ledger), `has_prior_ledger` |
| `code_audit_run_update` | P | `run_id`, `phase` recon/hunt/validate/output/verify/report, `status` in_progress/incomplete, `incomplete_reason` (required for incomplete), `budget`, `note` | `phase`, `run_status` |
| `code_audit_architecture_put` | P | `run_id`, `markdown` | `bytes` |
| `code_audit_agent_note` | P | `run_id`, `event` dispatched/returned/failed, `agent_id` (`^[a-z0-9][a-z0-9_-]{0,63}$`, fresh per delegation, no Windows device names), `role` recon/hunter/critic/verifier/record_verifier, `phase`, `unit_ids[]`, `summary` | `agent_calls`, `running`, `budget`, `remaining`. A dispatch past `budget` fails with `details.hint`. |
| `code_audit_ledger_put` | P | `run_id`, `units[]`, `mode` upsert (default) / replace, `remove[]` | `units`, `ids_derived`, `unit_status`. Validated with the ported coverage-ledger rules; on error nothing is written and `details.errors` has the validator messages. `coverage_id` is derived from `canonical_refs` when absent. Stored sorted. |
| `code_audit_findings_put` | P | `run_id`, `records[]`, `mode`, `remove[]` | `findings`, `stored_now`, verdict counts. Whole file validated with the ported findings validator; every trace/evidence `file`+`line` must exist in the target (symlinks may not leave it); snippets (±3 lines) and the file's sha256 are frozen in `findings.ext.json`. Nothing is written on error. Stored sorted by fingerprint. |
| `code_audit_finding_state_set` | P | `run_id`, `fingerprint`, `fix_status` proposed/fixed/still_present/cannot_determine/none, `fix_note`, `user_decision` confirmed_by_user/excluded_by_user/none, `user_note`, `vuln_id` ("" unlinks) | `state` |
| `code_audit_validate` | R | `run_id` | `ok`, `ledger` {units, errors[]}, `findings` {count, errors[]}, `warnings` {findings_not_linked_from_ledger[], open_units[]} |
| `code_audit_report_build` | P | `run_id`, `language` zh (default) / en, `summary` (Markdown) | writes the three reports; marks the run `complete` (an `incomplete` run stays incomplete). Refused while a validator fails, or while ledger units are planned/in_progress/candidate in a run not marked incomplete. |
| `code_audit_export` | P | `run_id`, `format` sarif/csv/markdown/json, `include_needs_validation` | `path` (under `exports/`), `records`, `bytes`. SARIF 2.1.0; CSV has a BOM and neutralises formula cells. |
| `code_audit_run_delete` | P | `run_id` | removes the run directory; per-finding state is kept |
| `code_audit_runs_list` | R | `repo`, `limit` | `runs[]` newest first: status, phase, counts, budget, agent_calls, agents_running |
| `code_audit_run_get` | R | `run_id`, `include_architecture`, `include_agents` | `run` (metadata), `files{}` presence, `agent_calls`, `agents_running[]`, `agent_events[]` (last 200) |
| `code_audit_coverage_get` | R | `run_id`, `status`, `coverage_id`, `summary_only`, `limit`, `offset` | `total`, `by_status`, `matching`, `units[]` |
| `code_audit_findings_list` | R | `run_id`, `verdict`, `severity`, `query`, `limit`, `offset` | `total`, `findings[]` rows (fingerprint, verdict, title, file, line, severity, confidence, `state`), `counts` |
| `code_audit_finding_get` | R | `run_id`, `fingerprint` | `record` (validated JSON), `ext.steps[]` (role, index, file, line, sha256, `snippet` {start_line, lines[]}), `state` |

Differences from the plan's draft table: `ledger_update` is folded into `ledger_put mode=upsert`; `finding_fix_status_set`
and `user_decision_set` are one tool, `code_audit_finding_state_set`; `code_audit_validate` was added (it replaces
`node validate-*.cjs`).

## Run metadata

`run-metadata.json` carries the fields the Cloudflare skill requires (`run_id`, `repo`, `target`, `source_ref`, `profile`,
`scope_paths`, `budget`, `execution_policy: "sandboxed-source-and-local-only"`, `selected_companion_files`,
`prior_run_paths`, `shared_file_owners`, `run_status`) plus `scope`, `phase`, `focus`, `notes`, `created_at`,
`updated_at`, `completed_at`, `incomplete_reason` and `counts` {confirmed, needs_validation, rejected, severity{},
units, unit_status{}}.

## Panel binding (for the frontend thread)

The manifest binds the read tools as frontend methods (`xsec.code-audit.runs.list`, `run.get`, `coverage.get`,
`findings.list`, `finding.get`, `validate`) and the two writes the panel may do itself (`finding.state.set`, `export`,
`run.delete`). Starting an audit is **not** a tool call from the panel: it sends a request into the conversation and the
session's Agent calls `code_audit_run_start` (plan §3.3). Poll `runs.list` / `run.get` every 2 s while a run is
`in_progress`; `run.get.agents_running` is the running list.
