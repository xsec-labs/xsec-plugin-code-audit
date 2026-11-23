package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/validate"
)

var (
	profiles = []string{"quick", "standard", "deep"}
	phases   = []string{"recon", "hunt", "validate", "output", "verify", "report"}
	revRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/~^@{}+-]{0,199}$`)
	commitRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	agentRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

const maxArchitectureBytes = 1 << 20

func runStart() *Tool {
	return &Tool{
		Name: "code_audit_run_start",
		Description: "Start a new source-code audit run and return its run_id plus a summary of earlier runs of the same repository. " +
			"Call this first. The target is only read; nothing in it is executed. Earlier runs are additive: read their ledger and findings before planning.",
		Schema:     schemaRunStart,
		ParentOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("target", "profile", "scope", "budget", "focus", "source_ref", "repo", "companions"); err != nil {
				return nil, err
			}
			target, err := c.str("target", true)
			if err != nil {
				return nil, err
			}
			target = filepath.Clean(target)
			if !filepath.IsAbs(target) {
				return nil, errf("target: must be an absolute directory path")
			}
			if st, err := os.Stat(target); err != nil || !st.IsDir() {
				return nil, errf("target: %s is not an accessible directory", target)
			}
			if rel, err := filepath.Rel(c.Env.Store.Root(), target); err == nil && !strings.HasPrefix(rel, "..") {
				return nil, errf("target: the audit data directory itself cannot be audited")
			}
			profile, err := c.enum("profile", false, profiles...)
			if err != nil {
				return nil, err
			}
			if profile == "" {
				profile = "standard"
			}
			scope, scopePaths, err := parseScope(c)
			if err != nil {
				return nil, err
			}
			var budget *int
			if b := c.Args.Get("budget"); b != nil && b.Kind != jsonv.Null {
				n, err := c.intArg("budget", 0, 1, 100000)
				if err != nil {
					return nil, err
				}
				budget = &n
			}
			focus, err := c.strList("focus", 20, 200)
			if err != nil {
				return nil, err
			}
			companions, err := c.strList("companions", 40, 200)
			if err != nil {
				return nil, err
			}
			var sref SourceRef
			if s := c.Args.Get("source_ref"); s != nil && s.Kind != jsonv.Null {
				if !s.IsObject() {
					return nil, errf("source_ref: expected an object {commit, dirty}")
				}
				if cm := s.Get("commit"); cm != nil && cm.Kind != jsonv.Null {
					if !cm.IsString() || !commitRe.MatchString(cm.S) {
						return nil, errf("source_ref.commit: expected a hex commit id")
					}
					sref.Commit = cm.S
				}
				if d := s.Get("dirty"); d != nil && d.Kind != jsonv.Null {
					if d.Kind != jsonv.Bool {
						return nil, errf("source_ref.dirty: expected a boolean")
					}
					sref.Dirty = d.B
				}
			}
			repo, err := c.str("repo", false)
			if err != nil {
				return nil, err
			}
			if repo == "" {
				repo = store.RepoSlug(target)
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			priors, err := priorRuns(c, repo)
			if err != nil {
				return nil, err
			}
			ref, err := c.Env.Store.NextRun(c.Identity.ProjectID, repo)
			if err != nil {
				return nil, errf("cannot create the run directory: %v", err)
			}
			meta := &Metadata{
				RunID: ref.ID(), Repo: repo, Target: target, SourceRef: sref, Profile: profile, ScopePaths: scopePaths,
				Scope: scope, Budget: budget, ExecutionPolicy: ExecutionPolicy, SelectedCompanions: orEmpty(companions),
				SharedFileOwners: map[string]string{
					"run-metadata.json": "parent", "architecture.md": "parent", "coverage-ledger.json": "parent",
					"findings.json": "parent", "REPORT.md": "parent", "FINDINGS-DETAIL.md": "parent", "NEEDS-VALIDATION.md": "parent",
				},
				RunStatus: StatusInProgress, Phase: "recon", Focus: orEmpty(focus), CreatedAt: c.now(),
				Counts: Counts{Severity: map[string]int{}, UnitStatus: map[string]int{}},
			}
			for _, p := range priors {
				meta.PriorRuns = append(meta.PriorRuns, p.RunID)
			}
			if meta.PriorRuns == nil {
				meta.PriorRuns = []string{}
			}
			if err := c.saveMeta(ref, meta); err != nil {
				return nil, errf("cannot write run metadata: %v", err)
			}
			return map[string]any{
				"ok": true, "run_id": ref.ID(), "repo": repo, "profile": profile, "scope": scope, "budget": budget,
				"output_dir": c.Env.Store.Dir(ref), "execution_policy": ExecutionPolicy,
				"prior_runs":       priors,
				"has_prior_ledger": hasPriorLedger(priors),
				"next":             "Write the architecture with code_audit_architecture_put, then the coverage ledger with code_audit_ledger_put. Prior runs can be read with code_audit_coverage_get and code_audit_findings_list (pass their run_id).",
			}, nil
		},
	}
}

type priorSummary struct {
	RunID     string `json:"run_id"`
	Status    string `json:"status"`
	Profile   string `json:"profile"`
	ScopeMode string `json:"scope_mode"`
	CreatedAt string `json:"created_at"`
	Commit    string `json:"source_commit,omitempty"`
	Counts    Counts `json:"counts"`
	HasLedger bool   `json:"has_ledger"`
}

func hasPriorLedger(p []priorSummary) bool {
	for _, x := range p {
		if x.HasLedger {
			return true
		}
	}
	return false
}

func priorRuns(c *Call, repo string) ([]priorSummary, error) {
	all, err := c.Env.Store.ListRuns(c.Identity.ProjectID)
	if err != nil {
		return nil, err
	}
	var out []priorSummary
	for _, r := range all {
		if r.Repo != repo {
			continue
		}
		m, err := c.loadMeta(r)
		if err != nil {
			continue
		}
		_, lerr := os.Stat(c.Env.Store.Path(r, store.FileLedger))
		out = append(out, priorSummary{RunID: r.ID(), Status: m.RunStatus, Profile: m.Profile, ScopeMode: m.Scope.Mode,
			CreatedAt: m.CreatedAt, Commit: m.SourceRef.Commit, Counts: m.Counts, HasLedger: lerr == nil})
		if len(out) >= 10 {
			break
		}
	}
	return out, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func parseScope(c *Call) (Scope, []string, error) {
	scope := Scope{Mode: "repo"}
	v := c.Args.Get("scope")
	if v == nil || v.Kind == jsonv.Null {
		return scope, []string{}, nil
	}
	if !v.IsObject() {
		return scope, nil, errf("scope: expected an object {mode, paths, base, head}")
	}
	for _, k := range v.Keys {
		if k != "mode" && k != "paths" && k != "base" && k != "head" {
			return scope, nil, errf("scope: unknown field %q", k)
		}
	}
	if m := v.Get("mode"); m != nil {
		if !m.IsString() || (m.S != "repo" && m.S != "paths" && m.S != "diff") {
			return scope, nil, errf("scope.mode: must be repo, paths or diff")
		}
		scope.Mode = m.S
	}
	switch scope.Mode {
	case "paths":
		p := v.Get("paths")
		if !p.IsArray() || len(p.A) == 0 || len(p.A) > 200 {
			return scope, nil, errf("scope.paths: 1 to 200 repository-relative paths are required for mode paths")
		}
		for i, e := range p.A {
			if !validate.IsSafeRelativeSourcePath(e) {
				return scope, nil, errf("scope.paths[%d]: must be a safe repository-relative path", i)
			}
			scope.Paths = append(scope.Paths, e.S)
		}
	case "diff":
		for name, dst := range map[string]*string{"base": &scope.Base, "head": &scope.Head} {
			s := v.Get(name)
			if !s.IsString() || !revRe.MatchString(s.S) {
				return scope, nil, errf("scope.%s: a git revision (branch, tag or commit) is required for mode diff", name)
			}
			*dst = s.S
		}
	}
	paths := scope.Paths
	if paths == nil {
		paths = []string{}
	}
	return scope, paths, nil
}

func runUpdate() *Tool {
	return &Tool{
		Name:        "code_audit_run_update",
		Description: "Update a run's phase or status. Use status=incomplete with incomplete_reason when the run must stop early. A run is marked complete only by code_audit_report_build.",
		Schema:      schemaRunUpdate,
		ParentOnly:  true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "phase", "status", "incomplete_reason", "budget", "note"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			phase, err := c.enum("phase", false, phases...)
			if err != nil {
				return nil, err
			}
			status, err := c.enum("status", false, StatusInProgress, StatusIncomplete)
			if err != nil {
				if s, _ := c.str("status", false); s == StatusComplete {
					return nil, errf("status: a run becomes complete only through code_audit_report_build")
				}
				return nil, err
			}
			reason, err := c.str("incomplete_reason", false)
			if err != nil {
				return nil, err
			}
			note, err := c.str("note", false)
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			if phase != "" {
				m.Phase = phase
			}
			if b := c.Args.Get("budget"); b != nil && b.Kind != jsonv.Null {
				n, err := c.intArg("budget", 0, 1, 100000)
				if err != nil {
					return nil, err
				}
				m.Budget = &n
			}
			switch status {
			case StatusIncomplete:
				if strings.TrimSpace(reason) == "" {
					return nil, errf("incomplete_reason: required when status is incomplete")
				}
				m.RunStatus, m.IncompleteReason = StatusIncomplete, reason
			case StatusInProgress:
				m.RunStatus, m.IncompleteReason = StatusInProgress, ""
			}
			if note != "" {
				if len(note) > 2000 {
					return nil, errf("note: at most 2000 bytes")
				}
				m.Notes = append(m.Notes, note)
				if len(m.Notes) > 50 {
					m.Notes = m.Notes[len(m.Notes)-50:]
				}
			}
			if err := c.saveMeta(ref, m); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "run_id": m.RunID, "phase": m.Phase, "run_status": m.RunStatus}, nil
		},
	}
}

func architecturePut() *Tool {
	return &Tool{
		Name:        "code_audit_architecture_put",
		Description: "Save the architecture and trust-boundary summary (Markdown) written during reconnaissance.",
		Schema:      schemaArchitecturePut,
		ParentOnly:  true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "markdown"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			md, err := c.str("markdown", true)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(md) == "" || len(md) > maxArchitectureBytes || !utf8.ValidString(md) {
				return nil, errf("markdown: expected non-empty text of at most %d bytes", maxArchitectureBytes)
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			if err := c.Env.Store.WriteRunFile(ref, store.FileArchitecture, []byte(md)); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "bytes": len(md)}, nil
		},
	}
}

func agentNote() *Tool {
	return &Tool{
		Name: "code_audit_agent_note",
		Description: "Record that a sub-agent was dispatched, returned or failed. The parent calls this for every delegation; the panel's " +
			"running-agents list and the run budget (agent invocations) come from it. A dispatch beyond the budget is refused.",
		Schema:     schemaAgentNote,
		ParentOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "event", "agent_id", "role", "phase", "unit_ids", "summary"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			event, err := c.enum("event", true, "dispatched", "returned", "failed")
			if err != nil {
				return nil, err
			}
			aid, err := c.str("agent_id", true)
			if err != nil {
				return nil, err
			}
			if !agentRe.MatchString(aid) || !validate.IsSafeAgentID(jsonv.Str(aid)) {
				return nil, errf("agent_id: must match ^[a-z0-9][a-z0-9_-]{0,63}$ and not be a Windows device name")
			}
			role, err := c.enum("role", true, "recon", "hunter", "critic", "verifier", "record_verifier")
			if err != nil {
				return nil, err
			}
			phase, err := c.enum("phase", false, phases...)
			if err != nil {
				return nil, err
			}
			units, err := c.strList("unit_ids", 200, 65536)
			if err != nil {
				return nil, err
			}
			summary, err := c.str("summary", false)
			if err != nil {
				return nil, err
			}
			if len(summary) > 2000 {
				return nil, errf("summary: at most 2000 bytes")
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			ag, err := c.loadAgents(ref)
			if err != nil {
				return nil, err
			}
			seen := false
			for _, e := range ag.Events {
				if e.AgentID == aid && e.Event == "dispatched" {
					seen = true
				}
			}
			switch event {
			case "dispatched":
				if seen {
					return nil, errf("agent_id %s was already dispatched; every delegation needs a fresh agent id", aid)
				}
				if m.Budget != nil && ag.dispatched()+1 > *m.Budget {
					return nil, errDetails("budget exhausted: no more agent invocations may be dispatched", map[string]any{
						"agent_calls": ag.dispatched(), "budget": *m.Budget,
						"hint": "Stop hunting. Validate what is pending if the budget allows, otherwise call code_audit_run_update with status=incomplete and an incomplete_reason such as validation_budget_exhausted.",
					})
				}
			default:
				if !seen {
					return nil, errf("agent_id %s was never dispatched", aid)
				}
			}
			ag.Events = append(ag.Events, AgentEvent{At: c.now(), Event: event, AgentID: aid, Role: role, Phase: phase, UnitIDs: units, Summary: summary})
			if err := c.saveAgents(ref, ag); err != nil {
				return nil, err
			}
			out := map[string]any{"ok": true, "agent_calls": ag.dispatched(), "running": len(ag.Running())}
			if m.Budget != nil {
				out["budget"] = *m.Budget
				out["remaining"] = *m.Budget - ag.dispatched()
			}
			return out, nil
		},
	}
}

// ---- reads ----

func runsList() *Tool {
	return &Tool{
		Name:        "code_audit_runs_list",
		Description: "List audit runs of this project, newest first, with status and finding counts. Optionally filter by repo.",
		Schema:      schemaRunsList,
		ReadOnly:    true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("repo", "limit"); err != nil {
				return nil, err
			}
			repo, err := c.str("repo", false)
			if err != nil {
				return nil, err
			}
			limit, err := c.intArg("limit", 50, 1, 500)
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			refs, err := c.Env.Store.ListRuns(c.Identity.ProjectID)
			if err != nil {
				return nil, err
			}
			var rows []*Metadata
			for _, r := range refs {
				if repo != "" && r.Repo != repo {
					continue
				}
				m, err := c.loadMeta(r)
				if err != nil {
					continue
				}
				rows = append(rows, m)
			}
			sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt > rows[j].CreatedAt })
			total := len(rows)
			if len(rows) > limit {
				rows = rows[:limit]
			}
			out := make([]map[string]any, 0, len(rows))
			for _, m := range rows {
				ref, _ := store.ParseRunID(c.Identity.ProjectID, m.RunID)
				row := map[string]any{
					"run_id": m.RunID, "repo": m.Repo, "target": m.Target, "profile": m.Profile, "scope": m.Scope,
					"status": m.RunStatus, "incomplete_reason": m.IncompleteReason, "phase": m.Phase, "budget": m.Budget,
					"source_ref": m.SourceRef, "created_at": m.CreatedAt, "updated_at": m.UpdatedAt, "completed_at": m.CompletedAt,
					"counts": m.Counts,
				}
				if ag, err := c.loadAgents(ref); err == nil {
					row["agent_calls"] = ag.dispatched()
					row["agents_running"] = len(ag.Running())
				}
				out = append(out, row)
			}
			return map[string]any{"ok": true, "total": total, "runs": out}, nil
		},
	}
}

func runGet() *Tool {
	return &Tool{
		Name:        "code_audit_run_get",
		Description: "Read one run: metadata, counts, agent activity and which files exist. Set include_architecture to also return the architecture Markdown.",
		Schema:      schemaRunGet,
		ReadOnly:    true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "include_architecture", "include_agents"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			withArch, err := c.boolean("include_architecture", false)
			if err != nil {
				return nil, err
			}
			withAgents, err := c.boolean("include_agents", true)
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			files := map[string]bool{}
			for _, n := range []string{store.FileArchitecture, store.FileLedger, store.FileFindings, store.FileReport, store.FileDetail, store.FileNeeds} {
				_, e := os.Stat(c.Env.Store.Path(ref, n))
				files[n] = e == nil
			}
			out := map[string]any{"ok": true, "run": m, "files": files, "output_dir": c.Env.Store.Dir(ref)}
			if withAgents {
				ag, err := c.loadAgents(ref)
				if err != nil {
					return nil, err
				}
				out["agent_calls"] = ag.dispatched()
				out["agents_running"] = ag.Running()
				if len(ag.Events) > 200 {
					out["agent_events"] = ag.Events[len(ag.Events)-200:]
				} else {
					out["agent_events"] = ag.Events
				}
			}
			if withArch {
				if raw, err := c.Env.Store.ReadFile(ref, store.FileArchitecture); err == nil {
					out["architecture"] = string(raw)
				}
			}
			return out, nil
		},
	}
}

func runDelete() *Tool {
	return &Tool{
		Name:        "code_audit_run_delete",
		Description: "Delete one run and its files. The per-finding state (fix status, user decisions) is kept.",
		Schema:      schemaRunOnly,
		ParentOnly:  true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			if err := c.Env.Store.RemoveRun(ref); err != nil {
				return nil, errf("cannot delete the run: %v", err)
			}
			return map[string]any{"ok": true, "deleted": ref.ID()}, nil
		},
	}
}

func jsonOf(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

var _ = fmt.Sprintf
