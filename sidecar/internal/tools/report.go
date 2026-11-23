package tools

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/validate"
)

// unresolvedStatuses are ledger states that a complete run may not end in.
var unresolvedStatuses = map[string]bool{"planned": true, "in_progress": true, "candidate": true}

// checkAll runs both validators over the stored documents and adds the cross-checks.
func (c *Call) checkAll(ref store.RunRef) (map[string]any, bool, error) {
	led, ledExists, err := c.loadLedger(ref)
	if err != nil {
		return nil, false, err
	}
	fnd, fndExists, err := c.loadFindings(ref)
	if err != nil {
		return nil, false, err
	}
	ledErrs := []string{}
	if ledExists {
		ledErrs = append(ledErrs, validate.ValidateLedger(led)...)
	} else {
		ledErrs = append(ledErrs, "coverage-ledger.json does not exist: store it with code_audit_ledger_put")
	}
	fndErrs := []string{}
	if fndExists {
		e, err := validate.ValidateFindings(fnd)
		if err != nil {
			return nil, false, err
		}
		fndErrs = append(fndErrs, e...)
	}
	// Cross checks (warnings): a finding should be linked from a ledger unit, and a complete run has no open unit.
	linked := map[string]bool{}
	open := []string{}
	for _, u := range led.A {
		for _, fp := range u.Field("result_fingerprints").A {
			linked[fp.S] = true
		}
		if unresolvedStatuses[u.Field("status").S] {
			open = append(open, u.Field("coverage_id").S)
		}
	}
	unlinked := []string{}
	for _, f := range fnd.A {
		if fp := f.Field("fingerprint").S; fp != "" && !linked[fp] {
			unlinked = append(unlinked, fp)
		}
	}
	ok := len(ledErrs) == 0 && len(fndErrs) == 0
	return map[string]any{
		"ok":       ok,
		"ledger":   map[string]any{"exists": ledExists, "units": len(led.A), "errors": ledErrs},
		"findings": map[string]any{"exists": fndExists, "count": len(fnd.A), "errors": fndErrs},
		"warnings": map[string]any{"findings_not_linked_from_ledger": unlinked, "open_units": open},
	}, ok, nil
}

func validateTool() *Tool {
	return &Tool{
		Name: "code_audit_validate",
		Description: "Run both validators (findings and coverage ledger, the skill's own rules ported to Go with identical messages) over a run's stored files and report " +
			"every error plus cross-check warnings. Use it instead of `node validate-*.cjs`.",
		Schema:   schemaRunOnly,
		ReadOnly: true,
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
			out, _, err := c.checkAll(ref)
			return out, err
		},
	}
}

type labels struct {
	title, profile, scope, budget, source, policy, prior, partial, incomplete, posture, confirmed, table, severity, name, location, result,
	needs, hardening, coverage, units, none, detail, trace, evidence, conditions, repro, fix, blocker, plan, leads, agents, unresolved, reason string
}

var langZH = labels{
	title: "代码审计报告", profile: "审计档位", scope: "范围", budget: "预算（子代理调用）", source: "源码版本", policy: "执行策略", prior: "沿用的历史运行",
	partial: "这是一次部分审计（quick、限定范围、预算受限或未完成），不能据此声称没有其他问题。", incomplete: "本次运行未完成", posture: "安全态势概述",
	confirmed: "已确认的漏洞", table: "漏洞汇总", severity: "严重度", name: "标题", location: "位置", result: "观察到的结果", needs: "待验证线索",
	hardening: "加固建议与已有良好实践", coverage: "覆盖情况", units: "覆盖单元", none: "无", detail: "漏洞详情", trace: "调用链", evidence: "证据",
	conditions: "利用条件", repro: "复现（仅源码与本地）", fix: "修复建议", blocker: "阻塞原因", plan: "验证计划", leads: "待验证记录", agents: "子代理调用",
	unresolved: "未决覆盖单元", reason: "原因",
}

var langEN = labels{
	title: "Code audit report", profile: "Profile", scope: "Scope", budget: "Budget (sub-agent calls)", source: "Source ref", policy: "Execution policy", prior: "Prior runs used",
	partial: "This is a partial pass (quick, scoped, budget-limited or incomplete); it does not show that nothing else is wrong.", incomplete: "This run is incomplete", posture: "Security posture",
	confirmed: "Confirmed findings", table: "Summary", severity: "Severity", name: "Title", location: "Location", result: "Observed result", needs: "Needs validation",
	hardening: "Hardening notes and positive patterns", coverage: "Coverage", units: "Coverage units", none: "None", detail: "Finding detail", trace: "Trace", evidence: "Evidence",
	conditions: "Conditions", repro: "Reproduction (source and local only)", fix: "Remediation", blocker: "Blockers", plan: "Validation plan", leads: "Leads", agents: "Sub-agent calls",
	unresolved: "Unresolved coverage units", reason: "Reason",
}

func labelsFor(lang string) labels {
	if lang == "en" {
		return langEN
	}
	return langZH
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

func cell(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	if r := []rune(s); len(r) > 240 {
		s = string(r[:240]) + "…"
	}
	return s
}

func loc(e *jsonv.Value) string {
	if !e.IsObject() {
		return ""
	}
	return fmt.Sprintf("%s:%d", e.Field("file").S, int(e.Field("line").N))
}

func listOf(arr []*jsonv.Value, f func(*jsonv.Value) string) []string {
	var out []string
	for _, e := range arr {
		out = append(out, f(e))
	}
	return out
}

func sortedRecords(fnd *jsonv.Value, verdict string) []*jsonv.Value {
	var rs []*jsonv.Value
	for _, f := range fnd.A {
		if f.Field("verdict").S == verdict {
			rs = append(rs, f)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := severityRank[rs[i].Field("severity").Field("overall_severity").S], severityRank[rs[j].Field("severity").Field("overall_severity").S]
		return a < b
	})
	return rs
}

type reportInput struct {
	meta    *Metadata
	agents  *Agents
	ledger  *jsonv.Value
	records *jsonv.Value
	summary string
	lang    string
}

func buildReport(in reportInput) (report, detail, needs string) {
	L := labelsFor(in.lang)
	m := in.meta
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", L.title)
	fmt.Fprintf(&b, "- %s: `%s`\n- %s: `%s`\n- %s: %s\n", "Run", m.RunID, L.profile, m.Profile, L.scope, scopeText(m.Scope))
	if m.Budget != nil {
		fmt.Fprintf(&b, "- %s: %d / %d\n", L.budget, in.agents.dispatched(), *m.Budget)
	} else {
		fmt.Fprintf(&b, "- %s: %d\n", L.agents, in.agents.dispatched())
	}
	src := "-"
	if m.SourceRef.Commit != "" {
		src = m.SourceRef.Commit
		if m.SourceRef.Dirty {
			src += " (dirty)"
		}
	}
	fmt.Fprintf(&b, "- %s: %s\n- %s: `%s`\n", L.source, src, L.policy, m.ExecutionPolicy)
	if len(m.PriorRuns) > 0 {
		fmt.Fprintf(&b, "- %s: %s\n", L.prior, strings.Join(m.PriorRuns, ", "))
	}
	if m.RunStatus == StatusIncomplete {
		fmt.Fprintf(&b, "\n> **%s**: %s\n", L.incomplete, m.IncompleteReason)
	}
	if m.Profile == "quick" || m.Scope.Mode != "repo" || m.Budget != nil || m.RunStatus == StatusIncomplete {
		fmt.Fprintf(&b, "\n> %s\n", L.partial)
	}
	if s := strings.TrimSpace(in.summary); s != "" {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", L.posture, s)
	}
	confirmed := sortedRecords(in.records, "confirmed")
	fmt.Fprintf(&b, "\n## %s (%d)\n\n", L.confirmed, len(confirmed))
	if len(confirmed) == 0 {
		fmt.Fprintf(&b, "%s\n", L.none)
	} else {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n|---|---|---|---|\n", L.severity, L.name, L.location, L.result)
		for _, f := range confirmed {
			file, line := firstLocation(f)
			fmt.Fprintf(&b, "| %s | %s | `%s:%d` | %s |\n", f.Field("severity").Field("overall_severity").S, cell(f.Field("title").S), file, line,
				cell(f.Field("execution").Field("observed_result").S))
		}
		for _, f := range confirmed {
			fmt.Fprintf(&b, "\n### %s — %s\n\n`%s`\n\n%s\n", strings.ToUpper(f.Field("severity").Field("overall_severity").S), f.Field("title").S, f.Field("fingerprint").S, f.Field("description").S)
			fmt.Fprintf(&b, "\n**%s**\n\n%s\n", L.fix, f.Field("remediation").Field("strategy").S)
		}
	}
	nv := sortedRecords(in.records, "needs_validation")
	fmt.Fprintf(&b, "\n## %s (%d)\n\n", L.needs, len(nv))
	if len(nv) == 0 {
		fmt.Fprintf(&b, "%s\n", L.none)
	} else {
		fmt.Fprintf(&b, "| %s | %s | %s |\n|---|---|---|\n", L.name, L.location, L.blocker)
		for _, f := range nv {
			file, line := firstLocation(f)
			fmt.Fprintf(&b, "| %s | `%s:%d` | %s |\n", cell(f.Field("title").S), file, line, cell(strings.Join(listOf(f.Field("blockers").A, func(e *jsonv.Value) string { return blockerText(e) }), "; ")))
		}
	}
	fmt.Fprintf(&b, "\n## %s\n\n", L.coverage)
	status := map[string]int{}
	var open []string
	for _, u := range in.ledger.A {
		s := u.Field("status").S
		status[s]++
		if unresolvedStatuses[s] || s == "blocked" || s == "deferred" {
			open = append(open, fmt.Sprintf("`%s` (%s)", u.Field("coverage_id").S, s))
		}
	}
	fmt.Fprintf(&b, "%s: %d\n\n", L.units, len(in.ledger.A))
	keys := make([]string, 0, len(status))
	for k := range status {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- %s: %d\n", k, status[k])
	}
	if len(open) > 0 {
		fmt.Fprintf(&b, "\n**%s**\n\n", L.unresolved)
		for _, o := range open {
			fmt.Fprintf(&b, "- %s\n", o)
		}
	}
	report = b.String()

	var d strings.Builder
	fmt.Fprintf(&d, "# %s\n", L.detail)
	any := false
	for _, f := range confirmed {
		if sv := f.Field("severity").Field("overall_severity").S; sv != "medium" && sv != "high" && sv != "critical" {
			continue
		}
		any = true
		fmt.Fprintf(&d, "\n## %s\n\n`%s` · %s\n\n%s\n\n", f.Field("title").S, f.Field("fingerprint").S, f.Field("severity").Field("overall_severity").S, f.Field("description").S)
		fmt.Fprintf(&d, "**Root cause.** %s\n\n**Intended behavior.** %s\n\n", f.Field("root_cause").S, f.Field("intended_behavior").S)
		fmt.Fprintf(&d, "### %s\n\n", L.trace)
		for i, e := range f.Field("trace").A {
			fmt.Fprintf(&d, "%d. **%s** `%s` — %s: %s\n", i+1, e.Field("kind").S, loc(e), e.Field("scope").S, e.Field("description").S)
		}
		fmt.Fprintf(&d, "\n### %s\n\n", L.evidence)
		for _, e := range f.Field("evidence").A {
			fmt.Fprintf(&d, "- `%s` — %s\n", loc(e), e.Field("description").S)
		}
		if cs := f.Field("conditions").A; len(cs) > 0 {
			fmt.Fprintf(&d, "\n### %s\n\n", L.conditions)
			for _, e := range cs {
				fmt.Fprintf(&d, "- %s: %s\n", e.Field("kind").S, e.Field("description").S)
			}
		}
		ex := f.Field("execution")
		fmt.Fprintf(&d, "\n### %s\n\n%s\n\n", L.repro, ex.Field("attacker_perspective").S)
		for i, s := range ex.Field("instructions").A {
			fmt.Fprintf(&d, "%d. %s\n", i+1, s.S)
		}
		for _, p := range ex.Field("payloads").A {
			fmt.Fprintf(&d, "\n```\n%s\n```\n", p.S)
		}
		fmt.Fprintf(&d, "\n%s\n", ex.Field("observed_result").S)
		fmt.Fprintf(&d, "\n### %s\n\n%s\n", L.fix, f.Field("remediation").Field("strategy").S)
		for _, ch := range f.Field("remediation").Field("code_changes").A {
			fmt.Fprintf(&d, "\n`%s`\n\n```\n%s\n```\n", ch.Field("file_name").S, ch.Field("fixed_code").S)
		}
	}
	if !any {
		fmt.Fprintf(&d, "\n%s\n", L.none)
	}
	detail = d.String()

	var n strings.Builder
	fmt.Fprintf(&n, "# %s\n", L.leads)
	if len(nv) == 0 {
		fmt.Fprintf(&n, "\n%s\n", L.none)
	}
	for _, f := range nv {
		fmt.Fprintf(&n, "\n## %s\n\n`%s`\n\n%s\n\n**%s**\n\n", f.Field("title").S, f.Field("fingerprint").S, f.Field("description").S, L.trace)
		for i, e := range f.Field("trace").A {
			fmt.Fprintf(&n, "%d. **%s** `%s` — %s: %s\n", i+1, e.Field("kind").S, loc(e), e.Field("scope").S, e.Field("description").S)
		}
		fmt.Fprintf(&n, "\n**%s**\n\n", L.evidence)
		for _, e := range f.Field("evidence").A {
			fmt.Fprintf(&n, "- `%s` — %s\n", loc(e), e.Field("description").S)
		}
		fmt.Fprintf(&n, "\n**%s**\n\n", L.blocker)
		for _, e := range f.Field("blockers").A {
			fmt.Fprintf(&n, "- %s\n", blockerText(e))
		}
		fmt.Fprintf(&n, "\n**%s**\n\n", L.plan)
		vp := f.Field("validation_plan")
		for _, k := range []string{"local", "deployment"} {
			if v := vp.Field(k); v.IsString() {
				fmt.Fprintf(&n, "- %s: %s\n", k, v.S)
			}
		}
	}
	needs = n.String()
	return
}

// blockerText renders a blocker or plan entry whatever shape the schema gives it (string or object).
func blockerText(e *jsonv.Value) string {
	if e.IsString() {
		return e.S
	}
	if e.IsObject() {
		var parts []string
		for _, k := range e.Keys {
			if v := e.Field(k); v.IsString() {
				parts = append(parts, k+": "+v.S)
			}
		}
		return strings.Join(parts, "; ")
	}
	return ""
}

func scopeText(s Scope) string {
	switch s.Mode {
	case "paths":
		return "paths: " + strings.Join(s.Paths, ", ")
	case "diff":
		return fmt.Sprintf("diff %s..%s", s.Base, s.Head)
	}
	return "repo"
}

func reportBuild() *Tool {
	return &Tool{
		Name: "code_audit_report_build",
		Description: "Finish a run: re-validate both files, write REPORT.md, FINDINGS-DETAIL.md and NEEDS-VALIDATION.md deterministically from the stored records and ledger, and mark the run complete " +
			"(or keep it incomplete when it was set so). Refused while a validator reports errors, or while ledger units are still planned, in_progress or candidate in a run not marked incomplete.",
		Schema:     schemaReportBuild,
		ParentOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "language", "summary"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			lang, err := c.enum("language", false, "zh", "en")
			if err != nil {
				return nil, err
			}
			summary, err := c.str("summary", false)
			if err != nil {
				return nil, err
			}
			if len(summary) > 64<<10 {
				return nil, errf("summary: at most 64 KiB")
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			check, ok, err := c.checkAll(ref)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errDetails("validation failed; fix the errors and call code_audit_report_build again", check)
			}
			led, _, _ := c.loadLedger(ref)
			fnd, fndExists, err := c.loadFindings(ref)
			if err != nil {
				return nil, err
			}
			if !fndExists {
				if err := writeDoc(c, ref, store.FileFindings, fnd); err != nil {
					return nil, err
				}
			}
			var open []string
			for _, u := range led.A {
				if unresolvedStatuses[u.Field("status").S] {
					open = append(open, u.Field("coverage_id").S)
				}
			}
			if len(open) > 0 && m.RunStatus != StatusIncomplete {
				return nil, errDetails("ledger units are not resolved; finish them, or mark the run incomplete with code_audit_run_update (status=incomplete, incomplete_reason)", map[string]any{"open_units": open})
			}
			ag, err := c.loadAgents(ref)
			if err != nil {
				return nil, err
			}
			report, detail, needs := buildReport(reportInput{meta: m, agents: ag, ledger: led, records: fnd, summary: summary, lang: lang})
			for name, text := range map[string]string{store.FileReport: report, store.FileDetail: detail, store.FileNeeds: needs} {
				if err := c.Env.Store.WriteRunFile(ref, name, []byte(text)); err != nil {
					return nil, err
				}
			}
			if m.RunStatus != StatusIncomplete {
				m.RunStatus, m.CompletedAt = StatusComplete, c.now()
			}
			m.Phase = "report"
			if err := c.refreshCounts(ref, m); err != nil {
				return nil, err
			}
			if err := c.saveMeta(ref, m); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "run_status": m.RunStatus, "counts": m.Counts, "output_dir": c.Env.Store.Dir(ref),
				"files": []string{store.FileReport, store.FileDetail, store.FileNeeds}, "warnings": check["warnings"]}, nil
		},
	}
}

var readableDocs = []string{store.FileReport, store.FileDetail, store.FileNeeds, store.FileArchitecture}

const maxReadDocBytes = 4 << 20

func reportRead() *Tool {
	return &Tool{
		Name: "code_audit_report_read",
		Description: "Read one generated document of a run: REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md or architecture.md. " +
			"Only these four names are accepted; the text is returned as is (at most 4 MiB, with truncated=true beyond that).",
		Schema:   schemaReportRead,
		ReadOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "name"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			name, err := c.enum("name", true, readableDocs...)
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			raw, err := c.Env.Store.ReadFile(ref, name)
			if errors.Is(err, os.ErrNotExist) {
				return nil, errf("%s has not been written for run %s yet", name, ref.ID())
			}
			if err != nil {
				return nil, err
			}
			out := map[string]any{"ok": true, "name": name, "bytes": len(raw)}
			if len(raw) > maxReadDocBytes {
				raw = raw[:maxReadDocBytes]
				out["truncated"] = true
			}
			out["markdown"] = strings.ToValidUTF8(string(raw), "�")
			return out, nil
		},
	}
}
