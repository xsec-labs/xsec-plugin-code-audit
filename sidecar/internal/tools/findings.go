package tools

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/validate"
)

var (
	fixStatuses   = []string{"proposed", "fixed", "still_present", "cannot_determine", "none"}
	userDecisions = []string{"confirmed_by_user", "excluded_by_user", "none"}
	severities    = []string{"informational", "low", "medium", "high", "critical"}
	verdicts      = []string{"confirmed", "needs_validation", "rejected"}
)

// sourceSteps lists the trace and evidence entries of one record as ext steps (without snippets yet).
func sourceSteps(rec *jsonv.Value) []ExtStep {
	var out []ExtStep
	for _, role := range []string{"trace", "evidence"} {
		for i, e := range rec.Field(role).A {
			if !e.IsObject() {
				continue
			}
			line := 0
			if l := e.Field("line"); l.IsInteger() {
				line = int(l.N)
			}
			out = append(out, ExtStep{Role: role, Index: i, Kind: e.Field("kind").S, File: e.Field("file").S, Line: line})
		}
	}
	return out
}

func findingsPut() *Tool {
	return &Tool{
		Name: "code_audit_findings_put",
		Description: "Store finding records (confirmed, needs_validation, rejected). The whole findings.json is checked with the skill's validator (ported to Go, identical messages), " +
			"and every cited file and line is checked against the audited source and frozen as a snippet. On any error nothing is written. Records are kept sorted by fingerprint.",
		Schema:     schemaFindingsPut,
		ParentOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "records", "mode", "remove"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			mode, err := c.enum("mode", false, "upsert", "replace")
			if err != nil {
				return nil, err
			}
			if mode == "" {
				mode = "upsert"
			}
			remove, err := c.strList("remove", 1000, 1024)
			if err != nil {
				return nil, err
			}
			recs := c.Args.Get("records")
			if recs != nil && recs.Kind != jsonv.Null && !recs.IsArray() {
				return nil, errf("records: expected an array of finding records")
			}
			if mode == "replace" && !recs.IsArray() {
				return nil, errf("records: required for mode replace (use [] to store a clean result)")
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			cur, _, err := c.loadFindings(ref)
			if err != nil {
				return nil, err
			}
			byFP := map[string]*jsonv.Value{}
			if mode == "upsert" {
				for _, f := range cur.A {
					byFP[f.Field("fingerprint").S] = f
				}
			}
			for _, fp := range remove {
				delete(byFP, fp)
			}
			incoming := map[string]bool{}
			var loose []*jsonv.Value
			for _, r := range recs.A {
				if fp := r.Field("fingerprint"); r.IsObject() && fp.IsString() {
					byFP[fp.S] = r
					incoming[fp.S] = true
				} else {
					loose = append(loose, r)
				}
			}
			fps := make([]string, 0, len(byFP))
			for fp := range byFP {
				fps = append(fps, fp)
			}
			sort.Slice(fps, func(i, j int) bool { return validate.UTF16Less(fps[i], fps[j]) })
			next := jsonv.NewArray()
			for _, fp := range fps {
				next.A = append(next.A, byFP[fp])
			}
			next.A = append(next.A, loose...)
			errs, err := validate.ValidateFindings(next)
			if err != nil {
				return nil, errf("validator failure: %v", err)
			}
			if len(errs) > 0 {
				return nil, errDetails("findings rejected by the validator; nothing was written", map[string]any{"errors": errs})
			}
			// Source references: only for the records that arrived with this call.
			src, err := newSourceReader(m.Target)
			if err != nil {
				return nil, errf("the audited source %s is not readable: %v", m.Target, err)
			}
			ext, err := c.loadExt(ref)
			if err != nil {
				return nil, err
			}
			var refErrs []string
			newExt := map[string]*ExtFinding{}
			for idx, rec := range next.A {
				fp := rec.Field("fingerprint").S
				if !incoming[fp] {
					continue
				}
				ef := &ExtFinding{}
				for _, st := range sourceSteps(rec) {
					loc := fmt.Sprintf("$[%d].%s[%d]", idx, st.Role, st.Index)
					f, why := src.open(st.File)
					if f == nil {
						refErrs = append(refErrs, fmt.Sprintf("%s.file: %q %s", loc, st.File, why))
						continue
					}
					sn, why := f.snippet(st.Line)
					if why != "" {
						refErrs = append(refErrs, fmt.Sprintf("%s.line: %s in %q", loc, why, st.File))
						continue
					}
					st.SHA256, st.Snippet = f.sha256, sn
					ef.Steps = append(ef.Steps, st)
				}
				newExt[fp] = ef
			}
			if len(refErrs) > 0 {
				return nil, errDetails("source references rejected; nothing was written", map[string]any{
					"errors": refErrs,
					"hint":   "Every trace/evidence file must be a repository-relative path that exists in the audited source, and every line must exist in that file.",
				})
			}
			for fp, ef := range newExt {
				if old := ext.Findings[fp]; old != nil {
					ef.CWE, ef.Tags, ef.Notes = old.CWE, old.Tags, old.Notes
				}
				ext.Findings[fp] = ef
			}
			for fp := range ext.Findings {
				if _, ok := byFP[fp]; !ok {
					delete(ext.Findings, fp)
				}
			}
			if err := writeDoc(c, ref, store.FileFindings, next); err != nil {
				return nil, err
			}
			rawExt, _ := json.MarshalIndent(ext, "", "  ")
			if err := c.Env.Store.WriteRunFile(ref, store.FileExt, append(rawExt, '\n')); err != nil {
				return nil, err
			}
			if err := c.touchState(m, next); err != nil {
				return nil, err
			}
			if err := c.refreshCounts(ref, m); err != nil {
				return nil, err
			}
			if err := c.saveMeta(ref, m); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "findings": len(next.A), "stored_now": len(incoming), "confirmed": m.Counts.Confirmed,
				"needs_validation": m.Counts.NeedsValidation, "rejected": m.Counts.Rejected}, nil
		},
	}
}

// touchState records first/last seen run for every stored fingerprint.
func (c *Call) touchState(m *Metadata, fnd *jsonv.Value) error {
	if len(fnd.A) == 0 {
		return nil
	}
	st, err := c.loadState()
	if err != nil {
		return err
	}
	for _, f := range fnd.A {
		fp := f.Field("fingerprint").S
		if fp == "" {
			continue
		}
		fs := st.Findings[stateKey(m.Repo, fp)]
		if fs == nil {
			fs = &FindingState{Repo: m.Repo, Fingerprint: fp, FirstSeenRun: m.RunID}
			st.Findings[stateKey(m.Repo, fp)] = fs
		}
		fs.LastSeenRun = m.RunID
		fs.UpdatedAt = c.now()
	}
	return c.saveState(st)
}

func firstLocation(rec *jsonv.Value) (string, int) {
	for _, role := range []string{"trace", "evidence"} {
		arr := rec.Field(role).A
		if role == "trace" && len(arr) > 0 {
			arr = arr[len(arr)-1:] // the sink
		}
		for _, e := range arr {
			if e.Field("file").IsString() && e.Field("line").IsInteger() {
				return e.Field("file").S, int(e.Field("line").N)
			}
		}
	}
	return "", 0
}

func findingRow(rec *jsonv.Value, st *FindingState) map[string]any {
	file, line := firstLocation(rec)
	row := map[string]any{
		"fingerprint": rec.Field("fingerprint").S, "verdict": rec.Field("verdict").S, "title": rec.Field("title").S,
		"file": file, "line": line,
	}
	if sv := rec.Field("severity"); sv.IsObject() {
		row["severity"] = sv.Field("overall_severity").S
		row["likelihood"] = sv.Field("likelihood").Field("score").S
		row["impact"] = sv.Field("impact").Field("score").S
	}
	if cf := rec.Field("confidence"); cf.IsObject() {
		row["confidence"] = cf.Field("score").S
	}
	if st != nil {
		row["state"] = st
	}
	return row
}

func findingsList() *Tool {
	return &Tool{
		Name:        "code_audit_findings_list",
		Description: "List a run's findings (one row each: fingerprint, verdict, title, location, severity, fix status, user decision). Filter by verdict, severity or text.",
		Schema:      schemaFindingsList,
		ReadOnly:    true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "verdict", "severity", "query", "limit", "offset"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			verdict, err := c.enum("verdict", false, verdicts...)
			if err != nil {
				return nil, err
			}
			sev, err := c.enum("severity", false, severities...)
			if err != nil {
				return nil, err
			}
			query, err := c.str("query", false)
			if err != nil {
				return nil, err
			}
			query = strings.ToLower(query)
			limit, err := c.intArg("limit", 200, 1, 500)
			if err != nil {
				return nil, err
			}
			offset, err := c.intArg("offset", 0, 0, 100000)
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			fnd, exists, err := c.loadFindings(ref)
			if err != nil {
				return nil, err
			}
			state, err := c.loadState()
			if err != nil {
				return nil, err
			}
			var rows []map[string]any
			for _, f := range fnd.A {
				if verdict != "" && f.Field("verdict").S != verdict {
					continue
				}
				if sev != "" && f.Field("severity").Field("overall_severity").S != sev {
					continue
				}
				if query != "" && !recordMatches(f, query) {
					continue
				}
				rows = append(rows, findingRow(f, state.Findings[stateKey(m.Repo, f.Field("fingerprint").S)]))
			}
			total := len(rows)
			if offset > total {
				offset = total
			}
			end := offset + limit
			if end > total {
				end = total
			}
			return map[string]any{"ok": true, "exists": exists, "total": total, "findings": rows[offset:end], "counts": m.Counts}, nil
		},
	}
}

func recordMatches(f *jsonv.Value, q string) bool {
	if strings.Contains(strings.ToLower(f.Field("title").S), q) || strings.Contains(strings.ToLower(f.Field("description").S), q) ||
		strings.Contains(strings.ToLower(f.Field("fingerprint").S), q) {
		return true
	}
	for _, role := range []string{"trace", "evidence"} {
		for _, e := range f.Field(role).A {
			if strings.Contains(strings.ToLower(e.Field("file").S), q) {
				return true
			}
		}
	}
	return false
}

func findingGet() *Tool {
	return &Tool{
		Name:        "code_audit_finding_get",
		Description: "Read one finding in full: the validated record, the source snippets frozen when it was stored, and its fix status, user decision and linked vulnerability.",
		Schema:      schemaFindingGet,
		ReadOnly:    true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "fingerprint"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			fp, err := c.str("fingerprint", true)
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			fnd, _, err := c.loadFindings(ref)
			if err != nil {
				return nil, err
			}
			var rec *jsonv.Value
			for _, f := range fnd.A {
				if f.Field("fingerprint").S == fp {
					rec = f
				}
			}
			if rec == nil {
				return nil, errf("run %s has no finding with fingerprint %q", ref.ID(), fp)
			}
			ext, err := c.loadExt(ref)
			if err != nil {
				return nil, err
			}
			state, err := c.loadState()
			if err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "run_id": ref.ID(), "target": m.Target, "record": rawJSON(rec), "ext": ext.Findings[fp],
				"state": state.Findings[stateKey(m.Repo, fp)]}, nil
		},
	}
}

func findingStateSet() *Tool {
	return &Tool{
		Name: "code_audit_finding_state_set",
		Description: "Set what outlives a run for one finding: fix status (proposed, fixed, still_present, cannot_determine), the user's decision (confirmed_by_user, excluded_by_user) " +
			"and the id of the project vulnerability it was linked to. Pass \"none\" or an empty vuln_id to clear a field.",
		Schema:     schemaFindingState,
		ParentOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "fingerprint", "fix_status", "fix_note", "user_decision", "user_note", "vuln_id"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			fp, err := c.str("fingerprint", true)
			if err != nil {
				return nil, err
			}
			fix, err := c.enum("fix_status", false, fixStatuses...)
			if err != nil {
				return nil, err
			}
			dec, err := c.enum("user_decision", false, userDecisions...)
			if err != nil {
				return nil, err
			}
			fixNote, err := c.str("fix_note", false)
			if err != nil {
				return nil, err
			}
			userNote, err := c.str("user_note", false)
			if err != nil {
				return nil, err
			}
			vuln, err := c.str("vuln_id", false)
			if err != nil {
				return nil, err
			}
			if len(fixNote) > 4000 || len(userNote) > 4000 || len(vuln) > 200 {
				return nil, errf("fix_note and user_note take at most 4000 bytes, vuln_id at most 200")
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			fnd, _, err := c.loadFindings(ref)
			if err != nil {
				return nil, err
			}
			found := false
			for _, f := range fnd.A {
				if f.Field("fingerprint").S == fp {
					found = true
				}
			}
			if !found {
				return nil, errf("run %s has no finding with fingerprint %q", ref.ID(), fp)
			}
			state, err := c.loadState()
			if err != nil {
				return nil, err
			}
			key := stateKey(m.Repo, fp)
			fs := state.Findings[key]
			if fs == nil {
				fs = &FindingState{Repo: m.Repo, Fingerprint: fp, FirstSeenRun: m.RunID, LastSeenRun: m.RunID}
				state.Findings[key] = fs
			}
			switch fix {
			case "none":
				fs.FixStatus, fs.FixNote, fs.FixRun = "", "", ""
			case "":
			default:
				fs.FixStatus, fs.FixRun = fix, m.RunID
			}
			if fix != "none" && c.Args.Has("fix_note") {
				fs.FixNote = fixNote
			}
			switch dec {
			case "none":
				fs.UserDecision, fs.UserNote = "", ""
			case "":
			default:
				fs.UserDecision = dec
			}
			if dec != "none" && c.Args.Has("user_note") {
				fs.UserNote = userNote
			}
			if c.Args.Has("vuln_id") {
				fs.VulnID = vuln
			}
			fs.UpdatedAt = c.now()
			if err := c.saveState(state); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "state": fs}, nil
		},
	}
}
