package tools

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
)

var sarifLevel = map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}
var sarifScore = map[string]string{"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "informational": "0.5"}

func exportTool() *Tool {
	return &Tool{
		Name: "code_audit_export",
		Description: "Write an export of a run's findings into its exports/ folder: sarif (SARIF 2.1.0), csv, markdown or json. Confirmed findings only, " +
			"plus needs_validation leads when include_needs_validation is true. Returns the file path.",
		Schema:     schemaExport,
		ParentOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "format", "include_needs_validation"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			format, err := c.enum("format", true, "sarif", "csv", "markdown", "json")
			if err != nil {
				return nil, err
			}
			withNeeds, err := c.boolean("include_needs_validation", false)
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
			if !exists {
				return nil, errf("run %s has no findings.json yet", ref.ID())
			}
			var recs []*jsonv.Value
			for _, f := range fnd.A {
				if v := f.Field("verdict").S; v == "confirmed" || (withNeeds && v == "needs_validation") {
					recs = append(recs, f)
				}
			}
			state, err := c.loadState()
			if err != nil {
				return nil, err
			}
			var data []byte
			var ext string
			switch format {
			case "sarif":
				data, err = buildSARIF(m, recs)
				ext = "sarif"
			case "csv":
				data, err = buildCSV(m, recs, state)
				ext = "csv"
			case "markdown":
				ag, _ := c.loadAgents(ref)
				led, _, _ := c.loadLedger(ref)
				only := jsonv.NewArray(recs...)
				report, detail, needs := buildReport(reportInput{meta: m, agents: ag, ledger: led, records: only, lang: "zh"})
				data = []byte(report + "\n---\n\n" + detail)
				if withNeeds {
					data = append(data, []byte("\n---\n\n"+needs)...)
				}
				ext = "md"
			default:
				data = jsonv.Marshal(jsonv.NewArray(recs...), "  ")
				data = append(data, '\n')
				ext = "json"
			}
			if err != nil {
				return nil, err
			}
			name := path.Join(store.DirExports, fmt.Sprintf("findings-%s.%s", strings.NewReplacer("-", "", ":", "", "T", "-", "Z", "").Replace(c.now()), ext))
			if err := c.Env.Store.WriteRunFile(ref, name, data); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "format": format, "path": c.Env.Store.Path(ref, name), "records": len(recs), "bytes": len(data)}, nil
		},
	}
}

func buildCSV(m *Metadata, recs []*jsonv.Value, st *State) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF") // BOM so Excel reads UTF-8
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"run", "fingerprint", "verdict", "severity", "confidence", "title", "file", "line", "fix_status", "user_decision", "vuln_id", "description"})
	for _, f := range recs {
		file, line := firstLocation(f)
		fp := f.Field("fingerprint").S
		s := st.Findings[stateKey(m.Repo, fp)]
		var fix, dec, vuln string
		if s != nil {
			fix, dec, vuln = s.FixStatus, s.UserDecision, s.VulnID
		}
		_ = w.Write([]string{m.RunID, fp, f.Field("verdict").S, f.Field("severity").Field("overall_severity").S, f.Field("confidence").Field("score").S,
			csvSafe(f.Field("title").S), file, fmt.Sprint(line), fix, dec, vuln, csvSafe(f.Field("description").S)})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// csvSafe stops spreadsheets from treating audited text as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func buildSARIF(m *Metadata, recs []*jsonv.Value) ([]byte, error) {
	var rules []map[string]any
	var results []map[string]any
	for _, f := range recs {
		fp := f.Field("fingerprint").S
		sev := f.Field("severity").Field("overall_severity").S
		rule := map[string]any{
			"id": fp, "name": f.Field("title").S, "shortDescription": map[string]any{"text": f.Field("title").S},
			"fullDescription": map[string]any{"text": f.Field("description").S},
		}
		if sev != "" {
			rule["properties"] = map[string]any{"security-severity": sarifScore[sev], "tags": []string{"security"}}
		}
		rules = append(rules, rule)
		file, line := firstLocation(f)
		level := "note"
		if l, ok := sarifLevel[sev]; ok {
			level = l
		}
		if f.Field("verdict").S == "needs_validation" {
			level = "none"
		}
		var flow []map[string]any
		for _, e := range f.Field("trace").A {
			flow = append(flow, map[string]any{"location": map[string]any{
				"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": e.Field("file").S}, "region": map[string]any{"startLine": int(e.Field("line").N)}},
				"message":          map[string]any{"text": e.Field("kind").S + ": " + e.Field("description").S},
			}})
		}
		res := map[string]any{
			"ruleId": fp, "level": level, "message": map[string]any{"text": f.Field("title").S + " — " + f.Field("description").S},
			"locations": []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": file}, "region": map[string]any{"startLine": line}}}},
			"partialFingerprints": map[string]any{"xsecFingerprint/v1": fp},
			"properties":          map[string]any{"verdict": f.Field("verdict").S},
		}
		if len(flow) > 0 {
			res["codeFlows"] = []map[string]any{{"threadFlows": []map[string]any{{"locations": flow}}}}
		}
		results = append(results, res)
	}
	run := map[string]any{
		"tool":       map[string]any{"driver": map[string]any{"name": "xSec Code Audit", "rules": nonNil(rules)}},
		"results":    nonNilR(results),
		"properties": map[string]any{"run_id": m.RunID, "profile": m.Profile, "source_commit": m.SourceRef.Commit},
	}
	return json.MarshalIndent(map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []any{run},
	}, "", "  ")
}

func nonNil(v []map[string]any) []map[string]any {
	if v == nil {
		return []map[string]any{}
	}
	return v
}
func nonNilR(v []map[string]any) []map[string]any { return nonNil(v) }
