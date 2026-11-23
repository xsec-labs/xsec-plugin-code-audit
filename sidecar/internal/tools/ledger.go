package tools

import (
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/validate"
)

// loadLedger reads coverage-ledger.json; a missing file is an empty ledger.
func (c *Call) loadLedger(ref store.RunRef) (*jsonv.Value, bool, error) {
	raw, err := c.Env.Store.ReadFile(ref, store.FileLedger)
	if errors.Is(err, os.ErrNotExist) {
		return jsonv.NewArray(), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		return nil, true, errf("coverage-ledger.json is damaged: %v", err)
	}
	if !v.IsArray() {
		return nil, true, errf("coverage-ledger.json is damaged: expected an array")
	}
	return v, true, nil
}

func (c *Call) loadFindings(ref store.RunRef) (*jsonv.Value, bool, error) {
	raw, err := c.Env.Store.ReadFile(ref, store.FileFindings)
	if errors.Is(err, os.ErrNotExist) {
		return jsonv.NewArray(), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		return nil, true, errf("findings.json is damaged: %v", err)
	}
	if !v.IsArray() {
		return nil, true, errf("findings.json is damaged: expected an array")
	}
	return v, true, nil
}

func rawJSON(v *jsonv.Value) json.RawMessage { return json.RawMessage(jsonv.Marshal(v, "")) }

// refreshCounts recomputes the summary counters of run-metadata.json from the ledger and findings.
func (c *Call) refreshCounts(ref store.RunRef, m *Metadata) error {
	counts := Counts{Severity: map[string]int{}, UnitStatus: map[string]int{}}
	led, _, err := c.loadLedger(ref)
	if err != nil {
		return err
	}
	counts.Units = len(led.A)
	for _, u := range led.A {
		if s := u.Field("status"); s.IsString() {
			counts.UnitStatus[s.S]++
		}
	}
	fnd, _, err := c.loadFindings(ref)
	if err != nil {
		return err
	}
	for _, f := range fnd.A {
		switch f.Field("verdict").S {
		case "confirmed":
			counts.Confirmed++
			if sv := f.Field("severity").Field("overall_severity"); sv.IsString() {
				counts.Severity[sv.S]++
			}
		case "needs_validation":
			counts.NeedsValidation++
		case "rejected":
			counts.Rejected++
		}
	}
	m.Counts = counts
	return nil
}

func ledgerPut() *Tool {
	return &Tool{
		Name: "code_audit_ledger_put",
		Description: "Store coverage-ledger units. The units are validated with the skill's own coverage-ledger rules (ported to Go, identical messages); " +
			"on any error nothing is written and the exact validator errors come back so you can fix and resend. coverage_id may be omitted: it is derived from canonical_refs.",
		Schema:     schemaLedgerPut,
		ParentOnly: true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "units", "mode", "remove"); err != nil {
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
			remove, err := c.strList("remove", 1000, 65536)
			if err != nil {
				return nil, err
			}
			units := c.Args.Get("units")
			if units != nil && units.Kind != jsonv.Null && !units.IsArray() {
				return nil, errf("units: expected an array of coverage units")
			}
			if mode == "replace" && !units.IsArray() {
				return nil, errf("units: required for mode replace")
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			m, err := c.loadMeta(ref)
			if err != nil {
				return nil, err
			}
			cur, _, err := c.loadLedger(ref)
			if err != nil {
				return nil, err
			}
			byID := map[string]*jsonv.Value{}
			if mode == "upsert" {
				for _, u := range cur.A {
					if id := u.Field("coverage_id"); id.IsString() {
						byID[id.S] = u
					}
				}
			}
			for _, id := range remove {
				delete(byID, id)
			}
			var extra []*jsonv.Value // units without a usable id stay in order so the validator reports them
			filled := 0
			if units.IsArray() {
				for _, u := range units.A {
					if u.IsObject() && !u.Has("coverage_id") {
						if id, ok := validate.CanonicalCoverageID(u.Field("canonical_refs")); ok {
							u.Set("coverage_id", jsonv.Str(id))
							filled++
						}
					}
					if u.IsObject() && u.Field("coverage_id").IsString() {
						byID[u.Field("coverage_id").S] = u
					} else {
						extra = append(extra, u)
					}
				}
			}
			ids := make([]string, 0, len(byID))
			for id := range byID {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return validate.UTF16Less(ids[i], ids[j]) })
			next := jsonv.NewArray()
			for _, id := range ids {
				next.A = append(next.A, byID[id])
			}
			next.A = append(next.A, extra...)
			if errs := validate.ValidateLedger(next); len(errs) > 0 {
				return nil, errDetails("coverage ledger rejected; nothing was written", map[string]any{"errors": errs, "units_checked": len(next.A)})
			}
			if err := writeDoc(c, ref, store.FileLedger, next); err != nil {
				return nil, err
			}
			if err := c.refreshCounts(ref, m); err != nil {
				return nil, err
			}
			if err := c.saveMeta(ref, m); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "units": len(next.A), "ids_derived": filled, "unit_status": m.Counts.UnitStatus}, nil
		},
	}
}

func coverageGet() *Tool {
	return &Tool{
		Name:        "code_audit_coverage_get",
		Description: "Read a run's coverage ledger: status counts and the units, optionally filtered by status or coverage_id. Works on earlier runs too, so a new run can build on them.",
		Schema:      schemaCoverageGet,
		ReadOnly:    true,
		Handler: func(c *Call) (any, error) {
			if err := c.strictKeys("run_id", "status", "coverage_id", "summary_only", "limit", "offset"); err != nil {
				return nil, err
			}
			ref, err := c.runRef()
			if err != nil {
				return nil, err
			}
			status, err := c.str("status", false)
			if err != nil {
				return nil, err
			}
			cid, err := c.str("coverage_id", false)
			if err != nil {
				return nil, err
			}
			sumOnly, err := c.boolean("summary_only", false)
			if err != nil {
				return nil, err
			}
			limit, err := c.intArg("limit", 200, 1, 1000)
			if err != nil {
				return nil, err
			}
			offset, err := c.intArg("offset", 0, 0, 100000)
			if err != nil {
				return nil, err
			}
			c.Env.Store.Lock()
			defer c.Env.Store.Unlock()
			led, exists, err := c.loadLedger(ref)
			if err != nil {
				return nil, err
			}
			byStatus := map[string]int{}
			var match []*jsonv.Value
			for _, u := range led.A {
				s := u.Field("status").S
				byStatus[s]++
				if (status == "" || s == status) && (cid == "" || u.Field("coverage_id").S == cid) {
					match = append(match, u)
				}
			}
			out := map[string]any{"ok": true, "exists": exists, "total": len(led.A), "by_status": byStatus, "matching": len(match)}
			if !sumOnly {
				if offset > len(match) {
					offset = len(match)
				}
				end := offset + limit
				if end > len(match) {
					end = len(match)
				}
				rows := make([]json.RawMessage, 0, end-offset)
				for _, u := range match[offset:end] {
					rows = append(rows, rawJSON(u))
				}
				out["units"] = rows
			}
			return out, nil
		},
	}
}
