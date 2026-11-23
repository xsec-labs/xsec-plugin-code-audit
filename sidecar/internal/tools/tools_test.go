package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/hostctx"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
)

type harness struct {
	t      *testing.T
	env    *Env
	target string
	tools  map[string]*Tool
	role   string
}

type fixedHost struct{ id hostctx.Identity }

func (f *fixedHost) Resolve(context.Context, string, string) (hostctx.Identity, error) {
	return f.id, nil
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	for name, lines := range map[string]int{"src/handler.c": 40, "src/model.c": 40, "src/store.c": 40} {
		var b strings.Builder
		for i := 1; i <= lines; i++ {
			fmt.Fprintf(&b, "line %d of %s\n", i, name)
		}
		p := filepath.Join(target, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC)
	h := &harness{t: t, target: target, tools: map[string]*Tool{}, role: "parent"}
	h.env = &Env{Store: st, Now: func() time.Time { now = now.Add(time.Second); return now }}
	h.env.Host = hostFunc(func() hostctx.Identity { return hostctx.Identity{ProjectID: "proj-1", Role: h.role} })
	for _, tl := range All() {
		h.tools[tl.Name] = tl
	}
	return h
}

type hostFunc func() hostctx.Identity

func (f hostFunc) Resolve(context.Context, string, string) (hostctx.Identity, error) { return f(), nil }

// call invokes a tool and returns the decoded body.
func (h *harness) call(name string, args any) (map[string]any, bool) {
	h.t.Helper()
	raw, _ := json.Marshal(args)
	res := h.tools[name].Invoke(context.Background(), h.env, Meta{ContextHandle: "h"}, raw)
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Text), &out); err != nil {
		h.t.Fatalf("%s: not JSON: %s", name, res.Text)
	}
	return out, !res.IsError
}

func (h *harness) must(name string, args any) map[string]any {
	h.t.Helper()
	out, ok := h.call(name, args)
	if !ok {
		h.t.Fatalf("%s failed: %v", name, out)
	}
	return out
}

func unit(status string) map[string]any {
	return map[string]any{
		"canonical_refs": map[string]any{"surface": "src/handler.c#handle", "boundary": "src/handler.c#owner", "subsystem": "api", "attack_class": "ATTACK-CLASSES.md#Access control"},
		"surface":        "Update route", "boundary": "Object ownership", "subsystem": "API", "attack_class": "Access control",
		"starting_paths": []string{"src/handler.c"}, "ordinary_attack_class_block": "ATTACK-CLASSES.md#Access control",
		"selected_companion_blocks": []string{}, "excluded_blocks": []any{}, "prior_status": "new", "attempts": []any{}, "wave": 1,
		"status": status, "agent_id": nil, "reviewed_paths": []string{}, "local_checks": []any{}, "result_fingerprints": []string{}, "unresolved": []string{},
	}
}

func step(kind, file string, line int) map[string]any {
	return map[string]any{"kind": kind, "file": file, "line": line, "scope": "handle", "description": "Attacker data reaches the operation."}
}

func confirmed(fp, file string) map[string]any {
	return map[string]any{
		"verdict": "confirmed", "fingerprint": fp, "title": "Missing ownership check",
		"description":       "An attacker can reach an operation without the intended ownership check.",
		"root_cause":        "handle omits the ownership check before changing the object.",
		"intended_behavior": "Only the object's owner can change it.",
		"trace":             []any{step("entrypoint", file, 10), step("propagation", "src/model.c", 20), step("sink", "src/store.c", 30)},
		"evidence":          []any{map[string]any{"file": file, "line": 10, "description": "The source performs the operation without the required check."}},
		"conditions":        []any{},
		"execution": map[string]any{"attacker_perspective": "An unprivileged remote user with their own account.", "payloads": []string{"An object identifier owned by another user."},
			"instructions": []string{"Submit the identifier through the public operation."}, "observed_result": "The other user's object changes."},
		"remediation": map[string]any{"strategy": "Check ownership before the state change."},
		"severity": map[string]any{"likelihood": map[string]any{"score": "medium", "reason": "The operation is directly reachable."},
			"impact": map[string]any{"score": "medium", "reason": "The attacker changes one protected object."}, "overall_severity": "medium"},
		"confidence": map[string]any{"score": "high", "reason": "The source path and result were reproduced."},
	}
}

func TestRunLifecycle(t *testing.T) {
	h := newHarness(t)
	start := h.must("code_audit_run_start", map[string]any{"target": h.target, "profile": "quick", "budget": 3})
	run := start["run_id"].(string)
	if !strings.HasSuffix(run, "/run-1") {
		t.Fatalf("run id %q", run)
	}
	h.must("code_audit_architecture_put", map[string]any{"run_id": run, "markdown": "# Arch\n"})

	// ledger: planned unit is accepted, coverage_id derived
	led := h.must("code_audit_ledger_put", map[string]any{"run_id": run, "units": []any{unit("planned")}})
	if led["ids_derived"].(float64) != 1 {
		t.Fatalf("ledger: %v", led)
	}
	if out, ok := h.call("code_audit_ledger_put", map[string]any{"run_id": run, "units": []any{map[string]any{"status": "bogus"}}}); ok {
		t.Fatalf("invalid unit accepted: %v", out)
	} else if _, has := out["details"].(map[string]any)["errors"]; !has {
		t.Fatalf("no errors in %v", out)
	}
	cov := h.must("code_audit_coverage_get", map[string]any{"run_id": run, "summary_only": true})
	if cov["total"].(float64) != 1 {
		t.Fatalf("coverage: %v", cov)
	}

	// findings: source references are checked
	if _, ok := h.call("code_audit_findings_put", map[string]any{"run_id": run, "records": []any{confirmed("src-handler-missing-check", "src/nope.c")}}); ok {
		t.Fatal("missing file accepted")
	}
	bad := confirmed("src-handler-missing-check", "src/handler.c")
	bad["trace"].([]any)[2].(map[string]any)["line"] = 999
	if out, ok := h.call("code_audit_findings_put", map[string]any{"run_id": run, "records": []any{bad}}); ok || !strings.Contains(fmt.Sprint(out), "outside the file") {
		t.Fatalf("line check: %v", out)
	}
	put := h.must("code_audit_findings_put", map[string]any{"run_id": run, "records": []any{confirmed("src-handler-missing-check", "src/handler.c")}})
	if put["confirmed"].(float64) != 1 {
		t.Fatalf("put: %v", put)
	}
	get := h.must("code_audit_finding_get", map[string]any{"run_id": run, "fingerprint": "src-handler-missing-check"})
	ext := get["ext"].(map[string]any)["steps"].([]any)
	if len(ext) != 4 || ext[0].(map[string]any)["snippet"].(map[string]any)["start_line"].(float64) != 7 {
		t.Fatalf("ext steps: %v", ext)
	}
	list := h.must("code_audit_findings_list", map[string]any{"run_id": run, "severity": "medium"})
	if list["total"].(float64) != 1 {
		t.Fatalf("list: %v", list)
	}

	// state outlives the run
	h.must("code_audit_finding_state_set", map[string]any{"run_id": run, "fingerprint": "src-handler-missing-check", "fix_status": "proposed", "vuln_id": "v-9", "user_decision": "confirmed_by_user"})
	if _, ok := h.call("code_audit_finding_state_set", map[string]any{"run_id": run, "fingerprint": "unknown"}); ok {
		t.Fatal("state for unknown finding accepted")
	}

	// the report is refused while a unit is planned
	if _, ok := h.call("code_audit_report_build", map[string]any{"run_id": run}); ok {
		t.Fatal("report built with an open unit")
	}
	h.must("code_audit_run_update", map[string]any{"run_id": run, "status": "incomplete", "incomplete_reason": "validation_budget_exhausted"})
	rep := h.must("code_audit_report_build", map[string]any{"run_id": run, "summary": "ok"})
	if rep["run_status"] != StatusIncomplete {
		t.Fatalf("report: %v", rep)
	}
	for _, f := range []string{"REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"} {
		if _, err := os.Stat(filepath.Join(rep["output_dir"].(string), f)); err != nil {
			t.Fatal(err)
		}
	}
	for _, fm := range []string{"sarif", "csv", "markdown", "json"} {
		ex := h.must("code_audit_export", map[string]any{"run_id": run, "format": fm})
		if _, err := os.Stat(ex["path"].(string)); err != nil {
			t.Fatal(err)
		}
	}

	// second run sees the first
	start2 := h.must("code_audit_run_start", map[string]any{"target": h.target})
	if start2["run_id"] != strings.TrimSuffix(run, "1")+"2" || len(start2["prior_runs"].([]any)) != 1 {
		t.Fatalf("second run: %v", start2)
	}
	if v := h.must("code_audit_validate", map[string]any{"run_id": run}); v["ok"] != true {
		t.Fatalf("validate: %v", v)
	}
}

func TestAgentBudgetAndRoles(t *testing.T) {
	h := newHarness(t)
	run := h.must("code_audit_run_start", map[string]any{"target": h.target, "budget": 1})["run_id"].(string)
	h.must("code_audit_agent_note", map[string]any{"run_id": run, "event": "dispatched", "agent_id": "hunter-1", "role": "hunter"})
	if out, ok := h.call("code_audit_agent_note", map[string]any{"run_id": run, "event": "dispatched", "agent_id": "hunter-2", "role": "hunter"}); ok || !strings.Contains(fmt.Sprint(out), "budget exhausted") {
		t.Fatalf("budget: %v", out)
	}
	if _, ok := h.call("code_audit_agent_note", map[string]any{"run_id": run, "event": "returned", "agent_id": "ghost", "role": "hunter"}); ok {
		t.Fatal("return of an unknown agent accepted")
	}
	h.must("code_audit_agent_note", map[string]any{"run_id": run, "event": "returned", "agent_id": "hunter-1", "role": "hunter"})
	h.role = "sub"
	if out, ok := h.call("code_audit_run_delete", map[string]any{"run_id": run}); ok || !strings.Contains(fmt.Sprint(out), "parent agent") {
		t.Fatalf("sub-agent delete: %v", out)
	}
	h.must("code_audit_runs_list", map[string]any{})
}

func TestProjectIsolation(t *testing.T) {
	h := newHarness(t)
	run := h.must("code_audit_run_start", map[string]any{"target": h.target})["run_id"].(string)
	h.env.Host = hostFunc(func() hostctx.Identity { return hostctx.Identity{ProjectID: "proj-2", Role: "parent"} })
	if _, ok := h.call("code_audit_run_get", map[string]any{"run_id": run}); ok {
		t.Fatal("run of another project readable")
	}
	for _, bad := range []string{"../x/run-1", "a/run-0", "a/b/run-1"} {
		if _, ok := h.call("code_audit_run_get", map[string]any{"run_id": bad}); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestSymlinkEscapeRefused(t *testing.T) {
	h := newHarness(t)
	outside := filepath.Join(t.TempDir(), "secret.c")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.target, "src", "link.c")); err != nil {
		t.Skip("symlinks unavailable")
	}
	run := h.must("code_audit_run_start", map[string]any{"target": h.target})["run_id"].(string)
	rec := confirmed("src-link", "src/link.c")
	if out, ok := h.call("code_audit_findings_put", map[string]any{"run_id": run, "records": []any{rec}}); ok || !strings.Contains(fmt.Sprint(out), "outside the audited source") {
		t.Fatalf("symlink escape: %v", out)
	}
}

func TestCompleteRun(t *testing.T) {
	h := newHarness(t)
	run := h.must("code_audit_run_start", map[string]any{"target": h.target})["run_id"].(string)
	u := unit("out_of_scope")
	u["unresolved"] = []string{"vendored third-party code is out of scope"}
	h.must("code_audit_ledger_put", map[string]any{"run_id": run, "units": []any{u}})
	h.must("code_audit_findings_put", map[string]any{"run_id": run, "mode": "replace", "records": []any{}})
	rep := h.must("code_audit_report_build", map[string]any{"run_id": run, "language": "en"})
	if rep["run_status"] != StatusComplete {
		t.Fatalf("report: %v", rep)
	}
	if r := h.must("code_audit_report_read", map[string]any{"run_id": run, "name": "REPORT.md"}); !strings.Contains(r["markdown"].(string), "Code audit report") {
		t.Fatalf("report_read: %v", r)
	}
	if _, ok := h.call("code_audit_report_read", map[string]any{"run_id": run, "name": "../run-metadata.json"}); ok {
		t.Fatal("report_read accepted a path")
	}
	if _, ok := h.call("code_audit_report_read", map[string]any{"run_id": run, "name": "architecture.md"}); ok {
		t.Fatal("architecture.md was never written, read must fail")
	}
	body, err := os.ReadFile(filepath.Join(rep["output_dir"].(string), "REPORT.md"))
	if err != nil || !strings.Contains(string(body), "Code audit report") {
		t.Fatalf("REPORT.md: %v %q", err, body)
	}
	if got := h.must("code_audit_run_get", map[string]any{"run_id": run})["run"].(map[string]any); got["run_status"] != StatusComplete || got["completed_at"] == "" {
		t.Fatalf("meta: %v", got)
	}
}

// records is optional: remove[] alone must work, and a failing handler must fail its call, not the process.
func TestFindingsPutRemoveOnly(t *testing.T) {
	h := newHarness(t)
	run := h.must("code_audit_run_start", map[string]any{"target": h.target})["run_id"].(string)
	h.must("code_audit_findings_put", map[string]any{"run_id": run, "records": []any{confirmed("src-handler-missing-check", "src/handler.c")}})
	h.must("code_audit_findings_put", map[string]any{"run_id": run, "remove": []string{"src-handler-missing-check"}})
	list := h.must("code_audit_findings_list", map[string]any{"run_id": run})
	if n, _ := list["total"].(float64); n != 0 {
		t.Fatalf("finding not removed: %v", list)
	}
}

func TestHandlerPanicFailsOnlyTheCall(t *testing.T) {
	h := newHarness(t)
	boom := &Tool{Name: "boom", Schema: `{"type":"object"}`, Handler: func(*Call) (any, error) {
		var m map[string]*int
		return *m["x"], nil
	}}
	res := boom.Invoke(context.Background(), h.env, Meta{ContextHandle: "h"}, json.RawMessage(`{}`))
	if !res.IsError || !strings.Contains(res.Text, "internal error in boom") {
		t.Fatalf("panic not turned into a tool failure: %+v", res)
	}
}

func TestUnknownRoleRefused(t *testing.T) {
	h := newHarness(t)
	h.env.Host = hostFunc(func() hostctx.Identity { return hostctx.Identity{ProjectID: "p", Role: "Parent "} })
	if out, ok := h.call("code_audit_run_start", map[string]any{"target": h.target}); ok || !strings.Contains(fmt.Sprint(out), "unknown agent role") {
		t.Fatalf("unknown role accepted: %v", out)
	}
}

func TestAuditDataDirNotAuditable(t *testing.T) {
	h := newHarness(t)
	if _, ok := h.call("code_audit_run_start", map[string]any{"target": h.env.Store.Root()}); ok {
		t.Fatal("the data directory itself was accepted as a target")
	}
	if !insideDir("/a/b", "/a/b/c") || insideDir("/a/b", "/a/..foo") || !insideDir("/a/b", "/a/b") {
		t.Fatal("insideDir")
	}
}

func TestFencedOutgrowsBackticks(t *testing.T) {
	got := fenced("a ``` b\n````x")
	if !strings.HasPrefix(got, "`````\n") || !strings.HasSuffix(got, "\n`````") {
		t.Fatalf("fence: %q", got)
	}
	if fenced("plain") != "```\nplain\n```" {
		t.Fatal("plain fence")
	}
	if store.SafeProject("a b") == store.SafeProject("b a") || store.SafeProject("x y") != store.SafeProject("x y") {
		t.Fatal("hashed project ids must differ for different ids and be stable")
	}
}

func TestDataDirCannotBeAuditedThroughALinkOrSubdirectory(t *testing.T) {
	h := newHarness(t)
	link := filepath.Join(t.TempDir(), "lnk")
	if err := os.Symlink(h.env.Store.Root(), link); err == nil {
		if _, ok := h.call("code_audit_run_start", map[string]any{"target": link}); ok {
			t.Fatal("symlink to the data directory accepted")
		}
	}
	if _, ok := h.call("code_audit_run_start", map[string]any{"target": filepath.Join(h.env.Store.Root(), "runs")}); ok {
		t.Fatal("subdirectory of the data directory accepted")
	}
}
