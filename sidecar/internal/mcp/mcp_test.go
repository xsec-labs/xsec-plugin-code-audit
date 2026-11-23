package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/hostctx"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/tools"
)

func TestProtocol(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Env: &tools.Env{Store: st, Host: hostctx.Standalone{}, Now: time.Now}, Tools: tools.All()}
	target := t.TempDir()
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"code_audit_run_start","arguments":{"target":` + mustJSON(target) + `},"_meta":{"com.xsec.desktop/contextHandle":"h"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"code_audit_run_get","arguments":{"run_id":"x/run-1"}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"resources/list"}`,
		`not json`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad output line %q", sc.Text())
		}
		got[string(mustMarshal(m["id"]))] = m
	}
	if v := got["1"]["result"].(map[string]any)["protocolVersion"]; v != "2025-03-26" {
		t.Fatalf("protocol %v", v)
	}
	if _, ok := got["null"]; !ok {
		t.Fatal("no parse error reply")
	}
	if len(got) != 7 { // 1,2,3,4,5,6,7 + null = 8 distinct keys minus none for the notification
		if len(got) != 8 {
			t.Fatalf("replies: %d", len(got))
		}
	}
	tl := got["3"]["result"].(map[string]any)["tools"].([]any)
	if len(tl) != len(tools.All()) {
		t.Fatalf("tools/list: %d", len(tl))
	}
	for _, x := range tl {
		tool := x.(map[string]any)
		if _, ok := tool["inputSchema"].(map[string]any); !ok {
			t.Fatalf("schema of %v is not an object", tool["name"])
		}
	}
	res := got["4"]["result"].(map[string]any)
	if res["isError"] != false || res["structuredContent"].(map[string]any)["ok"] != true {
		t.Fatalf("run_start: %v", res)
	}
	if got["5"]["error"] == nil || got["7"]["error"] == nil {
		t.Fatal("unknown tool / method must be JSON-RPC errors")
	}
	if got["6"]["result"].(map[string]any)["isError"] != true {
		t.Fatalf("tool failure must be isError: %v", got["6"])
	}
}

func mustJSON(s string) string { return string(mustMarshal(s)) }
func mustMarshal(v any) []byte { b, _ := json.Marshal(v); return b }
