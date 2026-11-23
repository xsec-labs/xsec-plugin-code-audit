package hostctx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serve(t *testing.T, body string) *Host {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer handle-1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	h, err := NewHost(srv.URL+"/plugin-host-rpc", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestResolve(t *testing.T) {
	h := serve(t, `{"jsonrpc":"2.0","id":1,"result":{"projectId":"p-7","role":"sub"}}`)
	id, err := h.Resolve(context.Background(), "handle-1", "code_audit_run_get")
	if err != nil || id.ProjectID != "p-7" || id.Role != "sub" {
		t.Fatalf("%v %v", id, err)
	}
	if _, err := h.Resolve(context.Background(), "", "x"); err == nil {
		t.Fatal("a call without a handle must fail")
	}
	if _, err := h.Resolve(context.Background(), "wrong", "x"); err == nil {
		t.Fatal("a rejected handle must fail")
	}
}

func TestFallbackWhenHostLacksMethod(t *testing.T) {
	h := serve(t, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not implemented: xsec.code-audit.context"}}`)
	id, err := h.Resolve(context.Background(), "handle-1", "t")
	if err != nil || id.ProjectID != FallbackProject || id.Role != "parent" {
		t.Fatalf("%v %v", id, err)
	}
}

func TestRemoteEndpointRefused(t *testing.T) {
	if _, err := NewHost("http://example.com/plugin-host-rpc", func(string) {}); err == nil {
		t.Fatal("a non-loopback endpoint must be refused")
	}
}

func TestFallbackOnlyForAHostWithoutTheMethod(t *testing.T) {
	for _, msg := range []string{"unsupported Host RPC method: xsec.code-audit.context", "code-audit Host RPC is not mounted",
		"plugin Host RPC method is not implemented in the Go host yet: xsec.code-audit.context"} {
		h := serve(t, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"`+msg+`"}}`)
		if id, err := h.Resolve(context.Background(), "handle-1", "t"); err != nil || id.ProjectID != FallbackProject {
			t.Errorf("%q: %v %v", msg, id, err)
		}
	}
	for _, msg := range []string{"com.xsec.code-audit Host RPC assignment identity missing", "com.xsec.code-audit Host RPC assignment scope is stale",
		"com.xsec.code-audit Host RPC parent capability is retired"} {
		h := serve(t, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"`+msg+`"}}`)
		if _, err := h.Resolve(context.Background(), "handle-1", "t"); err == nil {
			t.Errorf("%q fell back instead of failing closed", msg)
		}
	}
}
