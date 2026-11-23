// Package hostctx resolves which xSec project a tool call belongs to.
//
// The host signs a short-lived context handle for every tools/call of a trusted plugin and passes it in the
// request's _meta. The sidecar trades the handle for the call's identity through the host's loopback
// /plugin-host-rpc route (method xsec.code-audit.context, same pattern as the JWT and attack-path sidecars).
// Without a host endpoint (tests, standalone use) every call belongs to the project "local".
package hostctx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// MetaKey carries the context handle in a request's _meta.
	MetaKey = "com.xsec.desktop/contextHandle"
	// EndpointEnv names the environment variable with the host RPC endpoint.
	EndpointEnv = "XSEC_PLUGIN_HOST_RPC_ENDPOINT"

	contextMethod = "xsec.code-audit.context"
	// FallbackProject is used when the host does not implement the context method yet.
	FallbackProject = "default"
	// StandaloneProject is used when there is no host at all.
	StandaloneProject = "local"
)

// Identity is who is calling.
type Identity struct {
	ProjectID string
	// Role is "parent" or "sub"; empty is treated as parent (standalone).
	Role string
}

// Resolver turns a context handle into an Identity.
type Resolver interface {
	Resolve(ctx context.Context, handle, tool string) (Identity, error)
}

// Standalone resolves every call to the local project.
type Standalone struct{}

// Resolve implements Resolver.
func (Standalone) Resolve(context.Context, string, string) (Identity, error) {
	return Identity{ProjectID: StandaloneProject, Role: "parent"}, nil
}

// Host resolves through the host RPC route.
type Host struct {
	endpoint string
	client   *http.Client
	warn     func(string)
}

// NewHost validates a loopback endpoint.
func NewHost(endpoint string, warn func(string)) (*Host, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http") || u.User != nil {
		return nil, fmt.Errorf("host RPC endpoint must be a plain http URL")
	}
	hostname := u.Hostname()
	if ip := net.ParseIP(hostname); hostname != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("host RPC endpoint must be a loopback address")
	}
	if warn == nil {
		warn = func(string) {}
	}
	return &Host{
		endpoint: endpoint,
		warn:     warn,
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

// Resolve implements Resolver.
func (h *Host) Resolve(ctx context.Context, handle, tool string) (Identity, error) {
	if strings.TrimSpace(handle) == "" {
		return Identity{}, errors.New("the host did not send a context handle")
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": contextMethod, "params": map[string]any{"tool": tool}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+handle)
	resp, err := h.client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("host RPC: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Identity{}, err
	}
	var env struct {
		Result *struct {
			ProjectID *string `json:"projectId"`
			Role      string  `json:"role"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return Identity{}, fmt.Errorf("host RPC returned invalid JSON (HTTP %d)", resp.StatusCode)
	}
	if env.Error != nil {
		// A host that has not learned the code-audit context method yet: keep working, one shared project.
		if hostLacksMethod(env.Error.Message) {
			h.warn("host does not implement " + contextMethod + "; using project " + FallbackProject)
			return Identity{ProjectID: FallbackProject, Role: "parent"}, nil
		}
		return Identity{}, fmt.Errorf("host RPC rejected the call: %s", env.Error.Message)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 || env.Result == nil {
		return Identity{}, fmt.Errorf("host RPC failed (HTTP %d)", resp.StatusCode)
	}
	project := FallbackProject
	if env.Result.ProjectID != nil && *env.Result.ProjectID != "" {
		project = *env.Result.ProjectID
	}
	role := env.Result.Role
	if role == "" {
		role = "parent"
	}
	return Identity{ProjectID: project, Role: role}, nil
}

// hostLacksMethod recognises the answers of a Desktop that predates xsec.code-audit.context: the dispatcher of a
// host without the method family says "unsupported Host RPC method", a router without the mount says "not mounted",
// and a plugin dispatcher without the entry says "not implemented". Any other error (a refused identity, a retired
// lease, a stale project) is a real refusal and is returned to the caller: the call fails closed.
func hostLacksMethod(msg string) bool {
	for _, s := range []string{"not implemented", "unknown method", "unsupported Host RPC method", "Host RPC is not mounted"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
