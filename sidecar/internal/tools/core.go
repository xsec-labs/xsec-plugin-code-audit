// Package tools implements the MCP tools of the code-audit sidecar. Every tool is a quick read or write of
// files under PLUGIN_DATA (the host stops a plugin tool call after 20 seconds), never a long task, and none of
// them runs target code: the only thing they read from the audited tree is source text.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/hostctx"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
)

// Env is what every handler needs.
type Env struct {
	Store *store.Store
	Host  hostctx.Resolver
	Now   func() time.Time
}

// Call is one tools/call.
type Call struct {
	Ctx      context.Context
	Env      *Env
	Identity hostctx.Identity
	Args     *jsonv.Value
	tool     *Tool
}

// Tool is one MCP tool.
type Tool struct {
	Name        string
	Description string
	// Schema is the JSON Schema of the arguments.
	Schema string
	// ReadOnly tools never change data; the host may offer them to sub-agents.
	ReadOnly bool
	// ParentOnly tools are refused for a sub-agent identity.
	ParentOnly bool
	Handler    func(c *Call) (any, error)
}

// Error is a tool failure with optional structured details; the model sees both.
type Error struct {
	Msg     string
	Details any
}

func (e *Error) Error() string { return e.Msg }

func errf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

func errDetails(msg string, details any) error { return &Error{Msg: msg, Details: details} }

// Result is what the MCP layer sends back.
type Result struct {
	Text    string
	Struct  json.RawMessage
	IsError bool
}

// Invoke runs the tool.
func (t *Tool) Invoke(ctx context.Context, env *Env, meta Meta, rawArgs json.RawMessage) Result {
	args := jsonv.NewObject()
	if len(rawArgs) > 0 && string(rawArgs) != "null" {
		v, err := jsonv.Parse(rawArgs)
		if err != nil {
			return failure(errf("arguments are not valid JSON: %v", err))
		}
		if !v.IsObject() {
			return failure(errf("arguments must be a JSON object"))
		}
		args = v
	}
	ident, err := env.Host.Resolve(ctx, meta.ContextHandle, t.Name)
	if err != nil {
		return failure(errf("cannot resolve the project for this call: %v", err))
	}
	if t.ParentOnly && ident.Role == "sub" {
		return failure(errf("%s may only be called by the parent agent", t.Name))
	}
	c := &Call{Ctx: ctx, Env: env, Identity: ident, Args: args, tool: t}
	out, err := t.Handler(c)
	if err != nil {
		return failure(err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return failure(errf("internal error: %v", err))
	}
	return Result{Text: string(raw), Struct: raw}
}

// Meta is the request _meta.
type Meta struct{ ContextHandle string }

func failure(err error) Result {
	var te *Error
	body := map[string]any{"ok": false}
	if errors.As(err, &te) {
		body["error"] = te.Msg
		if te.Details != nil {
			body["details"] = te.Details
		}
	} else {
		body["error"] = err.Error()
	}
	raw, _ := json.Marshal(body)
	return Result{Text: string(raw), Struct: raw, IsError: true}
}

// ---- argument helpers ----

// strictKeys rejects unknown argument names so a typo does not silently pass.
func (c *Call) strictKeys(allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var unknown []string
	for _, k := range c.Args.Keys {
		if !ok[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return errf("unknown argument(s): %s (allowed: %s)", strings.Join(unknown, ", "), strings.Join(allowed, ", "))
	}
	return nil
}

func (c *Call) str(name string, required bool) (string, error) {
	v := c.Args.Get(name)
	if v == nil || v.Kind == jsonv.Null {
		if required {
			return "", errf("%s: required string", name)
		}
		return "", nil
	}
	if !v.IsString() {
		return "", errf("%s: expected a string", name)
	}
	if jsonv.HasLoneSurrogate(v.S) {
		return "", errf("%s: contains an invalid Unicode surrogate", name)
	}
	return v.S, nil
}

func (c *Call) boolean(name string, def bool) (bool, error) {
	v := c.Args.Get(name)
	if v == nil || v.Kind == jsonv.Null {
		return def, nil
	}
	if v.Kind != jsonv.Bool {
		return false, errf("%s: expected a boolean", name)
	}
	return v.B, nil
}

func (c *Call) intArg(name string, def, min, max int) (int, error) {
	v := c.Args.Get(name)
	if v == nil || v.Kind == jsonv.Null {
		return def, nil
	}
	if !v.IsInteger() || v.N < float64(min) || v.N > float64(max) {
		return 0, errf("%s: expected an integer between %d and %d", name, min, max)
	}
	return int(v.N), nil
}

func (c *Call) strList(name string, maxItems, maxLen int) ([]string, error) {
	v := c.Args.Get(name)
	if v == nil || v.Kind == jsonv.Null {
		return nil, nil
	}
	if !v.IsArray() {
		return nil, errf("%s: expected an array of strings", name)
	}
	if len(v.A) > maxItems {
		return nil, errf("%s: at most %d entries", name, maxItems)
	}
	out := make([]string, 0, len(v.A))
	for i, e := range v.A {
		if !e.IsString() || e.S == "" || len(e.S) > maxLen || jsonv.HasLoneSurrogate(e.S) {
			return nil, errf("%s[%d]: expected a non-empty string of at most %d bytes", name, i, maxLen)
		}
		out = append(out, e.S)
	}
	return out, nil
}

func (c *Call) enum(name string, required bool, allowed ...string) (string, error) {
	s, err := c.str(name, required)
	if err != nil || s == "" {
		return "", err
	}
	for _, a := range allowed {
		if s == a {
			return s, nil
		}
	}
	return "", errf("%s: must be one of %s", name, strings.Join(allowed, ", "))
}

func (c *Call) now() string { return c.Env.Now().UTC().Format(time.RFC3339) }

// runRef resolves the run_id argument against the caller's project.
func (c *Call) runRef() (store.RunRef, error) {
	id, err := c.str("run_id", true)
	if err != nil {
		return store.RunRef{}, err
	}
	ref, err := store.ParseRunID(c.Identity.ProjectID, id)
	if err != nil {
		return store.RunRef{}, &Error{Msg: err.Error()}
	}
	if !c.Env.Store.Exists(ref) {
		return store.RunRef{}, errf("run %s does not exist in this project", id)
	}
	return ref, nil
}

func compactJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}
