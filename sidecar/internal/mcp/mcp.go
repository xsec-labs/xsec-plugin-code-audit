// Package mcp serves the tools over the Model Context Protocol on stdio (newline-delimited JSON-RPC 2.0).
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/hostctx"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/tools"
)

const (
	// Version is the plugin sidecar's version, reported in serverInfo.
	Version = "0.1.0"

	maxMessage       = 48 << 20
	latestProtocol   = "2025-06-18"
	maxConcurrentRPC = 8
)

var supportedProtocols = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true}

// Server is one stdio MCP server.
type Server struct {
	Env   *tools.Env
	Tools []*tools.Tool
	Log   func(format string, a ...any)

	byName map[string]*tools.Tool
	wmu    sync.Mutex
	out    io.Writer
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads requests until in is closed.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.out = out
	s.byName = map[string]*tools.Tool{}
	for _, t := range s.Tools {
		s.byName[t.Name] = t
	}
	if s.Log == nil {
		s.Log = func(string, ...any) {}
	}
	r := bufio.NewReaderSize(in, 1<<20)
	sem := make(chan struct{}, maxConcurrentRPC)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		line, err := readLine(r)
		if len(line) > 0 {
			var req request
			if jerr := json.Unmarshal(line, &req); jerr != nil {
				s.reply(nil, nil, &rpcError{Code: -32700, Message: "parse error"})
			} else if req.Method == "tools/call" {
				sem <- struct{}{}
				wg.Add(1)
				go func() {
					defer func() { <-sem; wg.Done() }()
					s.handle(ctx, &req)
				}()
			} else {
				s.handle(ctx, &req)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxMessage {
			return nil, fmt.Errorf("message larger than %d bytes", maxMessage)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return trimEOL(buf), err
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func (s *Server) reply(id json.RawMessage, result any, e *rpcError) {
	if id == nil {
		id = json.RawMessage("null")
	}
	raw, err := json.Marshal(response{JSONRPC: "2.0", ID: id, Result: result, Error: e})
	if err != nil {
		raw, _ = json.Marshal(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32603, Message: "internal error"}})
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.out.Write(append(raw, '\n'))
}

func (s *Server) handle(ctx context.Context, req *request) {
	isNotification := len(req.ID) == 0
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := latestProtocol
		if supportedProtocols[p.ProtocolVersion] {
			version = p.ProtocolVersion
		}
		s.reply(req.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "xsec-code-audit", "version": Version},
			"instructions":    "Source-code audit bookkeeping. These tools store the run, ledger and findings; they never execute the audited code.",
		}, nil)
	case "ping":
		s.reply(req.ID, map[string]any{}, nil)
	case "tools/list":
		list := make([]map[string]any, 0, len(s.Tools))
		for _, t := range s.Tools {
			list = append(list, map[string]any{
				"name": t.Name, "description": t.Description, "inputSchema": json.RawMessage(t.Schema),
				"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Name == "code_audit_run_delete", "openWorldHint": false},
			})
		}
		s.reply(req.ID, map[string]any{"tools": list}, nil)
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      map[string]any  `json:"_meta"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			s.reply(req.ID, nil, &rpcError{Code: -32602, Message: "invalid params"})
			return
		}
		t := s.byName[p.Name]
		if t == nil {
			s.reply(req.ID, nil, &rpcError{Code: -32602, Message: "unknown tool " + p.Name})
			return
		}
		handle, _ := p.Meta[hostctx.MetaKey].(string)
		res := t.Invoke(ctx, s.Env, tools.Meta{ContextHandle: handle}, p.Arguments)
		out := map[string]any{
			"content": []map[string]any{{"type": "text", "text": res.Text}},
			"isError": res.IsError,
		}
		if len(res.Struct) > 0 {
			out["structuredContent"] = res.Struct
		}
		s.reply(req.ID, out, nil)
	default:
		if !isNotification {
			s.reply(req.ID, nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
		}
	}
}
