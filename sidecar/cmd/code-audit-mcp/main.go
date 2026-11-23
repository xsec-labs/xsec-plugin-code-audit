// Command code-audit-mcp is the xSec Code Audit plugin's MCP sidecar. It speaks MCP over stdio and keeps audit
// runs under PLUGIN_DATA. It never executes the audited code.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/hostctx"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/mcp"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/tools"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "code-audit-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(mcp.Version)
		return nil
	}
	dataDir := os.Getenv("PLUGIN_DATA")
	if dataDir == "" {
		return fmt.Errorf("PLUGIN_DATA is not set")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "code-audit-mcp: "+format+"\n", a...) }
	var resolver hostctx.Resolver = hostctx.Standalone{}
	if ep := os.Getenv(hostctx.EndpointEnv); ep != "" {
		h, err := hostctx.NewHost(ep, func(s string) { logf("%s", s) })
		if err != nil {
			return err
		}
		resolver = h
	}
	srv := &mcp.Server{
		Env:   &tools.Env{Store: st, Host: resolver, Now: time.Now},
		Tools: tools.All(),
		Log:   logf,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}
