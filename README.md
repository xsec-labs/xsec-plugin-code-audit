# com.xsec.code-audit

代码审计 (Code Audit): an xSec Desktop plugin that runs a source-code security audit with the session's Agent and keeps the
result as structured, validated records.

- **Method**: [`skills/security-audit`](skills/security-audit) is Cloudflare's
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT), vendored unchanged at the commit pinned
  in `skills/security-audit/UPSTREAM.json`. [`skills/xsec-code-audit`](skills/xsec-code-audit/SKILL.md) is the thin xSec
  adapter. The product ideas (scope modes, code snippets with findings, fix check, de-duplication, exports) follow
  openai/codex-security; no code is copied. See `THIRD_PARTY_NOTICES.md`.
- **Sidecar** (`sidecar/`, Go, no cgo, no Node): an MCP server for the run, coverage ledger, findings, reports and
  exports. It contains both upstream validators ported to Go with the same messages; `testdata/golden/` holds ~4,300
  cases recorded from the upstream Node validators, which the Go tests must reproduce exactly.
- **Source only**: v1 reads the target's source text and never builds, tests or runs it.
- **Panel** (`com.xsec.desktop/frontend`, source in `frontend-src/`): arrives in M2/M3; the file here is a placeholder.

Docs: [`docs/tool-contract.md`](docs/tool-contract.md) (sidecar tools), [`docs/m0-verification.md`](docs/m0-verification.md)
(real-device findings that shaped the design).

## Develop

```sh
cd sidecar && CGO_ENABLED=0 go vet ./... && go test ./...      # also GOOS=windows / darwin go vet
scripts/build-sidecar.sh [GOOS GOARCH]                          # dist/<os>-<arch>/code-audit-mcp
scripts/sync-upstream-skill.sh check                            # vendored skill still matches UPSTREAM.json
node scripts/gen-golden.cjs skills/security-audit               # re-record the golden corpus (needs Node 22)
```

Run the sidecar by hand: `PLUGIN_DATA=$(mktemp -d) sidecar/dist/.../code-audit-mcp`, then send newline-delimited
JSON-RPC (`initialize`, `tools/list`, `tools/call`) on stdin.

To move to a new upstream version: `scripts/sync-upstream-skill.sh sync <ref>`, re-record the golden corpus, fix any Go
validator difference the tests show, then update the adapter skill if upstream steps changed.
