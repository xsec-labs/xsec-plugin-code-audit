# com.xsec.code-audit

代码审计 (Code Audit): an xSec Desktop plugin that runs a source-code security audit with the session's Agent and keeps the
result as structured, validated records.

- **Method**: [`skills/security-audit`](skills/security-audit) is Cloudflare's
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT), vendored unchanged at the commit pinned
  in `skills/security-audit/UPSTREAM.json`. [`skills/xsec-code-audit`](skills/xsec-code-audit/SKILL.md) is the thin xSec
  adapter. The product ideas (scope modes, code snippets with findings, fix check, de-duplication, exports) follow
  openai/codex-security; no code is copied. See `THIRD_PARTY_NOTICES.md`.
- **Sidecar** (Go, no cgo, no Node): an MCP server for the run, coverage ledger, findings, reports and exports. Its
  source lives in xSecDesktop (`go/cmd/code-audit-mcp`, `go/internal/mcpsidecar/codeaudit`), like the other official
  native sidecars, and the xsec-plugins Factory builds it at a pinned Desktop commit. It contains both upstream
  validators ported to Go with the same messages; `testdata/golden/` holds ~4,300 cases recorded from the upstream Node
  validators. Desktop keeps a copy (`validate/testdata/golden`) that its Go tests must reproduce exactly; re-record here,
  then copy it over.
- **Source only**: v1 reads the target's source text and never builds, tests or runs it.
- **Panel** (`com.xsec.desktop/frontend/index.js`, generated from `frontend-src/`): a single-file WebView (Preact, host `--xsec-*` theme variables only) for the workspace tool (进度, 发现, 覆盖面, 报告, 新建审计, finding detail) and the settings page. It reads the sidecar through the `xsec.code-audit.*` frontend methods; an audit is started by putting a request into the conversation, never by a tool call from the panel.

Docs: [`docs/tool-contract.md`](docs/tool-contract.md) (sidecar tools), [`docs/m0-verification.md`](docs/m0-verification.md)
(real-device findings that shaped the design).

## Develop

```sh
# sidecar: in xSecDesktop/go (CGO_ENABLED=0 go test ./internal/mcpsidecar/codeaudit/... ; go build ./cmd/code-audit-mcp)
scripts/sync-upstream-skill.sh check                            # vendored skill still matches UPSTREAM.json
node scripts/gen-golden.cjs skills/security-audit               # re-record the golden corpus (needs Node 22)

pnpm install --frozen-lockfile && pnpm verify                   # panel: typecheck, build index.js, unit tests
NODE_PATH=$(npm root -g) node tests/harness/shoot.cjs com.xsec.desktop/frontend/index.js tests/harness/panel.fixture.cjs out panel
```

`com.xsec.desktop/frontend/index.js` is committed and CI fails if `pnpm build` changes it. `tests/harness/` replays fake sidecar
data (`data.cjs`) through Desktop's plugin page protocol in headless Chromium, in light and dark, at the 620 px side
width and at full width (fixtures: panel, running, wide, empty, settings, observe).

Run the sidecar by hand: `PLUGIN_DATA=$(mktemp -d) code-audit-mcp` (built from xSecDesktop), then send newline-delimited
JSON-RPC (`initialize`, `tools/list`, `tools/call`) on stdin.

To move to a new upstream version: `scripts/sync-upstream-skill.sh sync <ref>`, re-record the golden corpus, fix any Go
validator difference the tests show, then update the adapter skill if upstream steps changed.
