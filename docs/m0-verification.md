# M0: real-device verification (xiaosong-mac)

Date 2026-11-23. Probe: `~/dev/code-audit-m0/m0probe.py` on xiaosong-mac (not committed). It starts the Desktop-bundled
`omp` (v18.20.2 fork) in ACP mode with Desktop's own overlay config, against a local fake OpenAI-compatible model that
records every request. A fake model proves how OMP assembles prompts, tools and concurrency; it does **not** measure how
many calls or how much time a real audit takes (see "Not measured").

## Results

| Question (plan §8) | Result |
| --- | --- |
| Session cwd | `ResolveACPCwd` accepts an absolute path, so a session can run with any directory. The audit session's cwd must **not** be the target (see below); the target is passed to `code_audit_run_start` as an absolute path. |
| Sub-agent concurrency | The native `task` tool runs sub-agents concurrently: 6 tasks sent their first model request within 0.05 s of each other, and each stayed in flight for the whole 6 s fake latency. |
| Sub-agent isolation | A sub-agent request contains only its own task text (`sub_sees_parent_prompt: false`, 2 messages). It has the parent's tools except `todo`. |
| Instruction files in the target | With Desktop's disabled-provider list, only the `claude-md` provider still loads: a `CLAUDE.md` in the cwd tree reached **both** the parent and the sub-agent prompts. `AGENTS.md`, `.cursorrules`, Copilot instructions, `.claude/rules`, skills, `.mcp.json`, `.omp/rules`, `.agents/AGENTS.md` and `SECURITY.md` were not loaded. With `claude-md` disabled nothing from the target reached any prompt. |
| MCP for sub-agents | OMP connects the stdio server and lists its tools, but the fake-model runs never showed the tool in a request's tool list, for parent or sub-agent, so sub-agent access to plugin MCP tools is **not demonstrated**. The design does not depend on it: only the parent writes, and sub-agents return text. |

## Consequences for the design

1. **Do not start the audit session inside the target.** A hostile `CLAUDE.md` would be loaded as instructions into every
   agent. The skill says the cwd is not the target and tells agents to read the target by absolute path.
2. **Optional hardening in Desktop** (separate small PR, to raise with the coordinator): add `claude-md` to
   `disabledExternalDiscoveryProviders` in `go/internal/service/agent/omp/profile.go`, so a target opened as the cwd is
   inert too.
3. **Host context method.** The sidecar groups runs by project. That needs a Desktop method `xsec.code-audit.context`
   (same shape as the JWT and attack-path ones: tool name in, `{projectId, role}` out, plus the router prefix and plugin id
   wiring). Until it exists (Desktop PR xsec-labs/xSecDesktop#1162) the sidecar falls back to one shared project `default`, and works standalone as project
   `local`. Sub-agent role enforcement (`ParentOnly` tools) also relies on that method's `role`.

## Not measured

- Real-model call count and wall time per profile (`quick`, `standard`, `deep`). Needs a real model on a real repo; do it
  with the first end-to-end run once the panel exists, and tune the default budgets from it.
- A plugin MCP tool being offered to an OMP sub-agent. Check with a real Desktop session once the Desktop context method
  is in.
