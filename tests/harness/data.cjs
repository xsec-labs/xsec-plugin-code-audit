// Fake sidecar data for the screenshot harness: the invoice-api example of the design boards, in the sidecar's shapes.
const wrap = (obj) => ({ content: [{ type: "text", text: JSON.stringify(obj) }], structuredContent: obj, isError: false });

const T = (m) => new Date(Date.UTC(2026, 10, 23, 6, 20) - m * 60_000).toISOString();
const counts = (c, n, r, sev, units, us) => ({ confirmed: c, needs_validation: n, rejected: r, severity: sev, units, unit_status: us });

const RUNS = {
  r3: {
    run_id: "invoice-api-a1b2c3/run-3", repo: "invoice-api-a1b2c3", target: "/work/invoice-api", profile: "standard",
    scope: { mode: "repo" }, status: "complete", incomplete_reason: "", phase: "report", budget: 60,
    source_ref: { commit: "a41c9e7d2f", dirty: false }, created_at: T(95), updated_at: T(40), completed_at: T(40),
    counts: counts(4, 1, 1, { critical: 1, high: 2, medium: 1 }, 42, { covered: 29, candidate: 6, blocked: 3, deferred: 4 }),
    agent_calls: 58, agents_running: 0,
  },
  r2: {
    run_id: "invoice-api-a1b2c3/run-2", repo: "invoice-api-a1b2c3", target: "/work/invoice-api", profile: "quick",
    scope: { mode: "diff", base: "main", head: "feat/export" }, status: "complete", incomplete_reason: "", phase: "report", budget: 30,
    source_ref: { commit: "9f02b1d" }, created_at: "2026-11-20T09:10:00Z", updated_at: "2026-11-20T09:40:00Z", completed_at: "2026-11-20T09:40:00Z",
    counts: counts(1, 0, 0, { high: 1 }, 12, { covered: 12 }), agent_calls: 17, agents_running: 0,
  },
  r1: {
    run_id: "invoice-api-a1b2c3/run-1", repo: "invoice-api-a1b2c3", target: "/work/invoice-api", profile: "standard",
    scope: { mode: "repo" }, status: "incomplete", incomplete_reason: "validation_budget_exhausted", phase: "validate", budget: 40,
    source_ref: { commit: "c7d3a10" }, created_at: "2026-11-18T09:10:00Z", updated_at: "2026-11-18T10:40:00Z", completed_at: "",
    counts: counts(2, 2, 0, { high: 1, medium: 1 }, 30, { covered: 20, candidate: 4, deferred: 6 }), agent_calls: 40, agents_running: 0,
  },
};
const live = JSON.parse(JSON.stringify(RUNS.r3));
Object.assign(live, {
  run_id: "invoice-api-a1b2c3/run-3", status: "in_progress", phase: "hunt", completed_at: "", created_at: T(18), updated_at: T(0),
  counts: counts(3, 1, 0, { critical: 1, high: 2 }, 42, { covered: 18, candidate: 9, in_progress: 4, planned: 11 }), agent_calls: 31, agents_running: 4,
});

const step = (role, index, file, line, lines, start) => ({ role, index, file, line, snippet: { start_line: start, lines } });
const FINDINGS = {
  "tenant-export-noauth": {
    row: { fingerprint: "tenant-export-noauth", verdict: "confirmed", title: "未登录即可导出任意租户发票", file: "cmd/api/router.go", line: 57, severity: "critical", likelihood: "high", impact: "critical", confidence: "high", state: { first_seen_run: "invoice-api-a1b2c3/run-3" } },
    record: {
      verdict: "confirmed", fingerprint: "tenant-export-noauth", title: "未登录即可导出任意租户发票",
      description: "内部导出路由挂在没有鉴权中间件的路由组上，任何人传入租户 id 就能下载该租户的全部发票。",
      root_cause: "导出路由注册在 internal 组，组上只做了网络来源假设，没有 RequireLogin。", intended_behavior: "导出只允许已登录且属于目标租户的管理员调用。",
      trace: [
        { kind: "entrypoint", file: "cmd/api/router.go", line: 55, scope: "router", description: "internal 路由组没有挂鉴权" },
        { kind: "sink", file: "internal/export/handler.go", line: 40, scope: "export", description: "按路径里的租户 id 直接导出" },
      ],
      evidence: [{ file: "cmd/api/router.go", line: 57, description: "导出路由注册行" }],
      conditions: [{ kind: "authentication_level", description: "无需登录" }, { kind: "network_routing", description: "服务对外可达" }],
      execution: { attacker_perspective: "任何能访问服务的人。", payloads: ["GET /internal/export/42"], instructions: ["向服务发起不带会话的请求", "把路径里的 42 换成目标租户 id"], observed_result: "返回 200 和该租户的发票压缩包。" },
      remediation: { strategy: "把导出路由挂到带 RequireLogin 和租户校验的路由组上。", code_changes: [{ file_name: "cmd/api/router.go", fixed_code: "admin := r.Group(\"/internal\", mw.RequireLogin(), mw.RequireTenantAdmin())\nadmin.GET(\"/export/:tenant\", h.Export)" }] },
      severity: { likelihood: { score: "high", reason: "不需要任何凭据" }, impact: { score: "critical", reason: "跨租户导出全部发票" }, overall_severity: "critical" },
      confidence: { score: "high", reason: "完整路径已在源码中确认" },
    },
    ext: { cwe: ["CWE-306"], steps: [step("trace", 0, "cmd/api/router.go", 55, ["53  r := gin.New()", "54  internal := r.Group(\"/internal\")", "55  internal.GET(\"/export/:tenant\", h.Export)"].map((l) => l.replace(/^\d+ +/, "")), 53), step("trace", 1, "internal/export/handler.go", 40, ["39  func (h *Handler) Export(c *gin.Context) {", "40      zip, err := h.svc.ExportTenant(c, c.Param(\"tenant\"))"].map((l) => l.replace(/^\d+ +/, "")), 39), step("evidence", 0, "cmd/api/router.go", 57, ["internal.GET(\"/export/:tenant\", h.Export)"], 57)] },
    state: { first_seen_run: "invoice-api-a1b2c3/run-3" },
  },
  "invoice-idor": {
    row: { fingerprint: "invoice-idor", verdict: "confirmed", title: "发票详情接口未校验租户归属", file: "internal/store/invoice.go", line: 131, severity: "high", likelihood: "high", impact: "high", confidence: "high", state: { first_seen_run: "invoice-api-a1b2c3/run-3" } },
    record: {
      verdict: "confirmed", fingerprint: "invoice-idor", title: "发票详情接口未校验租户归属",
      description: "任一已登录用户把路径里的发票 id 换成其他租户的 id，就能读取对方发票的全部字段。查询只按 id 过滤，没有带上当前租户。",
      root_cause: "存储层 GetInvoice 的 SQL 只有 id 条件，租户隔离依赖调用方，而调用方没有传。", intended_behavior: "任何读取都必须带上会话里的租户条件。",
      trace: [
        { kind: "entrypoint", file: "cmd/api/router.go", line: 42, scope: "router", description: "路由只挂了登录校验，没有租户校验" },
        { kind: "propagation", file: "internal/handler/invoice.go", line: 88, scope: "handler", description: "路径参数原样传给存储层" },
        { kind: "sink", file: "internal/store/invoice.go", line: 131, scope: "store", description: "查询缺少 tenant_id 条件" },
      ],
      evidence: [{ file: "internal/store/invoice.go", line: 131, description: "SQL 只按 id 过滤" }],
      conditions: [{ kind: "authentication_level", description: "任一租户的已登录用户" }, { kind: "data_state", description: "目标租户存在发票" }],
      execution: { attacker_perspective: "租户 A 的普通用户。", payloads: ["GET /v1/invoices/1042"], instructions: ["用租户 A 的测试账号登录，记下会话。", "在租户 B 下创建一张发票，得到 id，例如 1042。", "用租户 A 的会话请求 GET /v1/invoices/1042。"], observed_result: "返回 200 和租户 B 的发票内容。" },
      remediation: { strategy: "在存储层强制带上租户条件，调用方从会话取租户，不接受参数传入。", code_changes: [{ file_name: "internal/store/invoice.go", fixed_code: "row := s.db.QueryRow(ctx,\n  `SELECT * FROM invoices WHERE id = $1 AND tenant_id = $2`, id, tenant.From(ctx))" }] },
      severity: { likelihood: { score: "high", reason: "只需一个普通账号，id 为自增整数" }, impact: { score: "high", reason: "跨用户读取发票金额、客户与税号" }, overall_severity: "high" },
      confidence: { score: "high", reason: "路径完整，已独立复核" },
    },
    ext: { cwe: ["CWE-639"], steps: [step("trace", 0, "cmd/api/router.go", 42, ["auth := r.Group(\"/v1\", mw.RequireLogin())", "auth.GET(\"/invoices/:id\", h.GetInvoice)"], 41), step("trace", 1, "internal/handler/invoice.go", 88, ["func (h *Handler) GetInvoice(c *gin.Context) {", "    inv, err := h.store.GetInvoice(c, c.Param(\"id\"))"], 87), step("trace", 2, "internal/store/invoice.go", 131, ["func (s *Store) GetInvoice(ctx context.Context, id string) (*Invoice, error) {", "    row := s.db.QueryRow(ctx, `SELECT * FROM invoices WHERE id = $1`, id)"], 130)] },
    state: { first_seen_run: "invoice-api-a1b2c3/run-3" },
  },
  "webhook-empty-key": {
    row: { fingerprint: "webhook-empty-key", verdict: "confirmed", title: "Webhook 签名在密钥为空时恒通过", file: "internal/webhook/verify.go", line: 24, severity: "high", likelihood: "medium", impact: "high", confidence: "high", state: { fix_status: "fixed", first_seen_run: "invoice-api-a1b2c3/run-1" } },
    record: {
      verdict: "confirmed", fingerprint: "webhook-empty-key", title: "Webhook 签名在密钥为空时恒通过", description: "密钥未配置时 HMAC 用空密钥计算，攻击者可以自己算出合法签名。",
      root_cause: "没有在启动时拒绝空密钥。", intended_behavior: "未配置密钥时拒绝所有 Webhook。",
      trace: [{ kind: "entrypoint", file: "internal/webhook/verify.go", line: 20, scope: "webhook", description: "入口读取配置密钥" }, { kind: "sink", file: "internal/webhook/verify.go", line: 24, scope: "webhook", description: "空密钥 HMAC 比较" }],
      evidence: [{ file: "internal/webhook/verify.go", line: 24, description: "未检查空密钥" }], conditions: [{ kind: "system_configuration", description: "WEBHOOK_SECRET 未设置" }],
      execution: { attacker_perspective: "外部调用者。", payloads: ["POST /webhook/stripe"], instructions: ["不设置密钥部署", "用空密钥计算签名后调用"], observed_result: "请求被接受。" },
      remediation: { strategy: "启动时校验密钥非空。" },
      severity: { likelihood: { score: "medium", reason: "依赖配置缺失" }, impact: { score: "high", reason: "可伪造支付事件" }, overall_severity: "high" }, confidence: { score: "high", reason: "已确认" },
    },
    ext: { cwe: ["CWE-347"], steps: [step("trace", 0, "internal/webhook/verify.go", 20, ["key := os.Getenv(\"WEBHOOK_SECRET\")"], 20), step("trace", 1, "internal/webhook/verify.go", 24, ["mac := hmac.New(sha256.New, []byte(key))"], 24)] },
    state: { fix_status: "fixed", fix_note: "第 2 次运行确认已加空密钥检查", first_seen_run: "invoice-api-a1b2c3/run-1" },
  },
  "pdf-template-traversal": {
    row: { fingerprint: "pdf-template-traversal", verdict: "confirmed", title: "PDF 模板可读取任意本地模板文件", file: "internal/pdf/render.go", line: 48, severity: "medium", likelihood: "medium", impact: "medium", confidence: "medium", state: { first_seen_run: "invoice-api-a1b2c3/run-3" } },
    record: {
      verdict: "confirmed", fingerprint: "pdf-template-traversal", title: "PDF 模板可读取任意本地模板文件", description: "模板名来自请求参数，没有限制在模板目录内。",
      root_cause: "文件名拼接后直接读取。", intended_behavior: "只能读取模板目录内的文件。",
      trace: [{ kind: "entrypoint", file: "internal/pdf/render.go", line: 40, scope: "pdf", description: "模板名来自请求" }, { kind: "sink", file: "internal/pdf/render.go", line: 48, scope: "pdf", description: "拼接路径读取" }],
      evidence: [{ file: "internal/pdf/render.go", line: 48, description: "未限制目录" }], conditions: [],
      execution: { attacker_perspective: "已登录用户。", payloads: ["../../etc/passwd"], instructions: ["把模板名设为 ../../etc/passwd"], observed_result: "返回非模板文件内容。" },
      remediation: { strategy: "用 filepath.Base 并校验目录前缀。" },
      severity: { likelihood: { score: "medium", reason: "需要登录" }, impact: { score: "medium", reason: "只读，限于可读文件" }, overall_severity: "medium" }, confidence: { score: "medium", reason: "未运行验证" },
    },
    ext: { cwe: ["CWE-22"], steps: [step("trace", 0, "internal/pdf/render.go", 40, ["name := req.Template"], 40), step("trace", 1, "internal/pdf/render.go", 48, ["b, err := os.ReadFile(filepath.Join(dir, name))"], 48)] },
    state: { first_seen_run: "invoice-api-a1b2c3/run-3" },
  },
  "upload-callback-ssrf": {
    row: { fingerprint: "upload-callback-ssrf", verdict: "needs_validation", title: "上传回调地址可能触发 SSRF", file: "internal/upload/callback.go", line: 66, state: { first_seen_run: "invoice-api-a1b2c3/run-3" } },
    record: {
      verdict: "needs_validation", fingerprint: "upload-callback-ssrf", title: "上传回调地址可能触发 SSRF",
      description: "上传完成后服务端会请求用户提交的回调地址。源码里没有限制内网地址，但出站流量是否经过拦截代理，仓库里看不到。",
      claimed_root_cause: "回调地址只校验了 scheme，没有拒绝内网段。",
      trace: [{ kind: "entrypoint", file: "internal/handler/upload.go", line: 52, scope: "handler", description: "回调地址来自请求体" }, { kind: "sink", file: "internal/upload/callback.go", line: 66, scope: "upload", description: "直接对该地址发起 POST" }],
      evidence: [{ file: "internal/upload/callback.go", line: 65, description: "只校验了 scheme" }],
      blockers: ["生产环境的出口代理是否拒绝 169.254.0.0/16 和 10.0.0.0/8", "HTTP_PROXY 在部署清单里由谁注入，仓库内没有对应配置"],
      validation_plan: { local: "用现有的 callback_test.go 起一个回环监听，提交 http://127.0.0.1 回调，看是否收到请求。", deployment: "请运维确认出口代理的内网拒绝规则。" },
    },
    ext: { cwe: ["CWE-918"], steps: [step("trace", 0, "internal/handler/upload.go", 52, ["cb := req.CallbackURL // 来自请求体"], 52), step("trace", 1, "internal/upload/callback.go", 66, ["// 只校验了 scheme", "resp, err := s.http.Post(cb, \"application/json\", body)"], 65), step("evidence", 0, "internal/upload/callback.go", 65, ["// 只校验了 scheme"], 65)] },
    state: { first_seen_run: "invoice-api-a1b2c3/run-3" },
  },
  "login-enum": {
    row: { fingerprint: "login-enum", verdict: "rejected", title: "登录接口可枚举用户名", file: "internal/auth/login.go", line: 39, state: {} },
    record: {
      verdict: "rejected", fingerprint: "login-enum", title: "登录接口可枚举用户名", description: "怀疑错误响应能区分用户是否存在。", claimed_root_cause: "不同错误文案。",
      trace: [{ kind: "sink", file: "internal/auth/login.go", line: 39, scope: "auth", description: "统一返回错误" }], evidence: [{ file: "internal/auth/login.go", line: 39, description: "错误响应一致" }],
      reason: "错误响应一致，且已有限速，无法区分用户是否存在。",
    },
    ext: { cwe: ["CWE-204"], steps: [step("trace", 0, "internal/auth/login.go", 39, ["return c.JSON(401, errInvalid)"], 39)] },
    state: {},
  },
};

const U = (id, surface, ref, boundary, bref, cls, status, extra = {}) => ({
  coverage_id: id, canonical_refs: { surface: ref, boundary: bref, subsystem: "internal", attack_class: "ATTACK-CLASSES.md#" + cls },
  surface, boundary, subsystem: "internal", attack_class: cls, starting_paths: [ref], prior_status: "none", wave: 1, status, agent_id: null,
  reviewed_paths: [], local_checks: [], result_fingerprints: [], unresolved: [], ...extra,
});
const SURF = [["公开 HTTP 接口", "cmd/api", "租户会话", "mw.RequireLogin"], ["内部导出路由", "internal/export", "导出鉴权", "mw.RequireTenantAdmin"], ["Webhook 接收", "internal/webhook", "签名校验", "verify.go#Verify"], ["文件上传与回调", "internal/upload", "出口代理", "callback.go#Post"], ["PDF 渲染", "internal/pdf", "模板目录", "render.go#Render"], ["管理端前端", "web/admin", "前端路由守卫", "guard.ts"], ["构建与发布", ".github, Dockerfile", "发布流水线", "release.yml"]];
const CLS = ["访问控制", "认证", "注入", "数据隔离", "出站请求", "资源耗尽", "供应链"];
const grid = [
  "cand cov cov cand na cov na", "cand cov cov cov na pl na", "cov cand cov cov cov cov na", "cov cov cov cov blk pl na", "na na cand cov cov cov na", "cov cov cand na na na cov", "na blk na na na pl blk",
];
const ST = { cov: "covered", cand: "candidate", blk: "blocked", pl: "deferred", na: "not_applicable", run: "in_progress", q: "planned" };
const UNITS = [];
SURF.forEach(([surface, ref, boundary, bref], ri) => {
  grid[ri].split(" ").forEach((c, ci) => {
    if (c === "na" && (ri + ci) % 2 === 0) return;
    const status = ST[c];
    const extra = status === "covered" || status === "candidate" || status === "blocked" ? { agent_id: "hunter-0" + (1 + ((ri + ci) % 4)), wave: 1 + (ci % 2), reviewed_paths: [ref + "/router.go", ref + "/handler.go", ref + "/store.go"], local_checks: [{ agent_id: "hunter-0" + (1 + ((ri + ci) % 4)), reviewed_paths: [ref + "/router.go"], invariant: "逐个核对 14 个读写接口的租户条件", method: "source", result: "2 个缺失", artifact: null }] } : {};
    if (status === "candidate" && ri === 0 && ci === 3) extra.result_fingerprints = ["invoice-idor"];
    if (status === "candidate" && ri === 1 && ci === 0) extra.result_fingerprints = ["tenant-export-noauth"];
    if (status === "candidate" && ri === 3) extra.result_fingerprints = ["upload-callback-ssrf"];
    if (status === "covered" && ri === 0 && ci === 3) { extra.result_fingerprints = []; }
    if (status === "deferred" || status === "blocked") extra.unresolved = ["预算内排不上，下一轮再审"];
    UNITS.push(U(`${ri}-${ci}`, surface, ref + "#" + surface, boundary, bref, CLS[ci], status, extra));
  });
});
// the (0,3) cell was left covered above; make it a candidate so the design's highlighted cell exists
const REPORTS = {
  "REPORT.md": "# invoice-api 安全审计报告\n\n本次审计共确认 **4** 个问题，另有 1 个待验证。\n\n## 结论\n\n- 严重 1：未登录即可导出任意租户发票\n- 高危 2\n- 中危 1\n\n| 严重程度 | 数量 |\n| --- | --- |\n| 严重 | 1 |\n| 高危 | 2 |\n\n> 待验证项需要运行环境事实才能判断。\n\n```text\ncode_audit_report_build\n```\n",
  "FINDINGS-DETAIL.md": "# 发现明细\n\n## 1. 未登录即可导出任意租户发票\n\n路径：`cmd/api/router.go:55` → `internal/export/handler.go:40`\n",
  "NEEDS-VALIDATION.md": "# 待验证清单\n\n1. 上传回调地址可能触发 SSRF\n2. 另一项\n",
  "architecture.md": "# 架构与信任边界\n\n五条信任边界：公开接口、内部导出、Webhook、上传回调、管理端。\n",
};

const AGENTS = [
  { at: T(9), event: "dispatched", agent_id: "hunter-07", role: "hunter", phase: "hunt", unit_ids: ["3-1"], summary: "Webhook 接收 × 签名校验 × 认证绕过" },
  { at: T(8), event: "dispatched", agent_id: "hunter-08", role: "hunter", phase: "hunt", unit_ids: ["1-3"], summary: "导出任务 × 租户边界 × 访问控制" },
  { at: T(8), event: "dispatched", agent_id: "hunter-09", role: "hunter", phase: "hunt", unit_ids: ["4-2"], summary: "PDF 模板 × 用户输入 × 注入" },
  { at: T(5), event: "dispatched", agent_id: "verifier-03", role: "verifier", phase: "validate", unit_ids: ["3-4"], summary: "反驳候选：上传回调 SSRF" },
  { at: T(12), event: "dispatched", agent_id: "hunter-01", role: "hunter", phase: "hunt" }, { at: T(10), event: "returned", agent_id: "hunter-01", role: "hunter" },
  { at: T(12), event: "dispatched", agent_id: "hunter-02", role: "hunter", phase: "hunt" }, { at: T(10), event: "returned", agent_id: "hunter-02", role: "hunter" },
];

module.exports = { wrap, RUNS, live, FINDINGS, UNITS, REPORTS, AGENTS, counts };
