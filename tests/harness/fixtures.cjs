const D = require("./data.cjs");
const { wrap } = D;

const wrapSrc = `const wrap=(o)=>({content:[{type:"text",text:JSON.stringify(o)}],structuredContent:o,isError:false});`;

// Build the fake host's method table; each handler is a source string because the harness evals it inside the page.
function methods({ runs, current, findings = D.FINDINGS, units = D.UNITS, agents = D.AGENTS, config = null, files }) {
  const data = JSON.stringify({ runs, current, findings, units, agents, config, files: files ?? { "REPORT.md": true, "FINDINGS-DETAIL.md": true, "NEEDS-VALIDATION.md": true, "architecture.md": true }, reports: D.REPORTS });
  const fn = (body) => `(p)=>{const D=${data};${wrapSrc}${body}}`;
  const byStatus = (u) => u.reduce((m, x) => { m[x.status] = (m[x.status] || 0) + 1; return m; }, {});
  void byStatus;
  return {
    "xsec.code-audit.runs.list": fn(`return wrap({ok:true,total:D.runs.length,runs:D.runs});`),
    "xsec.code-audit.run.get": fn(`const run=D.runs.find(r=>r.run_id===p.run_id)||D.runs[0];const ev=run.status==="in_progress"?D.agents:D.agents.filter(e=>e.event!=="dispatched"||e.agent_id<"hunter-07");const running=run.status==="in_progress"?D.agents.filter(e=>["hunter-07","hunter-08","hunter-09","verifier-03"].includes(e.agent_id)):[];return wrap({ok:true,run:Object.assign({focus:[]},run),files:D.files,output_dir:"/data/runs",agent_calls:run.agent_calls,agents_running:running,agent_events:ev});`),
    "xsec.code-audit.findings.list": fn(`return wrap({ok:true,exists:true,total:Object.keys(D.findings).length,findings:Object.values(D.findings).map(f=>f.row),counts:{}});`),
    "xsec.code-audit.finding.get": fn(`const f=D.findings[p.fingerprint];if(!f)throw new Error("no finding");return wrap({ok:true,run_id:p.run_id,target:"/work/invoice-api",record:f.record,ext:f.ext,state:f.state});`),
    "xsec.code-audit.coverage.get": fn(`const by={};D.units.forEach(u=>{by[u.status]=(by[u.status]||0)+1});return wrap({ok:true,exists:true,total:D.units.length,by_status:by,matching:D.units.length,units:D.units});`),
    "xsec.code-audit.report.read": fn(`const t=D.reports[p.name];if(!t)throw new Error("文件还没有生成");return wrap({ok:true,name:p.name,markdown:t,bytes:t.length,truncated:false});`),
    "xsec.code-audit.export": fn(`return wrap({ok:true,path:"/data/code-audit/runs/p1/invoice-api/run-3/exports/findings."+p.format,records:4,bytes:2048});`),
    "xsec.code-audit.finding.state.set": fn(`return wrap({ok:true,state:Object.assign({},D.findings[p.fingerprint].state,{user_decision:p.user_decision&&p.user_decision!=="none"?p.user_decision:undefined,fix_status:p.fix_status&&p.fix_status!=="none"?p.fix_status:undefined})});`),
    "xsec.code-audit.run.delete": fn(`return wrap({ok:true});`),
    "xsec.plugin.config.get": fn(`return {value:D.config};`),
    "xsec.plugin.config.set": fn(`return {ok:true};`),
  };
}

const workspace = (mode = "interactive") => ({ kind: "workspace-tool", visible: true, surface: { bindingRevision: "1" }, tool: { id: "t1", kind: "code-audit", title: "代码审计" }, workspace: { mode, dock: "side", canAddComposerReference: true } });
const ALL = [D.RUNS.r3, D.RUNS.r2, D.RUNS.r1];
const click = (sel, nth = 0) => async (page) => { await page.locator(sel).nth(nth).click(); };
const tab = (name) => async (page) => { await page.getByRole("button", { name, exact: false }).filter({ has: page.locator(":scope") }).first().click(); };
const nav = (label) => async (page) => { await page.locator("nav.seg button", { hasText: label }).click(); };

module.exports = {
  // 620px side panel, finished run
  panel: {
    width: 620, height: 900, context: workspace(),
    methods: methods({ runs: ALL, current: ALL[0] }),
    shots: [
      { name: "progress", run: nav("进度") },
      { name: "findings", run: nav("发现") },
      { name: "detail", run: async (p) => { await p.locator(".row .rowbody").nth(1).click(); } },
      { name: "detail-needs", run: async (p) => { await p.locator(".detbar .ib[aria-label='返回列表']").click(); await p.locator(".row .rowbody").nth(4).click(); } },
      { name: "coverage", run: async (p) => { await p.locator(".detbar .ib").first().click(); await nav("覆盖面")(p); await p.locator("button.cell.cand").first().click(); } },
      { name: "findings-hover", run: async (p) => { await nav("发现")(p); await p.locator(".row").nth(1).hover(); } },
      { name: "export", run: async (p) => { await p.locator(".foot .btn", { hasText: "导出" }).click(); await p.getByRole("button", { name: "SARIF" }).click(); await p.waitForTimeout(300); } },
      { name: "report", run: nav("报告") },
      { name: "doc", run: async (p) => { await p.getByRole("button", { name: "打开" }).first().click(); } },
      { name: "start", run: async (p) => { await p.locator(".detbar .ib").first().click(); await p.locator("button[aria-label='新建审计']").click(); } },
      { name: "start-manual", run: async (p) => { await p.getByRole("button", { name: "代码变更" }).click(); await p.locator("input[aria-label='起点']").fill("main"); await p.getByRole("button", { name: "开始审计" }).click(); await p.waitForTimeout(300); } },
    ],
  },
  running: {
    width: 620, height: 900, context: workspace(),
    methods: methods({ runs: [D.live, D.RUNS.r2, D.RUNS.r1], current: D.live }),
  },
  wide: {
    width: 1440, height: 900, context: workspace(),
    methods: methods({ runs: ALL, current: ALL[0] }),
    shots: [
      { name: "detail", run: async (p) => { await nav("发现")(p); await p.locator(".row .rowbody").nth(1).click(); } },
      { name: "detail-needs", run: async (p) => { await p.locator(".rail .row .rowbody").nth(4).click(); } },
      { name: "coverage", run: async (p) => { await p.locator("button[aria-label='关闭详情']").click(); await nav("覆盖面")(p); await p.locator("button.cell.cand").nth(2).click(); } },
    ],
  },
  empty: {
    width: 620, height: 900, context: workspace(), methods: methods({ runs: [], current: null }),
  },
  settings: {
    width: 1100, height: 800, context: { kind: "settings-page", settings: { id: "settings", page: "settings" } },
    methods: methods({ runs: ALL, current: ALL[0], config: null }),
  },
  observe: {
    width: 620, height: 700, context: workspace("observe"), methods: methods({ runs: ALL, current: ALL[0] }),
  },
};
