// 插件 WebView 前端的本地截图环境：按 Desktop 的 xsec-plugin:// 协议（同样的页面文档、CSP、bootstrap.js）
// 加载一个插件的 frontend/index.js，用假宿主回放数据，在亮/暗两套 Desktop token 下截图。
//
//   node shoot.cjs <frontend.js> <fixture.cjs> <输出目录> [名称前缀]
//
// fixture.cjs 导出 { width, height, context, methods, shots? }：
//   methods: { "<host 方法>": 返回值 | "(params) => 返回值" 的函数源码字符串 }
//   shots:   [{ name, run: async (page) => {} }]，在默认截图之外再做几步操作后截图
// bootstrap.js 取自 xSecDesktop/go/internal/pluginhost/webbridge/bootstrap.js（XSEC_BOOTSTRAP 可覆盖路径）。
const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const [frontendPath, fixturePath, outDir, prefix = "shot"] = process.argv.slice(2);
const bootstrapPath = process.env.XSEC_BOOTSTRAP || "/home/user/xSecDesktop/go/internal/pluginhost/webbridge/bootstrap.js";
const fixture = require(path.resolve(fixturePath));

// 与 xSecDesktop go/internal/app/webplugins.go 的 themeVars、theme/tokens_gen.go 一致（默认强调色 #0169cc）。
const THEMES = {
  light: { "window-background": "#f7f7f8", "content-surface": "#ffffff", "bg-subtle": "#f0f0f2", "bg-hover": "#eaeaed", "text-primary": "#18181b", "text-secondary": "#62626b", "text-accent": "#0169cc", "border-default": "#dcdce1", "border-subtle": "#dcdce1", "status-error": "#b42318", "status-success": "#187344", "status-warning": "#8a5700", "radius-md": "8px", "radius-lg": "12px", "space-3": "12px", "space-4": "16px" },
  dark: { "window-background": "#111113", "content-surface": "#19191c", "bg-subtle": "#232327", "bg-hover": "#2d2d33", "text-primary": "#f4f4f5", "text-secondary": "#a1a1aa", "text-accent": "#0169cc", "border-default": "#35353c", "border-subtle": "#35353c", "status-error": "#ff938a", "status-success": "#7ad6a0", "status-warning": "#e9bd70", "radius-md": "8px", "radius-lg": "12px", "space-3": "12px", "space-4": "16px" },
};
const CSP = ["default-src 'none'", "base-uri 'none'", "child-src 'none'", "connect-src 'none'", "font-src 'none'", "form-action 'none'", "frame-ancestors 'none'", "frame-src 'none'", "img-src data:", "media-src 'none'", "object-src 'none'", "script-src 'self'", "style-src 'unsafe-inline'", "worker-src 'none'"].join("; ");
const DOC = `<!doctype html><meta charset="utf-8"><title></title><style>html,body,[data-xsec-plugin-root]{width:100%;height:100%;margin:0}</style><script src="/__xsec/bootstrap.js" data-xsec-channel="ch-1" data-xsec-frontend-api="2"></script>`;

const server = http.createServer((req, res) => {
  const url = req.url.split("?")[0];
  const send = (type, body) => { res.writeHead(200, { "Content-Type": type, "Content-Security-Policy": CSP }); res.end(body); };
  if (url === "/" || url === "/index.html") return send("text/html; charset=utf-8", DOC);
  if (url === "/__xsec/bootstrap.js") return send("text/javascript; charset=utf-8", fs.readFileSync(bootstrapPath));
  if (url === "/frontend.js") return send("text/javascript; charset=utf-8", fs.readFileSync(frontendPath));
  res.writeHead(404); res.end();
});

// 页面里的假宿主：实现 window.xsecHost（文本消息），收到 ready 后发主题和上下文，按 fixture 回应请求。
function fakeHost({ theme, context, methods }) {
  const listeners = [];
  const deliver = (m) => setTimeout(() => listeners.forEach((l) => l(JSON.stringify({ channel: "ch-1", ...m }))), 0);
  const handlers = {};
  for (const [name, value] of Object.entries(methods)) {
    handlers[name] = typeof value === "string" && /^\s*(async\s*)?\(/.test(value) ? (0, eval)(value) : () => value;
  }
  window.__xsecCalls = [];
  window.__xsecPush = (stream, text) => deliver({ type: "data", stream, payload: btoa(unescape(encodeURIComponent(text))) });
  window.__xsecPushBytes = (stream, b64) => deliver({ type: "data", stream, payload: b64 });
  window.__xsecTheme = (t) => deliver({ type: "theme", theme: t });
  window.xsecHost = {
    addListener: (l) => listeners.push(l),
    postMessage: (text) => {
      const m = JSON.parse(text);
      if (m.type === "ready") { deliver({ type: "theme", theme }); deliver({ type: "context", context }); return; }
      if (m.type === "module-error") { console.error("module-error " + JSON.stringify(m.detail)); return; }
      if (m.type !== "request") return;
      const { id, method, params } = m.request;
      window.__xsecCalls.push({ method, params });
      const h = handlers[method];
      if (!h) return deliver({ type: "response", response: { id, error: { message: "fixture 没有方法 " + method } } });
      Promise.resolve().then(() => h(params)).then(
        (result) => deliver({ type: "response", response: { id, result } }),
        (error) => deliver({ type: "response", response: { id, error: { message: String(error && error.message || error) } } }),
      );
    },
  };
}

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch();
  for (const [look, theme] of Object.entries(THEMES)) {
    const page = await browser.newPage({ viewport: { width: fixture.width || 1120, height: fixture.height || 760 }, deviceScaleFactor: 2, colorScheme: look });
    page.on("console", (m) => { if (m.type() === "error") console.log(`[${look}] console.error: ${m.text()}`); });
    page.on("pageerror", (e) => console.log(`[${look}] pageerror: ${e.message}`));
    await page.addInitScript(fakeHost, { theme, context: fixture.context, methods: fixture.methods });
    await page.goto(origin + "/index.html");
    await page.waitForTimeout(fixture.settle || 700);
    if (fixture.ready) await fixture.ready(page);
    await page.screenshot({ path: path.join(outDir, `${prefix}-${look}.png`) });
    for (const shot of fixture.shots || []) {
      await shot.run(page);
      await page.waitForTimeout(300);
      await page.screenshot({ path: path.join(outDir, `${prefix}-${shot.name}-${look}.png`) });
    }
    await page.close();
  }
  await browser.close();
  server.close();
})().catch((e) => { console.error(e); process.exit(1); });
