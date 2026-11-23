import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const manifest = JSON.parse(readFileSync(join(process.cwd(), "plugin.json"), "utf8"));
const methods = manifest.extensions["com.xsec.desktop"].frontendApi.methods as Record<string, { capability: string; mcpTool?: string }>;

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...sources(path));
    else if (/\.(ts|tsx)$/.test(name)) out.push(path);
  }
  return out;
}

test("every host method the frontend calls is declared in plugin.json", () => {
  const used = new Set<string>();
  for (const file of sources(join(process.cwd(), "frontend-src"))) {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/"(xsec\.(?:plugin|workspace)\.[a-z.-]+)"/g)) used.add(m[1]!);
    for (const m of text.matchAll(/call\(host, "([a-z.]+)"/g)) used.add(`xsec.code-audit.${m[1]}`);
  }
  assert.ok(used.has("xsec.code-audit.report.read") && used.has("xsec.plugin.config.get"));
  // The composer text method is feature-detected: Desktop does not offer it to plugins yet, so it is not declared.
  used.delete("xsec.workspace.composer.text.add");
  for (const method of used) assert.ok(method in methods, `${method} is used by the frontend but not declared`);
});

test("the report tab's read tool is bound with the read capability", () => {
  assert.equal(methods["xsec.code-audit.report.read"]?.mcpTool, "code_audit_report_read");
  assert.equal(methods["xsec.code-audit.report.read"]?.capability, "workspace.project.read");
});
