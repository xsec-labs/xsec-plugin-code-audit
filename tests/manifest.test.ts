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

const agentTools = manifest.extensions["com.xsec.desktop"].contributes.agentTools as Record<
  string,
  { mcpTool: string; permission: string; roles?: string[] }
>;

test("the background audit tools are declared, read-only ones for parent and sub", () => {
  const readOnly = ["pass_status", "candidate_peek", "audit_list", "audit_get", "vuln_list", "vuln_get", "evidence_pack"];
  const writing = [
    "pass_start", "candidate_put", "coverage_put", "pass_finish",
    "verify_next", "verify_put", "verify_finish",
    "publish_next", "publish_ack",
  ];
  const byTool = new Map(Object.values(agentTools).map((t) => [t.mcpTool, t]));
  for (const name of readOnly) {
    const t = byTool.get(`code_audit_${name}`);
    assert.ok(t, `code_audit_${name} is not declared`);
    assert.equal(t.permission, "workspace.project.read");
    assert.deepEqual(t.roles, ["parent", "sub"]);
  }
  for (const name of writing) {
    const t = byTool.get(`code_audit_${name}`);
    assert.ok(t, `code_audit_${name} is not declared`);
    assert.equal(t.permission, "pluginData.write");
    assert.equal(t.roles, undefined, `${name} must stay parent-only`);
  }
});

test("the five host methods of the background audit carry the capabilities Desktop registers", () => {
  const expected: Record<string, string> = {
    "xsec.code-audit.preview": "workspace.project.read",
    "xsec.code-audit.start": "workspace.project.write",
    "xsec.code-audit.list": "workspace.project.read",
    "xsec.code-audit.get": "workspace.project.read",
    "xsec.code-audit.control": "workspace.project.write",
  };
  for (const [method, capability] of Object.entries(expected)) {
    assert.equal(methods[method]?.capability, capability, method);
    assert.equal(methods[method]?.mcpTool, undefined, `${method} is a host method, not an MCP tool`);
  }
});
