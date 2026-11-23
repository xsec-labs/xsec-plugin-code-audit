import assert from "node:assert/strict";
import { test } from "node:test";
import { AuditError, errorLines, listFindings, unwrap } from "../frontend-src/lib/api";

const ok = (obj: unknown) => ({ content: [{ type: "text", text: JSON.stringify(obj) }], structuredContent: obj, isError: false });

test("unwrap prefers structuredContent and falls back to the first text part", () => {
  assert.deepEqual(unwrap(ok({ ok: true, n: 1 })), { ok: true, n: 1 });
  assert.deepEqual(unwrap({ content: [{ type: "text", text: '{"ok":true,"n":2}' }] }), { ok: true, n: 2 });
});

test("unwrap turns isError and ok:false into AuditError with the sidecar message and validator lines", () => {
  const failure = { ok: false, error: "findings rejected", details: { errors: ["$[0].title: invalid text", 7] } };
  assert.throws(() => unwrap({ content: [{ type: "text", text: JSON.stringify(failure) }], structuredContent: failure, isError: true }), (e: unknown) => {
    assert.ok(e instanceof AuditError);
    assert.equal(e.message, "findings rejected");
    assert.deepEqual(errorLines(e), ["$[0].title: invalid text"]);
    return true;
  });
  assert.throws(() => unwrap({ content: [{ type: "text", text: "boom" }], isError: true }), /boom/);
  assert.throws(() => unwrap(null), AuditError);
  assert.throws(() => unwrap({ content: [] }), AuditError);
});

test("listFindings pages past the sidecar's 500-row limit", async () => {
  const calls: number[] = [];
  const host = {
    async request(_method: string, params: { offset: number; limit: number }) {
      calls.push(params.offset);
      const n = Math.min(params.limit, 1100 - params.offset);
      const findings = Array.from({ length: n }, (_, i) => ({ fingerprint: `fp-${params.offset + i}` }));
      const body = { ok: true, total: 1100, findings };
      return { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body };
    },
  };
  const rows = await listFindings(host as never, "repo/run-1");
  assert.equal(rows.length, 1100);
  assert.deepEqual(calls, [0, 500, 1000]);
});
