import assert from "node:assert/strict";
import { test } from "node:test";
import { AuditError, errorLines, unwrap } from "../frontend-src/lib/api";

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
