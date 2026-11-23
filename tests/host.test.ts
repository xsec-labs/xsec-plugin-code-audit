import assert from "node:assert/strict";
import { test } from "node:test";
import { themeFacts, toConversation } from "../frontend-src/lib/host";

test("the pushed colour mode and on-primary win over the guess from colours", () => {
  assert.deepEqual(themeFacts({ "color-mode": "dark", "on-primary": "#fafafa", "content-surface": "#ffffff", "text-accent": "#0169cc" }), { dark: true, onPrimary: "#fafafa" });
  assert.deepEqual(themeFacts({ "content-surface": "#101014", "text-accent": "#0169cc" }), { dark: true, onPrimary: "#fff" });
});

test("a host without the composer method yields the manual route with no reason", async () => {
  const host = { request: async () => { throw new Error("unsupported Host RPC method"); } };
  assert.deepEqual(await toConversation(host as never, "x"), { kind: "manual", reason: "" });
});

test("a refusal keeps the host's reason and a success is sent", async () => {
  const refused = { request: async () => { throw new Error("session is read only"); } };
  assert.deepEqual(await toConversation(refused as never, "x"), { kind: "manual", reason: "session is read only" });
  const fine = { request: async () => ({}) };
  assert.deepEqual(await toConversation(fine as never, "x"), { kind: "sent" });
});

test("Desktop's own refusals of an unknown method count as 'the host cannot', a real refusal does not", async () => {
  const { hostLacksMethod } = await import("../frontend-src/lib/host");
  for (const msg of ["METHOD_NOT_DECLARED: 插件 x 没有声明方法 y", "METHOD_UNIMPLEMENTED: 方法 y 是 context 绑定，但宿主没有对应的实现", "CAPABILITY_NOT_GRANTED: not granted", "unsupported Host RPC method"]) {
    assert.equal(hostLacksMethod(new Error(msg)), true, msg);
  }
  assert.equal(hostLacksMethod(new Error("当前会话不可编辑")), false);
});
