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
