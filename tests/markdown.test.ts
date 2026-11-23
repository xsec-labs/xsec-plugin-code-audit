import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMarkdown, parseInline } from "../frontend-src/lib/markdown";

test("blocks: headings, lists, tables, quotes, code fences and paragraphs", () => {
  const blocks = parseMarkdown("# T\n\ntext **bold** and `code`\n\n- a\n- b\n\n| h1 | h2 |\n| --- | --- |\n| 1 | 2 |\n\n> quote\n\n```go\nx := 1\n```\n");
  assert.deepEqual(blocks.map((b) => b.kind), ["heading", "paragraph", "list", "table", "quote", "code"]);
  const table = blocks[3]!;
  assert.ok(table.kind === "table");
  assert.equal(table.rows.length, 1);
  const code = blocks[5]!;
  assert.ok(code.kind === "code");
  assert.equal(code.text, "x := 1");
});

test("inline: code and bold are separated, links keep their label, HTML stays text", () => {
  assert.deepEqual(parseInline("a **b** `c` [d](http://x)"), [
    { kind: "text", text: "a " }, { kind: "strong", text: "b" }, { kind: "text", text: " " }, { kind: "code", text: "c" }, { kind: "text", text: " d" },
  ]);
  assert.deepEqual(parseInline("<img src=x onerror=alert(1)>"), [{ kind: "text", text: "<img src=x onerror=alert(1)>" }]);
});

test("an unterminated fence does not loop", () => {
  const blocks = parseMarkdown("```\nabc");
  assert.equal(blocks.length, 1);
});
