/** A small Markdown reader for the generated reports: blocks only, text is never interpreted as HTML. */

export type Inline = { kind: "text" | "code" | "strong" | "em"; text: string };
export type Block =
  | { kind: "heading"; level: number; inline: Inline[] }
  | { kind: "paragraph"; inline: Inline[] }
  | { kind: "list"; ordered: boolean; items: Inline[][] }
  | { kind: "code"; lang: string; text: string }
  | { kind: "quote"; inline: Inline[] }
  | { kind: "table"; header: Inline[][]; rows: Inline[][][] }
  | { kind: "rule" };

const INLINE = /`([^`]+)`|\*\*([^*]+)\*\*|__([^_]+)__|\*([^*\s][^*]*)\*/g;

export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  // Links keep their label: [label](url) -> label. The panel never navigates from report text.
  const plain = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1");
  for (const m of plain.matchAll(INLINE)) {
    if (m.index > last) out.push({ kind: "text", text: plain.slice(last, m.index) });
    if (m[1] !== undefined) out.push({ kind: "code", text: m[1] });
    else if (m[2] !== undefined || m[3] !== undefined) out.push({ kind: "strong", text: (m[2] ?? m[3])! });
    else out.push({ kind: "em", text: m[4]! });
    last = m.index + m[0].length;
  }
  if (last < plain.length) out.push({ kind: "text", text: plain.slice(last) });
  return out;
}

function splitRow(line: string): string[] {
  let body = line.trim();
  if (body.startsWith("|")) body = body.slice(1);
  if (body.endsWith("|")) body = body.slice(0, -1);
  return body.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
}

const isTableRule = (line: string) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line);
const listMatch = (line: string) => /^\s{0,3}([-*+]|\d+[.)])\s+(.*)$/.exec(line);

export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    if (!line.trim()) { i++; continue; }
    const fence = /^\s*(```|~~~)\s*([\w-]*)/.exec(line);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i]!.trim().startsWith(fence[1]!)) body.push(lines[i++]!);
      i++;
      blocks.push({ kind: "code", lang: fence[2] ?? "", text: body.join("\n") });
      continue;
    }
    const heading = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
    if (heading) { blocks.push({ kind: "heading", level: heading[1]!.length, inline: parseInline(heading[2]!) }); i++; continue; }
    if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(line)) { blocks.push({ kind: "rule" }); i++; continue; }
    if (line.includes("|") && i + 1 < lines.length && isTableRule(lines[i + 1]!)) {
      const header = splitRow(line).map(parseInline);
      const rows: Inline[][][] = [];
      i += 2;
      while (i < lines.length && lines[i]!.includes("|") && lines[i]!.trim()) rows.push(splitRow(lines[i++]!).map(parseInline));
      blocks.push({ kind: "table", header, rows });
      continue;
    }
    if (/^\s*>/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i]!)) body.push(lines[i++]!.replace(/^\s*>\s?/, ""));
      blocks.push({ kind: "quote", inline: parseInline(body.join(" ")) });
      continue;
    }
    const first = listMatch(line);
    if (first) {
      const ordered = /\d/.test(first[1]!);
      const items: Inline[][] = [];
      while (i < lines.length) {
        const m = listMatch(lines[i]!);
        if (!m || /\d/.test(m[1]!) !== ordered) {
          // A wrapped continuation line belongs to the previous item.
          if (items.length && lines[i]!.trim() && /^\s{2,}\S/.test(lines[i]!) && !m) { items[items.length - 1] = [...items[items.length - 1]!, ...parseInline(" " + lines[i]!.trim())]; i++; continue; }
          break;
        }
        items.push(parseInline(m[2]!));
        i++;
      }
      blocks.push({ kind: "list", ordered, items });
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i]!.trim() && !/^(#{1,6}\s|\s*```|\s*~~~|\s*>)/.test(lines[i]!) && !listMatch(lines[i]!)) para.push(lines[i++]!.trim());
    blocks.push({ kind: "paragraph", inline: parseInline(para.join(" ")) });
  }
  return blocks;
}
