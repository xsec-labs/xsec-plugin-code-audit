import { useEffect, useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import type { Session } from "./session";
import type { ReportName } from "../types";
import { readReport, AuditError } from "../lib/api";
import { parseMarkdown, type Block, type Inline } from "../lib/markdown";
import { ErrorNote } from "./common";
import { Icon } from "./icons";

function inline(parts: Inline[]): ComponentChildren {
  return parts.map((p, i) => p.kind === "code" ? <code key={i} class="tag">{p.text}</code> : p.kind === "strong" ? <strong key={i}>{p.text}</strong> : p.kind === "em" ? <em key={i}>{p.text}</em> : p.text);
}

function block(b: Block, i: number): ComponentChildren {
  switch (b.kind) {
    case "heading": {
      const level = Math.min(b.level + 1, 6);
      const Tag = `h${level}` as "h2";
      return <Tag key={i} class="mdh">{inline(b.inline)}</Tag>;
    }
    case "paragraph": return <p key={i} class="body-text">{inline(b.inline)}</p>;
    case "quote": return <blockquote key={i}>{inline(b.inline)}</blockquote>;
    case "rule": return <hr key={i} />;
    case "code": return <pre key={i} class="code plain">{b.text}</pre>;
    case "list": {
      const Tag = b.ordered ? "ol" : "ul";
      return <Tag key={i} class="bul">{b.items.map((it, j) => <li key={j}>{inline(it)}</li>)}</Tag>;
    }
    case "table": return (
      <div class="tablewrap" key={i}>
        <table class="md"><thead><tr>{b.header.map((h, j) => <th key={j}>{inline(h)}</th>)}</tr></thead>
          <tbody>{b.rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}>{inline(c)}</td>)}</tr>)}</tbody></table>
      </div>
    );
  }
}

export const DOC_TITLES: Record<ReportName, string> = {
  "REPORT.md": "总览报告",
  "FINDINGS-DETAIL.md": "发现明细",
  "NEEDS-VALIDATION.md": "待验证清单",
  "architecture.md": "架构与信任边界",
};

export function DocView({ s, name, onBack }: { s: Session; name: ReportName; onBack(): void }) {
  const run = s.run;
  const [text, setText] = useState<{ markdown: string; truncated: boolean } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const runId = run?.run_id;
  useEffect(() => {
    if (!runId) return;
    let live = true;
    setText(null);
    setError(null);
    readReport(s.host, runId, name).then((t) => { if (live) setText(t); }, (e) => { if (live) setError(e); });
    return () => { live = false; };
  }, [s.host, runId, name]);
  return (
    <div class="col">
      <div class="detbar">
        <button type="button" class="ib" onClick={onBack} aria-label="返回"><Icon name="chevronLeft" /></button>
        <b>{DOC_TITLES[name]}</b><span class="tag">{name}</span>
      </div>
      <div class="scroll pad doc">
        {error ? <ErrorNote message={error instanceof AuditError ? error.message : "读取失败"} /> : null}
        {!error && !text ? <span class="muted">正在读取…</span> : null}
        {text ? parseMarkdown(text.markdown).map(block) : null}
        {text?.truncated ? <p class="muted small">文档过长，只显示了前 4 MiB。</p> : null}
      </div>
    </div>
  );
}
