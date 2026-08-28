import { type ReactNode } from "react";
import { parseMarkdown, safeHref, type MarkdownBlock } from "../lib/markdown";

type Props = { text: string; streaming?: boolean };

// Emphasis and strikethrough spans require their content to start and end with
// a non-whitespace character: a delimiter run flanked by whitespace does not
// open or close emphasis in CommonMark. The naive `\*(.+?)\*` matched a space-
// surrounded asterisk pair, so ordinary prose the assistant writes -- "2 * 3 *
// 4", "$5 * qty and $10 * weight", a glob like "src/* and lib/*" -- had a whole
// run of text swallowed into <em> and the literal asterisks dropped. `\S(?:.*?
// \S)??` (rather than lookbehind, which older Safari cannot parse) captures a
// single non-space char, or a non-space run whose last char is also non-space;
// the tail group is lazy-optional (`??`) so the shortest valid span wins and
// single-character emphasis like *x* still matches while " * " does not.
const INLINE_RE =
  /`([^`\n]+)`|\*\*(\S(?:.*?\S)??)\*\*|\[([^\]]+)\]\(([^)\s]+)\)|~~(\S(?:.*?\S)??)~~|\*(\S(?:.*?\S)??)\*/g;

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let match: RegExpExecArray | null;
  let part = 0;
  const pattern = new RegExp(INLINE_RE.source, INLINE_RE.flags);
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) nodes.push(text.slice(last, match.index));
    const key = `${keyPrefix}-${part}`;
    part += 1;
    if (match[1] !== undefined) {
      nodes.push(<code key={key}>{match[1]}</code>);
    } else if (match[2] !== undefined) {
      nodes.push(<strong key={key}>{renderInline(match[2], key)}</strong>);
    } else if (match[3] !== undefined) {
      const href = safeHref(match[4] ?? "");
      const label = renderInline(match[3], key);
      nodes.push(href ? <a key={key} href={href} target="_blank" rel="noreferrer">{label}</a> : <span key={key}>{label}</span>);
    } else if (match[5] !== undefined) {
      nodes.push(<del key={key}>{renderInline(match[5], key)}</del>);
    } else if (match[6] !== undefined) {
      nodes.push(<em key={key}>{renderInline(match[6], key)}</em>);
    }
    last = match.index + match[0].length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function renderLines(text: string, keyPrefix: string): ReactNode[] {
  const lines = text.split("\n");
  return lines.flatMap((line, index) => {
    const inline = renderInline(line, `${keyPrefix}-${index}`);
    if (index === lines.length - 1) return inline;
    return [...inline, <br key={`${keyPrefix}-br-${index}`} />];
  });
}

function Heading({ level, children }: { level: number; children: ReactNode }) {
  if (level <= 1) return <h1>{children}</h1>;
  if (level === 2) return <h2>{children}</h2>;
  if (level === 3) return <h3>{children}</h3>;
  if (level === 4) return <h4>{children}</h4>;
  if (level === 5) return <h5>{children}</h5>;
  return <h6>{children}</h6>;
}

function renderBlock(block: MarkdownBlock, index: number): ReactNode {
  const key = `b${index}`;
  switch (block.type) {
    case "heading":
      return <Heading key={key} level={block.level}>{renderInline(block.text, key)}</Heading>;
    case "paragraph":
      return <p key={key}>{renderLines(block.text, key)}</p>;
    case "list": {
      const items = block.items.map((item, itemIndex) => <li key={`${key}-${itemIndex}`}>{renderInline(item, `${key}-${itemIndex}`)}</li>);
      return block.ordered ? <ol key={key}>{items}</ol> : <ul key={key}>{items}</ul>;
    }
    case "code":
      return <pre key={key}><code data-lang={block.lang || undefined}>{block.text}</code></pre>;
    case "quote":
      return <blockquote key={key}>{renderLines(block.text, key)}</blockquote>;
    case "hr":
      return <hr key={key} />;
  }
}

function looksLikeRawJson(text: string): boolean {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return true;
  if (!trimmed.startsWith("[")) return false;
  try {
    JSON.parse(trimmed);
    return true;
  } catch {
    return false;
  }
}

export function MarkdownMessage({ text, streaming = false }: Props) {
  if (text.length > 12000 || looksLikeRawJson(text)) {
    const clipped = text.length > 20000 ? `${text.slice(0, 20000)}\n…` : text;
    return (
      <div className="md">
        <pre><code>{clipped}</code></pre>
        {streaming && <span className="cursor" aria-hidden="true" />}
      </div>
    );
  }
  const blocks = parseMarkdown(text);
  return (
    <div className="md">
      {blocks.length === 0 ? (streaming ? null : <p />) : blocks.map(renderBlock)}
      {streaming && <span className="cursor" aria-hidden="true" />}
    </div>
  );
}
