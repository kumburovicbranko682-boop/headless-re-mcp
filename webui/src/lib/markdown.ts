export type MarkdownBlock =
  | { type: "heading"; level: number; text: string }
  | { type: "paragraph"; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "code"; lang: string; text: string }
  | { type: "quote"; text: string }
  | { type: "hr" };

// The info string after a backtick fence is any run of non-whitespace, and a
// language tag is regularly not word-only: c++, c#, f#, objective-c. Capturing
// \w* dropped at the first non-word character, so ```c++ failed to match as a
// fence at all -- the opener and its code fell through to a paragraph and the
// closing ``` opened a stray empty code block. Backticks stay excluded because
// a backtick fence's info string may not contain one.
const FENCE = /^```([^\s`]*)\s*$/;
const HEADING = /^(#{1,6})\s+(.+?)\s*#*\s*$/;
const HR = /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/;
const QUOTE = /^>\s?(.*)$/;
const UL = /^\s*[-*+]\s+(.+)$/;
const OL = /^\s*\d+[.)]\s+(.+)$/;

function isBlank(line: string): boolean {
  return /^\s*$/.test(line);
}

function isStructural(line: string): boolean {
  return FENCE.test(line) || HEADING.test(line) || HR.test(line) || QUOTE.test(line) || UL.test(line) || OL.test(line);
}

export function parseMarkdown(source: string): MarkdownBlock[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: MarkdownBlock[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];

    const fence = line.match(FENCE);
    if (fence) {
      const body: string[] = [];
      index += 1;
      while (index < lines.length && !FENCE.test(lines[index])) {
        body.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push({ type: "code", lang: fence[1] ?? "", text: body.join("\n") });
      continue;
    }

    if (HR.test(line)) {
      blocks.push({ type: "hr" });
      index += 1;
      continue;
    }

    const heading = line.match(HEADING);
    if (heading) {
      blocks.push({ type: "heading", level: heading[1].length, text: heading[2] });
      index += 1;
      continue;
    }

    const quote = line.match(QUOTE);
    if (quote) {
      const body: string[] = [];
      while (index < lines.length) {
        const next = lines[index].match(QUOTE);
        if (!next) break;
        body.push(next[1]);
        index += 1;
      }
      blocks.push({ type: "quote", text: body.join("\n") });
      continue;
    }

    const unordered = line.match(UL);
    if (unordered) {
      const items: string[] = [];
      while (index < lines.length) {
        const next = lines[index].match(UL);
        if (!next) break;
        items.push(next[1]);
        index += 1;
      }
      blocks.push({ type: "list", ordered: false, items });
      continue;
    }

    const ordered = line.match(OL);
    if (ordered) {
      const items: string[] = [];
      while (index < lines.length) {
        const next = lines[index].match(OL);
        if (!next) break;
        items.push(next[1]);
        index += 1;
      }
      blocks.push({ type: "list", ordered: true, items });
      continue;
    }

    if (isBlank(line)) {
      index += 1;
      continue;
    }

    const body: string[] = [];
    while (index < lines.length && !isBlank(lines[index]) && !isStructural(lines[index])) {
      body.push(lines[index]);
      index += 1;
    }
    blocks.push({ type: "paragraph", text: body.join("\n") });
  }

  return blocks;
}

export function prettyJson(text: string): string | null {
  const trimmed = text.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed) as unknown, null, 2);
  } catch {
    return null;
  }
}

export function safeHref(href: string): string | null {
  const trimmed = href.trim();
  if (/^https?:\/\//i.test(trimmed) || /^mailto:/i.test(trimmed)) return trimmed;
  return null;
}
