export type MarkdownBlock =
  | { type: "heading"; level: number; text: string }
  | { type: "paragraph"; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "code"; lang: string; text: string }
  | { type: "quote"; text: string }
  | { type: "hr" };

// An opening fence carries an info string that is any text without a backtick,
// not just word characters: models routinely tag blocks c++, c#, objective-c,
// sh-session and the like. Matching only \w meant the opening line was not
// recognised as a fence at all, so the code lines rendered as paragraphs and
// the trailing ``` was read as a *new* fence that swallowed the rest of the
// message. The language is the first whitespace-delimited token of the info
// string, per CommonMark.
const FENCE_OPEN = /^```([^`]*)$/;
// A closing fence is a bare ``` with only trailing whitespace and no info
// string, so an info-carrying line inside a block cannot close it early.
const FENCE_CLOSE = /^```\s*$/;
const HEADING = /^(#{1,6})\s+(.+?)\s*#*\s*$/;
const HR = /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/;
const QUOTE = /^>\s?(.*)$/;
const UL = /^\s*[-*+]\s+(.+)$/;
const OL = /^\s*\d+[.)]\s+(.+)$/;

function isBlank(line: string): boolean {
  return /^\s*$/.test(line);
}

function isStructural(line: string): boolean {
  return FENCE_OPEN.test(line) || HEADING.test(line) || HR.test(line) || QUOTE.test(line) || UL.test(line) || OL.test(line);
}

export function parseMarkdown(source: string): MarkdownBlock[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: MarkdownBlock[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];

    const fence = line.match(FENCE_OPEN);
    if (fence) {
      const body: string[] = [];
      index += 1;
      while (index < lines.length && !FENCE_CLOSE.test(lines[index])) {
        body.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      const lang = (fence[1] ?? "").trim().split(/\s+/)[0] ?? "";
      blocks.push({ type: "code", lang, text: body.join("\n") });
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
