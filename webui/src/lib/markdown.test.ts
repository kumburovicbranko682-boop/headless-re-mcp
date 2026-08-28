import { parseMarkdown, prettyJson, safeHref } from "./markdown";

describe("parseMarkdown", () => {
  it("keeps paragraph line breaks instead of collapsing them", () => {
    expect(parseMarkdown("第一行\n第二行\n\n下一段")).toEqual([
      { type: "paragraph", text: "第一行\n第二行" },
      { type: "paragraph", text: "下一段" },
    ]);
  });

  it("parses headings, lists, rules and fences from a typical assistant reply", () => {
    const source = [
      "## 可用工具概览",
      "",
      "这是**一套完整**的工具集。",
      "",
      "---",
      "",
      "### 1. 会话管理",
      "",
      "1. `session.create` 创建会话",
      "2. `session.list` 列出会话",
      "",
      "- 只读工具自动执行",
      "",
      "```json",
      "{\"ok\":true}",
      "```",
    ].join("\n");

    expect(parseMarkdown(source)).toEqual([
      { type: "heading", level: 2, text: "可用工具概览" },
      { type: "paragraph", text: "这是**一套完整**的工具集。" },
      { type: "hr" },
      { type: "heading", level: 3, text: "1. 会话管理" },
      { type: "list", ordered: true, items: ["`session.create` 创建会话", "`session.list` 列出会话"] },
      { type: "list", ordered: false, items: ["只读工具自动执行"] },
      { type: "code", lang: "json", text: "{\"ok\":true}" },
    ]);
  });

  it("treats an unclosed fence as a code block so streaming stays readable", () => {
    expect(parseMarkdown("```js\nconst x = 1;")).toEqual([
      { type: "code", lang: "js", text: "const x = 1;" },
    ]);
  });

  it.each(["c++", "c#", "objective-c", "sh-session", "f#"])(
    "recognises a fence tagged with the non-word language %s",
    (lang) => {
      // \w-only matching failed to see the opening fence, so the body rendered
      // as paragraphs and the closing ``` opened a new block that ate the rest.
      expect(parseMarkdown(`\`\`\`${lang}\ncode line\n\`\`\``)).toEqual([
        { type: "code", lang, text: "code line" },
      ]);
    },
  );

  it("keeps only the first token of the info string as the language", () => {
    expect(parseMarkdown("```ts title=example.ts\nconst x = 1;\n```")).toEqual([
      { type: "code", lang: "ts", text: "const x = 1;" },
    ]);
  });

  it("does not let an info-carrying inner line close the block early", () => {
    // Only a bare ``` closes a block; a nested ```bash line stays content.
    expect(parseMarkdown("```\n```bash\nstill code\n```")).toEqual([
      { type: "code", lang: "", text: "```bash\nstill code" },
    ]);
  });
});

describe("prettyJson", () => {
  it("formats tool payloads and rejects plain text", () => {
    expect(prettyJson("{\"ok\":true}")).toBe("{\n  \"ok\": true\n}");
    expect(prettyJson("not json")).toBeNull();
  });
});

describe("safeHref", () => {
  it("allows http(s) and mailto, and rejects other schemes", () => {
    expect(safeHref("https://example.com/a")).toBe("https://example.com/a");
    expect(safeHref("mailto:a@b.com")).toBe("mailto:a@b.com");
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("/local")).toBeNull();
  });
});
