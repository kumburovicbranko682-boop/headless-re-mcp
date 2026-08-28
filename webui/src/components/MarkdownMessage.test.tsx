import { render, screen } from "@testing-library/react";
import { ChatMessage, ThinkingMessage } from "./ChatMessage";
import { MarkdownMessage } from "./MarkdownMessage";

describe("MarkdownMessage", () => {
  it("renders headings, line breaks, emphasis and inline code", () => {
    render(
      <MarkdownMessage
        text={"## 可用工具\n这是**完整**工具集。\n下一行\n\n- `session.create`"}
      />,
    );

    expect(screen.getByRole("heading", { level: 2, name: "可用工具" })).toBeInTheDocument();
    expect(screen.getByText("完整").tagName).toBe("STRONG");
    expect(screen.getByText("session.create").tagName).toBe("CODE");
    expect(document.querySelector("br")).not.toBeNull();
    expect(screen.getByText((content, element) => element?.tagName === "P" && content.includes("下一行"))).toBeInTheDocument();
  });

  it("does not turn unsafe links into anchors", () => {
    render(<MarkdownMessage text={"[x](javascript:alert(1)) 和 [ok](https://example.com)"} />);
    expect(screen.queryByRole("link", { name: "x" })).toBeNull();
    expect(screen.getByRole("link", { name: "ok" })).toHaveAttribute("href", "https://example.com");
  });

  it("keeps parentheses that belong to a link's URL", () => {
    render(
      <MarkdownMessage
        text={"see [C++](https://en.wikipedia.org/wiki/C%2B%2B_(programming_language)) now"}
      />,
    );
    expect(screen.getByRole("link", { name: "C++" })).toHaveAttribute(
      "href",
      "https://en.wikipedia.org/wiki/C%2B%2B_(programming_language)",
    );
    // The closing paren was consumed by the URL, so it must not leak as text.
    expect(screen.queryByText(/\)\s*now/)).toBeNull();
  });

  it("escapes raw HTML instead of executing it", () => {
    render(<MarkdownMessage text={"<script>alert(1)</script>"} />);
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
  });
});

describe("ChatMessage", () => {
  it("pretty-prints tool JSON on separate lines", () => {
    render(<ChatMessage role="tool" content={'{"ok":true,"n":1}'} />);
    expect(screen.getByText("工具")).toBeInTheDocument();
    expect(screen.getByText(/"ok": true/)).toBeInTheDocument();
  });

  it("marks a streaming assistant reply", () => {
    render(<ChatMessage role="assistant" content={"## 标题"} streaming />);
    expect(screen.getByText("助手 · 实时")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "标题" })).toBeInTheDocument();
    expect(document.querySelector(".cursor")).not.toBeNull();
  });

  it("shows a thinking placeholder before visible tokens", () => {
    render(<ThinkingMessage text="hmm" />);
    expect(screen.getByText("正在思考")).toBeInTheDocument();
    expect(screen.getByText("hmm")).toBeInTheDocument();
    expect(document.querySelector(".thinking-dots")).not.toBeNull();
  });
});
