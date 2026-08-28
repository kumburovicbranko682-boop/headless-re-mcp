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

  it("leaves whitespace-flanked asterisks as literal text, not emphasis", () => {
    // "2 * 3 * 4" used to render as "2 <em> 3 </em> 4", silently dropping the
    // asterisks. CommonMark does not open emphasis on a space-flanked run.
    render(<MarkdownMessage text={"2 * 3 * 4 = 24"} />);
    expect(document.querySelector("em")).toBeNull();
    expect(
      screen.getByText((_content, element) => element?.tagName === "P" && element.textContent === "2 * 3 * 4 = 24"),
    ).toBeInTheDocument();
  });

  it("still renders single-character and internal-space emphasis", () => {
    render(<MarkdownMessage text={"*x* and *a b* and **c d**"} />);
    const ems = Array.from(document.querySelectorAll("em")).map((node) => node.textContent);
    expect(ems).toEqual(["x", "a b"]);
    expect(screen.getByText("c d").tagName).toBe("STRONG");
  });

  it("does not turn unsafe links into anchors", () => {
    render(<MarkdownMessage text={"[x](javascript:alert(1)) 和 [ok](https://example.com)"} />);
    expect(screen.queryByRole("link", { name: "x" })).toBeNull();
    expect(screen.getByRole("link", { name: "ok" })).toHaveAttribute("href", "https://example.com");
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
