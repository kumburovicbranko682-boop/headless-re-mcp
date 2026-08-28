import { useEffect, useRef, useState } from "react";
import { prettyJson } from "../lib/markdown";
import { MarkdownMessage } from "./MarkdownMessage";

const ROLE_LABEL: Record<string, string> = {
  user: "用户",
  assistant: "助手",
  system: "系统",
  tool: "工具",
};

type Props = {
  role: string;
  content: string;
  streaming?: boolean;
};

export function ChatMessage({ role, content, streaming = false }: Props) {
  const label = ROLE_LABEL[role] ?? role;
  const toolJson = role === "tool" ? prettyJson(content) : null;
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const prevContentRef = useRef(content);
  const [overflows, setOverflows] = useState(false);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    // A streaming reply grows purely by appending deltas, so each new content
    // extends the previous one. Collapsing on every change (as this used to)
    // snapped an expanded reply shut on the very next token, making a long
    // streaming answer impossible to keep open. Only reset when this is a
    // genuinely different message reusing the same element, not an append.
    if (!content.startsWith(prevContentRef.current)) setExpanded(false);
    prevContentRef.current = content;
    const node = bodyRef.current;
    if (!node) return;
    setOverflows(node.scrollHeight > 360);
  }, [content]);

  return (
    <article className={`message ${role}`}>
      <span className="message-role">{streaming ? `${label} · 实时` : label}</span>
      <div ref={bodyRef} className={expanded || !overflows ? "message-body" : "message-body clamp"}>
        {toolJson ? (
          <div className="md"><pre><code>{toolJson}</code></pre></div>
        ) : (
          <MarkdownMessage text={content} streaming={streaming} />
        )}
      </div>
      {overflows && !expanded && (
        <button type="button" className="message-expand" onClick={() => setExpanded(true)}>展开全部</button>
      )}
    </article>
  );
}

export function ThinkingMessage({ text = "" }: { text?: string }) {
  return (
    <article className="message assistant thinking-msg">
      <span className="message-role">助手 · 思考中</span>
      <div className="thinking-row">
        <span className="thinking-dots" aria-hidden="true"><span /><span /><span /></span>
        <span className="thinking-caption">正在思考</span>
      </div>
      {text ? <pre className="thinking-body">{text}</pre> : null}
    </article>
  );
}
