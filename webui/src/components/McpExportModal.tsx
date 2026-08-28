import { useCallback, useRef, useState } from "react";
import { api } from "../api/client";

type ClientKind = "cursor" | "vscode" | "claude_desktop" | "stdio";

type ExportPayload = {
  ok?: boolean;
  config?: unknown;
  stdio?: unknown;
  examples?: Record<string, unknown>;
  python?: unknown;
  doctor_ready?: boolean;
  notes?: unknown;
  config_path?: string;
};

const CLIENTS: { id: ClientKind; label: string }[] = [
  { id: "cursor", label: "Cursor" },
  { id: "vscode", label: "VS Code" },
  { id: "claude_desktop", label: "Claude" },
  { id: "stdio", label: "stdio" },
];

function snippetOf(payload: ExportPayload, client: ClientKind): unknown {
  if (client === "stdio") return payload.stdio ?? payload.config;
  return payload.config ?? payload.examples?.[client];
}

export function McpExportModal({ onClose }: { onClose: () => void }) {
  const [client, setClient] = useState<ClientKind>("cursor");
  const [payload, setPayload] = useState<{ kind: ClientKind; data: ExportPayload } | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Discovery runs doctor probes, so a generate takes long enough for the user
  // to click another tab meanwhile. Only the newest request may write state,
  // or the slower response repaints the modal with another client's config.
  const opSeq = useRef(0);

  // The backend returns the config of the client that was *requested*; a
  // payload generated for one tab must never render under another tab's name,
  // or copy/download hands out the wrong client's JSON under that name.
  const snippet = payload && payload.kind === client ? snippetOf(payload.data, client) : null;
  const text = snippet ? JSON.stringify(snippet, null, 2) : "";

  const generate = useCallback(async (kind: ClientKind) => {
    const token = ++opSeq.current;
    setBusy(true); setError(null); setNote(null);
    try {
      const result = await api<ExportPayload>(`/api/mcp/export?client=${encodeURIComponent(kind)}`);
      if (token !== opSeq.current) return;
      setPayload({ kind, data: result });
      setNote(result.doctor_ready ? "已按本机路径生成。" : "已生成。Doctor 尚未全部就绪，配置仍可复制。");
    } catch (reason) {
      if (token !== opSeq.current) return;
      setError(String(reason));
    } finally {
      if (token === opSeq.current) setBusy(false);
    }
  }, []);

  const persist = useCallback(async () => {
    const token = ++opSeq.current;
    setBusy(true); setError(null);
    try {
      const result = await api<ExportPayload & { persisted?: boolean }>("/api/mcp/export", {
        method: "POST",
        body: JSON.stringify({ confirm: true, persist: true }),
      });
      if (token !== opSeq.current) return;
      setNote(result.config_path ? `已写入 ${result.config_path}` : "已写入本机配置目录。");
    } catch (reason) {
      if (token !== opSeq.current) return;
      setError(String(reason));
    } finally {
      if (token === opSeq.current) setBusy(false);
    }
  }, []);

  const copy = useCallback(async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setNote("已复制到剪贴板。");
    } catch {
      setError("复制失败，请手动选择文本。");
    }
  }, [text]);

  const download = useCallback(() => {
    if (!text) return;
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `headless-re-mcp-${client}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }, [client, text]);

  return <div className="modal-backdrop" role="presentation" onClick={onClose}>
    <section className="modal wide" role="dialog" aria-modal="true" aria-label="导出 MCP 配置" onClick={(event) => event.stopPropagation()}>
      <button className="modal-close" onClick={onClose}>×</button>
      <h2>导出 MCP 配置</h2>
      <p>按本机 Python / IDA / x64dbg 路径生成可粘贴的 MCP JSON。密钥不会写进片段。</p>
      <div className="mcp-tabs">
        {CLIENTS.map((item) => <button key={item.id} className={item.id === client ? "active" : ""} type="button" onClick={() => { setClient(item.id); void generate(item.id); }}>{item.label}</button>)}
      </div>
      <div className="modal-actions">
        <button disabled={busy} type="button" onClick={() => void generate(client)}>{busy ? "生成中…" : "识别并生成"}</button>
        <button disabled={!text} type="button" onClick={() => void copy()}>复制</button>
        <button disabled={!text} type="button" onClick={download}>下载 JSON</button>
        <button disabled={busy} type="button" onClick={() => void persist()}>写入配置目录</button>
      </div>
      {note && <div className="findings-report">{note}</div>}
      {error && <div className="error">{error}</div>}
      <pre className="mcp-pre">{text || "点「识别并生成」后在此显示配置。"}</pre>
    </section>
  </div>;
}
