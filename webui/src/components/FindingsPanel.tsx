import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import { isSessionGone, inspectorDisconnectedHint } from "../lib/sessionGone";

type KnowledgeEntry = {
  kind: string;
  key: string;
  value?: Record<string, unknown> | null;
  updated_at?: string;
};

type KnowledgeData = {
  entries: KnowledgeEntry[];
  total: number;
  kinds?: Record<string, number>;
};

type ReportData = { path: string; bytes: number; findings: number };

type Envelope<T> = { ok: boolean; data?: T; error?: { message?: string } };

function summarize(value: KnowledgeEntry["value"]): string {
  if (!value || typeof value !== "object") return "—";
  const parts = Object.entries(value).slice(0, 3).map(([key, item]) => `${key}=${typeof item === "object" && item !== null ? "[object]" : String(item)}`);
  return parts.length ? parts.join(", ") : "—";
}

export function FindingsPanel({ sessionId, onSessionMissing }: { sessionId: string; onSessionMissing?: (id: string) => void }) {
  const [knowledge, setKnowledge] = useState<KnowledgeData | null>(null);
  const [report, setReport] = useState<ReportData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The panel doesn't remount when the bound session changes, and nothing polls
  // this list: a slow response for the previous session landing after the new
  // session's would stick as its findings until a manual refresh. Compare the
  // session each response was fetched for against the latest prop.
  const currentSession = useRef(sessionId);
  currentSession.current = sessionId;

  const load = useCallback(async () => {
    if (!sessionId) { setKnowledge(null); return; }
    const result = await api<Envelope<KnowledgeData>>(
      `/api/sessions/${encodeURIComponent(sessionId)}/knowledge`,
    );
    if (currentSession.current !== sessionId) return;
    if (!result.ok || !result.data) {
      setKnowledge(null);
      const gone = isSessionGone(result.error);
      setError(gone ? inspectorDisconnectedHint() : (result.error?.message ?? "暂无发现"));
      if (gone) onSessionMissing?.(sessionId);
      return;
    }
    setKnowledge(result.data);
    setError(null);
  }, [onSessionMissing, sessionId]);

  const generate = useCallback(async () => {
    if (!sessionId || busy) return;
    setBusy(true);
    try {
      const result = await api<Envelope<ReportData>>(
        `/api/sessions/${encodeURIComponent(sessionId)}/report`,
        { method: "POST", body: JSON.stringify({}) },
      );
      if (currentSession.current !== sessionId) return;
      if (!result.ok || !result.data) throw new Error(result.error?.message ?? "报告生成失败");
      setReport(result.data);
      setError(null);
    } catch (reason) {
      if (currentSession.current === sessionId) setError(String(reason));
    } finally {
      setBusy(false);
    }
  }, [busy, sessionId]);

  useEffect(() => {
    setReport(null);
    setError(null);
    void load();
  }, [load]);

  const grouped = useMemo(() => {
    const buckets = new Map<string, KnowledgeEntry[]>();
    for (const entry of knowledge?.entries ?? []) {
      const list = buckets.get(entry.kind) ?? [];
      list.push(entry);
      buckets.set(entry.kind, list);
    }
    return [...buckets.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [knowledge]);

  if (!sessionId) return <div className="findings-empty">关联会话后才会收集发现。</div>;

  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{knowledge?.total ?? 0} 条发现</span>
      <button onClick={() => void load()}>刷新</button>
      <button disabled={busy} onClick={() => void generate()}>{busy ? "生成中…" : "生成报告"}</button>
    </div>
    {error && <div className="findings-error">{error}</div>}
    {report && <div className="findings-report">
      已写入报告，含 {report.findings} 条发现 · <code>{report.path}</code>
    </div>}
    {grouped.length === 0
      ? <div className="findings-empty">还没有记录。Agent 用 <code>knowledge.record</code> 写入发现。</div>
      : grouped.map(([kind, entries]) => <details key={kind} open>
          <summary>{kind} ({entries.length})</summary>
          <div className="findings-list">
            {entries.map((entry) => <div className="finding" key={`${kind}:${entry.key}`}>
              <b>{entry.key}</b>
              <span>{summarize(entry.value)}</span>
            </div>)}
          </div>
        </details>)}
  </section>;
}
