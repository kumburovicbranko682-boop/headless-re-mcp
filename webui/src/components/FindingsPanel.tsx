import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";

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
  const parts = Object.entries(value).slice(0, 3).map(([key, item]) => `${key}=${String(item)}`);
  return parts.length ? parts.join(", ") : "—";
}

export function FindingsPanel({ sessionId }: { sessionId: string }) {
  const [knowledge, setKnowledge] = useState<KnowledgeData | null>(null);
  const [report, setReport] = useState<ReportData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!sessionId) { setKnowledge(null); return; }
    const result = await api<Envelope<KnowledgeData>>(
      `/api/sessions/${encodeURIComponent(sessionId)}/knowledge`,
    );
    if (!result.ok || !result.data) {
      setKnowledge(null);
      setError(result.error?.message ?? "Findings are unavailable for this session");
      return;
    }
    setKnowledge(result.data);
    setError(null);
  }, [sessionId]);

  const generate = useCallback(async () => {
    if (!sessionId || busy) return;
    setBusy(true);
    try {
      const result = await api<Envelope<ReportData>>(
        `/api/sessions/${encodeURIComponent(sessionId)}/report`,
        { method: "POST", body: JSON.stringify({}) },
      );
      if (!result.ok || !result.data) throw new Error(result.error?.message ?? "report failed");
      setReport(result.data);
      setError(null);
    } catch (reason) {
      setError(String(reason));
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

  if (!sessionId) return <div className="findings-empty">Link a session to collect findings.</div>;

  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{knowledge?.total ?? 0} findings</span>
      <button onClick={() => void load()}>Refresh</button>
      <button disabled={busy} onClick={() => void generate()}>{busy ? "Rendering…" : "Generate report"}</button>
    </div>
    {error && <div className="findings-error">{error}</div>}
    {report && <div className="findings-report">
      Report written with {report.findings} findings · <code>{report.path}</code>
    </div>}
    {grouped.length === 0
      ? <div className="findings-empty">Nothing recorded yet. Agents add findings with <code>knowledge.record</code>.</div>
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
