import { useCallback, useEffect, useRef, useState } from "react";
import type { RunEvent } from "../agent/state";
import { api, apiBlob } from "../api/client";
import type { WorkspaceProfile } from "../lib/inspectorSurface";
import { inspectorSurface, isSessionLive, peLiveMonitors, SURFACE_LABEL } from "../lib/inspectorSurface";
import { dormantHint, inspectorDisconnectedHint, isSessionGone } from "../lib/sessionGone";
import { asChildText, workflowSummary } from "../lib/textChild";
import { ApkMonitor } from "./ApkMonitor";
import { FindingsPanel } from "./FindingsPanel";
import { SessionReconnect, type LostSample } from "./SessionReconnect";
import { VirtualDesktopMonitor } from "./VirtualDesktopMonitor";
import { WebMonitor } from "./WebMonitor";

type Envelope<T> = { ok?: boolean; data?: T; error?: { code?: string; message?: string } };
type Artifact = { id: string; kind?: string; path?: string; created_at?: string; bytes?: number };
type AuditEntry = { id?: string; at?: string; action?: string; ok?: boolean; session_id?: string | null };
type TimelineItem = { at?: string; event?: string; message?: string };
type DebugEvent = { type?: string; name?: string; message?: string; event?: string };
type MonitorData = {
  ok?: boolean;
  session?: { id?: string; state?: string; binary?: string; target?: string };
  dynamic?: { state?: string; process_id?: number; debuggee_pid?: number; error?: { message?: string } | null };
  unpack?: { stage?: string | null };
  workflow?: { present?: boolean; data?: { state?: string; stage?: string; status?: string } | null };
  timeline?: { items?: TimelineItem[] };
  events?: { items?: DebugEvent[] };
  error?: { message?: string };
};

function EventList({ events }: { events: RunEvent[] }) {
  if (events.length === 0) return <div className="findings-empty">还没有工具事件。发送一条消息后会出现在这里。</div>;
  return <div className="event-list">{events.slice(-40).reverse().map((event) => <details className="event" key={`${event.run_id}-${event.seq}`}>
    <summary><b>{event.seq}</b><span>{event.type}</span></summary>
    <pre>{JSON.stringify(event.data, null, 2)}</pre>
  </details>)}</div>;
}

function MonitorPanel({
  sessionId,
  peLive,
  dormant,
  onSessionMissing,
  onSessionClosed,
}: {
  sessionId: string;
  peLive: boolean;
  dormant?: boolean;
  onSessionMissing?: (id: string) => void;
  onSessionClosed?: (id: string) => void;
}) {
  const [data, setData] = useState<MonitorData | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // These panels don't remount when the bound session changes -- they only get a
  // new prop -- so a slow response for the previous session can land after the
  // new session's and overwrite it. Each load compares the session it fetched
  // for against the latest prop and drops the result when the user moved on.
  const currentSession = useRef(sessionId);
  currentSession.current = sessionId;

  const load = useCallback(async () => {
    if (!sessionId) { setData(null); setError(null); return; }
    try {
      const result = await api<Envelope<MonitorData>>(`/api/sessions/${encodeURIComponent(sessionId)}/monitor`);
      if (currentSession.current !== sessionId) return;
      const payload = result.data ?? null;
      setData(payload);
      if (result.ok === false || payload?.ok === false) {
        const message = payload?.error?.message ?? result.error?.message ?? "";
        const gone = isSessionGone(payload?.error, message);
        setError(gone ? inspectorDisconnectedHint() : (message || "监控不可用"));
        if (gone) onSessionMissing?.(sessionId);
        return;
      }
      setError(null);
    } catch (reason) {
      if (currentSession.current !== sessionId) return;
      setError(String(reason));
    }
  }, [onSessionMissing, sessionId]);

  useEffect(() => {
    void load();
    if (!sessionId) return undefined;
    let cancelled = false;
    void (async () => {
      try {
        const result = await api<Envelope<MonitorData>>(`/api/sessions/${encodeURIComponent(sessionId)}/monitor`);
        if (cancelled) return;
        const payload = result.data ?? null;
        setData(payload);
        if (result.ok === false || payload?.ok === false) {
          const message = payload?.error?.message ?? "";
          const gone = isSessionGone(payload?.error, message);
          setError(gone ? inspectorDisconnectedHint() : (message || "监控不可用"));
          if (gone) onSessionMissing?.(sessionId);
          return;
        }
        const target = payload?.session?.target;
        const state = payload?.session?.state;
        if (!peLive || dormant || (target && target !== "pe") || (state && !isSessionLive(state))) return;
        await api(`/api/sessions/${encodeURIComponent(sessionId)}/dynamic/open`, { method: "POST", body: JSON.stringify({}) });
      } catch {
        /* APK/web sessions have no x64dbg */
      }
      if (!cancelled) await load();
    })();
    const timer = window.setInterval(() => void load(), 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [load, peLive, dormant, sessionId]);

  const call = async (label: string, path: string) => {
    setBusy(label); setError(null);
    try {
      const result = await api<Envelope<unknown>>(path, { method: "POST", body: JSON.stringify({}) });
      if (result.ok === false) throw new Error(result.error?.message ?? `${label}失败`);
      if (label === "关闭") onSessionClosed?.(sessionId);
      await load();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(null);
    }
  };

  if (!sessionId) return <div className="findings-empty">关联会话后显示调试状态，并可打开静态/动态后端。</div>;
  const session = data?.session;
  const dynamic = data?.dynamic;
  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{asChildText(session?.state, "unknown")}</span>
      <button disabled={Boolean(busy)} onClick={() => void load()}>刷新</button>
      {peLive && <button disabled={Boolean(busy)} onClick={() => void call("打开静态", `/api/sessions/${encodeURIComponent(sessionId)}/static/open`)}>{busy === "打开静态" ? "打开中…" : "打开静态"}</button>}
      {peLive && <button disabled={Boolean(busy)} onClick={() => void call("打开动态", `/api/sessions/${encodeURIComponent(sessionId)}/dynamic/open`)}>{busy === "打开动态" ? "打开中…" : "打开动态"}</button>}
      {peLive && asChildText(dynamic?.state) === "paused" && <button className="primary" disabled={Boolean(busy)} onClick={() => void call("继续运行", `/api/sessions/${encodeURIComponent(sessionId)}/dynamic/resume`)}>{busy === "继续运行" ? "继续中…" : "继续运行"}</button>}
      {peLive && asChildText(dynamic?.state) === "running" && <button disabled={Boolean(busy)} onClick={() => void call("暂停", `/api/sessions/${encodeURIComponent(sessionId)}/dynamic/pause`)}>{busy === "暂停" ? "暂停中…" : "暂停"}</button>}
      {peLive && <button disabled={Boolean(busy)} onClick={() => void call("关闭", `/api/sessions/${encodeURIComponent(sessionId)}/close`)}>关闭会话</button>}
    </div>
    {error && <div className="findings-error">{error}</div>}
    <div className="metric-grid">
      <span>目标 {asChildText(session?.target)}</span>
      <span>PID {asChildText(dynamic?.debuggee_pid ?? dynamic?.process_id, "idle")}</span>
      <span>动态 {asChildText(dynamic?.state ?? dynamic?.error?.message, "closed")}</span>
      <span>脱壳 {asChildText(data?.unpack?.stage)}</span>
      <span>工作流 {workflowSummary(data?.workflow?.data)}</span>
    </div>
    {typeof session?.binary === "string" && session.binary && <div className="hint">{session.binary}</div>}
    {(data?.timeline?.items?.length ?? 0) > 0 && <div className="timeline-list">
      {data?.timeline?.items?.slice(-12).reverse().map((item, index) => <div key={`${item.at ?? "t"}-${index}`}>
        <b>{asChildText(item.event, "event")}</b>
        <span>{asChildText(item.message ?? item.at)}</span>
      </div>)}
    </div>}
    {(data?.events?.items?.length ?? 0) > 0 && <div className="timeline-list">
      {data?.events?.items?.slice(-8).reverse().map((item, index) => <div key={`${item.type ?? item.event ?? "e"}-${index}`}>
        <b>{asChildText(item.type ?? item.event ?? item.name, "debug")}</b>
        <span>{asChildText(item.message ?? item.name)}</span>
      </div>)}
    </div>}
  </section>;
}

function TimelinePanel({ sessionId }: { sessionId: string }) {
  const [items, setItems] = useState<TimelineItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const currentSession = useRef(sessionId);
  currentSession.current = sessionId;

  const load = useCallback(async () => {
    if (!sessionId) { setItems([]); return; }
    const result = await api<Envelope<{ events?: TimelineItem[] }>>(`/api/sessions/${encodeURIComponent(sessionId)}/timeline?limit=40`);
    // Unlike the polling monitor, nothing refreshes this list on its own: a
    // stale response for a previous session would stick until a manual click.
    if (currentSession.current !== sessionId) return;
    if (result.ok === false) {
      setItems([]);
      setError(result.error?.message ?? "无法读取时间线");
      return;
    }
    setItems(result.data?.events ?? []);
    setError(null);
  }, [sessionId]);

  useEffect(() => { void load(); }, [load]);

  if (!sessionId) return <div className="findings-empty">关联会话后显示时间线。</div>;
  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{items.length} 条时间线</span>
      <button onClick={() => void load()}>刷新</button>
    </div>
    {error && <div className="findings-error">{error}</div>}
    {items.length === 0
      ? <div className="findings-empty">还没有时间线事件。</div>
      : <div className="timeline-list">{items.slice().reverse().map((item, index) => <div key={`${item.at ?? "t"}-${index}`}>
          <b>{asChildText(item.event, "event")}</b>
          <span>{asChildText(item.message ?? item.at)}</span>
        </div>)}</div>}
  </section>;
}

function ArtifactsPanel({ sessionId }: { sessionId: string }) {
  const [items, setItems] = useState<Artifact[]>([]);
  const [error, setError] = useState<string | null>(null);
  const currentSession = useRef(sessionId);
  currentSession.current = sessionId;

  const load = useCallback(async () => {
    const query = sessionId ? `session_id=${encodeURIComponent(sessionId)}&limit=40` : "limit=40";
    const result = await api<Envelope<{ artifacts?: Artifact[] }>>(`/api/artifacts?${query}`);
    if (currentSession.current !== sessionId) return;
    setItems(result.data?.artifacts ?? []);
    setError(result.ok === false ? (result.error?.message ?? "无法列出产物") : null);
  }, [sessionId]);

  useEffect(() => { void load(); }, [load]);

  const download = async (item: Artifact) => {
    try {
      const blob = await apiBlob(`/api/artifacts/${encodeURIComponent(item.id)}/file`);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = item.path?.split(/[\\/]/).pop() || item.id;
      link.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      setError(String(reason));
    }
  };

  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{items.length} 个产物</span>
      <button onClick={() => void load()}>刷新</button>
    </div>
    {error && <div className="findings-error">{error}</div>}
    {items.length === 0
      ? <div className="findings-empty">还没有产物。报告、dump 和重建文件会出现在这里。</div>
      : <div className="findings-list">{items.map((item) => <div className="finding" key={item.id}>
          <b>{item.kind || item.id}</b>
          <span>{item.path?.split(/[\\/]/).pop() || item.id}</span>
          <button type="button" onClick={() => void download(item)}>下载</button>
        </div>)}</div>}
  </section>;
}

function AuditPanel({ sessionId }: { sessionId: string }) {
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const currentSession = useRef(sessionId);
  currentSession.current = sessionId;

  const load = useCallback(async () => {
    const query = sessionId ? `session_id=${encodeURIComponent(sessionId)}&limit=40` : "limit=40";
    const result = await api<Envelope<{ entries?: AuditEntry[] }>>(`/api/audit?${query}`);
    if (currentSession.current !== sessionId) return;
    setItems(result.data?.entries ?? []);
    setError(result.ok === false ? (result.error?.message ?? "无法读取审计") : null);
  }, [sessionId]);

  useEffect(() => { void load(); }, [load]);

  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{items.length} 条审计</span>
      <button onClick={() => void load()}>刷新</button>
    </div>
    {error && <div className="findings-error">{error}</div>}
    {items.length === 0
      ? <div className="findings-empty">还没有审计记录。</div>
      : <div className="findings-list">{items.map((item, index) => <div className="finding" key={item.id ?? String(index)}>
          <b>{item.ok === false ? "失败" : "成功"}</b>
          <span>{item.action} · {item.at ?? ""}</span>
        </div>)}</div>}
  </section>;
}

type InspectorTab = "watch" | "events" | "findings" | "files";

type Props = {
  events: RunEvent[];
  sessionId: string;
  profile?: WorkspaceProfile | null;
  sessionTarget?: string;
  sessionState?: string;
  locator?: string;
  sessionRestored?: boolean;
  disconnected?: LostSample | null;
  onSessionMissing?: (id: string) => void;
  onSessionClosed?: (id: string) => void;
  onReopen?: () => void;
};
export function Inspector({
  events, sessionId, profile = null, sessionTarget, sessionState, locator, sessionRestored = false, disconnected, onSessionMissing, onSessionClosed, onReopen,
}: Props) {
  const surface = inspectorSurface({ profile, target: sessionTarget, hasSession: Boolean(sessionId) });
  const peLive = peLiveMonitors(surface, Boolean(sessionId), sessionState);
  const live = Boolean(sessionId) && isSessionLive(sessionState);
  const peDesktop = peLive && !sessionRestored;
  const [tab, setTab] = useState<InspectorTab>("watch");
  return <aside className="inspector">
    <header>
      <div>
        <strong>检查器</strong>
        <span className="inspector-chip">{SURFACE_LABEL[surface]}</span>
      </div>
      <span className={sessionRestored ? "live-dot dormant" : "live-dot"}>{sessionRestored ? "休眠" : "实时"}</span>
    </header>
    <div className="inspector-tabs" role="tablist">
      <button type="button" role="tab" aria-selected={tab === "watch"} className={tab === "watch" ? "active" : undefined} onClick={() => setTab("watch")}>监视</button>
      <button type="button" role="tab" aria-selected={tab === "events"} className={tab === "events" ? "active" : undefined} onClick={() => setTab("events")}>事件</button>
      <button type="button" role="tab" aria-selected={tab === "findings"} className={tab === "findings" ? "active" : undefined} onClick={() => setTab("findings")}>发现</button>
      <button type="button" role="tab" aria-selected={tab === "files"} className={tab === "files" ? "active" : undefined} onClick={() => setTab("files")}>产物</button>
    </div>
    {sessionRestored && !disconnected && <div className="dormant-banner">{dormantHint()}</div>}
    <div hidden={tab !== "watch"}>
    {disconnected ? <SessionReconnect lost={disconnected} compact onReopen={() => onReopen?.()} /> : surface === "web" ? (
      <section className="desktop-pane"><h3>页面监视</h3>
        <WebMonitor sessionId={sessionId} locator={locator} live={live} onSessionMissing={onSessionMissing} onSessionClosed={onSessionClosed} />
      </section>
    ) : surface === "apk" ? (
      <section><h3>应用监视</h3>
        <ApkMonitor sessionId={sessionId} locator={locator} live={live} onSessionClosed={onSessionClosed} />
      </section>
    ) : <>
    {(peDesktop || !sessionId) && <section className="desktop-pane"><h3>虚拟桌面 · 必开监视</h3><VirtualDesktopMonitor sessionId={sessionId} onSessionMissing={onSessionMissing} /></section>}
    <section><h3>监控</h3><MonitorPanel sessionId={sessionId} peLive={peLive} dormant={sessionRestored} onSessionMissing={onSessionMissing} onSessionClosed={onSessionClosed} /></section>
    </>}
    </div>
    <div hidden={tab !== "events"}>
      <h3>工具事件</h3>
      <EventList events={events} />
    </div>
    <div hidden={tab !== "findings"}>
      {disconnected ? null : <><h3>发现与报告</h3><FindingsPanel sessionId={sessionId} onSessionMissing={onSessionMissing} /></>}
    </div>
    <div hidden={tab !== "files"}>
      {disconnected ? null : <>
        <h3>时间线 / 产物</h3>
        <TimelinePanel sessionId={sessionId} />
        <ArtifactsPanel sessionId={sessionId} />
        <h3>审计</h3>
        <AuditPanel sessionId={sessionId} />
      </>}
    </div>
  </aside>;
}
