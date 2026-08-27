import { useCallback, useEffect, useRef, useState } from "react";
import { api, apiBlob } from "../api/client";
import { inspectorDisconnectedHint, isSessionGone } from "../lib/sessionGone";
import { asChildText } from "../lib/textChild";

type Envelope<T> = { ok?: boolean; data?: T; error?: { code?: string; message?: string } };
type WebStatus = {
  open?: boolean;
  opening?: boolean;
  responsive?: boolean;
  exited?: boolean;
  url?: string | null;
  title?: string | null;
  locator?: string | null;
  state?: string;
};
type NetworkRow = { url?: string; method?: string; status?: number; resourceType?: string };
type ConsoleRow = { type?: string; text?: string };
type ScriptRow = { scriptId?: string; url?: string; language?: string };

type Props = {
  sessionId: string;
  locator?: string;
  live: boolean;
  onSessionMissing?: (id: string) => void;
  onSessionClosed?: (id: string) => void;
};

export function WebMonitor({ sessionId, locator, live, onSessionMissing, onSessionClosed }: Props) {
  const [status, setStatus] = useState<WebStatus | null>(null);
  const [requests, setRequests] = useState<NetworkRow[]>([]);
  const [consoleLines, setConsoleLines] = useState<ConsoleRow[]>([]);
  const [scripts, setScripts] = useState<ScriptRow[]>([]);
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [nav, setNav] = useState(locator ?? "");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const openedRef = useRef(false);
  const frameUrlRef = useRef<string | null>(null);
  const capturingRef = useRef(false);

  useEffect(() => { setNav(locator ?? ""); }, [locator]);

  const load = useCallback(async () => {
    if (!sessionId) {
      setStatus(null); setRequests([]); setConsoleLines([]); setScripts([]); return;
    }
    try {
      const result = await api<Envelope<WebStatus>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/status`);
      if (result.ok === false) {
        const message = result.error?.message ?? "浏览器状态不可用";
        const gone = isSessionGone(result.error, message);
        setError(gone ? inspectorDisconnectedHint() : message);
        if (gone) onSessionMissing?.(sessionId);
        return;
      }
      const payload = result.data ?? {};
      setStatus(payload);
      setError(null);
      if (!payload.open) {
        setRequests([]); setConsoleLines([]); setScripts([]);
        return;
      }
      const [network, logs, listed] = await Promise.all([
        api<Envelope<{ requests?: NetworkRow[] }>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/network?limit=20`),
        api<Envelope<{ console?: ConsoleRow[] }>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/console?limit=20`),
        api<Envelope<{ scripts?: ScriptRow[] }>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/scripts?limit=20`),
      ]);
      setRequests(network.data?.requests ?? []);
      setConsoleLines(logs.data?.console ?? []);
      setScripts(listed.data?.scripts ?? []);
    } catch (reason) {
      setError(String(reason));
    }
  }, [onSessionMissing, sessionId]);

  const capture = useCallback(async () => {
    if (!sessionId || capturingRef.current) return;
    capturingRef.current = true;
    try {
      const blob = await apiBlob(`/api/sessions/${encodeURIComponent(sessionId)}/web/preview`);
      const next = URL.createObjectURL(blob);
      if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
      frameUrlRef.current = next;
      setFrameUrl(next);
    } catch {
      /* browser not open yet */
    } finally {
      capturingRef.current = false;
    }
  }, [sessionId]);

  const call = async (label: string, path: string, body: Record<string, unknown> = {}) => {
    if (!sessionId) return;
    setBusy(label); setError(null);
    try {
      const result = await api<Envelope<unknown>>(path, { method: "POST", body: JSON.stringify(body) });
      if (result.ok === false) throw new Error(result.error?.message ?? `${label}失败`);
      if (label === "关闭会话") onSessionClosed?.(sessionId);
      await load();
      if (label === "打开浏览器" || label === "导航") await capture();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(null);
    }
  };

  const reopen = async () => {
    if (!sessionId) return;
    setBusy("重开浏览器"); setError(null);
    try {
      await api<Envelope<unknown>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/close`, { method: "POST", body: "{}" });
      const result = await api<Envelope<unknown>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/open`, {
        method: "POST",
        body: JSON.stringify({ url: nav || locator || "" }),
      });
      if (result.ok === false) throw new Error(result.error?.message ?? "重开浏览器失败");
      await load();
      await capture();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(null);
    }
  };

  useEffect(() => {
    openedRef.current = false;
    setStatus(null);
    setError(null);
    setFrameUrl(null);
    if (frameUrlRef.current) { URL.revokeObjectURL(frameUrlRef.current); frameUrlRef.current = null; }
  }, [sessionId]);

  useEffect(() => {
    void load();
    if (!sessionId) return undefined;
    const timer = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(timer);
  }, [load, sessionId]);

  useEffect(() => {
    if (!sessionId || !live || openedRef.current) return undefined;
    openedRef.current = true;
    void (async () => {
      try {
        const result = await api<Envelope<WebStatus>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/status`);
        if (result.data?.open) { await load(); await capture(); return; }
        await api<Envelope<unknown>>(`/api/sessions/${encodeURIComponent(sessionId)}/web/open`, {
          method: "POST",
          body: JSON.stringify({ url: locator || "" }),
        });
        await load();
        await capture();
      } catch (reason) {
        setError(String(reason));
      }
    })();
    return undefined;
  }, [capture, live, load, locator, sessionId]);

  useEffect(() => {
    if (!status?.open || status?.exited || status?.responsive === false || !sessionId) return undefined;
    void capture();
    const timer = window.setInterval(() => void capture(), 4000);
    return () => window.clearInterval(timer);
  }, [capture, sessionId, status?.open, status?.exited, status?.responsive]);

  useEffect(() => () => {
    if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
  }, []);

  if (!sessionId) return <div className="findings-empty">打开 URL 会话后监视页面、请求和脚本。</div>;

  const open = Boolean(status?.open);
  const exited = Boolean(status?.exited);
  const alive = open && !exited && status?.responsive !== false;
  const openLabel = exited ? "浏览器已退出" : alive ? "浏览器已开" : "浏览器无响应";
  const pageUrl = asChildText(status?.url ?? locator, "—");
  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{open ? openLabel : live ? "浏览器未开" : asChildText(status?.state, "closed")}</span>
      <button disabled={Boolean(busy)} onClick={() => void load()}>刷新</button>
      {live && !open && <button className="primary" disabled={Boolean(busy)} onClick={() => void call("打开浏览器", `/api/sessions/${encodeURIComponent(sessionId)}/web/open`, { url: nav || locator || "" })}>{busy === "打开浏览器" ? "打开中…" : "打开浏览器"}</button>}
      {live && open && !alive && <button className="primary" disabled={Boolean(busy)} onClick={() => void reopen()}>{busy === "重开浏览器" ? "重开中…" : "重开浏览器"}</button>}
      {open && <button disabled={Boolean(busy)} onClick={() => void call("关闭浏览器", `/api/sessions/${encodeURIComponent(sessionId)}/web/close`)}>{busy === "关闭浏览器" ? "关闭中…" : "关闭浏览器"}</button>}
      {live && <button disabled={Boolean(busy)} onClick={() => void call("关闭会话", `/api/sessions/${encodeURIComponent(sessionId)}/close`)}>关闭会话</button>}
    </div>
    {error && <div className="findings-error">{error}</div>}
    <div className="metric-grid">
      <span>目标 web</span>
      <span>标题 {asChildText(status?.title)}</span>
    </div>
    <div className="hint">{pageUrl}</div>
    {live && <div className="session-open-path">
      <input aria-label="导航 URL" value={nav} onChange={(event) => setNav(event.target.value)} placeholder="https://example.com" />
      <button type="button" disabled={!alive || !nav.trim() || Boolean(busy)} onClick={() => void call("导航", `/api/sessions/${encodeURIComponent(sessionId)}/web/navigate`, { url: nav.trim() })}>{busy === "导航" ? "跳转中…" : "导航"}</button>
    </div>}
    <div className="desktop-preview">
      {frameUrl ? <img src={frameUrl} alt="页面预览" /> : <div><b>{alive ? "正在截取页面" : open ? "浏览器已退出" : "等待浏览器"}</b><span>{alive ? "打开页面后会出现截图。" : open ? "浏览器进程已不在，重开后继续；已抓到的请求与脚本仍在。" : "点打开浏览器，或让 Agent 调用 web.open。"}</span></div>}
    </div>
    <div className="timeline-list">
      {requests.slice(0, 8).map((row, index) => <div key={`${row.url ?? "req"}-${index}`}>
        <b>{asChildText(row.method, "GET")} {asChildText(row.status, "")}</b>
        <span>{asChildText(row.url)}</span>
      </div>)}
    </div>
    {consoleLines.length > 0 && <div className="timeline-list">
      {consoleLines.slice(-8).reverse().map((row, index) => <div key={`${row.text ?? "log"}-${index}`}>
        <b>{asChildText(row.type, "log")}</b>
        <span>{asChildText(row.text)}</span>
      </div>)}
    </div>}
    {scripts.length > 0 && <div className="timeline-list">
      {scripts.slice(0, 8).map((row, index) => <div key={`${row.scriptId ?? "js"}-${index}`}>
        <b>{asChildText(row.language, "js")}</b>
        <span>{asChildText(row.url)}</span>
      </div>)}
    </div>}
  </section>;
}
