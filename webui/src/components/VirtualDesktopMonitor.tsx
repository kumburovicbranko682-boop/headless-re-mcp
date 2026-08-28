import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, apiFrame } from "../api/client";
import {
  captureDegradedHint,
  captureFailureHint,
  desktopPreviewHint,
  desktopPreviewTitle,
  pickBestHwnd,
  stripErrorPrefix,
  windowIsCapturable,
} from "../lib/desktopPreview";
import { isSessionGone, inspectorDisconnectedHint } from "../lib/sessionGone";

type DesktopWindow = {
  hwnd: number;
  pid: number;
  title: string;
  class_name: string;
  visible: boolean;
  minimized: boolean;
  area: number;
  rect?: { width?: number; height?: number };
};

type DesktopSnapshot = {
  available: boolean;
  mode: string;
  name?: string;
  input_desktop: boolean;
  window_count: number;
  desktop_window_count?: number;
  windows: DesktopWindow[];
  debuggee_pid?: number | null;
  debugger_pid?: number;
  allowed_pids?: number[];
  capture_mode?: string;
  debuggee_state?: string | null;
  hint?: string | null;
  suggestion?: string | null;
};

const MODE_LABEL: Record<string, string> = {
  hidden_win32: "隐藏桌面",
  input_desktop: "当前桌面",
  default: "当前桌面",
  unavailable: "不可用",
};

type DesktopEnvelope = {
  ok: boolean;
  data?: DesktopSnapshot;
  error?: { code?: string; message?: string };
};

export function VirtualDesktopMonitor({ sessionId, onSessionMissing }: { sessionId: string; onSessionMissing?: (id: string) => void }) {
  const [snapshot, setSnapshot] = useState<DesktopSnapshot | null>(null);
  const [selectedHwnd, setSelectedHwnd] = useState<number | null>(null);
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [degraded, setDegraded] = useState<{ reason: string | null; backend: string | null } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const frameUrlRef = useRef<string | null>(null);
  const capturingRef = useRef(false);
  const windowsRef = useRef<DesktopWindow[]>([]);
  // The pane swaps sessionId without remounting (Inspector renders it with a
  // plain prop, not a key), and both loops apply their results with an
  // unconditional setState after an await. A busy debuggee's slow snapshot or
  // frame, started before a switch, then lands last and paints the previous
  // session's window list -- and its desktop screenshot -- onto the session the
  // user moved to. The 1s/800ms polls heal it, but a reordered slow response
  // holds the wrong desktop on screen until the next tick. Track the latest
  // sessionId and drop any continuation whose captured id is no longer current.
  const currentSession = useRef(sessionId);
  currentSession.current = sessionId;

  const loadSnapshot = useCallback(async () => {
    if (!sessionId) { setSnapshot(null); return; }
    try {
    const result = await api<DesktopEnvelope>(`/api/sessions/${encodeURIComponent(sessionId)}/virtual-desktop`);
    if (currentSession.current !== sessionId) return;
    if (!result.ok || !result.data) {
      setSnapshot(null);
      const gone = isSessionGone(result.error);
      setError(gone ? inspectorDisconnectedHint() : (result.error?.message ?? "动态后端未打开"));
      if (gone) onSessionMissing?.(sessionId);
      return;
    }
    const data = result.data;
    const windows = Array.isArray(data.windows) ? data.windows : [];
    setSnapshot({ ...data, windows, window_count: data.window_count ?? windows.length });
    setError(null);
    setSelectedHwnd((current) => {
      if (current && windows.some((row) => row.hwnd === current)) return current;
      return pickBestHwnd(windows);
    });
    if (windows.length > 0 && pickBestHwnd(windows) === null) {
      setDegraded({ reason: "empty_capture", backend: null });
    }
    } catch (reason) {
      if (currentSession.current !== sessionId) return;
      setSnapshot(null);
      setError(stripErrorPrefix(String(reason)));
    }
  }, [onSessionMissing, sessionId]);

  const capture = useCallback(async () => {
    if (!sessionId || !selectedHwnd || capturingRef.current) return;
    const row = windowsRef.current.find((item) => item.hwnd === selectedHwnd);
    if (row && !windowIsCapturable(row)) {
      if (frameUrlRef.current) {
        URL.revokeObjectURL(frameUrlRef.current);
        frameUrlRef.current = null;
      }
      setFrameUrl(null);
      setDegraded({ reason: "empty_capture", backend: null });
      setError(null);
      return;
    }
    capturingRef.current = true;
    try {
      const frame = await apiFrame(`/api/sessions/${encodeURIComponent(sessionId)}/virtual-desktop/frame?hwnd=${selectedHwnd}`);
      // Bail before creating the object URL so a stale frame from the session
      // the user left is neither shown nor leaked.
      if (currentSession.current !== sessionId) return;
      const next = URL.createObjectURL(frame.blob);
      if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
      frameUrlRef.current = next;
      setFrameUrl(next);
      setDegraded(frame.degraded ? { reason: frame.reason, backend: frame.backend } : null);
      setError(null);
    } catch (reason) {
      if (currentSession.current !== sessionId) return;
      const mapped = captureFailureHint(String(reason));
      if (mapped.kind === "degraded") {
        setDegraded({ reason: mapped.reason, backend: null });
        setError(null);
      } else {
        setError(mapped.text);
        setDegraded(null);
      }
    } finally {
      capturingRef.current = false;
    }
  }, [selectedHwnd, sessionId]);

  const call = async (label: string, path: string) => {
    if (!sessionId) return;
    setBusy(label); setError(null);
    try {
      const result = await api<{ ok?: boolean; error?: { message?: string } }>(path, { method: "POST", body: JSON.stringify({}) });
      if (result.ok === false) throw new Error(result.error?.message ?? `${label} failed`);
      await loadSnapshot();
    } catch (reason) {
      setError(stripErrorPrefix(String(reason)));
    } finally {
      setBusy(null);
    }
  };

  useEffect(() => {
    setSelectedHwnd(null);
    setError(null);
    setDegraded(null);
    void loadSnapshot();
    if (!sessionId) return undefined;
    const timer = window.setInterval(() => void loadSnapshot(), 1000);
    return () => window.clearInterval(timer);
  }, [loadSnapshot, sessionId]);

  useEffect(() => {
    if (!selectedHwnd) {
      if (frameUrlRef.current) {
        URL.revokeObjectURL(frameUrlRef.current);
        frameUrlRef.current = null;
      }
      setFrameUrl(null);
      return undefined;
    }
    void capture();
    const timer = window.setInterval(() => void capture(), 800);
    return () => window.clearInterval(timer);
  }, [capture, selectedHwnd]);

  useEffect(() => () => {
    if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
  }, []);

  windowsRef.current = snapshot?.windows ?? [];

  const selected = useMemo(
    () => snapshot?.windows.find((row) => row.hwnd === selectedHwnd) ?? null,
    [selectedHwnd, snapshot],
  );

  if (!sessionId) return <div className="desktop-empty">打开分析会话后会自动监视虚拟桌面。</div>;

  const paused = snapshot?.debuggee_state === "paused";
  const running = snapshot?.debuggee_state === "running";
  const modeClass = snapshot?.available ? (paused ? "paused" : "ready") : "off";

  return <section className="desktop-monitor">
    <div className="desktop-toolbar">
      <span className={`desktop-mode ${modeClass}`}>{snapshot?.available ? (MODE_LABEL[snapshot.mode] ?? (snapshot.mode || "监视中")) : "等待动态后端"}</span>
      <span className="desktop-live-tag">强制监视</span>
      {paused && <button type="button" className="primary" disabled={Boolean(busy)} onClick={() => void call("继续运行", `/api/sessions/${encodeURIComponent(sessionId)}/dynamic/resume`)}>{busy === "继续运行" ? "继续中…" : "继续运行"}</button>}
      {running && <button type="button" disabled={Boolean(busy)} onClick={() => void call("暂停", `/api/sessions/${encodeURIComponent(sessionId)}/dynamic/pause`)}>{busy === "暂停" ? "暂停中…" : "暂停"}</button>}
    </div>
    {snapshot && <div className="desktop-meta">
      <span>{snapshot.name ?? "默认桌面"}</span>
      <span>{snapshot.window_count} 个目标窗口{typeof snapshot.desktop_window_count === "number" && snapshot.desktop_window_count !== snapshot.window_count ? ` · 桌面共 ${snapshot.desktop_window_count}` : ""}</span>
      <span>目标 {snapshot.debuggee_pid ?? "空闲"}{snapshot.debuggee_state ? ` · ${snapshot.debuggee_state}` : ""}</span>
      <span>输入桌面：{snapshot.input_desktop ? "是" : "否"}</span>
    </div>}
    {error && !degraded && <div className="desktop-error">{error}</div>}
    <div className="desktop-preview">
      {frameUrl ? <img src={frameUrl} alt={`桌面窗口 ${selectedHwnd ?? ""}`} /> : <div><b>{desktopPreviewTitle(snapshot)}</b><span>{desktopPreviewHint(snapshot)}</span></div>}
    </div>
    {degraded && <div className="desktop-degraded">{captureDegradedHint(degraded.reason)}</div>}
    {selected && <div className="desktop-selection"><b>{selected.title || selected.class_name}</b><span>HWND {selected.hwnd} · PID {selected.pid} · {selected.rect?.width ?? 0}×{selected.rect?.height ?? 0}</span></div>}
    <div className="desktop-windows">
      {(snapshot?.windows ?? []).map((row) => <button className={row.hwnd === selectedHwnd ? "selected" : ""} key={row.hwnd} onClick={() => setSelectedHwnd(row.hwnd)}>
        <span>{row.title || row.class_name || `窗口 ${row.hwnd}`}</span>
        <small>{row.pid} · {row.visible ? "可见" : "隐藏"}{row.minimized ? " · 最小化" : ""}</small>
      </button>)}
    </div>
  </section>;
}
