import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, apiFrame } from "../api/client";

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
  windows: DesktopWindow[];
  debuggee_pid?: number | null;
  debugger_pid?: number;
  allowed_pids?: number[];
  capture_mode?: string;
};

type DesktopEnvelope = {
  ok: boolean;
  data?: DesktopSnapshot;
  error?: { code?: string; message?: string };
};

export function VirtualDesktopMonitor({ sessionId }: { sessionId: string }) {
  const [snapshot, setSnapshot] = useState<DesktopSnapshot | null>(null);
  const [selectedHwnd, setSelectedHwnd] = useState<number | null>(null);
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [degraded, setDegraded] = useState<{ reason: string | null; backend: string | null } | null>(null);
  const [live, setLive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const frameUrlRef = useRef<string | null>(null);
  const capturingRef = useRef(false);

  const loadSnapshot = useCallback(async () => {
    if (!sessionId) { setSnapshot(null); return; }
    const result = await api<DesktopEnvelope>(`/api/sessions/${encodeURIComponent(sessionId)}/virtual-desktop`);
    if (!result.ok || !result.data) {
      setSnapshot(null);
      setError(result.error?.message ?? "Dynamic backend is not open");
      return;
    }
    const data = result.data;
    setSnapshot(data);
    setError(null);
    setSelectedHwnd((current) => {
      if (current && data.windows.some((row) => row.hwnd === current)) return current;
      const ranked = [...data.windows].sort((a, b) => Number(b.visible) - Number(a.visible) || b.area - a.area);
      return ranked[0]?.hwnd ?? null;
    });
  }, [sessionId]);

  const capture = useCallback(async () => {
    if (!sessionId || !selectedHwnd || capturingRef.current) return;
    capturingRef.current = true;
    setBusy(true);
    try {
      const frame = await apiFrame(`/api/sessions/${encodeURIComponent(sessionId)}/virtual-desktop/frame?hwnd=${selectedHwnd}`);
      const next = URL.createObjectURL(frame.blob);
      if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
      frameUrlRef.current = next;
      setFrameUrl(next);
      setDegraded(frame.degraded ? { reason: frame.reason, backend: frame.backend } : null);
      setError(null);
    } catch (reason) {
      setError(String(reason));
    } finally {
      capturingRef.current = false;
      setBusy(false);
    }
  }, [selectedHwnd, sessionId]);

  useEffect(() => {
    setLive(false);
    setSelectedHwnd(null);
    setError(null);
    setDegraded(null);
    void loadSnapshot();
    if (!sessionId) return undefined;
    const timer = window.setInterval(() => void loadSnapshot(), 1500);
    return () => window.clearInterval(timer);
  }, [loadSnapshot, sessionId]);

  useEffect(() => {
    if (!live) return undefined;
    void capture();
    const timer = window.setInterval(() => void capture(), 2000);
    return () => window.clearInterval(timer);
  }, [capture, live]);

  useEffect(() => () => {
    if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
  }, []);

  const selected = useMemo(
    () => snapshot?.windows.find((row) => row.hwnd === selectedHwnd) ?? null,
    [selectedHwnd, snapshot],
  );

  if (!sessionId) return <div className="desktop-empty">Select an analysis session to monitor its desktop.</div>;

  return <section className="desktop-monitor">
    <div className="desktop-toolbar">
      <span className={`desktop-mode ${snapshot?.available ? "ready" : "off"}`}>{snapshot?.mode ?? "unavailable"}</span>
      <button onClick={() => void loadSnapshot()}>Refresh</button>
      <button disabled={!selectedHwnd || busy || !snapshot?.available} onClick={() => void capture()}>{busy ? "Capturing…" : "Capture"}</button>
      <label><input type="checkbox" checked={live} disabled={!selectedHwnd || !snapshot?.available} onChange={(event) => setLive(event.target.checked)} /> 2s live</label>
    </div>
    {snapshot && <div className="desktop-meta">
      <span>{snapshot.name ?? "Default desktop"}</span><span>{snapshot.window_count} windows</span>
      <span>target {snapshot.debuggee_pid ?? "idle"}</span><span>input: {snapshot.input_desktop ? "yes" : "no"}</span>
    </div>}
    {error && <div className="desktop-error">{error}</div>}
    <div className="desktop-preview">
      {frameUrl ? <img src={frameUrl} alt={`Hidden desktop window ${selectedHwnd ?? ""}`} /> : <div><b>Passive monitor</b><span>Choose a target window and capture on demand.</span></div>}
    </div>
    {degraded && <div className="desktop-degraded">Capture degraded{degraded.reason ? ` · ${degraded.reason}` : ""} — GPU/DirectX/Chromium surfaces can return a blank frame via PrintWindow; no desktop switch was attempted.</div>}
    {selected && <div className="desktop-selection"><b>{selected.title || selected.class_name}</b><span>HWND {selected.hwnd} · PID {selected.pid} · {selected.rect?.width ?? 0}×{selected.rect?.height ?? 0}</span></div>}
    <div className="desktop-windows">
      {(snapshot?.windows ?? []).map((row) => <button className={row.hwnd === selectedHwnd ? "selected" : ""} key={row.hwnd} onClick={() => setSelectedHwnd(row.hwnd)}>
        <span>{row.title || row.class_name || `Window ${row.hwnd}`}</span>
        <small>{row.pid} · {row.visible ? "visible" : "hidden"}{row.minimized ? " · minimized" : ""}</small>
      </button>)}
    </div>
  </section>;
}
