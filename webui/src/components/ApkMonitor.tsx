import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { asChildText } from "../lib/textChild";

type Envelope<T> = { ok?: boolean; data?: T; error?: { message?: string } };
type ApkInfo = { package?: string; version_name?: string; version_code?: string; label?: string };

type Props = {
  sessionId: string;
  locator?: string;
  live: boolean;
  onSessionClosed?: (id: string) => void;
};

export function ApkMonitor({ sessionId, locator, live, onSessionClosed }: Props) {
  const [info, setInfo] = useState<ApkInfo | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The panel swaps sessionId without remounting (Inspector renders it with a
  // plain prop, not a key). "打开 APK" applies its parsed metadata with an
  // unconditional setState after the await, and there is no poll to correct it:
  // switch sessions while A is parsing and A's package/version lands late and
  // sticks on B's panel until the user manually re-parses. Track the latest
  // sessionId and drop UI writes whose captured id is no longer current.
  const currentSession = useRef(sessionId);
  currentSession.current = sessionId;

  useEffect(() => { setInfo(null); setError(null); }, [sessionId]);

  const call = async (label: string, path: string) => {
    if (!sessionId) return;
    setBusy(label); setError(null);
    try {
      const result = await api<Envelope<ApkInfo>>(path, { method: "POST", body: JSON.stringify({}) });
      if (result.ok === false) throw new Error(result.error?.message ?? `${label}失败`);
      // A close genuinely happened, so tell the parent regardless of the
      // current selection; only this panel's own display must stay on-session.
      if (label === "关闭会话") onSessionClosed?.(sessionId);
      if (currentSession.current !== sessionId) return;
      if (label === "打开 APK") setInfo(result.data ?? {});
    } catch (reason) {
      if (currentSession.current !== sessionId) return;
      setError(String(reason));
    } finally {
      setBusy(null);
    }
  };

  if (!sessionId) return <div className="findings-empty">打开 APK 会话后解析包名、组件和设备。</div>;
  return <section className="findings">
    <div className="findings-toolbar">
      <span className="findings-count">{live ? "apk" : "closed"}</span>
      {live && <button disabled={Boolean(busy)} onClick={() => void call("打开 APK", `/api/sessions/${encodeURIComponent(sessionId)}/apk/open`)}>{busy === "打开 APK" ? "解析中…" : "打开 APK"}</button>}
      {live && <button disabled={Boolean(busy)} onClick={() => void call("关闭会话", `/api/sessions/${encodeURIComponent(sessionId)}/close`)}>关闭会话</button>}
    </div>
    {error && <div className="findings-error">{error}</div>}
    <div className="metric-grid">
      <span>目标 apk</span>
      <span>包名 {asChildText(info?.package)}</span>
      <span>版本 {asChildText(info?.version_name)}</span>
    </div>
    {locator && <div className="hint">{locator}</div>}
    <div className="findings-empty">静态解析走 apk.*，设备与 Frida 由 Agent 调用。这里不打开 x64dbg。</div>
  </section>;
}
