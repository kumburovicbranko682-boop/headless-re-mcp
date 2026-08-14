import { useEffect, useState } from "react";
import { api } from "../api/client";

export type WorkspaceProfile = "full" | "pe" | "android" | "web";

type ProfileOption = { id: string; label: string };
type WorkspaceMode = {
  data?: { profile?: WorkspaceProfile; label?: string; available?: ProfileOption[] };
};

const DIRECTIONS: { id: WorkspaceProfile; title: string; blurb: string; glyph: string }[] = [
  { id: "pe", title: "本地 PE 逆向", blurb: "IDA 静态 + x64dbg 动态调试，Windows 可执行文件。", glyph: "🖥" },
  { id: "web", title: "Web 逆向", blurb: "浏览器 CDP、JS 反混淆、WASM 与抓包。", glyph: "🌐" },
  { id: "android", title: "Android 应用逆向", blurb: "模拟器/真机、装包、APK 静态与 Frida hook。", glyph: "🤖" },
  { id: "full", title: "全部工具", blurb: "不裁剪，暴露全部分析工具。", glyph: "✦" },
];

export function WorkspaceLanding({
  onChoose,
}: {
  onChoose: (profile: WorkspaceProfile) => void;
}) {
  const [active, setActive] = useState<WorkspaceProfile | null>(null);
  const [busy, setBusy] = useState<WorkspaceProfile | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<WorkspaceMode>("/api/workspace/mode")
      .then((mode) => setActive((mode.data?.profile as WorkspaceProfile) ?? "full"))
      .catch(() => setActive("full"));
  }, []);

  const choose = async (profile: WorkspaceProfile) => {
    setBusy(profile);
    setError(null);
    try {
      await api("/api/workspace/mode", { method: "POST", body: JSON.stringify({ profile }) });
      window.localStorage.setItem("headless_ws_profile", profile);
      onChoose(profile);
    } catch (err) {
      setError(String(err));
      setBusy(null);
    }
  };

  return (
    <main className="landing">
      <div className="landing-inner">
        <div className="brand">
          <div className="logo">RE</div>
          <div>
            <b>Headless Workbench</b>
            <small>选择工作方向</small>
          </div>
        </div>
        <h1>你想逆向什么？</h1>
        <p className="landing-sub">
          选择一个方向即可精简工具面；随时可在侧边栏切换。此选择也决定 MCP 客户端下次连接时看到的工具集。
        </p>
        <div className="landing-grid">
          {DIRECTIONS.map((direction) => (
            <button
              key={direction.id}
              type="button"
              className={`direction-card${active === direction.id ? " current" : ""}`}
              disabled={busy !== null}
              onClick={() => void choose(direction.id)}
            >
              <span className="direction-glyph">{direction.glyph}</span>
              <b>{direction.title}</b>
              <span className="direction-blurb">{direction.blurb}</span>
              {active === direction.id && <span className="direction-active">当前</span>}
              {busy === direction.id && <span className="direction-active">切换中…</span>}
            </button>
          ))}
        </div>
        {error && <div className="error">{error}</div>}
      </div>
    </main>
  );
}
