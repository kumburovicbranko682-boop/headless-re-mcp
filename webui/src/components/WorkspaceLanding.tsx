import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { WorkspaceProfile } from "../lib/inspectorSurface";

export type { WorkspaceProfile };

type ProfileOption = { id: string; label: string };
type WorkspaceMode = {
  data?: { profile?: WorkspaceProfile; label?: string; available?: ProfileOption[] };
};

const DIRECTIONS: { id: WorkspaceProfile; title: string; blurb: string; index: string }[] = [
  { id: "pe", title: "本地 PE 逆向", blurb: "IDA 静态与 x64dbg 动态，Windows 可执行文件。", index: "01" },
  { id: "web", title: "Web 逆向", blurb: "浏览器 CDP、脚本反混淆、WASM 与抓包。", index: "02" },
  { id: "android", title: "Android 应用逆向", blurb: "模拟器或真机、装包、APK 静态与 Frida。", index: "03" },
  { id: "full", title: "全部工具", blurb: "不裁剪工具面，一次暴露全部能力。", index: "04" },
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
      <header className="landing-copy">
        <p className="landing-kicker">Headless RE-MCP</p>
        <h1>开始一段分析</h1>
        <p className="landing-sub">
          选择工作方向来裁剪工具。会话保存在本机，控制台重启后同一 ID 仍可继续，不会自动打开调试器。
        </p>
      </header>
      <ol className="toc">
        {DIRECTIONS.map((direction) => (
          <li key={direction.id}>
            <button
              type="button"
              className={`direction-card${active === direction.id ? " current" : ""}`}
              disabled={busy !== null}
              onClick={() => void choose(direction.id)}
            >
              <span className="direction-index">{direction.index}</span>
              <span className="direction-body">
                <b>{direction.title}</b>
                <span className="direction-blurb">{direction.blurb}</span>
              </span>
              {active === direction.id && <span className="direction-active">当前</span>}
              {busy === direction.id && <span className="direction-active">切换中…</span>}
            </button>
          </li>
        ))}
      </ol>
      {error && <div className="error">{error}</div>}
    </main>
  );
}
