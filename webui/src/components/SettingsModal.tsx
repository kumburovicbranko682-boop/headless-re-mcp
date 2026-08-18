import { FormEvent, useEffect, useState } from "react";
import type { ApprovalMode } from "../agent/autonomy";
import { api } from "../api/client";
import { ApprovalModeOptions } from "./ApprovalModeControl";

type ProviderPublic = {
  id: string;
  base_url: string;
  model: string;
  configured?: boolean;
  api_key_masked?: string | null;
  known_models?: string[];
};

type ProvidersResponse = { ok?: boolean; current?: string; profiles?: ProviderPublic[] };
type SetupStatus = {
  ida_home?: string | null;
  candidates?: string[];
  x64dbg_headless_x64?: string | null;
  x64dbg_headless_x86?: string | null;
  probe?: { status?: string; summary?: string };
};
type Persona = { id: string; title: string; builtin?: boolean; current?: boolean; bytes?: number };
type PersonasResponse = { ok?: boolean; current?: string; personas?: Persona[] };

export function SettingsModal({
  onClose,
  approvalMode = "request",
  approvalBusy = false,
  onApprovalModeChange,
}: {
  onClose: () => void;
  approvalMode?: ApprovalMode;
  approvalBusy?: boolean;
  onApprovalModeChange?: (mode: ApprovalMode) => void;
}) {
  const [baseUrl, setBaseUrl] = useState("https://api.openai.com/v1");
  const [model, setModel] = useState("gpt-4.1-mini");
  const [key, setKey] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [configured, setConfigured] = useState(false);
  const [masked, setMasked] = useState<string | null>(null);
  const [idaHome, setIdaHome] = useState("");
  const [candidates, setCandidates] = useState<string[]>([]);
  const [x64, setX64] = useState<string | null>(null);
  const [x86, setX86] = useState<string | null>(null);
  const [idaStatus, setIdaStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [personaId, setPersonaId] = useState("");
  const [personaPath, setPersonaPath] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const [providers, setup, listed] = await Promise.all([
          api<ProvidersResponse>("/api/providers"),
          api<SetupStatus>("/api/setup/status"),
          api<PersonasResponse>("/api/agent/personas"),
        ]);
        const currentId = providers.current ?? "default";
        const current = providers.profiles?.find((item) => item.id === currentId) ?? providers.profiles?.[0];
        if (current) {
          setBaseUrl(current.base_url);
          setModel(current.model);
          setConfigured(Boolean(current.configured));
          setMasked(current.api_key_masked ?? null);
          setModels(current.known_models ?? []);
        }
        setIdaHome(setup.ida_home ?? "");
        setCandidates(setup.candidates ?? []);
        setX64(setup.x64dbg_headless_x64 ?? null);
        setX86(setup.x64dbg_headless_x86 ?? null);
        setIdaStatus(setup.probe?.summary ?? setup.probe?.status ?? null);
        const rows = listed.personas ?? [];
        setPersonas(rows);
        setPersonaId(rows.find((item) => item.current)?.id ?? listed.current ?? "");
        if (current?.configured) {
          try {
            const probed = await api<{ models?: string[] }>("/api/providers/default/models", { method: "POST" });
            const list = probed.models ?? [];
            if (list.length) {
              setModels(list);
              if (current.model && !list.includes(current.model)) setModel(list[0] ?? current.model);
            }
          } catch {
            /* keep known_models; probe is best-effort on open */
          }
        }
      } catch (reason) {
        setError(String(reason));
      }
    })();
  }, []);

  const saveProvider = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true); setError(null); setNote(null);
    try {
      const body: Record<string, unknown> = { base_url: baseUrl, model, make_current: true };
      if (key.trim()) body.api_key = key.trim();
      const saved = await api<{ profile?: ProviderPublic }>("/api/providers/default", { method: "PUT", body: JSON.stringify(body) });
      setKey("");
      setConfigured(Boolean(saved.profile?.configured ?? (configured || Boolean(key.trim()))));
      setMasked(saved.profile?.api_key_masked ?? masked);
      setNote("模型设置已保存到本机服务。");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const probeModels = async () => {
    setBusy(true); setError(null);
    try {
      const result = await api<{ models?: string[] }>("/api/providers/default/models", { method: "POST" });
      const list = result.models ?? [];
      setModels(list);
      if (list[0] && !list.includes(model)) setModel(list[0]);
      setNote(list.length ? `探测到 ${list.length} 个模型。` : "接口没有返回模型列表。");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const applyPersonas = (listed: PersonasResponse) => {
    const rows = listed.personas ?? [];
    setPersonas(rows);
    setPersonaId(rows.find((item) => item.current)?.id ?? listed.current ?? "");
  };

  const selectPersona = async (id: string) => {
    setBusy(true); setError(null);
    try {
      applyPersonas(await api<PersonasResponse>("/api/agent/personas/select", { method: "POST", body: JSON.stringify({ id }) }));
      setNote("人设已切换。下一轮对话生效。");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const importPersonaPath = async () => {
    if (!personaPath.trim()) { setError("请填写本机 .md 路径。"); return; }
    setBusy(true); setError(null);
    try {
      applyPersonas(await api<PersonasResponse>("/api/agent/personas/import", { method: "POST", body: JSON.stringify({ path: personaPath.trim() }) }));
      setPersonaPath("");
      setNote("已导入人设并设为当前。");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const importPersonaFile = async (file: File) => {
    setBusy(true); setError(null);
    try {
      const content = await file.text();
      applyPersonas(await api<PersonasResponse>("/api/agent/personas/import", { method: "POST", body: JSON.stringify({ title: file.name.replace(/\.md$/i, ""), content }) }));
      setNote(`已导入 ${file.name} 并设为当前。`);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const saveIda = async () => {
    if (!idaHome.trim()) { setError("请先填写 IDA 安装目录。"); return; }
    setBusy(true); setError(null); setNote(null);
    try {
      const result = await api<{ ok?: boolean; ida_home?: string; message?: string }>("/api/setup/ida", {
        method: "POST",
        body: JSON.stringify({ confirm: true, ida_home: idaHome.trim(), activate: true }),
      });
      if (result.ida_home) setIdaHome(result.ida_home);
      setNote(result.ok ? "IDA 路径已写入配置。" : (result.message ?? "IDA 配置未成功。"));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  return <div className="modal-backdrop" role="presentation" onClick={onClose}>
    <section className="modal wide" role="dialog" aria-modal="true" aria-label="模型与设置" onClick={(event) => event.stopPropagation()}>
      <button className="modal-close" onClick={onClose}>×</button>
      <h2>模型与设置</h2>
      <p>密钥只提交到本机回环服务。已保存的密钥不会回显到页面。</p>
      {note && <div className="findings-report">{note}</div>}
      {error && <div className="error">{error}</div>}
      <form className="provider-form" onSubmit={(event) => void saveProvider(event)}>
        <label>接口地址<input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} /></label>
        <label>模型
          {models.length > 0
            ? <select value={model} onChange={(event) => setModel(event.target.value)}>{models.map((item) => <option key={item} value={item}>{item}</option>)}</select>
            : <input value={model} onChange={(event) => setModel(event.target.value)} />}
        </label>
        <label>API 密钥{configured ? `（已配置${masked ? ` · ${masked}` : ""}）` : "（未配置）"}
          <input type="password" autoComplete="off" value={key} placeholder={configured ? "留空则保留已保存的密钥" : ""} onChange={(event) => setKey(event.target.value)} />
        </label>
        <div className="modal-actions">
          <button disabled={busy} type="submit">保存模型</button>
          <button disabled={busy} type="button" onClick={() => void probeModels()}>{busy ? "拉取中…" : "拉取模型列表"}</button>
        </div>
      </form>
      <h3 className="modal-sub">Agent 人设</h3>
      <div className="provider-form">
        <label>当前人设
          <select value={personaId} onChange={(event) => void selectPersona(event.target.value)}>
            {personas.map((item) => <option key={item.id} value={item.id}>{item.title}{item.builtin ? " · 预装" : ""}</option>)}
          </select>
        </label>
        <p className="hint">预装「海鸥 3.0」（若本机有该文件）和「默认工作台」。可随时切回去。</p>
        <label>从本机路径导入 .md
          <input value={personaPath} onChange={(event) => setPersonaPath(event.target.value)} placeholder="C:\path\to\persona.md" />
        </label>
        <div className="modal-actions">
          <button disabled={busy} type="button" onClick={() => void importPersonaPath()}>导入路径</button>
          <label className="file-button">选择 .md 文件
            <input type="file" accept=".md,.txt" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importPersonaFile(file); event.target.value = ""; }} />
          </label>
        </div>
      </div>
      <h3 className="modal-sub">本机后端</h3>
      <form className="provider-form" onSubmit={(event) => { event.preventDefault(); void saveIda(); }}>
        <label>IDA 安装目录
          <input value={idaHome} onChange={(event) => setIdaHome(event.target.value)} placeholder="例如 C:\Program Files\IDA Professional 9.3" />
        </label>
        {idaStatus && <p className="hint">IDA 探针：{idaStatus}</p>}
        {candidates.length > 0 && <div className="chip-row">{candidates.map((path) => <button type="button" key={path} onClick={() => setIdaHome(path)}>{path}</button>)}</div>}
        <p className="hint">x64dbg x64：{x64 ?? "未发现"}</p>
        <p className="hint">x64dbg x86：{x86 ?? "未发现"}</p>
        <button disabled={busy} type="submit">保存 IDA 路径</button>
      </form>
      <h3 className="modal-sub">工具权限</h3>
      <p className="hint">只读工具本来就会自动跑。对话框右侧也可以切换这两档。没有「帮我批准」中间档。</p>
      <div className="approval-mode-settings">
        <ApprovalModeOptions mode={approvalMode} busy={approvalBusy} onSelect={(mode) => onApprovalModeChange?.(mode)} />
      </div>
    </section>
  </div>;
}
