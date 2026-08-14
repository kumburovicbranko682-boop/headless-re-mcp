import { FormEvent, useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { api, bootstrapToken, streamEvents } from "../api/client";
import { initialState, reducer, type Message, type RunEvent, type Thread } from "../agent/state";
import { ApprovalCard } from "../components/ApprovalCard";
import { Inspector } from "../components/Inspector";
import { WorkspaceLanding, type WorkspaceProfile } from "../components/WorkspaceLanding";

type Session = { id: string; binary?: string; state?: string };
type ThreadsResponse = { threads: Thread[] };
type ThreadResponse = { thread: Thread; messages: Message[] };
type SessionsResponse = { data?: { sessions?: Session[] } };

export function App() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionId, setSessionId] = useState("");
  const [draft, setDraft] = useState("");
  const [monitor, setMonitor] = useState<unknown>(null);
  const [artifacts, setArtifacts] = useState<unknown>(null);
  const [audit, setAudit] = useState<unknown>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [workspaceProfile, setWorkspaceProfile] = useState<WorkspaceProfile | null>(() => {
    const stored = typeof window !== "undefined" ? window.localStorage.getItem("headless_ws_profile") : null;
    return (stored as WorkspaceProfile | null) ?? null;
  });
  const [landingOpen, setLandingOpen] = useState(workspaceProfile === null);
  const abortRef = useRef<AbortController | null>(null);
  const cursorRef = useRef(0);

  const loadThreads = useCallback(async () => {
    const result = await api<ThreadsResponse>("/api/agent/threads");
    dispatch({ type: "threads", threads: result.threads });
  }, []);

  useEffect(() => {
    bootstrapToken();
    Promise.all([loadThreads(), api<SessionsResponse>("/api/sessions"), api<unknown>("/api/audit?limit=30")])
      .then(([, sessionResult, auditResult]) => { setSessions(sessionResult.data?.sessions ?? []); setAudit(auditResult); })
      .catch((error: unknown) => dispatch({ type: "error", message: String(error) }));
    const resumeRun = window.history.state?.activeRun;
    const resumeAfter = Number(window.history.state?.runSeq ?? 0);
    if (typeof resumeRun === "string") {
      api<{ events: RunEvent[] }>(`/api/agent/runs/${encodeURIComponent(resumeRun)}/events/history?after=0`)
        .then((history) => {
          dispatch({ type: "run", runId: resumeRun });
          history.events.forEach((event) => dispatch({ type: "event", event }));
          void consume(resumeRun, resumeAfter);
        })
        .catch(() => undefined);
    }
    return () => abortRef.current?.abort();
  }, [loadThreads]);

  useEffect(() => {
    if (!sessionId) return;
    Promise.all([
      api<unknown>(`/api/sessions/${encodeURIComponent(sessionId)}/monitor`),
      api<unknown>(`/api/artifacts?session_id=${encodeURIComponent(sessionId)}&limit=30`),
      api<unknown>(`/api/audit?session_id=${encodeURIComponent(sessionId)}&limit=30`),
    ]).then(([m, a, u]) => { setMonitor(m); setArtifacts(a); setAudit(u); }).catch(() => undefined);
  }, [sessionId, state.events.length]);

  const selectThread = async (id: string) => {
    const result = await api<ThreadResponse>(`/api/agent/threads/${encodeURIComponent(id)}`);
    dispatch({ type: "select", threadId: id, messages: result.messages });
    setSessionId(result.thread.session_id ?? "");
  };

  const createThread = async () => {
    const result = await api<{ thread: Thread }>("/api/agent/threads", { method: "POST", body: JSON.stringify({ title: "Analysis chat", session_id: sessionId || null }) });
    await loadThreads(); await selectThread(result.thread.id);
  };

  const consume = useCallback(async (runId: string, initialAfter = 0) => {
    abortRef.current?.abort();
    const controller = new AbortController(); abortRef.current = controller;
    cursorRef.current = initialAfter; dispatch({ type: "connected", value: true });
    for (let retries = 0; retries < 4 && !controller.signal.aborted; retries += 1) {
      try {
        await streamEvents(runId, cursorRef.current, ({ type, data }) => {
          if (type === "heartbeat") return;
          const parsed = JSON.parse(data) as RunEvent;
          cursorRef.current = Math.max(cursorRef.current, parsed.seq);
          window.history.replaceState({ ...(window.history.state ?? {}), activeRun: runId, runSeq: cursorRef.current }, "");
          dispatch({ type: "event", event: parsed });
        }, controller.signal);
        break;
      } catch (error) {
        if (controller.signal.aborted) return;
        if (retries === 3) dispatch({ type: "error", message: String(error) });
        await new Promise((resolve) => setTimeout(resolve, 400 * (retries + 1)));
      }
    }
    dispatch({ type: "connected", value: false });
    window.history.replaceState({ ...(window.history.state ?? {}), activeRun: null, runSeq: cursorRef.current }, "");
    if (state.selectedThread) await selectThread(state.selectedThread).catch(() => undefined);
  }, [state.selectedThread]);

  const send = async (event: FormEvent) => {
    event.preventDefault(); if (!draft.trim()) return;
    let selected = state.selectedThread;
    if (!selected) {
      const created = await api<{ thread: Thread }>("/api/agent/threads", { method: "POST", body: JSON.stringify({ title: draft.slice(0, 60), session_id: sessionId || null }) });
      selected = created.thread.id; await loadThreads(); dispatch({ type: "select", threadId: selected, messages: [] });
    }
    const text = draft; setDraft("");
    const result = await api<{ run_id: string }>("/api/agent/runs", { method: "POST", body: JSON.stringify({ thread_id: selected, message: text }) });
    window.history.replaceState({ ...(window.history.state ?? {}), activeRun: result.run_id, runSeq: 0 }, "");
    dispatch({ type: "run", runId: result.run_id }); void consume(result.run_id);
  };

  const decide = async (toolCallId: string, argsHash: string, approved: boolean) => {
    if (!state.activeRun) return;
    await api(`/api/agent/runs/${state.activeRun}/tool-calls/${toolCallId}/${approved ? "approve" : "reject"}`, { method: "POST", body: JSON.stringify({ args_sha256: argsHash }) });
    dispatch({ type: "approval_done", toolCallId });
  };

  const visibleMessages = useMemo(() => state.messages, [state.messages]);

  if (landingOpen) {
    return <WorkspaceLanding onChoose={(profile) => { setWorkspaceProfile(profile); setLandingOpen(false); }} />;
  }

  return <main className="workbench">
    <aside className="sidebar">
      <div className="brand"><div className="logo">RE</div><div><b>Headless Workbench</b><small>{state.connected ? "streaming" : "loopback"}</small></div></div>
      <button className="new-thread" onClick={createThread}>＋ New thread</button>
      <label>Analysis session<select value={sessionId} onChange={(e) => setSessionId(e.target.value)}><option value="">No linked session</option>{sessions.map((session) => <option key={session.id} value={session.id}>{session.binary?.split(/[\\/]/).pop() ?? session.id} · {session.state}</option>)}</select></label>
      <nav>{state.threads.map((thread) => <button className={thread.id === state.selectedThread ? "thread active" : "thread"} key={thread.id} onClick={() => void selectThread(thread.id)}><span>{thread.title}</span><small>{thread.session_id ? "linked" : "chat"}</small></button>)}</nav>
      <div className="sidebar-actions"><button onClick={() => setLandingOpen(true)}>Work direction{workspaceProfile ? ` · ${workspaceProfile}` : ""}</button><button onClick={() => setSettingsOpen(true)}>Provider & setup</button><a href="/api/mcp/export" onClick={(event) => event.preventDefault()}>MCP export</a></div>
    </aside>
    <section className="conversation">
      <header><div><h1>Agent analysis</h1><p>Read-only tools run automatically. Every mutation waits for one-time approval.</p></div>{state.activeRun && <button className="cancel" onClick={() => void api(`/api/agent/runs/${state.activeRun}/cancel`, { method: "POST" })}>Cancel run</button>}</header>
      <div className="messages">
        {visibleMessages.length === 0 && !state.streamingText && <div className="empty"><div>⌁</div><h2>Start with an authorized binary</h2><p>Link a session, ask for recon, then inspect tool evidence on the right.</p></div>}
        {visibleMessages.map((message) => <article className={`message ${message.role}`} key={message.id}><b>{message.role}</b><div>{message.content}</div></article>)}
        {state.streamingText && <article className="message assistant"><b>assistant · live</b><div>{state.streamingText}<span className="cursor" /></div></article>}
        {state.approvals.map((approval) => <ApprovalCard key={approval.tool_call_id} approval={approval} onDecision={(approved) => void decide(approval.tool_call_id, approval.args_sha256, approved)} />)}
        {state.error && <div className="error">{state.error}</div>}
      </div>
      <form className="composer" onSubmit={(event) => void send(event)}><textarea aria-label="Message" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Ask the Agent to inspect, explain, or operate…" rows={3}/><button disabled={!draft.trim() || Boolean(state.activeRun)}>Send</button></form>
    </section>
    <Inspector events={state.events} monitor={monitor} artifacts={artifacts} audit={audit} sessionId={sessionId} />
    {settingsOpen && <div className="modal-backdrop" role="presentation" onClick={() => setSettingsOpen(false)}><section className="modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}><button className="modal-close" onClick={() => setSettingsOpen(false)}>×</button><h2>Provider & setup</h2><p>Provider secrets are submitted directly to the loopback service and are never retained in DOM or browser storage.</p><ProviderForm onSaved={() => setSettingsOpen(false)} /></section></div>}
  </main>;
}

function ProviderForm({ onSaved }: { onSaved: () => void }) {
  const [baseUrl, setBaseUrl] = useState("https://api.openai.com/v1"); const [model, setModel] = useState("gpt-4.1-mini"); const [key, setKey] = useState("");
  const save = async (event: FormEvent) => { event.preventDefault(); await api("/api/providers/default", { method: "PUT", body: JSON.stringify({ base_url: baseUrl, model, api_key: key, make_current: true }) }); setKey(""); onSaved(); };
  return <form className="provider-form" onSubmit={(event) => void save(event)}><label>Base URL<input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} /></label><label>Model<input value={model} onChange={(e) => setModel(e.target.value)} /></label><label>API key<input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} /></label><button>Save server-side</button></form>;
}
