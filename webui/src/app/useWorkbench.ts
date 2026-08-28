import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { readApprovalMode, type ApprovalMode, type AutonomyResponse } from "../agent/autonomy";
import { initialState, reducer, type Message, type RunEvent, type Thread } from "../agent/state";
import type { LostSample } from "../components/SessionReconnect";
import { api, bootstrapToken, fetchRunHistory, streamEvents } from "../api/client";
import { createTargetForProfile, openFormMode, type WorkspaceProfile } from "../lib/inspectorSurface";
import { rememberSample, recallSample } from "../lib/sampleMemory";
import { asFileName, readSession, type ListedSession } from "../lib/sessionLabel";
import { boundSessionId } from "../lib/threadBadge";

type Session = ListedSession;
type ThreadsResponse = { threads: Thread[] };
type ThreadResponse = { thread: Thread; messages: Message[]; events?: RunEvent[] };
type SessionsResponse = { data?: { sessions?: Session[] } };
type SessionCreateResponse = { ok?: boolean; data?: { session?: Session }; error?: { message?: string } };
type PickFileResponse = {
  ok?: boolean;
  data?: { path?: string | null; cancelled?: boolean; available?: boolean; busy?: boolean; error?: string | null };
};
type LastKnownResponse = { ok?: boolean; data?: { live?: boolean; binary?: string } };
type UncleanResponse = { ok?: boolean; data?: { sessions?: { id?: string; binary?: string }[] } };

export type StudioNav = "sessions" | "threads";

export function useWorkbench() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionId, setSessionId] = useState("");
  const [binaryPath, setBinaryPath] = useState("");
  const [opening, setOpening] = useState(false);
  const [picking, setPicking] = useState(false);
  const openingRef = useRef(false);
  const [draft, setDraft] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [mcpOpen, setMcpOpen] = useState(false);
  const [nav, setNav] = useState<StudioNav>("sessions");
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [workspaceProfile, setWorkspaceProfile] = useState<WorkspaceProfile | null>(() => {
    const stored = typeof window !== "undefined" ? window.localStorage.getItem("headless_ws_profile") : null;
    return (stored as WorkspaceProfile | null) ?? null;
  });
  const [landingOpen, setLandingOpen] = useState(workspaceProfile === null);
  const abortRef = useRef<AbortController | null>(null);
  const cursorRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const sessionsRef = useRef<Session[]>([]);
  const selectedThreadRef = useRef<string | null>(null);
  const sessionIdRef = useRef("");
  const lostRef = useRef<LostSample | null>(null);
  const [lost, setLost] = useState<LostSample | null>(null);
  sessionsRef.current = sessions;
  selectedThreadRef.current = state.selectedThread;
  sessionIdRef.current = sessionId;
  lostRef.current = lost;

  const [personaTitle, setPersonaTitle] = useState("");
  const [approvalMode, setApprovalMode] = useState<ApprovalMode>("request");
  const [approvalBusy, setApprovalBusy] = useState(false);
  const approvalsRef = useRef(state.approvals);
  approvalsRef.current = state.approvals;

  const loadThreads = useCallback(async () => {
    const result = await api<ThreadsResponse>("/api/agent/threads");
    dispatch({ type: "threads", threads: Array.isArray(result.threads) ? result.threads : [] });
  }, []);

  const loadSessions = useCallback(async () => {
    const result = await api<SessionsResponse>("/api/sessions");
    const listed = (result.data?.sessions ?? []).map(readSession).filter((item): item is Session => item !== null);
    setSessions(listed);
    return listed;
  }, []);

  const bindSession = useCallback(async (threadId: string, next: string, refresh = true) => {
    await api(`/api/agent/threads/${encodeURIComponent(threadId)}`, {
      method: "PATCH",
      body: JSON.stringify({ session_id: next || null }),
    });
    if (refresh) await loadThreads();
  }, [loadThreads]);

  const consume = useCallback(async (runId: string, initialAfter = 0) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    cursorRef.current = initialAfter;
    dispatch({ type: "connected", value: true });
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
        if (retries === 3 && !lostRef.current) dispatch({ type: "error", message: String(error) });
        await new Promise((resolve) => setTimeout(resolve, 400 * (retries + 1)));
      }
    }
    dispatch({ type: "connected", value: false });
    window.history.replaceState({ ...(window.history.state ?? {}), activeRun: null, runSeq: cursorRef.current }, "");
    dispatch({ type: "stream_ended", runId });
    const threadId = selectedThreadRef.current;
    if (threadId) {
      const result = await api<ThreadResponse>(`/api/agent/threads/${encodeURIComponent(threadId)}`).catch(() => null);
      if (result) dispatch({ type: "messages", messages: result.messages });
    }
  }, []);

  useEffect(() => {
    bootstrapToken();
    let cancelled = false;
    const boot = async () => {
      try {
        const threadResult = await api<ThreadsResponse>("/api/agent/threads");
        await loadSessions();
        await api<{ current?: string; personas?: { id: string; title: string; current?: boolean }[] }>("/api/agent/personas")
          .then((personaList) => {
            const current = personaList.personas?.find((item) => item.current) ?? personaList.personas?.find((item) => item.id === personaList.current);
            setPersonaTitle(current?.title ?? "");
          })
          .catch(() => undefined);
        await api<AutonomyResponse>("/api/agent/autonomy")
          .then((listed) => setApprovalMode(readApprovalMode(listed)))
          .catch(() => undefined);
        const threads = threadResult.threads;
        if (cancelled) return;
        dispatch({ type: "threads", threads: Array.isArray(threads) ? threads : [] });
        const resumeRun = window.history.state?.activeRun;
        const resumeAfter = Number(window.history.state?.runSeq ?? 0);
        if (typeof resumeRun === "string") {
          try {
            // Paged: one history page caps at 1000 events and one long answer
            // exceeds that in message.delta events alone, so a single fetch
            // replayed a hole between its last event and the live cursor.
            const replay = await fetchRunHistory<RunEvent>(resumeRun);
            if (cancelled) return;
            dispatch({ type: "run", runId: resumeRun });
            replay.forEach((event) => dispatch({ type: "event", event }));
            void consume(resumeRun, resumeAfter);
          } catch {
            window.history.replaceState({ ...(window.history.state ?? {}), activeRun: null }, "");
          }
        }
      } catch (error: unknown) {
        dispatch({ type: "error", message: String(error) });
      }
    };
    void boot();
    return () => {
      cancelled = true;
      abortRef.current?.abort();
    };
  }, [consume, loadSessions]);

  const markLost = useCallback(async (id: string, threadId: string | null) => {
    if (!id || lostRef.current?.sessionId === id) return;
    const listed = sessionsRef.current.find((session) => session.id === id);
    const recalled = recallSample(threadId, id);
    let path = listed?.binary || listed?.locator || recalled?.path || "";
    if (!path) {
      try {
        const known = await api<LastKnownResponse>(`/api/sessions/${encodeURIComponent(id)}/last-known`);
        if (known.ok) path = known.data?.binary || "";
      } catch { /* process just came back without this id */ }
    }
    if (!path) {
      try {
        const unclean = await api<UncleanResponse>("/api/sessions/unclean?limit=20");
        const hit = (unclean.data?.sessions ?? []).find((row) => row.id === id);
        path = hit?.binary || "";
      } catch { /* optional */ }
    }
    const name = asFileName(path) || recalled?.name || "sample";
    const next: LostSample = { sessionId: id, path, name };
    lostRef.current = next;
    setLost(next);
    if (path) setBinaryPath(path);
    setSessions((prev) => prev.filter((session) => session.id !== id));
    if (path) rememberSample({ threadId, sessionId: id, path });
  }, []);

  const selectThread = async (id: string) => {
    const result = await api<ThreadResponse>(`/api/agent/threads/${encodeURIComponent(id)}`);
    dispatch({ type: "select", threadId: id, messages: result.messages, events: result.events ?? [] });
    const bound = result.thread.session_id ?? "";
    let listed = sessionsRef.current;
    if (bound && !listed.some((session) => session.id === bound)) {
      listed = await loadSessions();
    }
    if (bound && !listed.some((session) => session.id === bound)) {
      setSessionId(bound);
      await markLost(bound, id);
      return;
    }
    setLost(null);
    lostRef.current = null;
    setSessionId(bound);
  };

  const createThread = async () => {
    const result = await api<{ thread: Thread }>("/api/agent/threads", {
      method: "POST",
      body: JSON.stringify({ title: "分析对话", session_id: lost ? null : (sessionId || null) }),
    });
    await loadThreads();
    await selectThread(result.thread.id);
    setNav("threads");
  };

  const removeThread = async (id: string) => {
    await api(`/api/agent/threads/${encodeURIComponent(id)}`, { method: "DELETE" });
    const remaining = (Array.isArray(state.threads) ? state.threads : []).filter((thread) => thread.id !== id);
    dispatch({ type: "threads", threads: remaining });
    if (state.selectedThread !== id) return;
    const next = remaining[0];
    if (next) {
      await selectThread(next.id);
      return;
    }
    dispatch({ type: "select", threadId: null, messages: [] });
    setLost(null);
    lostRef.current = null;
    setSessionId("");
  };

  const send = async () => {
    if (!draft.trim()) return;
    let selected = state.selectedThread;
    if (!selected) {
      const created = await api<{ thread: Thread }>("/api/agent/threads", {
        method: "POST",
        body: JSON.stringify({ title: draft.slice(0, 60), session_id: lost ? null : (sessionId || null) }),
      });
      selected = created.thread.id;
      await loadThreads();
      dispatch({ type: "select", threadId: selected, messages: [] });
    }
    const text = draft;
    setDraft("");
    const result = await api<{ run_id: string }>("/api/agent/runs", {
      method: "POST",
      body: JSON.stringify({ thread_id: selected, message: text }),
    });
    window.history.replaceState({ ...(window.history.state ?? {}), activeRun: result.run_id, runSeq: 0 }, "");
    dispatch({ type: "run", runId: result.run_id, userMessage: text });
    void consume(result.run_id);
  };

  const cancelRun = async () => {
    if (!state.activeRun) return;
    await api(`/api/agent/runs/${state.activeRun}/cancel`, { method: "POST" });
  };

  const decide = async (toolCallId: string, argsHash: string, approved: boolean, remember?: "tool" | "effect") => {
    if (!state.activeRun) return;
    const result = await api<AutonomyResponse>(
      `/api/agent/runs/${state.activeRun}/tool-calls/${toolCallId}/${approved ? "approve" : "reject"}`,
      { method: "POST", body: JSON.stringify({ args_sha256: argsHash, remember }) },
    );
    if (result.policy) setApprovalMode(readApprovalMode(result));
    dispatch({ type: "approval_done", toolCallId });
  };

  const changeApprovalMode = async (mode: ApprovalMode) => {
    if (approvalBusy) return;
    const previous = approvalMode;
    setApprovalMode(mode);
    setApprovalBusy(true);
    dispatch({ type: "error", message: null });
    try {
      const listed = await api<AutonomyResponse>("/api/agent/autonomy", { method: "PUT", body: JSON.stringify({ mode }) });
      setApprovalMode(readApprovalMode(listed));
      if (mode === "full_access" && state.activeRun) {
        for (const approval of approvalsRef.current) {
          await decide(approval.tool_call_id, approval.args_sha256, true);
        }
      }
    } catch (reason) {
      setApprovalMode(previous);
      dispatch({ type: "error", message: String(reason) });
    } finally {
      setApprovalBusy(false);
    }
  };

  const changeSession = async (next: string) => {
    setLost(null);
    lostRef.current = null;
    setSessionId(next);
    if (state.selectedThread) {
      try {
        await bindSession(state.selectedThread, next);
      } catch (reason) {
        dispatch({ type: "error", message: String(reason) });
      }
    }
  };

  const noteMissingSession = useCallback((id: string) => {
    if (!id || lostRef.current?.sessionId === id) return;
    void markLost(id, selectedThreadRef.current);
  }, [markLost]);

  const noteClosedSession = useCallback((id: string) => {
    if (!id) return;
    setLost(null);
    lostRef.current = null;
    setSessionId((current) => (current === id ? "" : current));
    const threadId = selectedThreadRef.current;
    if (threadId) void bindSession(threadId, "", true);
    void loadSessions();
  }, [bindSession, loadSessions]);

  useEffect(() => {
    let started = "";
    let cancelled = false;
    const tick = async () => {
      try {
        const body = await fetch("/healthz").then((response) => response.json()) as { started_at?: string };
        const mark = String(body.started_at || "");
        if (!mark || cancelled) return;
        if (!started) { started = mark; return; }
        if (mark === started) {
          await loadSessions();
          return;
        }
        started = mark;
        const listed = await loadSessions();
        const current = sessionIdRef.current;
        if (current && !listed.some((session) => session.id === current)) {
          void markLost(current, selectedThreadRef.current);
          return;
        }
        if (lostRef.current && current && listed.some((session) => session.id === current)) {
          setLost(null);
          lostRef.current = null;
        }
      } catch {
        /* backend is down; wait for it */
      }
    };
    const timer = window.setInterval(() => void tick(), 4000);
    void tick();
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [loadSessions, markLost]);

  const openPickedSession = async (path: string) => {
    const binary = path.trim();
    if (!binary || openingRef.current) return;
    openingRef.current = true;
    setOpening(true);
    dispatch({ type: "error", message: null });
    try {
      const target = createTargetForProfile(workspaceProfile, binary);
      const body: Record<string, unknown> = { binary };
      if (target !== "pe") body.target = target;
      const result = await api<SessionCreateResponse>("/api/sessions", {
        method: "POST",
        body: JSON.stringify(body),
      });
      const created = readSession(result.data?.session);
      if (!result.ok || !created?.id) throw new Error(result.error?.message ?? "打开会话失败");
      await loadSessions();
      setSessions((prev) => {
        if (prev.some((item) => item.id === created.id)) {
          return prev.map((item) => item.id === created.id ? { ...item, ...created } : item);
        }
        return [created, ...prev];
      });
      setLost(null);
      lostRef.current = null;
      setSessionId(created.id);
      rememberSample({ threadId: state.selectedThread, sessionId: created.id, path: created.binary || created.locator || binary });
      if (state.selectedThread) await bindSession(state.selectedThread, created.id);
      setBinaryPath("");
      setNav("sessions");
    } catch (reason) {
      dispatch({ type: "error", message: String(reason) });
    } finally {
      openingRef.current = false;
      setOpening(false);
    }
  };

  const pickBinary = async () => {
    if (picking || openingRef.current) return;
    setPicking(true);
    dispatch({ type: "error", message: null });
    try {
      const result = await api<PickFileResponse>("/api/ui/pick-file", { method: "POST", body: "{}" });
      const picked = result.data;
      if (picked?.path) {
        setBinaryPath(picked.path);
        await openPickedSession(picked.path);
        return;
      }
      if (picked?.busy) {
        dispatch({ type: "error", message: "文件对话框还在打开，先关掉再选。" });
        return;
      }
      if (picked?.error) {
        dispatch({ type: "error", message: `无法打开系统文件框：${picked.error}` });
        return;
      }
      if (picked?.available === false) {
        dispatch({ type: "error", message: "本机没有系统文件对话框，请粘贴路径。" });
      }
    } catch (reason) {
      dispatch({ type: "error", message: String(reason) });
    } finally {
      setPicking(false);
    }
  };

  const visibleMessages = useMemo(() => state.messages.slice(-80), [state.messages]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: "end" });
  }, [visibleMessages, state.streamingText, state.streamingReasoning, state.approvals.length]);

  const reopenLost = () => {
    const path = lost?.path || binaryPath.trim();
    if (!path) return;
    void openPickedSession(path);
  };

  const liveSessionId = boundSessionId(sessionId, sessions);
  const liveSession = sessions.find((session) => session.id === liveSessionId) ?? null;
  const formMode = openFormMode(workspaceProfile);
  const pendingName = binaryPath.trim() ? asFileName(binaryPath) : "";
  const unlinkLabel = lost && !liveSessionId
    ? `${lost.name} · 已断开`
    : pendingName && !liveSessionId ? `${pendingName} · 待打开` : "未关联会话";
  const pathLabel = formMode === "url" ? "目标 URL" : formMode === "apk" ? "APK 路径" : "二进制路径";
  const pathPlaceholder = formMode === "url"
    ? "https://example.com"
    : formMode === "apk"
      ? "粘贴 APK 路径，或点右侧浏览"
      : workspaceProfile === "full"
        ? "本机路径或 http(s) URL"
        : "粘贴路径，或点右侧浏览";
  const openHint = liveSessionId
    ? "已关联到当前对话。"
    : opening
      ? "正在打开会话…"
      : formMode === "url"
        ? (pendingName ? "URL 已填入。点打开会话。" : "粘贴 http(s) 地址后打开 Web 会话。")
        : pendingName
          ? "路径已填入。点打开会话，不要把浅色提示当成已选文件。"
          : formMode === "apk"
            ? "点浏览选本机 APK。"
            : "点浏览选本机文件。浅色提示不是已选路径，所以打开会话会是灰的。";

  const chooseProfile = (profile: WorkspaceProfile) => {
    setWorkspaceProfile(profile);
    setLandingOpen(false);
  };

  return {
    state,
    sessions,
    sessionId,
    binaryPath,
    setBinaryPath,
    opening,
    picking,
    draft,
    setDraft,
    settingsOpen,
    setSettingsOpen,
    mcpOpen,
    setMcpOpen,
    nav,
    setNav,
    inspectorOpen,
    setInspectorOpen,
    workspaceProfile,
    landingOpen,
    setLandingOpen,
    bottomRef,
    lost,
    personaTitle,
    approvalMode,
    approvalBusy,
    visibleMessages,
    liveSessionId,
    liveSession,
    formMode,
    pendingName,
    unlinkLabel,
    pathLabel,
    pathPlaceholder,
    openHint,
    loadSessions,
    selectThread,
    createThread,
    removeThread,
    send,
    cancelRun,
    decide,
    changeApprovalMode,
    changeSession,
    noteMissingSession,
    noteClosedSession,
    openPickedSession,
    pickBinary,
    reopenLost,
    chooseProfile,
  };
}
