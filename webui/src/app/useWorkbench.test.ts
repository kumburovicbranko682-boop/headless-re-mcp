import { act, renderHook, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { useWorkbench } from "./useWorkbench";

function jsonOk(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function httpError(status: number, detail: string): Response {
  return jsonOk({ detail }, status);
}

const THREAD = { id: "t1", title: "分析对话", session_id: null, created_at: "", updated_at: "" };

type Route = (url: string, init?: RequestInit) => Response | Promise<Response> | null;

/** Per-test routes first, then the happy-path boot endpoints the hook always hits. */
function stubFetch(route: Route = () => null): void {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const routed = route(url, init);
    if (routed) return routed;
    if (url.includes("/api/agent/threads/")) {
      return jsonOk({ ok: true, thread: THREAD, messages: [], events: [] });
    }
    if (url.includes("/api/agent/threads")) return jsonOk({ ok: true, threads: [THREAD] });
    if (url.includes("/api/agent/personas")) return jsonOk({ ok: true, personas: [] });
    if (url.includes("/api/agent/autonomy")) {
      return jsonOk({ ok: true, policy: { mode: "request", auto_approve_effects: [] } });
    }
    if (url.includes("/api/sessions")) return jsonOk({ ok: true, data: { sessions: [] } });
    if (url.includes("/healthz")) return jsonOk({ started_at: "boot" });
    return jsonOk({ ok: true });
  }));
}

/** Route pair that leaves a run active: the POST succeeds, the SSE never settles. */
function activeRunRoutes(url: string, init?: RequestInit): Response | Promise<Response> | null {
  if (url.includes("/api/agent/runs/r1/events")) return new Promise<Response>(() => undefined);
  if (url.endsWith("/api/agent/runs") && init?.method === "POST") {
    return jsonOk({ ok: true, run_id: "r1" }, 202);
  }
  return null;
}

async function bootWithThread(route: Route = () => null) {
  stubFetch(route);
  const rendered = renderHook(() => useWorkbench());
  await waitFor(() => expect(rendered.result.current.state.threads).toHaveLength(1));
  await act(async () => {
    await rendered.result.current.selectThread("t1");
  });
  expect(rendered.result.current.state.selectedThread).toBe("t1");
  return rendered;
}

describe("useWorkbench user actions surface their failures", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
    // send() records the active run here; an earlier test's success must not
    // make the next boot try to resume that run.
    window.history.replaceState(null, "", window.location.pathname);
  });

  afterEach(() => {
    setTokenForTests("");
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("keeps the typed message and shows why when the run POST is refused", async () => {
    // The backend really refuses this call: an oversized message is a 413, a
    // deleted thread a 404. The draft is cleared before the POST, so without
    // the restore the user's text is destroyed with no feedback at all.
    const { result } = await bootWithThread((url, init) => {
      if (url.endsWith("/api/agent/runs") && init?.method === "POST") {
        return httpError(413, "message exceeds 1 MiB");
      }
      return null;
    });
    act(() => result.current.setDraft("分析这个样本"));
    await act(async () => {
      await result.current.send();
    });
    expect(result.current.draft).toBe("分析这个样本");
    expect(result.current.state.error).toContain("message exceeds 1 MiB");
    expect(result.current.state.activeRun).toBeNull();
  });

  it("does not clobber a newer draft typed while the failed send was in flight", async () => {
    let releaseRun: (response: Response) => void = () => undefined;
    const { result } = await bootWithThread((url, init) => {
      if (url.endsWith("/api/agent/runs") && init?.method === "POST") {
        return new Promise<Response>((resolve) => { releaseRun = resolve; });
      }
      return null;
    });
    act(() => result.current.setDraft("第一句"));
    let inFlight: Promise<void> = Promise.resolve();
    act(() => { inFlight = result.current.send(); });
    act(() => result.current.setDraft("第二句，还没发"));
    await act(async () => {
      releaseRun(httpError(404, "thread_not_found"));
      await inFlight;
    });
    expect(result.current.draft).toBe("第二句，还没发");
    expect(result.current.state.error).toContain("thread_not_found");
  });

  it("reports a failed cancel and keeps the run marked active", async () => {
    const { result } = await bootWithThread((url, init) => {
      if (url.includes("/api/agent/runs/r1/cancel")) return httpError(500, "cancel exploded");
      return activeRunRoutes(url, init);
    });
    act(() => result.current.setDraft("跑一轮"));
    await act(async () => {
      await result.current.send();
    });
    expect(result.current.state.activeRun).toBe("r1");
    await act(async () => {
      await result.current.cancelRun();
    });
    expect(result.current.state.error).toContain("cancel exploded");
    expect(result.current.state.activeRun).toBe("r1");
  });

  it("reports a rejected approval decision instead of dying silently", async () => {
    const { result } = await bootWithThread((url, init) => {
      if (url.includes("/tool-calls/tc1/approve")) {
        return httpError(409, "approval already decided or consumed");
      }
      return activeRunRoutes(url, init);
    });
    act(() => result.current.setDraft("跑一轮"));
    await act(async () => {
      await result.current.send();
    });
    await act(async () => {
      await result.current.decide("tc1", "hash", true);
    });
    expect(result.current.state.error).toContain("approval already decided");
  });

  it("reports a failed thread creation", async () => {
    const { result } = await bootWithThread((url, init) => {
      if (url.endsWith("/api/agent/threads") && init?.method === "POST") {
        throw new TypeError("fetch failed");
      }
      return null;
    });
    await act(async () => {
      await result.current.createThread();
    });
    expect(result.current.state.error).toContain("fetch failed");
  });

  it("keeps a thread listed when deleting it fails", async () => {
    const { result } = await bootWithThread((url, init) => {
      if (url.includes("/api/agent/threads/t1") && init?.method === "DELETE") {
        return httpError(500, "delete exploded");
      }
      return null;
    });
    await act(async () => {
      await result.current.removeThread("t1");
    });
    expect(result.current.state.error).toContain("delete exploded");
    expect(result.current.state.threads).toHaveLength(1);
  });

  it("reports a thread that fails to open and leaves the selection alone", async () => {
    stubFetch((url, init) => {
      if (url.includes("/api/agent/threads/t1") && (!init?.method || init.method === "GET")) {
        return httpError(404, "thread_not_found");
      }
      return null;
    });
    const { result } = renderHook(() => useWorkbench());
    await waitFor(() => expect(result.current.state.threads).toHaveLength(1));
    await act(async () => {
      await result.current.selectThread("t1");
    });
    expect(result.current.state.selectedThread).toBeNull();
    expect(result.current.state.error).toContain("thread_not_found");
  });
});
