import { act, renderHook, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { useWorkbench } from "./useWorkbench";

function jsonOk(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const T1 = { id: "t1", title: "线程一", session_id: null, created_at: "", updated_at: "" };
const T2 = { id: "t2", title: "线程二", session_id: null, created_at: "", updated_at: "" };

type Route = (url: string, init?: RequestInit) => Response | Promise<Response> | null;

function stubFetch(route: Route): void {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const routed = route(url, init);
    if (routed) return routed;
    if (url.includes("/api/agent/threads/")) {
      return jsonOk({ ok: true, thread: T1, messages: [], events: [] });
    }
    if (url.includes("/api/agent/threads")) return jsonOk({ ok: true, threads: [T1, T2] });
    if (url.includes("/api/agent/personas")) return jsonOk({ ok: true, personas: [] });
    if (url.includes("/api/agent/autonomy")) {
      return jsonOk({ ok: true, policy: { mode: "request", auto_approve_effects: [] } });
    }
    if (url.includes("/api/sessions")) return jsonOk({ ok: true, data: { sessions: [] } });
    if (url.includes("/healthz")) return jsonOk({ started_at: "boot" });
    return jsonOk({ ok: true });
  }));
}

/**
 * Boot, select t1, and start a run whose SSE stream stays open until aborted.
 * Returns the AbortSignal consume() handed to the parked stream fetch.
 */
async function startRunOnT1() {
  let sseSignal: AbortSignal | undefined;
  stubFetch((url, init) => {
    if (url.includes("/api/agent/runs/r1/events")) {
      sseSignal = init?.signal ?? undefined;
      // Park the stream open; reject only when consume aborts it so nothing
      // dangles once the hook unmounts.
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("Aborted", "AbortError")),
        );
      });
    }
    if (url.endsWith("/api/agent/runs") && init?.method === "POST") {
      return jsonOk({ ok: true, run_id: "r1" }, 202);
    }
    return null;
  });
  const rendered = renderHook(() => useWorkbench());
  await waitFor(() => expect(rendered.result.current.state.threads).toHaveLength(2));
  await act(async () => {
    await rendered.result.current.selectThread("t1");
  });
  act(() => rendered.result.current.setDraft("跑一轮"));
  await act(async () => {
    await rendered.result.current.send();
  });
  await waitFor(() => expect(sseSignal).toBeDefined());
  return { rendered, signal: () => sseSignal! };
}

describe("switching threads tears down the previous run's stream", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
    window.history.replaceState(null, "", window.location.pathname);
  });

  afterEach(() => {
    setTokenForTests("");
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("aborts the stream when the user opens a different thread", async () => {
    const { rendered, signal } = await startRunOnT1();
    expect(signal().aborted).toBe(false);
    expect(rendered.result.current.state.activeRun).toBe("r1");
    await act(async () => {
      await rendered.result.current.selectThread("t2");
    });
    // Without the abort the r1 stream keeps feeding events -- and its terminal
    // banner -- into t2, the thread that never started it.
    expect(signal().aborted).toBe(true);
  });

  it("keeps the stream live when re-selecting the same thread", async () => {
    const { rendered, signal } = await startRunOnT1();
    await act(async () => {
      await rendered.result.current.selectThread("t1");
    });
    expect(signal().aborted).toBe(false);
    expect(rendered.result.current.state.activeRun).toBe("r1");
  });

  it("aborts the stream when the running thread is deleted with none left", async () => {
    let sseSignal: AbortSignal | undefined;
    stubFetch((url, init) => {
      if (url.includes("/api/agent/runs/r1/events")) {
        sseSignal = init?.signal ?? undefined;
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError")),
          );
        });
      }
      if (url.endsWith("/api/agent/runs") && init?.method === "POST") {
        return jsonOk({ ok: true, run_id: "r1" }, 202);
      }
      // Only t1 remains, so removeThread("t1") falls to the no-thread branch.
      if (url.includes("/api/agent/threads") && !url.includes("/api/agent/threads/")) {
        return jsonOk({ ok: true, threads: [T1] });
      }
      return null;
    });
    const rendered = renderHook(() => useWorkbench());
    await waitFor(() => expect(rendered.result.current.state.threads).toHaveLength(1));
    await act(async () => {
      await rendered.result.current.selectThread("t1");
    });
    act(() => rendered.result.current.setDraft("跑一轮"));
    await act(async () => {
      await rendered.result.current.send();
    });
    await waitFor(() => expect(sseSignal).toBeDefined());
    expect(sseSignal!.aborted).toBe(false);
    await act(async () => {
      await rendered.result.current.removeThread("t1");
    });
    expect(sseSignal!.aborted).toBe(true);
    expect(rendered.result.current.state.selectedThread).toBeNull();
  });
});
