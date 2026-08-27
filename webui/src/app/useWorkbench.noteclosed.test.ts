import { act, renderHook, waitFor } from "@testing-library/react";
import { useWorkbench } from "./useWorkbench";

function jsonOk(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

// Boot + selectThread succeed; then bindSession (PATCH) and loadSessions (GET
// /api/sessions) are made to reject to simulate a backend restarting or a
// concurrently deleted thread at the moment a session closes.
function makeFetch(failRef: { fail: boolean }) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (url.includes("/healthz")) return jsonOk({ started_at: "t0" });
    if (url.endsWith("/api/agent/threads")) {
      return jsonOk({ ok: true, threads: [{ id: "t1", title: "x", session_id: "s1", created_at: "", updated_at: "" }] });
    }
    if (url.includes("/api/agent/threads/t1") && method === "PATCH") {
      if (failRef.fail) throw new Error("boom-patch");
      return jsonOk({ ok: true, thread: { id: "t1", title: "x", session_id: null, created_at: "", updated_at: "" } });
    }
    if (url.includes("/api/agent/threads/t1")) {
      return jsonOk({ ok: true, thread: { id: "t1", title: "x", session_id: "s1", created_at: "", updated_at: "" }, messages: [], events: [] });
    }
    if (url.includes("/api/sessions")) {
      if (failRef.fail) throw new Error("boom-sessions");
      return jsonOk({ ok: true, data: { sessions: [{ id: "s1" }] } });
    }
    if (url.includes("/api/agent/personas")) return jsonOk({ ok: true, personas: [], current: "" });
    if (url.includes("/api/agent/autonomy")) return jsonOk({ ok: true, mode: "request", policy: {} });
    return jsonOk({ ok: true });
  });
}

describe("useWorkbench.noteClosedSession", () => {
  afterEach(() => vi.restoreAllMocks());

  it("does not leak an unhandled rejection when close cleanup fails", async () => {
    const failRef = { fail: false };
    vi.stubGlobal("fetch", makeFetch(failRef));
    const { result } = renderHook(() => useWorkbench());

    await waitFor(() => expect(result.current.state.threads).toHaveLength(1));
    await act(async () => { await result.current.selectThread("t1"); });
    await waitFor(() => expect(result.current.sessionId).toBe("s1"));

    // Now the backend rejects both the unbind PATCH and the session refresh.
    failRef.fail = true;
    act(() => result.current.noteClosedSession("s1"));

    // Flush the fire-and-forget promises. Before the fix these were bare void
    // calls, so both rejections surfaced as unhandled and failed the test.
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(result.current.sessionId).toBe("");
  });
});
