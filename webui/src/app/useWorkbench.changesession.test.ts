import { act, renderHook, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { useWorkbench } from "./useWorkbench";

type Route = (init?: RequestInit) => Response | Promise<Response>;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status });
}

const THREAD = {
  id: "t1",
  title: "分析对话",
  session_id: "sess-a",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const SESSIONS = [
  { id: "sess-a", binary: "C:/samples/a.exe", state: "open", target: "pe" },
  { id: "sess-b", binary: "C:/samples/b.exe", state: "open", target: "pe" },
];

/** fetch stub routing by "METHOD url-substring"; later entries never shadow earlier ones. */
function stubFetch(overrides: Record<string, Route> = {}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    for (const [key, route] of Object.entries(overrides)) {
      const [routeMethod, fragment] = key.split(" ", 2);
      if (method === routeMethod && url.includes(fragment)) return route(init);
    }
    if (method === "GET" && url.includes("/api/agent/threads/t1")) {
      return jsonResponse({ thread: THREAD, messages: [], events: [] });
    }
    if (method === "GET" && url.includes("/api/agent/threads")) {
      return jsonResponse({ threads: [THREAD] });
    }
    if (method === "GET" && url.includes("/api/sessions")) {
      return jsonResponse({ ok: true, data: { sessions: SESSIONS } });
    }
    if (method === "GET" && url.includes("/api/agent/personas")) {
      return jsonResponse({ current: "default", personas: [] });
    }
    if (method === "GET" && url.includes("/api/agent/autonomy")) {
      return jsonResponse({ ok: true, mode: "request" });
    }
    if (method === "GET" && url.includes("/healthz")) {
      return jsonResponse({ ok: true, started_at: "boot-1" });
    }
    if (method === "PATCH" && url.includes("/api/agent/threads/")) {
      return jsonResponse({ ok: true });
    }
    return jsonResponse({ ok: true, data: {} });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function bootWithThreadSelected() {
  const rendered = renderHook(() => useWorkbench());
  await waitFor(() => expect(rendered.result.current.state.threads).toHaveLength(1));
  await act(async () => {
    await rendered.result.current.selectThread("t1");
  });
  await waitFor(() => expect(rendered.result.current.sessionId).toBe("sess-a"));
  return rendered;
}

describe("useWorkbench changeSession", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    setTokenForTests("");
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("rolls the shown binding back when the bind PATCH fails", async () => {
    stubFetch({
      "PATCH /api/agent/threads/t1": () => Promise.reject(new Error("boom-bind")),
    });
    const rendered = await bootWithThreadSelected();

    await act(async () => {
      await rendered.result.current.changeSession("sess-b");
    });

    // The server-side binding is unchanged, so the UI must not keep pointing
    // the inspector/header at sess-b.
    expect(rendered.result.current.sessionId).toBe("sess-a");
    expect(rendered.result.current.state.error).toContain("boom-bind");
  });

  it("keeps the new binding when the bind PATCH succeeds", async () => {
    stubFetch();
    const rendered = await bootWithThreadSelected();

    await act(async () => {
      await rendered.result.current.changeSession("sess-b");
    });

    expect(rendered.result.current.sessionId).toBe("sess-b");
    expect(rendered.result.current.state.error).toBeNull();
  });

  it("restores the lost-sample banner when unbinding away from it fails", async () => {
    stubFetch({
      "PATCH /api/agent/threads/t1": () => Promise.reject(new Error("boom-bind")),
      // sess-a is gone from the list and from every fallback lookup, so
      // selecting the thread marks it lost.
      "GET /api/sessions/sess-a/last-known": () => jsonResponse({ ok: true, data: {} }),
      "GET /api/sessions/unclean": () => jsonResponse({ ok: true, data: { sessions: [] } }),
      "GET /api/sessions": () =>
        jsonResponse({ ok: true, data: { sessions: [SESSIONS[1]] } }),
    });
    const rendered = renderHook(() => useWorkbench());
    await waitFor(() => expect(rendered.result.current.state.threads).toHaveLength(1));
    await act(async () => {
      await rendered.result.current.selectThread("t1");
    });
    await waitFor(() => expect(rendered.result.current.lost?.sessionId).toBe("sess-a"));

    await act(async () => {
      await rendered.result.current.changeSession("sess-b");
    });

    expect(rendered.result.current.sessionId).toBe("sess-a");
    expect(rendered.result.current.lost?.sessionId).toBe("sess-a");
    expect(rendered.result.current.state.error).toContain("boom-bind");
  });
});
