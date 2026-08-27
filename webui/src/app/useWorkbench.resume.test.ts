import { renderHook, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { useWorkbench } from "./useWorkbench";

// The SSE reconnect is the one boot call that never returns on its own: keep it
// pending so a resumed run stays "in flight" for the duration of the assertions,
// exactly as it is after a real reload onto a run paused at an approval.
vi.mock("../api/client", async (importActual) => {
  const actual = await importActual<typeof import("../api/client")>();
  return { ...actual, streamEvents: vi.fn(() => new Promise<void>(() => undefined)) };
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const APPROVAL_EVENT = {
  run_id: "run-1",
  seq: 2,
  type: "approval.required",
  data: {
    tool_call_id: "tc1",
    name: "report.generate",
    args_sha256: "abc",
    effects: ["file_write"],
    arguments: {},
  },
  created_at: "2026-01-01T00:00:00Z",
};

const THREAD = { id: "t1", title: "T", session_id: null, created_at: "", updated_at: "" };
const TRANSCRIPT = [
  { id: "m1", role: "user", content: "danger approve" },
  { id: "m2", role: "assistant", content: "tool round finished", run_id: "run-1" },
];

type RunBody = { thread_id?: string };

function installBootFetch(run: RunBody): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    // Order matters: the more specific run/thread paths are prefixes of the
    // collection paths.
    if (url.includes("/api/agent/threads/t1")) {
      return json({ ok: true, thread: THREAD, messages: TRANSCRIPT, events: [] });
    }
    if (url.includes("/api/agent/threads")) return json({ ok: true, threads: [THREAD] });
    if (url.includes("/api/agent/runs/run-1/events/history")) {
      return json({ ok: true, events: [APPROVAL_EVENT] });
    }
    if (url.includes("/api/agent/runs/run-1")) {
      return json({ ok: true, run: { id: "run-1", status: "awaiting_approval", ...run } });
    }
    if (url.includes("/api/sessions")) return json({ ok: true, data: { sessions: [] } });
    if (url.includes("/api/agent/personas")) return json({ personas: [] });
    if (url.includes("/api/agent/autonomy")) return json({});
    return json({ ok: true });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("useWorkbench resume on reload", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
    history.replaceState({ activeRun: "run-1", runSeq: 1 }, "", "/");
  });

  afterEach(() => {
    setTokenForTests("");
    history.replaceState({}, "", "/");
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("reselects the run's thread so the transcript and pending approval survive a reload", async () => {
    installBootFetch({ thread_id: "t1" });

    const { result } = renderHook(() => useWorkbench());

    // The run's own thread is reselected from its thread id...
    await waitFor(() => expect(result.current.state.selectedThread).toBe("t1"));
    // ...which restores the persisted transcript rather than leaving it blank...
    await waitFor(() =>
      expect(result.current.state.messages.map((m) => m.content)).toContain("tool round finished"),
    );
    // ...while the run stays live and its pending approval is replayed.
    expect(result.current.state.activeRun).toBe("run-1");
    expect(result.current.state.approvals.map((a) => a.tool_call_id)).toEqual(["tc1"]);
  });

  it("still restores the run and its approval when the run has no thread id", async () => {
    // A since-deleted thread (or an older run row) must not sink the restore.
    installBootFetch({});

    const { result } = renderHook(() => useWorkbench());

    await waitFor(() => expect(result.current.state.activeRun).toBe("run-1"));
    await waitFor(() => expect(result.current.state.approvals.map((a) => a.tool_call_id)).toEqual(["tc1"]));
    expect(result.current.state.selectedThread).toBeNull();
  });
});
