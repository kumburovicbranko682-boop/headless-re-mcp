/**
 * Reload-resume must reconcile into the run's thread, or the run goes dark.
 *
 * A run is a detached server-side task: it survives a page reload and keeps
 * executing (the orchestrator polls the store for approval decisions, not the
 * SSE connection). The reloaded client resumes the event stream from
 * history.state, but with *no thread selected*: terminal run events clear
 * streamingText without committing it, and consume()'s end-of-stream message
 * reconciliation was gated on a selected thread -- so everything the run said
 * after the reload flashed at most briefly and then vanished, and a follow-up
 * typed into the composer would even land in a brand-new thread. Observed
 * live (Chromium via Playwright): reload while a tool approval was pending,
 * approve it, and the continued assistant turn never appeared; the transcript
 * stayed empty.
 *
 * consume() now falls back to selecting the run's own thread when the stream
 * ends with nothing selected. These tests pin the whole reload shape: the
 * pending approval survives the replay, the stream resumes from the recorded
 * cursor, and once the resumed run ends its messages are durably in the
 * transcript with the thread selected again.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { useWorkbench } from "./useWorkbench";

const harness = vi.hoisted(() => {
  const state = {
    runFinished: false,
    apiPaths: [] as string[],
    streamRequests: [] as { runId: string; after: number }[],
    releaseStream: () => {},
    streamGate: Promise.resolve(),
  };
  const armStreamGate = () => {
    state.streamGate = new Promise<void>((resolve) => {
      state.releaseStream = resolve;
    });
  };
  const thread = {
    id: "t-1",
    title: "analysis",
    session_id: null,
    created_at: "2026-01-01T00:00:00+00:00",
    updated_at: "2026-01-01T00:00:00+00:00",
  };
  const userMessage = { id: "m-1", role: "user", content: "danger approve", run_id: "run-1", tool_call_id: null };
  const finalMessage = { id: "m-2", role: "assistant", content: "tool round finished", run_id: "run-1", tool_call_id: null };
  const api = async (path: string): Promise<unknown> => {
    state.apiPaths.push(path);
    if (path === "/api/agent/threads") return { threads: [thread] };
    if (path === "/api/sessions") return { data: { sessions: [] } };
    if (path === "/api/agent/personas") return { personas: [] };
    if (path === "/api/agent/autonomy") return { ok: true, mode: "request" };
    if (path === "/api/agent/runs/run-1/events/history?after=0") {
      return {
        events: [
          { run_id: "run-1", seq: 4, type: "message.delta", data: { delta: "dangerous operation proposed" }, created_at: "2026-01-01T00:00:01+00:00" },
          { run_id: "run-1", seq: 5, type: "approval.required", data: { tool_call_id: "call-1", name: "report.generate", args_sha256: "abc", effects: ["file_write"], arguments: {} }, created_at: "2026-01-01T00:00:02+00:00" },
        ],
      };
    }
    if (path === "/api/agent/runs/run-1") return { ok: true, run: { id: "run-1", thread_id: "t-1", status: "awaiting_approval" } };
    if (path === "/api/agent/threads/t-1") {
      // While the run is still going only the user's message is stored; the
      // run's own messages are there once it finished.
      const messages = state.runFinished ? [userMessage, finalMessage] : [userMessage];
      return { thread, messages, events: [] };
    }
    throw new Error(`unmocked api path: ${path}`);
  };
  const streamEvents = async (
    runId: string,
    after: number,
    onEvent: (event: { type: string; data: string }) => void,
  ): Promise<void> => {
    state.streamRequests.push({ runId, after });
    // The stream stays open while the approval is pending -- exactly the
    // window the reloaded user looks at the approval card in. The test
    // releases the gate to stand in for "the user approved and the run
    // continued".
    await state.streamGate;
    // The continuation the pre-reload client never saw: the approved tool ran
    // and the model produced one more turn, then the run completed and the
    // server closed the stream.
    onEvent({ type: "message", data: JSON.stringify({ run_id: runId, seq: 6, type: "message.delta", data: { delta: "tool round finished" }, created_at: "2026-01-01T00:00:03+00:00" }) });
    state.runFinished = true;
    onEvent({ type: "message", data: JSON.stringify({ run_id: runId, seq: 7, type: "run.completed", data: { status: "completed" }, created_at: "2026-01-01T00:00:04+00:00" }) });
  };
  return { state, api, streamEvents, armStreamGate };
});

vi.mock("../api/client", () => ({
  bootstrapToken: () => "",
  api: harness.api,
  streamEvents: harness.streamEvents,
}));

describe("reload with an in-flight run", () => {
  beforeEach(() => {
    harness.state.runFinished = false;
    harness.state.apiPaths.length = 0;
    harness.state.streamRequests.length = 0;
    harness.armStreamGate();
    window.localStorage.clear();
    window.history.replaceState({ activeRun: "run-1", runSeq: 5 }, "", "/");
  });

  it("keeps the pending approval and lands the run's messages when it ends", async () => {
    const { result } = renderHook(() => useWorkbench());

    // The pending approval replayed from history survives the reload, the run
    // is active again, and the replayed streaming text is showing.
    await waitFor(() =>
      expect(result.current.state.approvals.some((item) => item.tool_call_id === "call-1")).toBe(true),
    );
    expect(result.current.state.activeRun).toBe("run-1");
    expect(result.current.state.streamingText).toContain("dangerous operation proposed");

    // The stream resumed from the recorded cursor, not from zero.
    await waitFor(() => expect(harness.state.streamRequests).toEqual([{ runId: "run-1", after: 5 }]));

    // The user approves; the server-side run continues, the stream delivers
    // the rest of the run and closes on the terminal event.
    await act(async () => {
      harness.state.releaseStream();
    });

    // The end-of-stream reconciliation must not be skipped just because the
    // reloaded client had no thread selected: the run's own thread is selected
    // and its stored messages -- including the assistant text produced
    // entirely after the reload -- are durably in the transcript, not cleared
    // along with streamingText.
    await waitFor(() => expect(result.current.state.selectedThread).toBe("t-1"));
    await waitFor(() =>
      expect(result.current.state.messages.some((message) => message.content === "tool round finished")).toBe(true),
    );
    expect(result.current.state.messages.some((message) => message.content === "danger approve")).toBe(true);
    expect(result.current.state.activeRun).toBeNull();
    expect(result.current.state.streamingText).toBe("");
  });
});
