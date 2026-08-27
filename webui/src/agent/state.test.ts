import { reducer, initialState } from "./state";

describe("agent reducer", () => {
  it("orders replayed events and deduplicates by seq", () => {
    const later = { run_id: "r", seq: 2, type: "tool.started", data: {}, created_at: "" };
    const earlier = { run_id: "r", seq: 1, type: "run.started", data: {}, created_at: "" };
    let state = reducer(initialState, { type: "event", event: later });
    state = reducer(state, { type: "event", event: earlier });
    state = reducer(state, { type: "event", event: earlier });
    expect(state.events.map((item) => item.seq)).toEqual([1, 2]);
  });
  it("appends reasoning while a run is waiting on the first visible token", () => {
    const started = { run_id: "r", seq: 1, type: "run.started", data: {}, created_at: "" };
    const think = { run_id: "r", seq: 2, type: "reasoning.delta", data: { delta: "hmm" }, created_at: "" };
    let state = reducer(initialState, { type: "run", runId: "r", userMessage: "look" });
    state = reducer(state, { type: "event", event: started });
    state = reducer(state, { type: "event", event: think });
    expect(state.messages[0]).toMatchObject({ role: "user", content: "look" });
    expect(state.streamingReasoning).toBe("hmm");
    expect(state.activeRun).toBe("r");
  });
  it("keeps run events when the same thread is refreshed", () => {
    const event = { run_id: "r", seq: 1, type: "llm.started", data: { round: 1 }, created_at: "2026-08-17T09:59:28.362794+00:00" };
    let state = reducer(initialState, { type: "select", threadId: "t1", messages: [] });
    state = reducer(state, { type: "event", event });
    state = reducer(state, { type: "select", threadId: "t1", messages: [{ id: "m", role: "user", content: "hi" }] });
    expect(state.events).toHaveLength(1);
    expect(state.messages[0]?.content).toBe("hi");
  });
  it("does not drop earlier run events when a new run starts", () => {
    const event = { run_id: "r1", seq: 1, type: "llm.started", data: { round: 1 }, created_at: "2026-08-17T09:59:28.362Z" };
    let state = reducer(initialState, { type: "event", event });
    state = reducer(state, { type: "run", runId: "r2", userMessage: "again" });
    expect(state.events).toHaveLength(1);
    expect(state.activeRun).toBe("r2");
  });
  it("creates an approval card from a required event", () => {
    const event = { run_id: "r", seq: 3, type: "approval.required", data: { tool_call_id: "c", name: "dynamic.resume", args_sha256: "a".repeat(64), effects: ["state_change"], arguments: { session_id: "s" } }, created_at: "" };
    const state = reducer(initialState, { type: "event", event });
    expect(state.approvals[0]?.name).toBe("dynamic.resume");
  });

  it("stops the live cursor when a run fails", () => {
    let state = reducer(initialState, { type: "run", runId: "r", userMessage: "go" });
    state = reducer(state, { type: "event", event: { run_id: "r", seq: 1, type: "message.delta", data: { delta: "\u5de5\u4f5c" }, created_at: "" } });
    expect(state.streamingText).toBe("\u5de5\u4f5c");
    state = reducer(state, { type: "event", event: { run_id: "r", seq: 2, type: "run.failed", data: { error: "RuntimeError: tool timed out: static.open (incident abc)" }, created_at: "" } });
    expect(state.activeRun).toBeNull();
    expect(state.streamingText).toBe("");
    expect(state.error).toContain("static.open");
    expect(state.error).toContain("\u4e0d\u662f\u81ea\u5df1\u4e0b\u73ed");
  });

  it("does not present a spent tool-round budget as a crash", () => {
    let state = reducer(initialState, { type: "run", runId: "r", userMessage: "go" });
    state = reducer(state, {
      type: "event",
      event: {
        run_id: "r",
        seq: 1,
        type: "run.failed",
        data: { error: "RuntimeError: maximum tool rounds exceeded (incident f0d699c82d3842f5992cf74356537b1d)" },
        created_at: "",
      },
    });
    expect(state.error).toContain("\u5de5\u5177\u6b65\u6570\u7528\u5b8c");
    expect(state.error).not.toContain("incident");
    expect(state.error).not.toContain("RuntimeError");
  });

  it("does not present a spent run deadline as a crash", () => {
    let state = reducer(initialState, { type: "run", runId: "r", userMessage: "go" });
    state = reducer(state, {
      type: "event",
      event: {
        run_id: "r",
        seq: 1,
        type: "run.failed",
        data: { error: "run deadline exceeded" },
        created_at: "",
      },
    });
    // A long analysis that met the run's own time bound is not broken; it must
    // read like the rounds-exhausted case, not leak the raw English string.
    expect(state.error).toContain("\u8fd0\u884c\u65f6\u9650");
    expect(state.error).not.toContain("run deadline exceeded");
    expect(state.error).toContain("\u4e0d\u662f\u5d29\u6e83");
  });
});
