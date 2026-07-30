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
  it("creates an approval card from a required event", () => {
    const event = { run_id: "r", seq: 3, type: "approval.required", data: { tool_call_id: "c", name: "dynamic.resume", args_sha256: "a".repeat(64), effects: ["state_change"], arguments: { session_id: "s" } }, created_at: "" };
    const state = reducer(initialState, { type: "event", event });
    expect(state.approvals[0]?.name).toBe("dynamic.resume");
  });
});
