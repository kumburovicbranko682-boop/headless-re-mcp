export type Thread = { id: string; title: string; session_id: string | null; created_at: string; updated_at: string };
export type Message = { id: string; role: string; content: string; run_id?: string | null; tool_call_id?: string | null };
export type RunEvent = { run_id: string; seq: number; type: string; data: Record<string, unknown>; created_at: string };
export type Approval = { tool_call_id: string; name: string; args_sha256: string; effects: string[]; arguments: Record<string, unknown> };
export type AgentState = {
  threads: Thread[];
  selectedThread: string | null;
  messages: Message[];
  events: RunEvent[];
  approvals: Approval[];
  streamingText: string;
  activeRun: string | null;
  connected: boolean;
  error: string | null;
};
export type AgentAction =
  | { type: "threads"; threads: Thread[] }
  | { type: "select"; threadId: string; messages: Message[] }
  | { type: "run"; runId: string }
  | { type: "event"; event: RunEvent }
  | { type: "approval_done"; toolCallId: string }
  | { type: "connected"; value: boolean }
  | { type: "error"; message: string | null };

export const initialState: AgentState = { threads: [], selectedThread: null, messages: [], events: [], approvals: [], streamingText: "", activeRun: null, connected: false, error: null };

export function reducer(state: AgentState, action: AgentAction): AgentState {
  switch (action.type) {
    case "threads": return { ...state, threads: action.threads };
    case "select": return { ...state, selectedThread: action.threadId, messages: action.messages, events: [], approvals: [], streamingText: "", error: null };
    case "run": return { ...state, activeRun: action.runId, events: [], approvals: [], streamingText: "", error: null };
    case "connected": return { ...state, connected: action.value };
    case "error": return { ...state, error: action.message };
    case "approval_done": return { ...state, approvals: state.approvals.filter((item) => item.tool_call_id !== action.toolCallId) };
    case "event": {
      if (state.events.some((item) => item.seq === action.event.seq && item.run_id === action.event.run_id)) return state;
      const events = [...state.events, action.event].sort((a, b) => a.seq - b.seq);
      if (action.event.type === "message.delta") {
        return { ...state, events, streamingText: state.streamingText + String(action.event.data.delta ?? "") };
      }
      if (action.event.type === "approval.required") {
        const data = action.event.data;
        const approval: Approval = {
          tool_call_id: String(data.tool_call_id), name: String(data.name), args_sha256: String(data.args_sha256),
          effects: Array.isArray(data.effects) ? data.effects.map(String) : [],
          arguments: typeof data.arguments === "object" && data.arguments !== null ? data.arguments as Record<string, unknown> : {},
        };
        return { ...state, events, approvals: [...state.approvals.filter((item) => item.tool_call_id !== approval.tool_call_id), approval] };
      }
      if (["run.completed", "run.failed", "run.cancelled", "run.rejected"].includes(action.event.type)) return { ...state, events, activeRun: null, connected: false };
      return { ...state, events };
    }
  }
}
