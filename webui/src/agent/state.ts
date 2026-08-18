export type Thread = { id: string; title: string; session_id: string | null; created_at: string; updated_at: string };
export type Message = { id: string; role: string; content: string; run_id?: string | null; tool_call_id?: string | null };
export type RunEvent = { run_id: string; seq: number; type: string; data: Record<string, unknown>; created_at: string; created_ms?: number };
export type Approval = { tool_call_id: string; name: string; args_sha256: string; effects: string[]; arguments: Record<string, unknown> };
export type AgentState = {
  threads: Thread[];
  selectedThread: string | null;
  messages: Message[];
  events: RunEvent[];
  approvals: Approval[];
  streamingText: string;
  streamingReasoning: string;
  activeRun: string | null;
  connected: boolean;
  error: string | null;
};
export type AgentAction =
  | { type: "threads"; threads: Thread[] }
  | { type: "select"; threadId: string | null; messages: Message[]; events?: RunEvent[] }
  | { type: "messages"; messages: Message[] }
  | { type: "run"; runId: string; userMessage?: string }
  | { type: "event"; event: RunEvent }
  | { type: "approval_done"; toolCallId: string }
  | { type: "connected"; value: boolean }
  | { type: "error"; message: string | null }
  | { type: "stream_ended"; runId: string };

export function runFailureHint(type: string, data: Record<string, unknown>): string | null {
  if (type === "run.completed") return null;
  if (type === "run.cancelled") return "\u672c\u8f6e\u5df2\u53d6\u6d88";
  if (type === "run.rejected") return "\u5199\u64cd\u4f5c\u88ab\u62d3\u7edd\uff0c\u672c\u8f6e\u5df2\u505c";
  const raw = String(data.error ?? type);
  if (/maximum tool rounds exceeded/i.test(raw)) {
    return "\u672c\u8f6e\u5de5\u5177\u6b65\u6570\u7528\u5b8c\u4e86\uff0c\u4e0d\u662f\u5d29\u6e83\u3002\u4f1a\u8bdd\u8fd8\u5728\uff0c\u63a5\u7740\u53d1\u4e00\u53e5\u5373\u53ef\u7ee7\u7eed\u3002";
  }
  const timed = /tool timed out:\s*([A-Za-z0-9._]+)/i.exec(raw);
  if (timed) {
    return `${timed[1]} \u8d85\u8fc7\u65f6\u9650\uff0c\u672c\u8f6e\u5df2\u505c\u3002\u4e0d\u662f\u81ea\u5df1\u4e0b\u73ed\u4e86\uff1bIDA \u9996\u6b21\u6253\u5f00\u5927\u6587\u4ef6\u7ecf\u5e38\u8981\u66f4\u4e45\u3002`;
  }
  if (type === "run.failed") return raw.replace(/^Error:\s*/i, "") || "\u672c\u8f6e\u5931\u8d25";
  return null;
}

export const initialState: AgentState = { threads: [], selectedThread: null, messages: [], events: [], approvals: [], streamingText: "", streamingReasoning: "", activeRun: null, connected: false, error: null };

const MAX_RETAINED_EVENTS = 200;

function capEvents(events: RunEvent[]): RunEvent[] {
  return events.length <= MAX_RETAINED_EVENTS ? events : events.slice(-MAX_RETAINED_EVENTS);
}

export function reducer(state: AgentState, action: AgentAction): AgentState {
  switch (action.type) {
    case "threads": return { ...state, threads: action.threads };
    case "select": {
      const same = action.threadId === state.selectedThread;
      return {
        ...state,
        selectedThread: action.threadId,
        messages: action.messages,
        events: capEvents(action.events ?? (same ? state.events : [])),
        approvals: [],
        streamingText: "",
        streamingReasoning: "",
        activeRun: same ? state.activeRun : null,
        connected: same ? state.connected : false,
        error: null,
      };
    }
    case "messages": return { ...state, messages: action.messages };
    case "run": {
      const messages = action.userMessage
        ? [...state.messages, { id: `local-${action.runId}`, role: "user", content: action.userMessage }]
        : state.messages;
      return { ...state, activeRun: action.runId, messages, approvals: [], streamingText: "", streamingReasoning: "", error: null };
    }
    case "connected": return { ...state, connected: action.value };
    case "error": return { ...state, error: action.message };
    case "approval_done": return { ...state, approvals: state.approvals.filter((item) => item.tool_call_id !== action.toolCallId) };
    case "event": {
      if (state.events.some((item) => item.seq === action.event.seq && item.run_id === action.event.run_id)) return state;
      const events = capEvents([...state.events, action.event].sort((a, b) => a.seq - b.seq));
      if (action.event.type === "message.delta") {
        return { ...state, events, streamingText: state.streamingText + String(action.event.data.delta ?? "") };
      }
      if (action.event.type === "reasoning.delta") {
        return { ...state, events, streamingReasoning: state.streamingReasoning + String(action.event.data.delta ?? "") };
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
      if (["run.completed", "run.failed", "run.cancelled", "run.rejected"].includes(action.event.type)) {
        return {
          ...state,
          events,
          activeRun: null,
          connected: false,
          streamingText: "",
          streamingReasoning: "",
          approvals: [],
          error: runFailureHint(action.event.type, action.event.data) ?? state.error,
        };
      }
      return { ...state, events };
    }
    case "stream_ended": {
      if (state.activeRun && state.activeRun !== action.runId) return state;
      return {
        ...state,
        activeRun: null,
        connected: false,
        streamingText: "",
        streamingReasoning: "",
        error: state.activeRun === action.runId
          ? (state.error ?? "\u4e8b\u4ef6\u63a8\u9001\u65ad\u4e86\uff0c\u82e5\u52a9\u624b\u8fd8\u505c\u5728\u534a\u53e5\uff0c\u518d\u53d1\u4e00\u53e5\u5373\u53ef\u3002")
          : state.error,
      };
    }
  }
}
