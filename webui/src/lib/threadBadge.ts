import type { Thread } from "../agent/state";
import type { LostSample } from "../components/SessionReconnect";
import { recallSample } from "./sampleMemory";
import { sessionName, type ListedSession } from "./sessionLabel";

export function threadBadge(thread: Thread, sessions: ListedSession[], lost: LostSample | null): string {
  if (!thread.session_id) return "对话";
  const live = sessions.find((session) => session.id === thread.session_id);
  if (live) {
    const name = sessionName(live);
    return live.metadata?.restored ? `${name} · 休眠` : name;
  }
  if (lost && lost.sessionId === thread.session_id) return `${lost.name} · 已断开`;
  const remembered = recallSample(thread.id, thread.session_id);
  if (remembered?.name) return `${remembered.name} · 已断开`;
  return "会话已断开";
}

export function boundSessionId(sessionId: string, sessions: ListedSession[]): string {
  return sessions.some((session) => session.id === sessionId) ? sessionId : "";
}
