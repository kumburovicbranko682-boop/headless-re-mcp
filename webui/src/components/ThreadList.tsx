import type { Thread } from "../agent/state";
import type { LostSample } from "./SessionReconnect";
import { threadBadge } from "../lib/threadBadge";
import type { ListedSession } from "../lib/sessionLabel";

type Props = {
  threads: Thread[];
  selectedId: string | null;
  sessions: ListedSession[];
  lost: LostSample | null;
  onSelect: (id: string) => void;
  onRemove: (id: string) => void;
  onCreate: () => void;
};

export function ThreadList({ threads, selectedId, sessions, lost, onSelect, onRemove, onCreate }: Props) {
  return (
    <section className="thread-panel">
      <div className="rail-heading">
        <span>对话</span>
        <button type="button" className="new-thread" onClick={onCreate}>新对话</button>
      </div>
      {threads.length === 0 ? (
        <p className="rail-empty">还没有对话。发送第一条消息会自动创建。</p>
      ) : (
        <nav>
          {threads.map((thread) => (
            <div className={thread.id === selectedId ? "thread-row active" : "thread-row"} key={thread.id}>
              <button className="thread" type="button" onClick={() => onSelect(thread.id)}>
                <span>{thread.title}</span>
                <small>{threadBadge(thread, sessions, lost)}</small>
              </button>
              <button type="button" className="thread-delete" aria-label={`删除 ${thread.title}`} onClick={() => onRemove(thread.id)}>×</button>
            </div>
          ))}
        </nav>
      )}
    </section>
  );
}
