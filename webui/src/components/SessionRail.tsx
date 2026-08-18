import { sessionName, sessionStateLabel, targetLabel, type ListedSession } from "../lib/sessionLabel";

type Props = {
  sessions: ListedSession[];
  selectedId: string;
  unlinkLabel: string;
  onSelect: (id: string) => void;
  onRefresh: () => void;
};

export function SessionRail({ sessions, selectedId, unlinkLabel, onSelect, onRefresh }: Props) {
  return (
    <section className="session-rail">
      <div className="rail-heading">
        <span>会话</span>
        <button type="button" onClick={onRefresh}>刷新</button>
      </div>
      <button
        type="button"
        className={`session-card ghost${selectedId ? "" : " active"}`}
        onClick={() => onSelect("")}
      >
        <b>{unlinkLabel}</b>
        <small>对话可以不绑定样本</small>
      </button>
      {sessions.length === 0 ? (
        <p className="rail-empty">打开样本后会保存在本机，重启后也还在。</p>
      ) : (
        <div className="session-cards">
          {sessions.map((session) => {
            const dormant = Boolean(session.metadata?.restored);
            return (
              <button
                key={session.id}
                type="button"
                className={`session-card${session.id === selectedId ? " active" : ""}${dormant ? " dormant" : ""}`}
                onClick={() => onSelect(session.id)}
              >
                <span className="session-card-meta">
                  <em>{targetLabel(session.target)}</em>
                  {dormant && <em className="warn">休眠</em>}
                </span>
                <b>{sessionName(session)}</b>
                <small>{sessionStateLabel(session)}</small>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
