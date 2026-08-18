import { reconnectHint } from "../lib/sessionGone";

export type LostSample = { sessionId: string; path: string; name: string };

type Props = { lost: LostSample; busy?: boolean; compact?: boolean; onReopen: () => void };

export function SessionReconnect({ lost, busy, compact, onReopen }: Props) {
  return (
    <div className={compact ? "reconnect compact" : "reconnect"}>
      <div>
        <b>分析进程已断开</b>
        <p>{reconnectHint(lost.name)}</p>
      </div>
      {lost.path ? (
        <button type="button" disabled={busy} onClick={onReopen}>
          {busy ? "打开中…" : `重新打开 ${lost.name}`}
        </button>
      ) : (
        <p className="reconnect-fallback">请在左侧重新打开同一个文件。对话不用重开。</p>
      )}
    </div>
  );
}
