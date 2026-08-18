import type { FormEvent } from "react";
import type { OpenFormMode } from "../lib/inspectorSurface";

type Props = {
  formMode: OpenFormMode;
  pathLabel: string;
  pathPlaceholder: string;
  binaryPath: string;
  onPathChange: (value: string) => void;
  picking: boolean;
  opening: boolean;
  pendingName: string;
  liveSessionId: string;
  openHint: string;
  onPick: () => void;
  onOpen: () => void;
};

export function OpenTarget({
  formMode,
  pathLabel,
  pathPlaceholder,
  binaryPath,
  onPathChange,
  picking,
  opening,
  pendingName,
  liveSessionId,
  openHint,
  onPick,
  onOpen,
}: Props) {
  const submit = (event: FormEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (!binaryPath.trim() || opening) return;
    onOpen();
  };
  return (
    <form className="session-open" onSubmit={submit}>
      <div className="session-open-path">
        <input aria-label={pathLabel} value={binaryPath} onChange={(event) => onPathChange(event.target.value)} placeholder={pathPlaceholder} />
        {formMode !== "url" && (
          <button type="button" disabled={picking || opening} onClick={onPick}>
            {picking ? "选择中…" : "浏览…"}
          </button>
        )}
      </div>
      <div className="session-open-actions">
        <button
          type="button"
          className={opening ? "is-busy" : undefined}
          disabled={!binaryPath.trim() || opening}
          onClick={onOpen}
        >
          {opening ? "打开中…" : "打开会话"}
        </button>
      </div>
      {pendingName && !liveSessionId && <p className="session-open-picked">已选 {pendingName}</p>}
      <p className="session-open-hint">{openHint}</p>
    </form>
  );
}
