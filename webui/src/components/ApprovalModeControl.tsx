import { useEffect, useId, useRef, useState } from "react";
import type { ApprovalMode } from "../agent/autonomy";

type Props = {
  mode: ApprovalMode;
  busy?: boolean;
  onChange: (mode: ApprovalMode) => void;
};

function HandIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 11.2V6.4a1.4 1.4 0 0 1 2.8 0V11" />
      <path d="M10.8 10.6V5.6a1.4 1.4 0 1 1 2.8 0V11" />
      <path d="M13.6 10.8V7.6a1.4 1.4 0 1 1 2.8 0V12" />
      <path d="M7.8 11.2c-1.4-.9-3.1.1-3.1 1.8 0 1.2.4 2.3 1.4 3.6C7.6 18.4 9.4 20 12 20c3.3 0 5.8-2.1 5.8-5.1v-3" />
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3.2 19 6.6v5.1c0 4.3-2.8 7.4-7 8.6-4.2-1.2-7-4.3-7-8.6V6.6L12 3.2z" />
      <path d="M12 8.2v4.6" />
      <circle cx="12" cy="15.6" r="0.85" fill="currentColor" stroke="none" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg className="approval-mode-check" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 12.6 10 17.4 19 7" />
    </svg>
  );
}

const OPTIONS: { id: ApprovalMode; title: string; detail: string; icon: typeof HandIcon }[] = [
  { id: "request", title: "请求批准", detail: "写文件、改调试状态或访问外网时始终询问", icon: HandIcon },
  { id: "full_access", title: "完全访问权限", detail: "写操作与外网访问不再询问，可直接改本机会话里的文件与状态", icon: ShieldIcon },
];

export function ApprovalModeOptions({
  mode,
  busy = false,
  onSelect,
}: {
  mode: ApprovalMode;
  busy?: boolean;
  onSelect: (mode: ApprovalMode) => void;
}) {
  return (
    <div className="approval-mode-options" role="listbox" aria-label="批准模式">
      {OPTIONS.map((option) => {
        const selected = mode === option.id;
        const Icon = option.icon;
        return (
          <button
            key={option.id}
            type="button"
            role="option"
            aria-selected={selected}
            disabled={busy}
            className={`approval-mode-option${option.id === "full_access" ? " is-full" : ""}${selected ? " is-selected" : ""}`}
            onClick={() => onSelect(option.id)}
          >
            <span className="approval-mode-icon"><Icon /></span>
            <span className="approval-mode-copy">
              <b>{option.title}</b>
              <small>{option.detail}</small>
            </span>
            {selected ? <CheckIcon /> : <span className="approval-mode-check-slot" />}
          </button>
        );
      })}
    </div>
  );
}

export function ApprovalModeControl({ mode, busy = false, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const [help, setHelp] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const menuId = useId();
  const full = mode === "full_access";

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="approval-mode" ref={rootRef}>
      <button
        type="button"
        className={`approval-mode-pill${full ? " is-full" : ""}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={menuId}
        disabled={busy}
        onClick={() => setOpen((value) => !value)}
      >
        {full ? <ShieldIcon /> : <HandIcon />}
        <span>{full ? "完全访问" : "请求批准"}</span>
      </button>
      {open && (
        <div className="approval-mode-menu" id={menuId} role="dialog" aria-label="应如何批准 Agent 操作？">
          <header>
            <span>应如何批准 Agent 操作？</span>
            <button type="button" className="approval-mode-more" onClick={() => setHelp((value) => !value)}>
              了解更多
            </button>
          </header>
          {help && (
            <p className="approval-mode-help">
              只读分析始终自动执行。此设置只影响会改状态、写文件或出网的工具，并写入本机配置。没有「帮我批准」中间档：要么每次询问，要么全部放行。
            </p>
          )}
          <ApprovalModeOptions
            mode={mode}
            busy={busy}
            onSelect={(next) => {
              onChange(next);
              setOpen(false);
            }}
          />
        </div>
      )}
    </div>
  );
}
