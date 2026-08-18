export type SessionMetadata = {
  restored?: boolean;
  missing_file?: boolean;
};

export type ListedSession = {
  id: string;
  binary?: string;
  locator?: string;
  state?: string;
  target?: string;
  metadata?: SessionMetadata;
};

const STATE_LABEL: Record<string, string> = {
  created: "待打开",
  opening: "打开中",
  ready: "就绪",
  running: "运行中",
  suspended: "挂起",
  closing: "关闭中",
  closed: "已关闭",
  failed: "失败",
};

export function asFileName(path: string): string {
  const trimmed = path.trim();
  return trimmed.split(/[\\/]/).pop() || trimmed;
}

export function sessionName(session: { id?: unknown; binary?: unknown; locator?: unknown }): string {
  const binary = typeof session.binary === "string" ? session.binary : "";
  const locator = typeof session.locator === "string" ? session.locator : "";
  const id = typeof session.id === "string" ? session.id : "";
  const raw = binary || locator || id || "session";
  return asFileName(raw) || id || "session";
}

export function readSession(raw: unknown): ListedSession | null {
  if (!raw || typeof raw !== "object") return null;
  const item = raw as Record<string, unknown>;
  const id = typeof item.id === "string" ? item.id : "";
  if (!id) return null;
  return {
    id,
    binary: typeof item.binary === "string" ? item.binary : undefined,
    locator: typeof item.locator === "string" ? item.locator : undefined,
    state: typeof item.state === "string" ? item.state : undefined,
    target: typeof item.target === "string" ? item.target : undefined,
    metadata: readMetadata(item.metadata),
  };
}

export function sessionStateLabel(session: ListedSession): string {
  if (session.metadata?.missing_file) return "文件已不在原路径";
  if (session.metadata?.restored) return "休眠 · 重启后保留";
  const state = session.state ?? "";
  return STATE_LABEL[state] || state || "会话";
}

export function targetLabel(target?: string): string {
  if (target === "web") return "Web";
  if (target === "apk") return "APK";
  return "PE";
}

function readMetadata(raw: unknown): SessionMetadata | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const item = raw as Record<string, unknown>;
  const metadata: SessionMetadata = {};
  if ("restored" in item) metadata.restored = Boolean(item.restored);
  if ("missing_file" in item) metadata.missing_file = Boolean(item.missing_file);
  return metadata;
}
