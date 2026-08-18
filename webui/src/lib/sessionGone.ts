export function isSessionGone(error?: { code?: string; message?: string } | null, extra?: string): boolean {
  const text = [error?.code ?? "", error?.message ?? "", extra ?? ""].join(" ");
  return /session_not_found|session not found/i.test(text);
}

export function reconnectHint(fileName?: string): string {
  const name = (fileName ?? "").trim();
  const named = name
    ? `重新打开 ${name} 即可继续。`
    : "重新打开同一个文件即可继续。";
  return `样本分析进程已断开（监控台重启会结束调试进程）。对话和记录还在，没有清掉。${named}`;
}

export function dormantHint(): string {
  return "此会话在控制台重启后仍保留同一 ID。分析进程需要重新打开，继续发消息或点「打开静态」即可唤醒。";
}

export function inspectorDisconnectedHint(): string {
  return "监视已暂停。对话还在，重新打开样本后会恢复。";
}

export function staleSessionHint(): string {
  return reconnectHint();
}
