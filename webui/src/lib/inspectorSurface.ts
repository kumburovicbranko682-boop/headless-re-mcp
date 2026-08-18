export type WorkspaceProfile = "full" | "pe" | "android" | "web";
export type SessionTarget = "pe" | "web" | "apk";
export type InspectorSurface = SessionTarget;
export type OpenFormMode = "url" | "apk" | "file";

const CLOSED = new Set(["closed", "closing", "failed"]);

export function isSessionLive(state?: string | null): boolean {
  if (!state) return false;
  return !CLOSED.has(state);
}

export function looksLikeUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

export function looksLikeApk(value: string): boolean {
  return /\.apk$/i.test(value.trim());
}

export function openFormMode(profile: WorkspaceProfile | null): OpenFormMode {
  if (profile === "web") return "url";
  if (profile === "android") return "apk";
  return "file";
}

export function createTargetForProfile(
  profile: WorkspaceProfile | null,
  input: string,
): SessionTarget {
  if (profile === "web") return "web";
  if (profile === "android") return "apk";
  if (profile === "full" || profile === null) {
    if (looksLikeUrl(input)) return "web";
    if (looksLikeApk(input)) return "apk";
  }
  return "pe";
}

export function inspectorSurface(options: {
  profile: WorkspaceProfile | null;
  target?: string | null;
  hasSession: boolean;
}): InspectorSurface {
  if (options.hasSession) {
    if (options.target === "web") return "web";
    if (options.target === "apk") return "apk";
    if (options.target === "pe") return "pe";
  }
  if (options.profile === "web") return "web";
  if (options.profile === "android") return "apk";
  return "pe";
}

export function peLiveMonitors(surface: InspectorSurface, hasSession: boolean, state?: string | null): boolean {
  return surface === "pe" && hasSession && isSessionLive(state);
}

export const SURFACE_LABEL: Record<InspectorSurface, string> = {
  pe: "当前：PE · IDA / x64dbg",
  web: "当前：Web · 浏览器 / 脚本 / WASM / 抓包",
  apk: "当前：Android · APK / 设备 / Frida",
};

export const PROFILE_LABEL: Record<WorkspaceProfile, string> = {
  pe: "本地 PE",
  web: "Web",
  android: "Android",
  full: "全部工具",
};
