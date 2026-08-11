let token = "";

export function bootstrapToken(locationLike: Location = window.location): string {
  const url = new URL(locationLike.href);
  const supplied = url.searchParams.get("token");
  if (supplied) {
    token = supplied;
    url.searchParams.delete("token");
    window.history.replaceState({ ...(window.history.state ?? {}), __headlessToken: supplied }, "", `${url.pathname}${url.search}${url.hash}`);
  } else if (typeof window.history.state?.__headlessToken === "string") {
    token = window.history.state.__headlessToken;
  }
  return token;
}

export function setTokenForTests(value: string): void { token = value; }

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  if (!token) throw new Error("Web token missing; reopen the launch URL");
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const payload = await response.json().catch(() => ({ detail: response.statusText })) as Record<string, unknown>;
  if (!response.ok) throw new Error(String(payload.detail ?? `HTTP ${response.status}`));
  return payload as T;
}

export async function apiBlob(path: string, signal?: AbortSignal): Promise<Blob> {
  if (!token) throw new Error("Web token missing; reopen the launch URL");
  const response = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` },
    credentials: "same-origin",
    cache: "no-store",
    signal,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText })) as Record<string, unknown>;
    const error = payload.error as Record<string, unknown> | undefined;
    throw new Error(String(error?.message ?? payload.detail ?? `HTTP ${response.status}`));
  }
  return response.blob();
}

export type FrameResult = { blob: Blob; degraded: boolean; reason: string | null; backend: string | null };

export async function apiFrame(path: string, signal?: AbortSignal): Promise<FrameResult> {
  if (!token) throw new Error("Web token missing; reopen the launch URL");
  const response = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` },
    credentials: "same-origin",
    cache: "no-store",
    signal,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText })) as Record<string, unknown>;
    const error = payload.error as Record<string, unknown> | undefined;
    throw new Error(String(error?.message ?? payload.detail ?? `HTTP ${response.status}`));
  }
  const blob = await response.blob();
  return {
    blob,
    degraded: response.headers.get("X-Capture-Degraded") === "1",
    reason: response.headers.get("X-Capture-Degraded-Reason"),
    backend: response.headers.get("X-Capture-Backend"),
  };
}

export async function streamEvents(
  runId: string,
  after: number,
  onEvent: (event: { type: string; data: string; id?: string }) => void,
  signal: AbortSignal,
): Promise<void> {
  if (!token) throw new Error("Web token missing");
  const response = await fetch(`/api/agent/runs/${encodeURIComponent(runId)}/events?after=${after}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "text/event-stream" }, signal, credentials: "same-origin",
  });
  if (!response.ok || !response.body) throw new Error(`SSE HTTP ${response.status}`);
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    let split = buffer.indexOf("\n\n");
    while (split >= 0) {
      const frame = buffer.slice(0, split).replace(/\r/g, "");
      buffer = buffer.slice(split + 2);
      let type = "message"; let data = ""; let id: string | undefined;
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:")) type = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
        else if (line.startsWith("id:")) id = line.slice(3).trim();
      }
      if (data) onEvent({ type, data, id });
      split = buffer.indexOf("\n\n");
    }
  }
}
