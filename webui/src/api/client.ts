const TOKEN_MISSING = "缺少 Web 令牌，请用启动时带 token 的链接重新打开";

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

function authHeaders(init?: HeadersInit): Headers {
  const headers = new Headers(init);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return headers;
}

function throwIfFailed(response: Response, payload: Record<string, unknown>): void {
  if (response.ok) return;
  if (response.status === 401) throw new Error(TOKEN_MISSING);
  const error = payload.error as Record<string, unknown> | undefined;
  throw new Error(String(error?.message ?? payload.detail ?? `HTTP ${response.status}`));
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = authHeaders(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const payload = await response.json().catch(() => ({ detail: response.statusText })) as Record<string, unknown>;
  throwIfFailed(response, payload);
  return payload as T;
}

export async function fetchRunHistory<T extends { seq: number }>(runId: string, maxPages = 8): Promise<T[]> {
  // The server caps one history page (list_events: 1000 events / 8 MiB), and
  // message.delta is one event per flush, so a single long answer overruns a
  // page. Replaying only the first page left a permanent hole between it and
  // the live cursor on resume. Page by last seq until an empty read; the
  // store retains at most 5000 events per run, so the page guard is a bound
  // against a misbehaving server, not a limit an intact run reaches.
  const events: T[] = [];
  let after = 0;
  for (let page = 0; page < maxPages; page += 1) {
    const result = await api<{ events?: T[] }>(
      `/api/agent/runs/${encodeURIComponent(runId)}/events/history?after=${after}`,
    );
    const batch = Array.isArray(result.events) ? result.events : [];
    if (batch.length === 0) break;
    events.push(...batch);
    after = batch[batch.length - 1].seq;
  }
  return events;
}

export async function apiBlob(path: string, signal?: AbortSignal): Promise<Blob> {
  const response = await fetch(path, {
    headers: authHeaders(),
    credentials: "same-origin",
    cache: "no-store",
    signal,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText })) as Record<string, unknown>;
    throwIfFailed(response, payload);
  }
  return response.blob();
}

export type FrameResult = { blob: Blob; degraded: boolean; reason: string | null; backend: string | null };

export async function apiFrame(path: string, signal?: AbortSignal): Promise<FrameResult> {
  const response = await fetch(path, {
    headers: authHeaders(),
    credentials: "same-origin",
    cache: "no-store",
    signal,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText })) as Record<string, unknown>;
    throwIfFailed(response, payload);
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
  const headers = authHeaders();
  headers.set("Accept", "text/event-stream");
  const response = await fetch(`/api/agent/runs/${encodeURIComponent(runId)}/events?after=${after}`, {
    headers, signal, credentials: "same-origin",
  });
  if (response.status === 401) throw new Error(TOKEN_MISSING);
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
