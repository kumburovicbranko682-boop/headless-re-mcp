import { asFileName } from "./sessionLabel";

export type RememberedSample = {
  threadId?: string | null;
  sessionId: string;
  path: string;
  name: string;
};

const KEY = "headless_re_sample_v1";

type Store = {
  byThread: Record<string, RememberedSample>;
  bySession: Record<string, RememberedSample>;
};

function emptyStore(): Store {
  return { byThread: {}, bySession: {} };
}

function readStore(): Store {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return emptyStore();
    const parsed = JSON.parse(raw) as Partial<Store>;
    return {
      byThread: parsed.byThread && typeof parsed.byThread === "object" ? parsed.byThread : {},
      bySession: parsed.bySession && typeof parsed.bySession === "object" ? parsed.bySession : {},
    };
  } catch {
    return emptyStore();
  }
}

function writeStore(store: Store): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(store));
  } catch {
    /* quota / private mode */
  }
}

export function rememberSample(sample: {
  threadId?: string | null;
  sessionId: string;
  path: string;
}): RememberedSample {
  const name = asFileName(sample.path) || sample.sessionId;
  const row: RememberedSample = {
    threadId: sample.threadId ?? null,
    sessionId: sample.sessionId,
    path: sample.path,
    name,
  };
  const store = readStore();
  if (row.threadId) store.byThread[row.threadId] = row;
  store.bySession[row.sessionId] = row;
  writeStore(store);
  return row;
}

export function recallSample(threadId?: string | null, sessionId?: string | null): RememberedSample | null {
  const store = readStore();
  if (threadId && store.byThread[threadId]) return store.byThread[threadId];
  if (sessionId && store.bySession[sessionId]) return store.bySession[sessionId];
  return null;
}
