import { afterEach, vi } from "vitest";
import { bootstrapToken, fetchRunHistory, setTokenForTests } from "./client";

describe("token bootstrap", () => {
  it("removes the token from the visible URL without browser storage", () => {
    history.replaceState({}, "", "/workbench?token=secret-value&x=1#chat");
    expect(bootstrapToken(window.location)).toBe("secret-value");
    expect(window.location.href).not.toContain("secret-value");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    setTokenForTests("");
  });
});

describe("fetchRunHistory", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const pageResponse = (events: { seq: number }[]) => ({
    ok: true,
    status: 200,
    json: async () => ({ ok: true, events }),
  });

  it("pages by last seq until an empty read instead of trusting one page", async () => {
    // One server page caps at 1000 events / 8 MiB; message.delta alone
    // overruns that on a long answer. A single fetch replayed the first page
    // and left a permanent hole up to the live cursor.
    const pages: Record<string, { seq: number }[]> = {
      "0": [{ seq: 1 }, { seq: 2 }, { seq: 3 }],
      "3": [{ seq: 4 }, { seq: 5 }],
      "5": [],
    };
    const fetchSpy = vi.fn(async (path: string) => {
      const after = new URL(path, "http://localhost").searchParams.get("after") ?? "";
      return pageResponse(pages[after]);
    });
    vi.stubGlobal("fetch", fetchSpy);

    const replay = await fetchRunHistory("run-1");

    expect(replay.map((event) => event.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(fetchSpy.mock.calls.map(([path]) => path)).toEqual([
      "/api/agent/runs/run-1/events/history?after=0",
      "/api/agent/runs/run-1/events/history?after=3",
      "/api/agent/runs/run-1/events/history?after=5",
    ]);
  });

  it("stops at the page guard when the server never returns an empty page", async () => {
    let seq = 0;
    vi.stubGlobal("fetch", vi.fn(async () => pageResponse([{ seq: (seq += 1) }])));

    const replay = await fetchRunHistory("run-2", 3);

    expect(replay.map((event) => event.seq)).toEqual([1, 2, 3]);
  });
});
