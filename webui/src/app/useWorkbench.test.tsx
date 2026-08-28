import { act, renderHook } from "@testing-library/react";
import { useWorkbench } from "./useWorkbench";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));

vi.mock("../api/client", () => ({
  api: apiMock,
  bootstrapToken: vi.fn(),
  streamEvents: vi.fn(async () => undefined),
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function threadResponse(id: string) {
  return {
    thread: { id, title: id, session_id: null, created_at: "", updated_at: "" },
    messages: [{ id: `m-${id}`, role: "user", content: id }],
    events: [],
  };
}

describe("useWorkbench thread selection", () => {
  it("keeps the last-clicked thread when an earlier click's response arrives late", async () => {
    // A heavy thread's GET can outlive a lighter one's: click slow, click fast,
    // fast renders -- then slow's stale response used to flip the workbench back
    // to the thread the user had already left.
    const slow = deferred<unknown>();
    const fast = deferred<unknown>();
    apiMock.mockImplementation((path: string) => {
      if (path === "/api/agent/threads/slow") return slow.promise;
      if (path === "/api/agent/threads/fast") return fast.promise;
      if (path === "/api/agent/threads") return Promise.resolve({ threads: [] });
      if (path === "/api/sessions") return Promise.resolve({ data: { sessions: [] } });
      return Promise.resolve({});
    });

    const hook = renderHook(() => useWorkbench());
    await act(async () => {});

    let slowDone!: Promise<void>;
    let fastDone!: Promise<void>;
    act(() => {
      slowDone = hook.result.current.selectThread("slow");
      fastDone = hook.result.current.selectThread("fast");
    });

    await act(async () => {
      fast.resolve(threadResponse("fast"));
      await fastDone;
    });
    expect(hook.result.current.state.selectedThread).toBe("fast");

    await act(async () => {
      slow.resolve(threadResponse("slow"));
      await slowDone;
    });
    expect(hook.result.current.state.selectedThread).toBe("fast");
    expect(hook.result.current.state.messages.map((message) => message.content)).toEqual(["fast"]);
  });
});
