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
  beforeEach(() => {
    apiMock.mockReset();
  });

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

  it("drops the post-run message reload when the user switched threads meanwhile", async () => {
    // When a run's stream ends, consume() refetches the then-selected thread to
    // commit the final transcript. If the user moves to another thread while
    // that refetch is in flight, the old thread's messages must not replace the
    // transcript the user is now reading.
    let t1Calls = 0;
    const reload = deferred<unknown>();
    apiMock.mockImplementation((path: string) => {
      if (path === "/api/agent/threads/t1") {
        t1Calls += 1;
        // First call selects t1; the second is consume's post-run reload.
        return t1Calls === 1 ? Promise.resolve(threadResponse("t1")) : reload.promise;
      }
      if (path === "/api/agent/threads/t2") return Promise.resolve(threadResponse("t2"));
      if (path === "/api/agent/threads") return Promise.resolve({ threads: [] });
      if (path === "/api/sessions") return Promise.resolve({ data: { sessions: [] } });
      if (path === "/api/agent/runs") return Promise.resolve({ run_id: "r1" });
      return Promise.resolve({});
    });

    const hook = renderHook(() => useWorkbench());
    await act(async () => {});
    await act(async () => {
      await hook.result.current.selectThread("t1");
    });
    act(() => {
      hook.result.current.setDraft("go");
    });
    // send() starts the run; the mocked stream ends at once, so by the end of
    // this flush consume's reload of t1 is in flight on the deferred promise.
    await act(async () => {
      await hook.result.current.send();
    });
    expect(t1Calls).toBe(2);
    await act(async () => {
      await hook.result.current.selectThread("t2");
    });
    expect(hook.result.current.state.selectedThread).toBe("t2");
    await act(async () => {
      reload.resolve({
        ...threadResponse("t1"),
        messages: [{ id: "m-old", role: "assistant", content: "t1-final" }],
      });
    });
    expect(hook.result.current.state.selectedThread).toBe("t2");
    expect(hook.result.current.state.messages.map((message) => message.content)).toEqual(["t2"]);
  });
});
