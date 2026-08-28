import { act, render } from "@testing-library/react";
import { VirtualDesktopMonitor } from "./VirtualDesktopMonitor";

const { apiMock, apiFrameMock } = vi.hoisted(() => ({
  apiMock: vi.fn(),
  apiFrameMock: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: apiMock,
  apiFrame: apiFrameMock,
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function snapshotFor(id: string) {
  return {
    ok: true,
    data: {
      available: true,
      mode: "hidden_win32",
      input_desktop: false,
      window_count: 1,
      windows: [
        {
          hwnd: id === "a" ? 111 : 222,
          pid: 1,
          title: `win-${id}`,
          class_name: "C",
          visible: true,
          minimized: false,
          area: 10_000,
          rect: { width: 100, height: 100 },
        },
      ],
      debuggee_state: "paused",
    },
  };
}

describe("VirtualDesktopMonitor stale-session responses", () => {
  beforeEach(() => {
    apiMock.mockReset();
    apiFrameMock.mockReset();
    apiFrameMock.mockResolvedValue({ blob: new Blob(["x"]), degraded: false, reason: null, backend: null });
    (URL as unknown as { createObjectURL: unknown }).createObjectURL = vi.fn(() => "blob:frame");
    (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = vi.fn();
  });

  it("drops session A's late desktop snapshot after the user switches to session B", async () => {
    const slow = deferred<unknown>();
    apiMock.mockImplementation((path: string) => {
      if (path.startsWith("/api/sessions/a/virtual-desktop")) return slow.promise;
      if (path.startsWith("/api/sessions/b/virtual-desktop")) return Promise.resolve(snapshotFor("b"));
      return Promise.resolve({ ok: true, data: {} });
    });

    const view = render(<VirtualDesktopMonitor sessionId="a" />);
    await act(async () => {});

    // Switch to B before A's snapshot resolves; B renders its own window row.
    view.rerender(<VirtualDesktopMonitor sessionId="b" />);
    await act(async () => {});
    expect(view.container.textContent).toContain("win-b");

    // A's slow snapshot now lands; it must not repaint the window list.
    await act(async () => {
      slow.resolve(snapshotFor("a"));
      await Promise.resolve();
    });
    expect(view.container.textContent).not.toContain("win-a");
    expect(view.container.textContent).toContain("win-b");
  });
});
