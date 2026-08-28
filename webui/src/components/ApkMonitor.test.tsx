import { act, fireEvent, render } from "@testing-library/react";
import { ApkMonitor } from "./ApkMonitor";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));

vi.mock("../api/client", () => ({ api: apiMock }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("ApkMonitor stale-session response", () => {
  beforeEach(() => {
    apiMock.mockReset();
  });

  it("does not paint session A's late APK metadata after the user switches to B", async () => {
    const slowOpen = deferred<unknown>();
    apiMock.mockImplementation((path: string) => {
      if (path.startsWith("/api/sessions/a/apk/open")) return slowOpen.promise;
      return Promise.resolve({ ok: true, data: {} });
    });

    const view = render(<ApkMonitor sessionId="a" locator="a.apk" live={true} />);

    // Kick off A's parse, then switch to B before it resolves.
    fireEvent.click(view.getByText("打开 APK"));
    await act(async () => {});
    view.rerender(<ApkMonitor sessionId="b" locator="b.apk" live={true} />);
    await act(async () => {});

    // A's parse now lands with a package name; it must not stick on B's panel.
    await act(async () => {
      slowOpen.resolve({ ok: true, data: { package: "com.stale.a", version_name: "9.9" } });
      await Promise.resolve();
    });
    expect(view.container.textContent).not.toContain("com.stale.a");
    expect(view.container.textContent).not.toContain("9.9");
  });

  it("still tells the parent that a genuinely closed session is gone even after a switch", async () => {
    const slowClose = deferred<unknown>();
    apiMock.mockImplementation((path: string) => {
      if (path.startsWith("/api/sessions/a/close")) return slowClose.promise;
      return Promise.resolve({ ok: true, data: {} });
    });
    const onSessionClosed = vi.fn();

    const view = render(<ApkMonitor sessionId="a" locator="a.apk" live={true} onSessionClosed={onSessionClosed} />);
    fireEvent.click(view.getByText("关闭会话"));
    await act(async () => {});
    view.rerender(<ApkMonitor sessionId="b" locator="b.apk" live={true} onSessionClosed={onSessionClosed} />);
    await act(async () => {});

    await act(async () => {
      slowClose.resolve({ ok: true, data: {} });
      await Promise.resolve();
    });
    expect(onSessionClosed).toHaveBeenCalledWith("a");
  });
});
