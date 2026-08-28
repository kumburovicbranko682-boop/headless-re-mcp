import { act, render } from "@testing-library/react";
import { WebMonitor } from "./WebMonitor";

const { apiMock, apiBlobMock } = vi.hoisted(() => ({
  apiMock: vi.fn(),
  apiBlobMock: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: apiMock,
  apiBlob: apiBlobMock,
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function statusEnvelope(url: string) {
  return { ok: true, data: { open: true, url } };
}

describe("WebMonitor stale-session responses", () => {
  beforeEach(() => {
    apiMock.mockReset();
    apiBlobMock.mockReset();
    // jsdom does not implement the object-URL API the capture loop uses. Define
    // the two methods on the real URL so they survive React's unmount cleanup.
    (URL as unknown as { createObjectURL: unknown }).createObjectURL = vi.fn(() => "blob:frame");
    (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = vi.fn();
  });

  it("drops session A's late network rows after the user switches to session B", async () => {
    const slowStatus = deferred<unknown>();
    apiMock.mockImplementation((path: string) => {
      // Session A's status is slow; everything else resolves immediately.
      if (path.startsWith("/api/sessions/a/web/status")) return slowStatus.promise;
      if (path.startsWith("/api/sessions/b/web/status")) return Promise.resolve(statusEnvelope("https://b"));
      if (path.includes("/web/network")) {
        const forA = path.includes("/sessions/a/");
        return Promise.resolve({ ok: true, data: { requests: [{ url: forA ? "https://a/req" : "https://b/req", method: "GET" }] } });
      }
      if (path.includes("/web/console")) return Promise.resolve({ ok: true, data: { console: [] } });
      if (path.includes("/web/scripts")) return Promise.resolve({ ok: true, data: { scripts: [] } });
      return Promise.resolve({ ok: true, data: {} });
    });
    apiBlobMock.mockResolvedValue(new Blob(["x"]));

    const view = render(<WebMonitor sessionId="a" locator="https://a" live={false} />);
    await act(async () => {});

    // Switch to B before A's status resolves; B renders its own request row.
    view.rerender(<WebMonitor sessionId="b" locator="https://b" live={false} />);
    await act(async () => {});
    expect(view.container.textContent).toContain("https://b/req");

    // A's slow status now lands; its follow-up network fetch must not paint.
    await act(async () => {
      slowStatus.resolve(statusEnvelope("https://a"));
      await Promise.resolve();
    });
    expect(view.container.textContent).not.toContain("https://a/req");
    expect(view.container.textContent).toContain("https://b/req");
  });
});
