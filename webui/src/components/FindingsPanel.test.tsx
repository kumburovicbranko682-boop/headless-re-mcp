import { act, render } from "@testing-library/react";
import { FindingsPanel } from "./FindingsPanel";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));

vi.mock("../api/client", () => ({ api: apiMock }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("FindingsPanel", () => {
  it("drops a previous session's slow findings landing after a session switch", async () => {
    // The panel does not remount on a session change and nothing polls this
    // list, so session a's slow response arriving after session b's used to
    // stick as b's findings until a manual refresh.
    const slow = deferred<unknown>();
    apiMock.mockImplementation((path: string) => {
      if (path === "/api/sessions/a/knowledge") return slow.promise;
      if (path === "/api/sessions/b/knowledge") {
        return Promise.resolve({
          ok: true,
          data: { entries: [{ kind: "packer", key: "b-key", value: { note: "b" } }], total: 1 },
        });
      }
      return Promise.resolve({ ok: true, data: {} });
    });

    const view = render(<FindingsPanel sessionId="a" />);
    await act(async () => {});
    view.rerender(<FindingsPanel sessionId="b" />);
    await act(async () => {});
    expect(view.container.textContent).toContain("b-key");
    expect(view.container.textContent).toContain("1 条发现");

    await act(async () => {
      slow.resolve({
        ok: true,
        data: { entries: [{ kind: "packer", key: "a-key", value: { note: "a" } }], total: 9 },
      });
    });
    expect(view.container.textContent).not.toContain("a-key");
    expect(view.container.textContent).toContain("b-key");
    expect(view.container.textContent).toContain("1 条发现");
  });
});
