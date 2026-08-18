import { render, screen, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { Inspector } from "./Inspector";

function jsonOk(data: unknown) {
  return new Response(JSON.stringify({ ok: true, data }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("Inspector surfaces", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/web/status")) return jsonOk({ open: false, locator: "https://example.com" });
      if (url.includes("/virtual-desktop")) {
        return jsonOk({ available: false, mode: "unavailable", windows: [], window_count: 0, input_desktop: false });
      }
      if (url.includes("/monitor")) {
        return jsonOk({
          ok: true,
          session: { id: "s1", state: "created", target: "pe", binary: "F:\\test.exe" },
          dynamic: {},
          timeline: { items: [] },
          events: { items: [] },
        });
      }
      if (url.includes("/dynamic/open") || url.includes("/web/open")) return jsonOk({});
      if (url.includes("/knowledge")) return jsonOk({ entries: [], total: 0 });
      if (url.includes("/timeline")) return jsonOk({ events: [] });
      if (url.includes("/artifacts")) return jsonOk({ artifacts: [] });
      if (url.includes("/audit")) return jsonOk({ entries: [] });
      return jsonOk({});
    }));
  });

  afterEach(() => {
    setTokenForTests("");
    vi.restoreAllMocks();
  });

  it("hides the PE debugger when the workspace is web and no session is bound", () => {
    render(<Inspector events={[]} sessionId="" profile="web" />);
    expect(screen.getByText("当前：Web · 浏览器 / 脚本 / WASM / 抓包")).toBeInTheDocument();
    expect(screen.getByText("页面监视")).toBeInTheDocument();
    expect(screen.queryByText("虚拟桌面 · 必开监视")).toBeNull();
    expect(screen.queryByText("打开静态")).toBeNull();
    expect(screen.queryByText("打开动态")).toBeNull();
  });

  it("follows a web session even if the workspace profile is PE", async () => {
    render(<Inspector events={[]} sessionId="web-1" profile="pe" sessionTarget="web" sessionState="created" locator="https://example.com" />);
    expect(screen.getByText("页面监视")).toBeInTheDocument();
    expect(screen.queryByText("虚拟桌面 · 必开监视")).toBeNull();
    expect(screen.queryByText("打开静态")).toBeNull();
    await waitFor(() => expect(screen.getByText("打开浏览器")).toBeInTheDocument());
  });

  it("keeps the PE live monitors for an open PE session", async () => {
    render(<Inspector events={[]} sessionId="pe-1" profile="pe" sessionTarget="pe" sessionState="created" locator="F:\\test.exe" />);
    expect(screen.getByText("虚拟桌面 · 必开监视")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("打开静态")).toBeInTheDocument());
    expect(screen.getByText("打开动态")).toBeInTheDocument();
  });

  it("does not auto-open x64dbg for a restored session", async () => {
    render(
      <Inspector
        events={[]}
        sessionId="pe-restored"
        profile="pe"
        sessionTarget="pe"
        sessionState="created"
        locator="F:\\test.exe"
        sessionRestored
      />,
    );
    expect(screen.queryByText("虚拟桌面 · 必开监视")).toBeNull();
    await waitFor(() => expect(screen.getByText("打开静态")).toBeInTheDocument());
    const fetchMock = vi.mocked(fetch);
    const calls = fetchMock.mock.calls.map((call) => String(call[0]));
    expect(calls.some((url) => url.includes("/dynamic/open"))).toBe(false);
    expect(screen.getByText(/休眠/)).toBeInTheDocument();
  });

  it("does not keep the x64dbg live pane on a closed PE session", () => {
    render(<Inspector events={[]} sessionId="pe-closed" profile="pe" sessionTarget="pe" sessionState="closed" />);
    expect(screen.queryByText("虚拟桌面 · 必开监视")).toBeNull();
    expect(screen.queryByText("打开静态")).toBeNull();
    expect(screen.queryByText("打开动态")).toBeNull();
    expect(screen.getByText("监控")).toBeInTheDocument();
  });
});
