import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { WebMonitor } from "./WebMonitor";

function jsonOk(data: unknown) {
  return new Response(JSON.stringify({ ok: true, data }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function stubFetch(status: Record<string, unknown>) {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/web/status")) return jsonOk(status);
    if (url.includes("/web/network")) return jsonOk({ requests: [] });
    if (url.includes("/web/console")) return jsonOk({ console: [] });
    if (url.includes("/web/scripts")) return jsonOk({ scripts: [] });
    return jsonOk({});
  }));
}

describe("WebMonitor stays honest about a crashed browser", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
  });

  afterEach(() => {
    setTokenForTests("");
    vi.restoreAllMocks();
  });

  it("labels an exited browser and blocks navigation", async () => {
    stubFetch({ open: true, responsive: false, exited: true, url: "https://example.com", title: null });
    render(<WebMonitor sessionId="web-1" locator="https://example.com" live />);
    expect(await screen.findAllByText("浏览器已退出")).not.toHaveLength(0);
    expect(screen.getByRole("button", { name: "导航" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "重开浏览器" })).toBeInTheDocument();
    expect(screen.queryByText("浏览器已开")).toBeNull();
  });

  it("reopens a crashed browser with close then open", async () => {
    stubFetch({ open: true, responsive: false, exited: true, url: "https://example.com", title: null });
    render(<WebMonitor sessionId="web-1" locator="https://example.com" live />);
    fireEvent.click(await screen.findByRole("button", { name: "重开浏览器" }));
    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls.map((call) => String(call[0]));
      expect(calls.some((url) => url.includes("/web/close"))).toBe(true);
      expect(calls.some((url) => url.includes("/web/open"))).toBe(true);
    });
  });

  it("labels a wedged browser as unresponsive without the exited wording", async () => {
    stubFetch({ open: true, responsive: false, wedged: true });
    render(<WebMonitor sessionId="web-1" locator="https://example.com" live />);
    await screen.findByText("浏览器无响应");
    expect(screen.getByRole("button", { name: "导航" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "重开浏览器" })).toBeInTheDocument();
  });

  it("keeps a healthy browser fully interactive", async () => {
    stubFetch({ open: true, responsive: true, url: "https://example.com", title: "t" });
    render(<WebMonitor sessionId="web-1" locator="https://example.com" live />);
    await screen.findByText("浏览器已开");
    expect(screen.getByRole("button", { name: "导航" })).not.toBeDisabled();
    expect(screen.queryByRole("button", { name: "重开浏览器" })).toBeNull();
  });
});
