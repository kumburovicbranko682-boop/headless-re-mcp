import { act, fireEvent, render } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { McpExportModal } from "./McpExportModal";

function jsonBody(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

const CURSOR_EXPORT = {
  ok: true,
  doctor_ready: true,
  config: { mcpServers: { "headless-re-mcp": { command: "python-cursor" } } },
  examples: { cursor: { mcpServers: { "headless-re-mcp": { command: "python-cursor" } } } },
};

const VSCODE_EXPORT = {
  ok: true,
  doctor_ready: true,
  config: { servers: { "headless-re-mcp": { type: "stdio", command: "python-vscode" } } },
  examples: { vscode: { servers: { "headless-re-mcp": { type: "stdio", command: "python-vscode" } } } },
};

describe("McpExportModal client tabs", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
  });

  afterEach(() => {
    setTokenForTests("");
    vi.restoreAllMocks();
  });

  it("keeps the last-clicked client's config when an earlier tab's response lands late", async () => {
    const slowCursor = deferred<Response>();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("client=cursor")) return slowCursor.promise;
      if (url.includes("client=vscode")) return jsonBody(VSCODE_EXPORT);
      return jsonBody({ ok: true });
    }));

    const view = render(<McpExportModal onClose={() => {}} />);
    // Generate for the cursor tab; its response hangs.
    fireEvent.click(view.getByText("识别并生成"));
    await act(async () => {});
    // Switch to the VS Code tab, whose generate resolves immediately.
    fireEvent.click(view.getByText("VS Code"));
    await act(async () => {});
    expect(view.container.querySelector(".mcp-pre")?.textContent).toContain("python-vscode");

    // The stale cursor response finally lands -- it must not repaint the
    // modal with cursor JSON while the VS Code tab is active.
    await act(async () => {
      slowCursor.resolve(jsonBody(CURSOR_EXPORT));
      await Promise.resolve();
    });
    const text = view.container.querySelector(".mcp-pre")?.textContent ?? "";
    expect(text).toContain("python-vscode");
    expect(text).not.toContain("python-cursor");
  });

  it("does not show the previous tab's config under a new tab while its fetch is in flight", async () => {
    const hangingVscode = deferred<Response>();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("client=cursor")) return jsonBody(CURSOR_EXPORT);
      if (url.includes("client=vscode")) return hangingVscode.promise;
      return jsonBody({ ok: true });
    }));

    const view = render(<McpExportModal onClose={() => {}} />);
    fireEvent.click(view.getByText("识别并生成"));
    await act(async () => {});
    expect(view.container.querySelector(".mcp-pre")?.textContent).toContain("python-cursor");

    // Copying right after switching tabs must not hand out cursor JSON
    // labeled as VS Code, so the pane empties until the new config lands.
    fireEvent.click(view.getByText("VS Code"));
    await act(async () => {});
    const text = view.container.querySelector(".mcp-pre")?.textContent ?? "";
    expect(text).not.toContain("python-cursor");

    await act(async () => {
      hangingVscode.resolve(jsonBody(VSCODE_EXPORT));
      await Promise.resolve();
    });
    expect(view.container.querySelector(".mcp-pre")?.textContent).toContain("python-vscode");
  });
});
