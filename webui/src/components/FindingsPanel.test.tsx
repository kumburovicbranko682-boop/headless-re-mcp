import { render, screen, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { FindingsPanel } from "./FindingsPanel";

function jsonOk(data: unknown) {
  return new Response(JSON.stringify({ ok: true, data }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("FindingsPanel", () => {
  beforeEach(() => setTokenForTests("test-token"));
  afterEach(() => {
    setTokenForTests("");
    vi.restoreAllMocks();
  });

  it("lists recorded knowledge grouped by kind", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonOk({
      total: 1,
      entries: [{ kind: "api", key: "login", value: { url: "/login" } }],
    })));
    render(<FindingsPanel sessionId="s1" />);
    await waitFor(() => expect(screen.getByText("1 条发现")).toBeInTheDocument());
    expect(screen.getByText("login")).toBeInTheDocument();
    expect(screen.getByText("url=/login")).toBeInTheDocument();
  });

  it("surfaces a knowledge load failure instead of staying silently empty", async () => {
    // load() awaits api() with no catch and runs as void load(); api() rejects
    // on a non-2xx or a network drop, and the !result.ok branch only fires when
    // it resolves. Before the fix the rejection went unhandled and the panel
    // showed nothing -- no banner, no hint.
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("boom-knowledge"); }));
    render(<FindingsPanel sessionId="s1" />);
    await waitFor(() => expect(screen.getByText(/boom-knowledge/)).toBeInTheDocument());
  });
});
