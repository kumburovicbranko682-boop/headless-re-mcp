import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { WorkspaceLanding } from "./WorkspaceLanding";

describe("WorkspaceLanding", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
    localStorage.clear();
  });

  afterEach(() => {
    setTokenForTests("");
    vi.restoreAllMocks();
  });

  it("marks the active profile from the backend and posts a new choice", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/api/workspace/mode") && (!init || init.method === undefined)) {
        return new Response(JSON.stringify({ ok: true, data: { profile: "pe", available: [] } }), { status: 200 });
      }
      return new Response(JSON.stringify({ ok: true, data: { profile: "android" } }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const chosen: string[] = [];
    render(<WorkspaceLanding onChoose={(profile) => chosen.push(profile)} />);

    // The current profile from the backend is highlighted.
    await waitFor(() => expect(screen.getByText("本地 PE 逆向").closest("button")).toHaveClass("current"));

    fireEvent.click(screen.getByText("Android 应用逆向"));

    await waitFor(() => expect(chosen).toEqual(["android"]));
    expect(localStorage.getItem("headless_ws_profile")).toBe("android");
    const postCall = fetchMock.mock.calls.find((call) => call[1]?.method === "POST");
    expect(postCall).toBeTruthy();
    expect(String(postCall?.[1]?.body)).toContain("android");
  });
});
