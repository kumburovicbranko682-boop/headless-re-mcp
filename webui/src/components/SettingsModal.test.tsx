import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { setTokenForTests } from "../api/client";
import { SettingsModal } from "./SettingsModal";

function jsonResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), { status: 200 });
}

function stubFetch(options: { configured: boolean; probed: string[] }) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "POST" && url.includes("/api/providers/default/models")) {
      return jsonResponse({ ok: true, models: options.probed });
    }
    if (method === "GET" && url.includes("/api/providers")) {
      return jsonResponse({
        ok: true,
        current: "default",
        profiles: [
          {
            id: "default",
            base_url: "https://example.invalid/v1",
            model: "custom-model",
            configured: options.configured,
            api_key_masked: options.configured ? "sk-**cd" : null,
            known_models: [],
          },
        ],
      });
    }
    if (method === "GET" && url.includes("/api/setup/status")) {
      return jsonResponse({ ida_home: null, candidates: [] });
    }
    if (method === "GET" && url.includes("/api/agent/personas")) {
      return jsonResponse({ ok: true, current: "default", personas: [] });
    }
    return jsonResponse({ ok: true });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("SettingsModal model selection", () => {
  beforeEach(() => {
    setTokenForTests("test-token");
  });

  afterEach(() => {
    setTokenForTests("");
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("keeps the configured model when the probed list does not contain it", async () => {
    // Gateways routinely return partial /models lists (aliases, dated
    // snapshots and fine-tunes are often missing). The dialog auto-probes on
    // open when a key is configured; it must not swap the stored model for
    // list[0] — a user who came to update the key would then save and
    // silently destroy the model setting.
    stubFetch({ configured: true, probed: ["model-a", "model-b"] });

    render(<SettingsModal onClose={() => undefined} />);

    const select = await waitFor(() => {
      const element = screen.getByLabelText("模型") as HTMLSelectElement;
      expect(element.tagName).toBe("SELECT");
      return element;
    });
    expect(select.value).toBe("custom-model");
    const options = [...select.options].map((option) => option.value);
    expect(options).toEqual(["custom-model", "model-a", "model-b"]);
  });

  it("keeps the typed model when the probe button returns a list without it", async () => {
    stubFetch({ configured: false, probed: ["model-a", "model-b"] });

    render(<SettingsModal onClose={() => undefined} />);
    // No key configured, so no auto-probe: the model renders as a text input.
    const input = await waitFor(() => {
      const element = screen.getByLabelText("模型") as HTMLInputElement;
      expect(element.tagName).toBe("INPUT");
      return element;
    });
    expect(input.value).toBe("custom-model");

    fireEvent.click(screen.getByText("拉取模型列表"));

    const select = await waitFor(() => {
      const element = screen.getByLabelText("模型") as HTMLSelectElement;
      expect(element.tagName).toBe("SELECT");
      return element;
    });
    expect(select.value).toBe("custom-model");
    expect([...select.options].map((option) => option.value)).toEqual([
      "custom-model",
      "model-a",
      "model-b",
    ]);
  });

  it("lists the probed models plainly when the configured model is among them", async () => {
    stubFetch({ configured: true, probed: ["custom-model", "model-a"] });

    render(<SettingsModal onClose={() => undefined} />);

    const select = await waitFor(() => {
      const element = screen.getByLabelText("模型") as HTMLSelectElement;
      expect(element.tagName).toBe("SELECT");
      return element;
    });
    expect(select.value).toBe("custom-model");
    expect([...select.options].map((option) => option.value)).toEqual([
      "custom-model",
      "model-a",
    ]);
  });
});
