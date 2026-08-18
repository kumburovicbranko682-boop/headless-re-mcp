import { asChildText, workflowSummary } from "./textChild";

describe("asChildText", () => {
  it("never returns an object that React would refuse to render", () => {
    expect(asChildText({ cursor: 1, generation: 2 })).toBe("-");
    expect(asChildText("paused")).toBe("paused");
    expect(asChildText(3)).toBe("3");
  });
});

describe("workflowSummary", () => {
  it("summarizes the workflow state object instead of passing it to JSX", () => {
    const label = workflowSummary({
      status: "idle",
      state: {
        cursor: 4,
        generation: 2,
        stream_reliable: true,
        modules: [{ key: "main" }],
        breakpoints: {},
        navigation: { status: "waiting" },
      },
    });
    expect(label).toBe("idle · g2 · 1 modules · waiting");
    expect(typeof label).toBe("string");
  });
});
