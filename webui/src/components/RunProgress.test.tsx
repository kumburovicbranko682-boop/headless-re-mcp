import { render, screen } from "@testing-library/react";
import type { RunEvent } from "../agent/state";
import { computeRunMetrics, formatDuration, formatHarnessLine, formatTokPerSec, RunProgress } from "./RunProgress";

function ev(type: string, created_at: string, data: Record<string, unknown> = {}, seq = 1): RunEvent {
  return { run_id: "r1", seq, type, data, created_at };
}

describe("RunProgress harness metrics", () => {
  it("formats durations like DeepSeek Harness", () => {
    expect(formatDuration(22800)).toBe("22.8s");
    expect(formatDuration(24900)).toBe("24.9s");
    expect(formatDuration(980000)).toBe("16m20s");
  });

  it("matches the 1 round / 5 step status line", () => {
    const t0 = Date.parse("2026-08-17T08:00:00.000Z");
    const events = [
      ev("llm.started", "2026-08-17T08:00:00.000Z", { round: 1 }, 1),
      ev("message.delta", "2026-08-17T08:00:01.200Z", { delta: "ok" }, 2),
      ev("llm.completed", "2026-08-17T08:00:22.800Z", { round: 1 }, 3),
      ev("tool.started", "2026-08-17T08:00:22.800Z", { tool_call_id: "a", name: "dynamic.open" }, 4),
      ev("tool.completed", "2026-08-17T08:00:28.000Z", { tool_call_id: "a", name: "dynamic.open" }, 5),
      ev("tool.started", "2026-08-17T08:00:28.000Z", { tool_call_id: "b", name: "dynamic.launch" }, 6),
      ev("tool.completed", "2026-08-17T08:00:47.700Z", { tool_call_id: "b", name: "dynamic.launch" }, 7),
      ev("tool.started", "2026-08-17T08:00:47.700Z", { tool_call_id: "c", name: "ui.virtual_desktop.snapshot" }, 8),
      ev("tool.completed", "2026-08-17T08:00:48.000Z", { tool_call_id: "c", name: "ui.virtual_desktop.snapshot" }, 9),
      ev("tool.started", "2026-08-17T08:00:48.000Z", { tool_call_id: "d", name: "static.open" }, 10),
    ];
    const metrics = computeRunMetrics(events, t0 + 47800, 1);
    expect(metrics.rounds).toBe(1);
    expect(metrics.steps).toBe(5);
    expect(metrics.llmMs).toBe(22800);
    expect(metrics.ttftMs).toBe(1200);
    expect(metrics.tokPerSec).toBeCloseTo(1 / 21.6, 2);
    expect(formatHarnessLine(metrics)).toContain("1 轮 · 5 步");
    expect(formatHarnessLine(metrics)).toContain("LLM 22.8s");
    expect(formatHarnessLine(metrics)).toContain("首 token 平均 1.2s");
    expect(formatHarnessLine(metrics)).toContain("0.05 tok/s");
    expect(formatHarnessLine(metrics)).toContain("\u6b63\u5728\u8c03\u7528 static.open");
  });

  it("shows elapsed seconds while a long tool is still running", () => {
    const t0 = Date.parse("2026-08-17T08:00:00.000Z");
    const events = [
      ev("tool.started", "2026-08-17T08:00:00.000Z", { tool_call_id: "a", name: "static.open" }, 1),
      ev("tool.progress", "2026-08-17T08:00:08.000Z", { tool_call_id: "a", name: "static.open", elapsed_s: 8 }, 2),
    ];
    const metrics = computeRunMetrics(events, t0 + 8000, 1);
    expect(metrics.activity).toContain("static.open");
    expect(metrics.activity).toContain("8.0s");
  });

  it("keeps generation speed after the LLM round ends", () => {
    const t0 = Date.parse("2026-08-17T08:00:00.000Z");
    const events = [
      ev("llm.started", "2026-08-17T08:00:00.000Z", { round: 1 }, 1),
      ev("message.delta", "2026-08-17T08:00:01.000Z", { delta: "a".repeat(400) }, 2),
      ev("llm.completed", "2026-08-17T08:00:03.000Z", { round: 1 }, 3),
      ev("tool.started", "2026-08-17T08:00:03.000Z", { tool_call_id: "a", name: "dynamic.open" }, 4),
    ];
    const metrics = computeRunMetrics(events, t0 + 10000, 1);
    expect(metrics.tokPerSec).toBeCloseTo(50, 0);
  });

  it("counts hidden tool-call tokens when there is no chat text", () => {
    const t0 = Date.parse("2026-08-17T08:00:00.000Z");
    const events = [
      ev("llm.started", "2026-08-17T08:00:00.000Z", { round: 1 }, 1),
      ev("llm.progress", "2026-08-17T08:00:00.400Z", { tokens: 40 }, 2),
      ev("llm.progress", "2026-08-17T08:00:01.000Z", { tokens: 100 }, 3),
      ev("llm.completed", "2026-08-17T08:00:02.000Z", { round: 1, tokens: 100 }, 4),
      ev("tool.started", "2026-08-17T08:00:02.000Z", { tool_call_id: "a", name: "static.open" }, 5),
    ];
    const metrics = computeRunMetrics(events, t0 + 10000, 1);
    expect(metrics.tokPerSec).toBeCloseTo(100 / 1.6, 1);
    expect(metrics.ttftMs).toBe(400);
    expect(formatTokPerSec(metrics.tokPerSec)).not.toBe("0 tok/s");
  });

  it("reads Python UTC timestamps and hidden reasoning tokens", () => {
    const t0 = Date.parse("2026-08-17T09:59:28.362Z");
    const events = [
      ev("llm.started", "2026-08-17T09:59:28.362794+00:00", { round: 1 }, 1),
      ev("llm.progress", "2026-08-17T09:59:53.507823+00:00", { tokens: 1 }, 2),
      ev("reasoning.delta", "2026-08-17T09:59:53.915825+00:00", { delta: "plan" }, 3),
      ev("llm.completed", "2026-08-17T09:59:54.593036+00:00", { round: 1, tokens: 84 }, 4),
    ];
    events[0] = { ...events[0], created_ms: t0 };
    const metrics = computeRunMetrics(events, t0 + 30_000, 1);
    expect(metrics.rounds).toBe(1);
    expect(metrics.llmMs).toBeGreaterThan(20_000);
    expect(metrics.ttftMs).toBeGreaterThan(20_000);
    expect(metrics.tokPerSec).toBeGreaterThan(1);
  });

  it("renders the compact status line", () => {
    render(<RunProgress events={[]} rounds={1} />);
    expect(screen.getByRole("status").textContent).toMatch(/1 轮/);
    expect(screen.getByRole("status").textContent).toMatch(/tok\/s/);
  });
});
