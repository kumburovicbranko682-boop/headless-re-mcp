import { useEffect, useState } from "react";
import type { RunEvent } from "../agent/state";

export type RunMetrics = {
  rounds: number;
  steps: number;
  llmMs: number;
  toolMs: number;
  ttftMs: number;
  tokPerSec: number;
  activity: string | null;
};

type Props = { events: RunEvent[]; rounds: number };

const TERMINAL = new Set(["run.completed", "run.failed", "run.cancelled", "run.rejected"]);

function eventTime(event: RunEvent, fallback: number): number {
  if (typeof event.created_ms === "number" && Number.isFinite(event.created_ms) && event.created_ms > 0) {
    return event.created_ms;
  }
  const raw = event.created_at.trim();
  if (!raw) return fallback;
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function estimateTokens(text: string): number {
  let latin = 0;
  let other = 0;
  for (const char of text) {
    if (char <= "~") latin += 1;
    else other += 1;
  }
  return Math.max(0, other + Math.round(latin / 4));
}

export function formatDuration(ms: number): string {
  const seconds = Math.max(0, ms) / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const total = Math.round(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const rest = total % 60;
  if (hours > 0) return `${hours}h${String(minutes).padStart(2, "0")}m`;
  return `${minutes}m${String(rest).padStart(2, "0")}s`;
}

function eventsForLatestRun(events: RunEvent[]): RunEvent[] {
  // The event buffer holds every run in the thread -- the reducer's "run" action
  // clears streaming text and approvals but keeps events -- so a thread with
  // earlier runs used to fold their LLM and tool time into this run's harness,
  // reporting "LLM 67s" for a run that spent 22s. The harness is a per-run view
  // (rounds is a single run's count, first-token averages that run's rounds, and
  // the activity line describes the current call), so keep only the newest run.
  // The run with the latest event timestamp is the current or just-finished one.
  if (events.length === 0) return events;
  let latestRun = events[0].run_id;
  let latestAt = eventTime(events[0], 0);
  for (const event of events) {
    const at = eventTime(event, 0);
    if (at >= latestAt) {
      latestAt = at;
      latestRun = event.run_id;
    }
  }
  return events.filter((event) => event.run_id === latestRun);
}

export function computeRunMetrics(allEvents: RunEvent[], now: number, rounds: number): RunMetrics {
  const events = eventsForLatestRun(allEvents);
  let llmMs = 0;
  let toolMs = 0;
  let llmOpen: number | null = null;
  let llmRoundStart: number | null = null;
  let sawLlmStarted = false;
  let llmRounds = 0;
  let gotDelta = false;
  let currentRoundText = "";
  let firstDeltaAt: number | null = null;
  let lastDeltaAt: number | null = null;
  let lastTokPerSec = 0;
  let roundTokens = 0;
  const ttfts: number[] = [];
  const toolOpen = new Map<string, number>();
  const tools = new Set<string>();
  let openToolName: string | null = null;

  const closeLlm = (at: number) => {
    if (llmOpen == null) return;
    llmMs += Math.max(0, at - llmOpen);
    llmOpen = null;
  };
  const recordTokRate = (end: number) => {
    const tokens = roundTokens > 0 ? roundTokens : estimateTokens(currentRoundText);
    if (tokens <= 0) return;
    const start = firstDeltaAt ?? llmRoundStart;
    if (start == null) return;
    const streamed = lastDeltaAt != null && firstDeltaAt != null ? lastDeltaAt - firstDeltaAt : 0;
    const elapsed = streamed >= 200 ? streamed : Math.max(end - start, 200);
    lastTokPerSec = tokens / (elapsed / 1000);
  };
  const noteOutput = (at: number, tokens?: number) => {
    if (tokens != null && Number.isFinite(tokens) && tokens > 0) roundTokens = tokens;
    lastDeltaAt = at;
    if (!gotDelta && llmRoundStart != null) {
      ttfts.push(Math.max(0, at - llmRoundStart));
      gotDelta = true;
      firstDeltaAt = at;
    }
  };
  const openLlm = (at: number) => {
    closeLlm(at);
    llmOpen = at;
    llmRoundStart = at;
    gotDelta = false;
    currentRoundText = "";
    firstDeltaAt = null;
    lastDeltaAt = null;
    roundTokens = 0;
  };
  const closeTool = (id: string, at: number) => {
    const started = toolOpen.get(id);
    if (started == null) return;
    toolMs += Math.max(0, at - started);
    toolOpen.delete(id);
  };

  let toolDetail: string | null = null;

  for (const event of events) {
    const at = eventTime(event, now);
    if (event.type === "llm.started") {
      sawLlmStarted = true;
      const marked = Number(event.data.round);
      llmRounds = Number.isFinite(marked) && marked > 0 ? Math.max(llmRounds, marked) : llmRounds + 1;
      openLlm(at);
      continue;
    }
    if (event.type === "run.started" && !sawLlmStarted && llmOpen == null) {
      openLlm(at);
      continue;
    }
    if (event.type === "llm.completed") {
      const tokens = Number(event.data.tokens ?? 0);
      if (Number.isFinite(tokens) && tokens > 0) roundTokens = tokens;
      lastDeltaAt = at;
      recordTokRate(at);
      closeLlm(at);
      continue;
    }
    if (event.type === "llm.progress") {
      noteOutput(at, Number(event.data.tokens ?? 0));
      continue;
    }
    if (event.type === "tool.progress") {
      const elapsed = Number(event.data.elapsed_s);
      const label = String(event.data.name ?? openToolName ?? "tool");
      if (Number.isFinite(elapsed) && elapsed >= 2) {
        toolDetail = `\u6b63\u5728\u8c03\u7528 ${label}\uff08\u5df2 ${formatDuration(elapsed * 1000)}\uff09`;
      }
      continue;
    }
    if (event.type === "tool.started" || event.type === "tool.proposed") {
      const id = String(event.data.tool_call_id ?? event.data.name ?? event.seq);
      tools.add(id);
      if (event.type === "tool.started") {
        if (llmOpen != null) recordTokRate(at);
        closeLlm(at);
        openToolName = String(event.data.name ?? "tool");
        if (!toolOpen.has(id)) toolOpen.set(id, at);
      }
      continue;
    }
    if (event.type === "tool.completed") {
      const id = String(event.data.tool_call_id ?? event.data.name ?? event.seq);
      tools.add(id);
      openToolName = null;
      toolDetail = null;
      closeTool(id, at);
      continue;
    }
    if (event.type === "message.delta" || event.type === "reasoning.delta") {
      const delta = String(event.data.delta ?? "");
      currentRoundText += delta;
      noteOutput(at);
      continue;
    }
    if (TERMINAL.has(event.type)) {
      recordTokRate(at);
      closeLlm(at);
      openToolName = null;
      toolDetail = null;
      for (const id of [...toolOpen.keys()]) closeTool(id, at);
    }
  }

  const generating = llmOpen != null && (firstDeltaAt != null || roundTokens > 0);
  const waitingFirst = llmOpen != null && !gotDelta && llmRoundStart != null;
  const waitElapsed = llmRoundStart == null ? 0 : now - llmRoundStart;
  const activity = toolDetail
    ? toolDetail
    : openToolName
      ? `\u6b63\u5728\u8c03\u7528 ${openToolName}`
      : llmOpen != null
        ? (gotDelta ? "\u6b63\u5728\u751f\u6210" : "\u6b63\u5728\u7b49\u6a21\u578b")
        : null;

  if (generating) recordTokRate(now);
  closeLlm(now);
  for (const id of [...toolOpen.keys()]) closeTool(id, now);

  const tokPerSec = lastTokPerSec;

  const ttftMs = ttfts.length ? ttfts.reduce((sum, item) => sum + item, 0) / ttfts.length : waitingFirst ? Math.max(0, waitElapsed) : 0;
  const steps = Math.max(1, llmRounds + tools.size);

  return {
    rounds: Math.max(1, llmRounds || rounds),
    steps,
    llmMs,
    toolMs,
    ttftMs,
    tokPerSec,
    activity,
  };
}

export function formatTokPerSec(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 tok/s";
  if (value < 1) return `${value.toFixed(2)} tok/s`;
  if (value < 10) return `${value.toFixed(1)} tok/s`;
  return `${Math.round(value)} tok/s`;
}

export function formatHarnessLine(metrics: RunMetrics): string {
  const line = `${metrics.rounds} 轮 · ${metrics.steps} 步 | LLM ${formatDuration(metrics.llmMs)} · 工具调用 ${formatDuration(metrics.toolMs)} | 首 token 平均 ${(metrics.ttftMs / 1000).toFixed(1)}s · ${formatTokPerSec(metrics.tokPerSec)}`;
  return metrics.activity ? `${line} | ${metrics.activity}` : line;
}

export function RunProgress({ events, rounds }: Props) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, []);
  const line = formatHarnessLine(computeRunMetrics(events, now, rounds));
  return (
    <p className="run-harness" role="status" aria-live="polite" aria-label={line}>
      {line.split(" | ").map((part, index) => (
        <span key={part}>
          {index > 0 && <span data-sep>|</span>}
          {part.split(" · ").map((item, itemIndex) => (
            <span key={`${part}-${item}`}>
              {itemIndex > 0 && <span data-dot>·</span>}
              {item}
            </span>
          ))}
        </span>
      ))}
    </p>
  );
}
