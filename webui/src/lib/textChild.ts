export function asChildText(value: unknown, fallback = "-"): string {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || fallback;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  return fallback;
}

export function workflowSummary(data: unknown): string {
  if (!data || typeof data !== "object") return asChildText(data, "-");
  const record = data as Record<string, unknown>;
  const status = asChildText(record.status, "");
  const nested = record.state && typeof record.state === "object"
    ? record.state as Record<string, unknown>
    : record;
  const generation = typeof nested.generation === "number" ? `g${nested.generation}` : "";
  const modules = Array.isArray(nested.modules) ? `${nested.modules.length} modules` : "";
  const navigation = nested.navigation && typeof nested.navigation === "object"
    ? asChildText((nested.navigation as Record<string, unknown>).status, "")
    : "";
  const stream = nested.stream_reliable === false ? "stream stale" : "";
  const parts = [status, generation, modules, navigation, stream].filter(Boolean);
  return parts.join(" · ") || (record.present === false ? "-" : "ready");
}
