"""Render collected telemetry in the Prometheus text exposition format.

Kept as a pure function over already-collected dictionaries so it can be tested
without a server, and so adding a scrape target never becomes a reason to import
a metrics client library into the analysis code.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

JsonObject = dict[str, Any]

PREFIX = "headless_re"
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_LABEL_ESCAPES = str.maketrans({"\\": "\\\\", '"': '\\"', "\n": "\\n"})


def _labels(pairs: Mapping[str, str]) -> str:
    if not pairs:
        return ""
    rendered = ",".join(
        f'{key}="{value.translate(_LABEL_ESCAPES)}"' for key, value in pairs.items()
    )
    return "{" + rendered + "}"


def _has_been_measured(disk: Mapping[str, object]) -> bool:
    """Whether the artifact walk has produced a figure yet.

    The walk runs in the background so a readiness probe never waits on it, and
    until the first one finishes the answer is zero bytes marked truncated: a
    floor, not a measurement. Emitted as a gauge that reads as the disk having
    been emptied, and the supervisor restarts the console often enough that a
    scrape catches that window. No sample is the honest answer -- a gap in the
    series says nothing, where a zero says something false.
    """
    return not (disk.get("truncated") and not disk.get("bytes"))


def _family(
    name: str,
    kind: str,
    help_text: str,
    samples: Iterable[tuple[Mapping[str, str], float]],
) -> list[str]:
    rows = [f"{name}{_labels(labels)} {value}" for labels, value in samples]
    if not rows:
        return []
    return [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}", *rows]


def render(
    metrics: JsonObject,
    build: Mapping[str, str],
    readiness: JsonObject | None = None,
) -> str:
    """Return one exposition document for the current process.

    Latency is published as a gauge rather than a summary because it is computed
    over a bounded recent window: it is a current observation, not a quantile
    over all time, and typing it as a summary would invite wrong aggregation.
    """
    lines: list[str] = []
    tools = [item for item in metrics.get("tools", []) if isinstance(item, dict)]

    lines += _family(
        f"{PREFIX}_build_info",
        "gauge",
        "Running build, always 1. Labels carry the version and commit.",
        [
            (
                {
                    "version": str(build.get("version", "")),
                    "commit": str(build.get("commit", "")),
                    "python": str(build.get("python", "")),
                },
                1.0,
            )
        ],
    )
    lines += _family(
        f"{PREFIX}_tool_calls_total",
        "counter",
        "Tool invocations since this process started.",
        [({"tool": str(item["tool"])}, float(item.get("calls_total", 0))) for item in tools],
    )
    lines += _family(
        f"{PREFIX}_tool_failures_total",
        "counter",
        "Tool invocations that returned an error envelope or raised.",
        [({"tool": str(item["tool"])}, float(item.get("failures_total", 0))) for item in tools],
    )
    lines += _family(
        f"{PREFIX}_tool_duration_ms",
        "gauge",
        "Tool latency over the retained recent-call window, in milliseconds.",
        [
            ({"tool": str(item["tool"]), "quantile": quantile}, float(item.get(key, 0.0)))
            for item in tools
            for quantile, key in (("0.5", "p50_ms"), ("0.95", "p95_ms"))
        ],
    )
    lines += _family(
        f"{PREFIX}_tool_duration_max_ms",
        "gauge",
        "Slowest call in the retained recent-call window, in milliseconds.",
        [({"tool": str(item["tool"])}, float(item.get("max_ms", 0.0))) for item in tools],
    )

    if readiness is not None:
        sessions = readiness.get("sessions", {})
        backends = readiness.get("backends", {})
        lines += _family(
            f"{PREFIX}_ready",
            "gauge",
            "1 when this instance should receive traffic, 0 when it should be drained.",
            [({}, 1.0 if readiness.get("ready") else 0.0)],
        )
        lines += _family(
            f"{PREFIX}_sessions_open",
            "gauge",
            "Sessions that are neither closed nor failed.",
            [({}, float(sessions.get("open", 0)))],
        )
        lines += _family(
            f"{PREFIX}_backends_total",
            "gauge",
            "Backends the health monitor observed on its last sweep.",
            [({}, float(backends.get("total", 0)))],
        )
        lines += _family(
            f"{PREFIX}_backends_unhealthy",
            "gauge",
            "Observed backends whose worker died or whose transport is down.",
            [({}, float(backends.get("unhealthy", 0)))],
        )
        disk = readiness.get("disk", {})
        if disk:
            if _has_been_measured(disk):
                lines += _family(
                    f"{PREFIX}_artifact_bytes",
                    "gauge",
                    "Bytes under the artifact root, including files no collector tracks.",
                    [({}, float(disk.get("bytes", 0)))],
                )
            # The budget is configuration rather than a measurement, so it is
            # known from the first scrape and always reported.
            lines += _family(
                f"{PREFIX}_artifact_budget_bytes",
                "gauge",
                "Byte budget for registered artifacts. 0 means collection is off.",
                [({}, float(disk.get("budget_bytes", 0)))],
            )

    return "\n".join(lines) + "\n"
