"""The Prometheus exposition renderer, pinned to its format and its honesty rule.

``metrics_exposition.render`` turns already-collected telemetry dicts into a
``text/plain; version=0.0.4`` document. It had no dedicated test, yet it carries
two contracts a scraper depends on and an edit could quietly break:

* An empty metric family is omitted whole -- no ``# HELP``/``# TYPE`` with zero
  samples -- because a family with a HELP line but no series is noise, not data.
* The artifact-bytes gauge is withheld until the background disk walk has
  actually produced a figure. Until then ``disk`` is ``{truncated, bytes: 0}``:
  a floor, not a measurement. Emitting ``0`` would read as "the disk was
  emptied", and the supervisor restarts the console often enough that a scrape
  catches that window -- so a missing sample (an honest gap) is chosen over a
  false zero. The byte *budget* is configuration, known from the first scrape,
  so it is always emitted.

These tests lock both, plus the label escaping a scraper's parser requires and
the readiness-absent shape.
"""

from __future__ import annotations

from headless_re_mcp.metrics_exposition import (
    CONTENT_TYPE,
    PREFIX,
    _has_been_measured,
    _labels,
    render,
)

_BUILD = {"version": "0.2.1", "commit": "abc123", "python": "3.11.9"}


def _lines(document: str) -> list[str]:
    assert document.endswith("\n"), "exposition documents must end with a newline"
    return document.strip("\n").split("\n")


def _sample(document: str, name: str) -> str | None:
    """Return the single sample line for ``name`` (no HELP/TYPE), or None."""
    for line in _lines(document):
        if line.startswith(name) and not line.startswith("#"):
            return line
    return None


# --- always-present build_info ------------------------------------------------


def test_build_info_is_emitted_even_with_no_metrics() -> None:
    document = render({}, _BUILD)
    lines = _lines(document)

    assert f"# HELP {PREFIX}_build_info" in lines[0]
    assert lines[1] == f"# TYPE {PREFIX}_build_info gauge"
    # The sample is always 1.0; the identity lives in the labels.
    assert lines[2] == (
        f'{PREFIX}_build_info'
        '{version="0.2.1",commit="abc123",python="3.11.9"} 1.0'
    )


def test_the_content_type_names_the_prometheus_text_format() -> None:
    assert CONTENT_TYPE == "text/plain; version=0.0.4; charset=utf-8"


# --- tool families ------------------------------------------------------------


def test_tool_families_render_as_counters_and_gauges() -> None:
    metrics = {
        "tools": [
            {
                "tool": "static.functions",
                "calls_total": 10,
                "failures_total": 2,
                "p50_ms": 1.5,
                "p95_ms": 9.0,
                "max_ms": 12.0,
            }
        ]
    }
    document = render(metrics, _BUILD)

    assert f"# TYPE {PREFIX}_tool_calls_total counter" in document
    assert f"# TYPE {PREFIX}_tool_failures_total counter" in document
    # Latency is a gauge (a bounded recent-window observation, not an all-time
    # quantile), split into p50/p95 series by a quantile label.
    assert f"# TYPE {PREFIX}_tool_duration_ms gauge" in document

    assert _sample(document, f"{PREFIX}_tool_calls_total") == (
        f'{PREFIX}_tool_calls_total{{tool="static.functions"}} 10.0'
    )
    assert _sample(document, f"{PREFIX}_tool_failures_total") == (
        f'{PREFIX}_tool_failures_total{{tool="static.functions"}} 2.0'
    )
    assert (
        f'{PREFIX}_tool_duration_ms{{tool="static.functions",quantile="0.5"}} 1.5'
        in document
    )
    assert (
        f'{PREFIX}_tool_duration_ms{{tool="static.functions",quantile="0.95"}} 9.0'
        in document
    )
    assert _sample(document, f"{PREFIX}_tool_duration_max_ms") == (
        f'{PREFIX}_tool_duration_max_ms{{tool="static.functions"}} 12.0'
    )


def test_a_family_with_no_samples_is_omitted_whole() -> None:
    # No tools -> no tool_* family at all, not a HELP/TYPE header with zero rows.
    document = render({"tools": []}, _BUILD)
    assert f"{PREFIX}_tool_calls_total" not in document
    assert f"# HELP {PREFIX}_tool_calls_total" not in document


def test_non_dict_tool_entries_are_ignored() -> None:
    metrics = {"tools": ["not-a-dict", {"tool": "x", "calls_total": 1}]}
    document = render(metrics, _BUILD)
    # The junk entry is dropped; the real one still renders.
    assert _sample(document, f"{PREFIX}_tool_calls_total") == (
        f'{PREFIX}_tool_calls_total{{tool="x"}} 1.0'
    )


# --- readiness ----------------------------------------------------------------


def test_readiness_absent_emits_no_readiness_gauges() -> None:
    document = render({}, _BUILD, None)
    assert f"{PREFIX}_ready" not in document
    assert f"{PREFIX}_sessions_open" not in document
    assert f"{PREFIX}_backends_total" not in document


def test_readiness_gauges_render_when_present() -> None:
    readiness = {
        "ready": False,
        "sessions": {"open": 3},
        "backends": {"total": 2, "unhealthy": 1},
    }
    document = render({}, _BUILD, readiness)

    assert _sample(document, f"{PREFIX}_ready") == f"{PREFIX}_ready 0.0"
    assert _sample(document, f"{PREFIX}_sessions_open") == f"{PREFIX}_sessions_open 3.0"
    assert _sample(document, f"{PREFIX}_backends_total") == f"{PREFIX}_backends_total 2.0"
    assert (
        _sample(document, f"{PREFIX}_backends_unhealthy")
        == f"{PREFIX}_backends_unhealthy 1.0"
    )


# --- the disk-walk honesty rule ----------------------------------------------


def test_artifact_bytes_is_withheld_until_the_disk_walk_finishes() -> None:
    # {truncated, bytes: 0} is the pre-measurement floor. Emitting 0 would read
    # as an emptied disk, so the bytes gauge is withheld -- a gap, not a lie --
    # while the always-known budget is still emitted.
    readiness = {"disk": {"truncated": True, "bytes": 0, "budget_bytes": 1024}}
    document = render({}, _BUILD, readiness)

    assert f"{PREFIX}_artifact_bytes" not in document
    assert _sample(document, f"{PREFIX}_artifact_budget_bytes") == (
        f"{PREFIX}_artifact_budget_bytes 1024.0"
    )


def test_artifact_bytes_appears_once_a_real_figure_exists() -> None:
    readiness = {"disk": {"truncated": False, "bytes": 4096, "budget_bytes": 1024}}
    document = render({}, _BUILD, readiness)

    assert _sample(document, f"{PREFIX}_artifact_bytes") == (
        f"{PREFIX}_artifact_bytes 4096.0"
    )


def test_a_truncated_figure_with_real_bytes_still_reports() -> None:
    # A truncated walk that has counted *something* is a real (if low) figure,
    # so it is reported -- only the zero-bytes floor is withheld.
    readiness = {"disk": {"truncated": True, "bytes": 5, "budget_bytes": 0}}
    document = render({}, _BUILD, readiness)
    assert _sample(document, f"{PREFIX}_artifact_bytes") == f"{PREFIX}_artifact_bytes 5.0"


def test_an_empty_disk_mapping_emits_no_disk_gauges() -> None:
    document = render({}, _BUILD, {"disk": {}})
    assert f"{PREFIX}_artifact_bytes" not in document
    assert f"{PREFIX}_artifact_budget_bytes" not in document


# --- label escaping and the measurement predicate -----------------------------


def test_labels_escape_backslash_quote_and_newline() -> None:
    # A Prometheus parser needs these three escaped inside a label value; an
    # unescaped quote or newline ends the value early and corrupts the line.
    assert _labels({"k": 'a"b\\c\nd'}) == '{k="a\\"b\\\\c\\nd"}'


def test_labels_of_an_empty_mapping_is_the_empty_string() -> None:
    assert _labels({}) == ""


def test_has_been_measured_only_rejects_the_zero_byte_floor() -> None:
    assert _has_been_measured({"truncated": True, "bytes": 0}) is False
    assert _has_been_measured({"truncated": True, "bytes": 5}) is True
    assert _has_been_measured({"truncated": False, "bytes": 0}) is True
    assert _has_been_measured({}) is True


def test_every_sample_line_has_a_type_header_before_it() -> None:
    # Structural invariant of the exposition format: a bare metric line without
    # a preceding TYPE is what a scraper rejects. Walk the whole document.
    readiness = {
        "ready": True,
        "sessions": {"open": 1},
        "backends": {"total": 1, "unhealthy": 0},
        "disk": {"truncated": False, "bytes": 8, "budget_bytes": 16},
    }
    metrics = {"tools": [{"tool": "t", "calls_total": 1, "p50_ms": 1.0}]}
    typed: set[str] = set()
    for line in _lines(render(metrics, _BUILD, readiness)):
        if line.startswith("# TYPE "):
            typed.add(line.split()[2])
        elif not line.startswith("#"):
            name = line.split("{", 1)[0].split(" ", 1)[0]
            assert name in typed, f"sample {name!r} appeared before its # TYPE header"
