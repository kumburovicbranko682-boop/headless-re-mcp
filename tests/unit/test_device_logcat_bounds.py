"""``device.logcat``'s ``lines`` is a page-size param, and both halves are pinned.

``lines`` is the number of tail log entries to return -- a page size, like the
``limit`` on every other non-PE reader -- but it is spelled ``lines``, so the
generic pagination schema guard (which scans params named ``limit`` / ``offset``)
never sees it. That leaves the one page-size param on the non-PE surface without
the two guarantees the guard gives the others:

* the schema declares a ceiling (so the MCP path fail-fasts an absurd request,
  and the advertised contract is honest about the largest page), and
* the backend clamps to that same ceiling (the backstop for the agent and
  OpenAI-bridge transports, which call the handler directly and skip the schema,
  so a raw ``lines=10**9`` cannot turn a tail read into an unbounded ``-t``).

This is the sibling of ``test_apk_page_clamp``'s schema/cap parity assertions,
scoped to logcat: it pins that the schema maximum *equals* the backend clamp
constant (drift either way is the bug -- a schema that promises more than the
backend will serve, or a backend cap raised without updating the contract) and
that an over-cap request really is clamped before it reaches ``adb``.
"""

from __future__ import annotations

from typing import Any, cast

from headless_re_mcp.backends.adb.client import _MAX_LOGCAT_LINES, AdbBackend
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.device import build_device_tools


def _logcat_lines_schema() -> dict[str, Any]:
    for bound in build_device_tools(cast(Any, object())):
        if bound.name == "device.logcat":
            return input_schema_for(bound.handler)["properties"]["lines"]
    raise AssertionError("device.logcat is not in the device tool surface")


def test_logcat_lines_schema_ceiling_equals_the_backend_cap() -> None:
    lines = _logcat_lines_schema()
    assert lines.get("type") == "integer", f"lines must be an integer, got {lines}"
    assert lines.get("minimum") == 1, f"lines minimum must be 1, got {lines.get('minimum')}"
    # Parity is the point: the advertised ceiling and the runtime clamp must be
    # the same number, so neither can drift into promising a page the other will
    # not serve.
    assert lines.get("maximum") == _MAX_LOGCAT_LINES, (
        f"lines maximum {lines.get('maximum')} must equal the backend cap {_MAX_LOGCAT_LINES}"
    )


def test_logcat_over_cap_lines_is_clamped_before_it_reaches_adb() -> None:
    """A schema-skipping transport handing a huge ``lines`` must still be clamped:
    the backend passes ``-t _MAX_LOGCAT_LINES`` to adb, not the raw request."""
    recorded: dict[str, Any] = {}

    class _RecordingDev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            recorded["args"] = args
            del timeout
            return "line 0\nline 1"

    backend = AdbBackend()
    backend._device = lambda serial: _RecordingDev()  # type: ignore[method-assign]
    result = backend.logcat("emulator-5554", lines=10**9)

    assert recorded["args"] == ["logcat", "-d", "-t", str(_MAX_LOGCAT_LINES)]
    assert result["count"] == 2
    assert result["truncated"] is False


def test_logcat_floors_a_nonpositive_lines_request_at_one() -> None:
    """The clamp is ``max(1, min(...))``: 0 or negative is not a page size, so it
    floors at one entry rather than passing ``-t 0`` (which adb reads as "all")."""
    recorded: dict[str, Any] = {}

    class _RecordingDev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            recorded["args"] = args
            del timeout
            return "only line"

    backend = AdbBackend()
    backend._device = lambda serial: _RecordingDev()  # type: ignore[method-assign]
    backend.logcat("emulator-5554", lines=0)

    assert recorded["args"] == ["logcat", "-d", "-t", "1"]
