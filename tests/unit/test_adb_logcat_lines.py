"""device.logcat must count its lines and never hand back a fragment.

logcat's on-device ``-t N`` bounds the line count, but a secondary character
cap protects against pathologically long lines. When that cap fires it keeps
the newest characters -- which slices the oldest surviving line in half. The
pre-fix code returned that half-line as if it were a whole log entry and never
reported how many lines came back. These tests pin the count and the dropped
partial line.
"""

from __future__ import annotations

from typing import Any

import headless_re_mcp.backends.adb.client as adb_client
from headless_re_mcp.backends.adb.client import AdbBackend


class _Dev:
    def __init__(self, text: str) -> None:
        self._text = text

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return self._text


def _backend(text: str) -> AdbBackend:
    backend = AdbBackend()
    backend._device = lambda serial: _Dev(text)  # type: ignore[assignment,method-assign]
    return backend


def test_normal_logcat_reports_count_and_whole_lines() -> None:
    backend = _backend("line-a\nline-b\nline-c\n")
    payload = backend.logcat("emulator-5554", lines=200)
    assert payload["lines"] == ["line-a", "line-b", "line-c"]
    assert payload["count"] == 3
    assert payload["truncated"] is False
    assert payload["requested"] == 200


def test_count_equals_the_number_of_lines_returned() -> None:
    backend = _backend("\n".join(f"row{i}" for i in range(50)) + "\n")
    payload = backend.logcat("emulator-5554", lines=10)
    # -t is faked away, so the char path returns everything; count still must
    # equal the list length exactly, whatever slicing happened.
    assert payload["count"] == len(payload["lines"])


def test_truncation_drops_the_partial_leading_line(monkeypatch: Any) -> None:
    """The char cut lands mid-line; that broken fragment must not be returned."""
    monkeypatch.setattr(adb_client, "_MAX_LOGCAT_CHARS", 10)
    backend = _backend("HEADLINE_LONG\nBBB\nCCC\n")
    payload = backend.logcat("emulator-5554", lines=200)
    assert payload["truncated"] is True
    # "G" (the tail of HEADLINE_LONG left by the cut) is gone; only whole lines.
    assert payload["lines"] == ["BBB", "CCC"]
    assert payload["count"] == 2
    assert all(line in {"BBB", "CCC"} for line in payload["lines"])


def test_truncation_with_no_newline_keeps_the_single_line(monkeypatch: Any) -> None:
    """One giant line has no newline to split on, so it stays (still flagged)."""
    monkeypatch.setattr(adb_client, "_MAX_LOGCAT_CHARS", 8)
    backend = _backend("X" * 40)
    payload = backend.logcat("emulator-5554", lines=200)
    assert payload["truncated"] is True
    assert payload["count"] == 1
    assert payload["lines"] == ["X" * 8]
