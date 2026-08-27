"""A char-truncated logcat must not hand back a half-a-line fragment.

``logcat`` asks the device for the last N lines, then clamps the reply to
``_MAX_LOGCAT_CHARS`` by keeping the last chars. That slice lands in the middle
of a line, so before this guard the oldest returned "line" was the tail of a
real line with its start cut off -- and ``truncated: True`` was the only hint,
which reads as "some old lines are missing", not "the first line you see is
half a line". The backend already reports partial pagination honestly
(``has_more`` on classes/packages, ``truncated`` on the HAR export); a returned
line should likewise be a whole line or nothing.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import _MAX_LOGCAT_CHARS, AdbBackend


class _FakeDev:
    def __init__(self, text: str) -> None:
        self._text = text

    def shell(self, args: Any, timeout: float | None = None) -> str:
        return self._text


def _backend(text: str) -> AdbBackend:
    backend = AdbBackend()
    backend._device = lambda serial: _FakeDev(text)  # type: ignore[method-assign]
    return backend


def test_truncated_logcat_drops_the_partial_first_line() -> None:
    line = "BEGIN-" + "z" * 94 + "\n"  # 101 chars; the cap is not a multiple of it
    assert _MAX_LOGCAT_CHARS % len(line) != 0
    count = (_MAX_LOGCAT_CHARS // len(line)) + 50
    payload = _backend(line * count).logcat("emulator-5554", lines=5000)

    assert payload["truncated"] is True
    # Every surviving line is whole: the mid-line slice would otherwise leave a
    # leading "zzz..." with no "BEGIN-" prefix.
    assert payload["lines"], "expected whole lines to remain after dropping the fragment"
    assert all(row == line.rstrip("\n") for row in payload["lines"])
    assert payload["lines"][0].startswith("BEGIN-")


def test_untruncated_logcat_is_passed_through_unchanged() -> None:
    text = "one\ntwo\nthree\n"
    payload = _backend(text).logcat("emulator-5554", lines=200)

    assert payload["truncated"] is False
    assert payload["lines"] == ["one", "two", "three"]
    assert payload["requested"] == 200


def test_one_line_longer_than_the_cap_keeps_the_fragment_rather_than_nothing() -> None:
    """No newline to cut on: a lone giant line is better than an empty answer."""
    text = "x" * (_MAX_LOGCAT_CHARS + 5000)
    payload = _backend(text).logcat("emulator-5554", lines=200)

    assert payload["truncated"] is True
    assert len(payload["lines"]) == 1
    assert payload["lines"][0]  # non-empty
