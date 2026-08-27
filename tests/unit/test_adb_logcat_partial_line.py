"""adb.logcat must not pass a truncated first line off as a whole log entry.

When the dump exceeds the character cap, logcat tails the buffer to the last
``_MAX_LOGCAT_CHARS`` characters. That slice lands on a character boundary, so
unless it happens to sit right after a newline the first surviving line is a
fragment missing its start. The reply used to hand that fragment back as an
ordinary line -- a caller parsing its timestamp/tag then reads corrupt data,
and ``truncated`` alone did not say the first line was half a line. These pin
that the fragment is dropped (and disclosed via ``partial_line_dropped``) while
a slice that lands on a newline keeps its intact first line.
"""

from __future__ import annotations

import pytest

import headless_re_mcp.backends.adb.client as adb_client
from headless_re_mcp.backends.adb.client import AdbBackend

# Three whole lines, 23 chars including the trailing newlines:
#   "0123456789\n" (11)  "ABCDE\n" (6)  "FGHIJ\n" (6)
_TEXT = "0123456789\nABCDE\nFGHIJ\n"


def _backend(monkeypatch: pytest.MonkeyPatch, *, cap: int) -> AdbBackend:
    backend = AdbBackend()
    monkeypatch.setattr(backend, "_device", lambda serial: object())
    monkeypatch.setattr(adb_client, "_device_shell", lambda dev, args, **kw: _TEXT)
    monkeypatch.setattr(adb_client, "_MAX_LOGCAT_CHARS", cap)
    return backend


def test_logcat_drops_a_leading_fragment_when_the_cut_lands_mid_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # cap 20 tails to "3456789\nABCDE\nFGHIJ\n"; the char before the slice is a
    # digit, not a newline, so "3456789" is a fragment of "0123456789".
    backend = _backend(monkeypatch, cap=20)
    payload = backend.logcat("emulator-5554", lines=100)
    assert payload["truncated"] is True
    assert payload["partial_line_dropped"] is True
    assert payload["lines"] == ["ABCDE", "FGHIJ"], "the half line must not survive"


def test_logcat_keeps_the_first_line_when_the_cut_lands_on_a_newline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # cap 12 tails to "ABCDE\nFGHIJ\n"; the char before the slice is the newline
    # after "0123456789", so "ABCDE" is a whole line and must be kept.
    backend = _backend(monkeypatch, cap=12)
    payload = backend.logcat("emulator-5554", lines=100)
    assert payload["truncated"] is True
    assert "partial_line_dropped" not in payload
    assert payload["lines"] == ["ABCDE", "FGHIJ"]


def test_logcat_does_not_flag_or_drop_when_the_dump_fits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _backend(monkeypatch, cap=10_000)
    payload = backend.logcat("emulator-5554", lines=100)
    assert payload["truncated"] is False
    assert "partial_line_dropped" not in payload
    assert payload["lines"] == ["0123456789", "ABCDE", "FGHIJ"]
