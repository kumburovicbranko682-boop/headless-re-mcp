"""``device.logcat`` drops a whole oversized line rather than return half of one.

When the dump is longer than ``_MAX_LOGCAT_CHARS`` (200 000), ``logcat`` keeps
the newest bytes -- but that suffix begins mid-line, so it drops the leading
partial fragment before splitting into lines::

    if truncated:
        text = text[-_MAX_LOGCAT_CHARS:]
        newline = text.find("\n")
        text = text[newline + 1 :] if newline != -1 else ""
    out_lines = text.splitlines()[-capped:]

The ``else ""`` is the case a homogeneous fixture never reaches. Every existing
logcat truncation test builds the dump from short lines (200- or 2 000-char
entries), so the kept 200 000-char tail always straddles several newlines: the
``newline != -1`` branch fires and one leading fragment is trimmed off the
front. None of them produces a tail with **no** newline at all.

That happens for real when a single logcat line is itself larger than the whole
character cap -- an app that logs a full stack trace, a serialized blob, or a
base64 payload on one line. Then ``text[-_MAX_LOGCAT_CHARS:]`` lands entirely
inside that one line, ``find("\n")`` returns -1, and the fragment is *all*
partial. The ``else ""`` throws it away, so ``lines`` comes back empty with
``truncated=True`` -- an honest "the tail was one unterminated line, here is
none of it" rather than a 200 000-char run masquerading as ``lines[0]``.

Drop the ``else ""`` (let a -1 index fall through to ``text[0:]``) and that
giant fragment is returned as a single complete-looking log entry, exactly the
mis-parse the truncation trim exists to prevent. These pin the empty result
with a genuinely unterminated oversized tail; the existing short-line tests
keep the ``newline != -1`` side honest.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import _MAX_LOGCAT_CHARS, AdbBackend


class _OneShotDev:
    """A device whose ``shell`` returns one canned logcat dump and records argv."""

    def __init__(self, dump: str) -> None:
        self._dump = dump
        self.calls: list[list[str] | str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        return self._dump


def _backend_with(dump: str) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _OneShotDev(dump)  # type: ignore[method-assign]
    return backend


def test_a_single_line_bigger_than_the_cap_yields_no_lines() -> None:
    """One unterminated line over the cap is dropped whole, not returned halved.

    The kept tail is entirely inside this one line, so it has no newline and is
    all partial. Returning it as ``lines[0]`` would hand a parser a 205 000-char
    fragment as a complete record; the guard makes it an empty, truncated
    snapshot instead.
    """
    giant = "A" * (_MAX_LOGCAT_CHARS + 5000)
    payload = _backend_with(giant).logcat("emulator-5554", lines=200)
    assert payload["truncated"] is True
    assert payload["lines"] == []
    assert payload["count"] == 0


def test_short_lines_trailing_a_giant_final_line_are_lost_with_it() -> None:
    """When the oversized line is the tail, the earlier short lines fell out of it.

    The final line alone exceeds the cap, so the kept suffix never reaches the
    short lines ahead of it and the suffix itself is one unterminated fragment:
    the result is empty rather than salvaging the giant line as a record.
    """
    dump = "short-1\nshort-2\n" + "B" * (_MAX_LOGCAT_CHARS + 5000)
    payload = _backend_with(dump).logcat("emulator-5554", lines=200)
    assert payload["truncated"] is True
    assert payload["lines"] == []
    assert payload["count"] == 0


def test_a_giant_head_line_still_leaves_the_whole_tail_intact() -> None:
    """A newline inside the kept tail keeps the complete lines after the cut.

    This is the ``newline != -1`` side that the short-line fixtures already
    exercise, re-pinned here as the contrast: an oversized *leading* line is
    trimmed to its terminator and every whole entry after it survives, so the
    empty result above is specific to a tail with no newline, not truncation in
    general.
    """
    tail = "\n".join(f"line-{index}" for index in range(50))
    dump = "H" * (_MAX_LOGCAT_CHARS + 5000) + "\n" + tail
    payload = _backend_with(dump).logcat("emulator-5554", lines=200)
    assert payload["truncated"] is True
    assert payload["lines"] == [f"line-{index}" for index in range(50)]
    assert payload["count"] == 50
    # No surviving line is the giant fragment: the partial head was dropped.
    assert all("H" not in line for line in payload["lines"])
