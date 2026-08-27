"""Contract tests for the bounded subprocess-diagnostic line reader.

``read_bounded_text_line`` retains at most ``max_chars`` characters of one line
while *draining* the rest, so a hostile or merely chatty subprocess cannot make
a diagnostic read consume unbounded memory and cannot leave an unread half-line
wedged in the pipe for the next call. The truncation must also be honest: a
line whose visible content exceeds the cap always comes back ending in the
marker and never longer than the cap. These properties live in a handful of
off-by-one boundaries (exactly-cap, cap+1, no trailing newline at EOF), so they
are pinned here rather than left to the reader's eye.
"""

from __future__ import annotations

import io

from headless_re_mcp.backends.common.text_stream import read_bounded_text_line

_MARKER = "… [truncated]"


def _drain(text: str, cap: int) -> list[str | None]:
    """Read the whole stream one bounded line at a time, ending on the None."""
    stream = io.StringIO(text)
    out: list[str | None] = []
    for _ in range(1000):  # guard against a draining bug spinning forever
        value = read_bounded_text_line(stream, max_chars=cap)
        out.append(value)
        if value is None:
            break
    return out


def test_empty_stream_reports_end_with_none() -> None:
    assert read_bounded_text_line(io.StringIO(""), max_chars=10) is None


def test_short_line_has_its_newline_stripped() -> None:
    assert read_bounded_text_line(io.StringIO("hi\n"), max_chars=100) == "hi"


def test_trailing_crlf_is_stripped() -> None:
    assert read_bounded_text_line(io.StringIO("hi\r\n"), max_chars=100) == "hi"


def test_final_line_without_a_newline_is_returned_whole() -> None:
    assert read_bounded_text_line(io.StringIO("tail"), max_chars=100) == "tail"


def test_lines_are_yielded_one_at_a_time_then_none() -> None:
    assert _drain("a\nb\n", cap=100) == ["a", "b", None]


def test_line_exactly_at_the_cap_with_newline_is_not_truncated() -> None:
    assert _drain("abcde\n", cap=5) == ["abcde", None]


def test_line_exactly_at_the_cap_without_newline_at_eof_is_not_truncated() -> None:
    # cap+2 is read, but the line is exactly cap long, so nothing is dropped and
    # the reader must not mistake a full-but-short final line for an overrun.
    assert _drain("abcde", cap=5) == ["abcde", None]


def test_overlong_line_with_newline_is_truncated_with_the_marker() -> None:
    result = read_bounded_text_line(io.StringIO("abcdefghijklmnopqrstuvwxyz\n"), max_chars=20)
    assert result == "abcdefg" + _MARKER
    assert result is not None and result.endswith(_MARKER)
    assert result is not None and len(result) == 20


def test_overlong_line_without_newline_at_eof_is_truncated_and_does_not_spin() -> None:
    # The draining loop stops on EOF (empty read) rather than on a newline; a
    # regression there would hang. _drain's own iteration cap would surface it.
    assert _drain("abcdefghijklmnopqrstuvwxyz", cap=20) == ["abcdefg" + _MARKER, None]


def test_truncation_drains_exactly_through_the_newline_leaving_the_next_line() -> None:
    # The overrun is consumed up to and including its newline; the following
    # line must remain intact for the next call.
    assert _drain("0123456789ABCDEF\nnext\n", cap=10) == [_MARKER[:10], "next", None]


def test_a_truncated_result_never_exceeds_the_cap() -> None:
    line = "x" * 500 + "\n"
    for cap in (1, 5, 13, 14, 50):
        result = read_bounded_text_line(io.StringIO(line), max_chars=cap)
        assert result is not None
        assert len(result) == cap  # marker + retained prefix fill the budget exactly


def test_non_positive_cap_is_coerced_to_one() -> None:
    # max(1, int(max_chars)) keeps readline(cap + 2) legal and the marker slice
    # non-empty; the overrun still drains rather than raising.
    assert _drain("abc\n", cap=0) == ["…", None]
    assert _drain("abc\n", cap=-3) == ["…", None]
