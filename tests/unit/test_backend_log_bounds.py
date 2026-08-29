from __future__ import annotations

from collections import deque
from io import StringIO
from queue import Queue

import pytest

from headless_re_mcp.backends.common.text_stream import read_bounded_text_line
from headless_re_mcp.backends.ida import client as ida_client


def test_backend_log_reader_drains_oversized_lines() -> None:
    stream = StringIO("x" * 100 + "\nnext\n")

    first = read_bounded_text_line(stream, max_chars=32)
    second = read_bounded_text_line(stream, max_chars=32)

    assert first is not None
    assert len(first) == 32
    assert first.endswith("[truncated]")
    assert second == "next"
    assert read_bounded_text_line(stream, max_chars=32) is None


def test_backend_log_reader_accepts_exact_limit_with_crlf() -> None:
    stream = StringIO("x" * 32 + "\r\n")

    assert read_bounded_text_line(stream, max_chars=32) == "x" * 32


@pytest.mark.timeout(5)
def test_backend_log_reader_drains_an_unterminated_oversized_line_at_eof() -> None:
    """An oversized final line with no trailing newline must still terminate.

    The existing oversized case ends in ``\\n`` and never enters the drain loop.
    A line that overflows the cap *and* runs to EOF without a newline is the
    path that does: ``read_bounded_text_line`` keeps calling ``readline`` to
    discard the tail so the producer cannot block on a full pipe, and the loop
    stops only because ``readline`` returns ``""`` at EOF. Drop the ``chunk``
    guard on that loop and the empty string never ends with ``"\\n"``, so the
    reader spins forever on a truncated log. The timeout turns that regression
    into a clean failure instead of a hung suite, and the assertions pin the
    bounded, marked result the caller receives.
    """
    stream = StringIO("x" * 100)

    line = read_bounded_text_line(stream, max_chars=32)

    assert line is not None
    assert len(line) == 32
    assert line.endswith("[truncated]")
    # The discarded tail is gone, so the stream is now empty.
    assert read_bounded_text_line(stream, max_chars=32) is None


def test_backend_log_reader_returns_a_short_unterminated_final_line() -> None:
    """A sub-cap last line with no newline is returned whole, not dropped.

    Process stdout routinely ends without a trailing newline. That line is
    ``complete=False`` yet fits the cap, so it must come back verbatim rather
    than being treated as truncated.
    """
    stream = StringIO("tail without newline")

    assert read_bounded_text_line(stream, max_chars=32) == "tail without newline"
    assert read_bounded_text_line(stream, max_chars=32) is None


def test_backend_log_reader_marker_never_exceeds_a_tiny_cap() -> None:
    """A cap shorter than the truncation marker still yields at most ``cap``.

    The marker is 13 characters. For a cap below that, the reader truncates the
    marker itself to the cap (``_TRUNCATION_MARKER[:cap]``) and prepends no line
    text, so the caller's byte bound holds even when the marker cannot fit whole.
    The wider contract this guards is that a truncated result is never longer
    than the cap the caller asked for, which the oversized tests only check at a
    cap far above the marker length.
    """
    stream = StringIO("x" * 100 + "\n")

    line = read_bounded_text_line(stream, max_chars=5)

    assert line is not None
    assert len(line) == 5


def test_ida_rpc_reader_bounds_an_invalid_unterminated_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ida_client, "_MAX_RPC_LINE_CHARS", 32)
    client = ida_client.IdaWorkerClient.__new__(ida_client.IdaWorkerClient)
    client._messages = Queue()
    client._stdout_log = deque(maxlen=10)

    client._read_stdout(StringIO("x" * 1024))

    assert len(client._stdout_log) == 1
    assert len(client._stdout_log[0]) == 32
    assert client._stdout_log[0].endswith("[truncated]")
    assert client._messages.get_nowait() is None
