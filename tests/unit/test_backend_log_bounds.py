from __future__ import annotations

from io import StringIO

from headless_re_mcp.backends.common.text_stream import read_bounded_text_line


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
