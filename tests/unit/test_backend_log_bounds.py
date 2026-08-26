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


def test_ida_rpc_reader_bounds_an_invalid_unterminated_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ida_client, "_MAX_RPC_LINE_CHARS", 32)
    client = ida_client.IdaClient.__new__(ida_client.IdaClient)
    client._messages = Queue()
    client._stdout_log = deque(maxlen=10)

    client._read_stdout(StringIO("x" * 1024))

    assert len(client._stdout_log) == 1
    assert len(client._stdout_log[0]) == 32
    assert client._stdout_log[0].endswith("[truncated]")
    assert client._messages.get_nowait() is None
