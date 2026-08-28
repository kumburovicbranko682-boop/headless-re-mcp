"""Socket-free coverage for the web launcher's healthz parsing and port helpers.

``test_web_launch`` drives the happy paths through real listeners; this file
pins the pure decision logic those tests reach only indirectly: the /healthz
envelope parser's rejection branches (which decide whether a port is *our*
console or someone else's), the loopback-name normalization in
``port_is_free``, the exhausted-span verdict of ``choose_bind_port``, and the
bounded-recv loop's exits. Keeping these deterministic and listener-free makes
the guard rails cheap to re-run and independent of host networking.
"""

from __future__ import annotations

import socket
import time
from typing import cast

import pytest

from headless_re_mcp.web import launch_util
from headless_re_mcp.web.launch_util import (
    _parse_healthz_http,
    _recv_until,
    choose_bind_port,
    port_is_free,
)

_OURS = b'{"ok":true,"service":"headless-re-mcp-web"}'


def _envelope(status: str, body: bytes, *, extra_headers: str = "") -> bytes:
    head = f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra_headers}\r\n"
    return head.encode("ascii") + body


# --------------------------------------------------------------------------- #
# _parse_healthz_http                                                         #
# --------------------------------------------------------------------------- #
def test_parse_accepts_a_wellformed_healthz_envelope() -> None:
    parsed = _parse_healthz_http(_envelope("200 OK", _OURS))
    assert parsed is not None
    assert parsed["service"] == "headless-re-mcp-web"


def test_parse_accepts_http_1_0_status() -> None:
    raw = b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(_OURS)).encode() + b"\r\n\r\n" + _OURS
    assert _parse_healthz_http(raw) is not None


def test_parse_accepts_repeated_but_agreeing_content_length() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(_OURS)).encode()
        + b"\r\nContent-Length: "
        + str(len(_OURS)).encode()
        + b"\r\n\r\n"
        + _OURS
    )
    assert _parse_healthz_http(raw) is not None


def test_parse_rejects_a_response_without_a_header_terminator() -> None:
    assert _parse_healthz_http(b"HTTP/1.1 200 OK\r\nContent-Length: 5") is None


def test_parse_rejects_a_malformed_status_line() -> None:
    assert _parse_healthz_http(b"GARBAGE\r\nContent-Length: 3\r\n\r\nabc") is None


def test_parse_rejects_a_non_integer_content_length() -> None:
    assert _parse_healthz_http(_envelope("200 OK", _OURS).replace(
        b"Content-Length: " + str(len(_OURS)).encode(),
        b"Content-Length: not-a-number",
    )) is None


def test_parse_rejects_a_content_length_over_the_cap() -> None:
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n" + _OURS
    assert _parse_healthz_http(raw) is None


def test_parse_rejects_a_body_that_is_not_json() -> None:
    body = b"this is not json"
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    assert _parse_healthz_http(raw) is None


def test_parse_rejects_json_that_is_not_an_object() -> None:
    body = b'["not","an","object"]'
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    assert _parse_healthz_http(raw) is None


def test_parse_rejects_a_different_service() -> None:
    body = b'{"ok":true,"service":"some-other-daemon"}'
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    assert _parse_healthz_http(raw) is None


# --------------------------------------------------------------------------- #
# port_is_free / choose_bind_port                                             #
# --------------------------------------------------------------------------- #
def test_port_is_free_normalizes_the_localhost_name() -> None:
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    busy = holder.getsockname()[1]
    try:
        # "localhost" must resolve to the 127.0.0.1 the holder occupies.
        assert port_is_free("localhost", busy) is False
    finally:
        holder.close()
    # After release the same name reports free.
    assert port_is_free("localhost", busy) is True


def test_choose_bind_port_reports_exhausted_when_the_whole_span_is_busy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch_util, "port_is_free", lambda host, port: False)
    chosen, reason = choose_bind_port("127.0.0.1", 9000, span=3, auto=True)
    assert chosen == 9000
    assert reason == "exhausted"


def test_choose_bind_port_returns_the_first_free_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    free_port = 9000 + 2

    def _free(host: str, port: int) -> bool:
        return port == free_port

    monkeypatch.setattr(launch_util, "port_is_free", _free)
    chosen, reason = choose_bind_port("127.0.0.1", 9000, span=5, auto=True)
    assert chosen == free_port
    assert reason == "fallback"


# --------------------------------------------------------------------------- #
# _recv_until                                                                 #
# --------------------------------------------------------------------------- #
class _ScriptedSocket:
    """A socket whose recv() replays a script of chunks and exceptions."""

    def __init__(self, script: list[bytes | BaseException]) -> None:
        self._script: list[bytes | BaseException] = list(script)
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def recv(self, size: int) -> bytes:
        if not self._script:
            return b""
        item = self._script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item[:size]


def _future_deadline() -> float:
    return time.monotonic() + 5.0


def _drain(sock: _ScriptedSocket, *, cap: int, deadline: float) -> bytes:
    result: bytes = _recv_until(cast(socket.socket, sock), cap=cap, deadline=deadline)
    return result


def test_recv_until_stops_at_eof() -> None:
    sock = _ScriptedSocket([b"partial", b""])
    assert _drain(sock, cap=1024, deadline=_future_deadline()) == b"partial"


def test_recv_until_retries_after_a_timeout_then_reads() -> None:
    sock = _ScriptedSocket([TimeoutError(), b"late", b""])
    assert _drain(sock, cap=1024, deadline=_future_deadline()) == b"late"


def test_recv_until_breaks_on_a_socket_error() -> None:
    sock = _ScriptedSocket([b"some", OSError("connection reset")])
    assert _drain(sock, cap=1024, deadline=_future_deadline()) == b"some"


def test_recv_until_stops_once_the_cap_is_reached() -> None:
    sock = _ScriptedSocket([b"x" * 200, b"never-read"])
    assert _drain(sock, cap=4, deadline=_future_deadline()) == b"xxxx"


def test_recv_until_gives_up_at_the_deadline() -> None:
    sock = _ScriptedSocket([TimeoutError(), TimeoutError()])
    # A deadline already in the past means not a single recv is attempted.
    result = _drain(sock, cap=1024, deadline=time.monotonic() - 1.0)
    assert result == b""
    assert sock.timeouts == []
