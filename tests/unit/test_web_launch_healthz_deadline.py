"""probe_our_healthz must honour its deadline at every blocking step.

The probe runs on the launcher's critical path: it decides whether an existing
console already owns the port. Each step -- connecting, then talking -- re-checks
the single overall deadline, because a connect that ate the whole budget must
not be followed by a read with a fresh one. These tests pin the two giving-up
points by driving the module's clock directly: once before the connect is even
attempted, and once between a successful connect and the request.
"""

from __future__ import annotations

import socket

import pytest

from headless_re_mcp.web import launch_util


class _Clock:
    """Stand-in for the time module: monotonic() replays a scripted sequence."""

    def __init__(self, values: list[float]) -> None:
        self._values = list(values)

    def monotonic(self) -> float:
        return self._values.pop(0)


def test_a_deadline_spent_before_connecting_returns_none_without_dialing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First reading sets the deadline; by the second the budget is already
    # gone, so the probe gives up before it ever opens a socket. Port 9 would
    # otherwise fail the test by raising from create_connection.
    monkeypatch.setattr(launch_util, "time", _Clock([0.0, 10.0]))

    assert launch_util.probe_our_healthz("127.0.0.1", 9, timeout=0.5) is None


def test_a_deadline_spent_by_the_connect_itself_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The connect succeeds against a real listener, but by the third clock
    # reading the whole budget was consumed by it, so no request is sent: the
    # peer must observe the connection close without receiving a byte.
    monkeypatch.setattr(launch_util, "time", _Clock([0.0, 0.0, 10.0]))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        assert launch_util.probe_our_healthz("127.0.0.1", port, timeout=0.5) is None

        conn, _ = server.accept()
        try:
            conn.settimeout(5.0)
            assert conn.recv(1) == b""
        finally:
            conn.close()
    finally:
        server.close()
