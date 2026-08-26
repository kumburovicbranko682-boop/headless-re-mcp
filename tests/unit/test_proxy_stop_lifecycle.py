"""Proxy shutdown must not lose a listener that is still alive."""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError, _ProxyInstance


class _StillAliveThread:
    def __init__(self) -> None:
        self.join_timeout: float | None = None

    def join(self, timeout: float | None = None) -> None:
        self.join_timeout = timeout

    def is_alive(self) -> bool:
        return True


def test_proxy_stop_reports_a_wedged_thread_and_keeps_it_tracked() -> None:
    """A ten-second join used to become success even when the thread survived.

    Measured with one wedged thread: stop returned ``stopped=True`` and the
    tracked instance count fell from one to zero, while one listener thread
    remained alive. The next start then had no handle with which to free the
    occupied port.
    """
    backend = ProxyBackend()
    instance = _ProxyInstance("127.0.0.1", 18080)
    thread = _StillAliveThread()
    instance._thread = thread  # type: ignore[assignment]
    backend._instances["session"] = instance

    with pytest.raises(ProxyError, match="did not stop") as raised:
        backend.stop("session")

    assert raised.value.code == "timeout"
    assert raised.value.details["host"] == "127.0.0.1"
    assert raised.value.details["port"] == 18080
    assert thread.join_timeout == 10.0
    assert backend._instances == {"session": instance}
