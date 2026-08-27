"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.proxy.client import _port_accepts


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


@pytest.mark.integration
def test_proxy_start_means_listening_and_stop_releases_the_port() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    started = backend.start("gate-session", host="127.0.0.1", port=port)
    try:
        assert started["running"] is True
        assert started["port"] == port
        # start() must not return before the socket actually accepts.
        assert _port_accepts("127.0.0.1", port, timeout=1.0) is True

        status = backend.status("gate-session")
        assert status["running"] is True
        assert status["flow_count"] == 0
        assert status["retained_max"] > 0
    finally:
        stopped = backend.stop("gate-session")

    assert stopped["stopped"] is True
    assert backend.status("gate-session") == {"running": False}

    # The listener must actually go away, or the next run cannot rebind.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if not _port_accepts("127.0.0.1", port, timeout=0.25):
            break
        time.sleep(0.1)
    else:
        pytest.fail("proxy port was still accepting connections after stop")


@pytest.mark.integration
def test_start_on_an_occupied_port_fails_instead_of_reporting_success() -> None:
    """A leftover listener must not be mistaken for our own healthy capture."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    squatter = socket.socket()
    squatter.bind(("127.0.0.1", 0))
    squatter.listen(1)
    port = int(squatter.getsockname()[1])
    try:
        with pytest.raises(ProxyError) as info:
            backend.start("gate-occupied", host="127.0.0.1", port=port)
        assert info.value.code == "invalid_state"
        # A refused start must leave no half-registered session behind.
        assert backend.status("gate-occupied") == {"running": False}
    finally:
        squatter.close()
        backend.stop("gate-occupied")


@pytest.mark.integration
def test_two_sessions_cannot_silently_share_one_port() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("first", host="127.0.0.1", port=port)
    try:
        with pytest.raises(ProxyError):
            backend.start("second", host="127.0.0.1", port=port)
        assert backend.status("first")["running"] is True
        assert backend.status("second") == {"running": False}
    finally:
        backend.close_all()


@pytest.mark.integration
def test_start_returns_only_after_the_masters_startup_hooks_have_run() -> None:
    """A returned start must mean the shared mitmproxy ctx is fully settled.

    mitmproxy stores options in a process global set in each ``Master.__init__``.
    If start() returned while its own startup hooks were still running, the next
    master's construction could overwrite that global mid-bind. The recorder's
    ``started`` event is set by the last startup hook, so it must be set by the
    time start() returns.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("gate-hooks", host="127.0.0.1", port=port)
    try:
        inst = backend._instances["gate-hooks"]
        assert inst.recorder.started.is_set() is True
    finally:
        backend.stop("gate-hooks")


@pytest.mark.integration
def test_concurrent_starts_do_not_corrupt_the_shared_mitmproxy_context() -> None:
    """Overlapping master construction must not trip mitmproxy's global ctx.

    Six threads race to stand up and tear down their own capture. Before the
    startup lock this intermittently failed with "No such option: rfile" or a
    bind against another session's port (a backend_error). A plain port
    collision between two workers is a different, expected outcome, so only a
    backend_error counts as the corruption this guards against.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    corruption: list[str] = []

    def worker(wid: int) -> None:
        backend = ProxyBackend()
        for _ in range(4):
            port = _free_port()
            try:
                backend.start(f"race-{wid}", host="127.0.0.1", port=port)
            except ProxyError as exc:
                if exc.code == "backend_error":
                    corruption.append(f"race-{wid}: {exc}")
            finally:
                backend.stop(f"race-{wid}")

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60.0)
    assert not corruption, corruption


@pytest.mark.integration
def test_close_all_releases_every_running_capture() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    ports = [_free_port(), _free_port()]
    for index, port in enumerate(ports):
        backend.start(f"session-{index}", host="127.0.0.1", port=port)
    backend.close_all()
    for index, port in enumerate(ports):
        assert backend.status(f"session-{index}") == {"running": False}
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if not _port_accepts("127.0.0.1", port, timeout=0.25):
                break
            time.sleep(0.1)
        else:
            pytest.fail(f"port {port} still accepting after close_all")
