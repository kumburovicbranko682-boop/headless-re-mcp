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
def test_concurrent_starts_do_not_cross_the_mitmproxy_global_ctx() -> None:
    """Several proxies starting at once must all come up cleanly.

    mitmproxy keeps its addon context in process-global module attributes, so a
    second master under construction repoints the global that a first master's
    startup ``running`` hook reads; the resulting AttributeError is logged and
    then escalated by mitmproxy's errorcheck into a fatal "mitmproxy failed to
    start". Before the startup lock this failed a large fraction of overlapping
    starts (~9 of 24 in a 4-wide barrier stress); now every concurrent start
    must succeed. A barrier maximises the overlap the lock has to absorb.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    rounds, width = 5, 4
    failures: list[str] = []
    try:
        for rnd in range(rounds):
            ports = [_free_port() for _ in range(width)]
            barrier = threading.Barrier(width)
            errors: dict[str, str] = {}
            errors_lock = threading.Lock()

            def worker(
                index: int,
                port: int,
                rnd: int = rnd,
                barrier: threading.Barrier = barrier,
                errors: dict[str, str] = errors,
                errors_lock: threading.Lock = errors_lock,  # noqa: F821
            ) -> None:
                session = f"round{rnd}-{index}"
                try:
                    barrier.wait(timeout=10.0)
                    backend.start(session, host="127.0.0.1", port=port)
                except Exception as exc:  # noqa: BLE001 - record any start failure
                    with errors_lock:
                        errors[session] = f"{type(exc).__name__}: {exc}"

            threads = [
                threading.Thread(target=worker, args=(i, ports[i])) for i in range(width)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30.0)
            failures.extend(f"{name}: {reason}" for name, reason in errors.items())
            backend.close_all()
    finally:
        backend.close_all()
    assert not failures, "concurrent proxy starts failed:\n" + "\n".join(failures)


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
