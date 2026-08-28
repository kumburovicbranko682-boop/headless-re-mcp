"""Pin the supervisor arms only a live process or socket can reach.

``test_supervisor.py`` drives the restart loop with fakes and
``test_supervisor_probe.py`` probes a refused port, which leaves exactly the
arms production leans on unexercised: a probe that actually succeeds (and one
that gets a definite non-2xx verdict), the rescue path that shuts the socket
out from under a worker blocked on a child that accepted the connection and
then answered nothing, the final give-up verdict when even the rescue join
comes back empty, the log line for a Windows child that could not join the
kill group, and the ``Popen`` arm of ``_terminate`` that must go through
``terminate_process_tree`` rather than a bare ``terminate()`` -- the exact
difference that once left a debuggee running after an unhealthy restart.
"""

from __future__ import annotations

import http.client
import socket
import subprocess
import sys
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from headless_re_mcp import supervisor as supervisor_module
from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.supervisor import Supervisor, probe_ready


class _Answers(BaseHTTPRequestHandler):
    """A child that is actually serving: 200 on /readyz, 503 elsewhere."""

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        code = 200 if self.path == "/readyz" else 503
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture(name="answering_port")
def _answering_port() -> Any:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Answers)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def test_a_child_that_answers_200_is_reported_ready(answering_port: int) -> None:
    # No query string on purpose: every other probe test carries one, so the
    # plain-path arm had never run.
    assert probe_ready(f"http://127.0.0.1:{answering_port}/readyz", timeout=5.0) == (
        True,
        "http 200",
    )


def test_a_definite_error_status_is_a_verdict_not_unreachable(answering_port: int) -> None:
    # A 503 means the process answered and is not serving; conflating it with
    # unreachable would hide the difference the docstring exists to preserve.
    assert probe_ready(f"http://127.0.0.1:{answering_port}/failz", timeout=5.0) == (
        False,
        "http 503",
    )


def test_the_probe_rescues_its_worker_from_a_child_that_drips_bytes() -> None:
    """The measured wedge: one header byte per interval, so no timeout fires.

    Each byte resets the worker's socket timeout, so the request never returns
    on its own -- getresponse() blocks for as long as the peer keeps dripping.
    The probe must shut the socket down from under its worker, collect the
    worker's verdict, and return within its own deadline, not the child's.
    """
    server = socket.create_server(("127.0.0.1", 0))
    server.settimeout(10.0)
    stop_dripping = threading.Event()

    def drip_bytes_forever() -> None:
        with suppress(OSError):
            connection, _ = server.accept()
            while not stop_dripping.wait(0.05):
                connection.send(b"H")

    thread = threading.Thread(target=drip_bytes_forever, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        ok, detail = probe_ready(f"http://127.0.0.1:{server.getsockname()[1]}/readyz", timeout=0.2)
        elapsed = time.monotonic() - started
    finally:
        stop_dripping.set()
        thread.join(5.0)
        server.close()

    assert ok is False
    assert detail.startswith("unreachable:")
    # The verdict must be the worker's own (the shutdown made its read raise),
    # not the give-up fallback: dripping bytes means its timeout never fired,
    # so a TimeoutError here would mean the rescue never reached the socket --
    # the leak that once cost one thread and one descriptor per probe.
    assert detail != "unreachable: TimeoutError"
    assert elapsed < 5.0, f"probe took {elapsed:.1f}s against a dripping child"


class _NeverConnects:
    """A connection whose request outlives both joins and owns no socket yet."""

    sock = None

    def __init__(self, host: Any, port: Any, timeout: float | None = None) -> None:
        pass

    def request(self, method: str, path: str) -> None:
        # Longer than the probe bound plus the 1s rescue join, so the worker
        # is still stuck when the probe makes its final decision.
        time.sleep(3.0)

    def close(self) -> None:
        pass


def test_the_probe_gives_up_when_even_the_rescue_join_collects_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A connect the network swallows (a firewalled address that drops SYNs)
    # blocks before the connection owns a socket, so there is nothing to shut
    # down and the rescue join comes back empty. The probe must still return
    # its own verdict instead of hanging with the worker.
    monkeypatch.setattr(http.client, "HTTPConnection", _NeverConnects)

    ok, detail = probe_ready("http://127.0.0.1:9/readyz", timeout=0.05)

    assert (ok, detail) == (False, "unreachable: TimeoutError")


def test_a_child_that_cannot_join_the_kill_group_is_logged_not_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Grouping ties the child to the supervisor's own force-kill.

    When the assignment fails the child still runs -- refusing it would be an
    outage -- but the operator must be told this one will outlive a
    TerminateProcess on the supervisor.
    """
    monkeypatch.setattr(supervisor_module, "is_windows_host", lambda: True)
    monkeypatch.setattr(supervisor_module, "assign_to_process_group", lambda pid: False)
    records: list[dict[str, Any]] = []

    report = Supervisor(
        argv=["unused"],
        spawn=lambda argv: subprocess.Popen([sys.executable, "-c", "raise SystemExit(0)"]),
        check_interval_s=0.05,
        grace_period_s=0.0,
        log=records.append,
    ).run_forever()

    assert report.stopped_reason == "child_exited_cleanly"
    assert "child.not_grouped" in [record["event"] for record in records]


def test_an_unhealthy_real_child_is_terminated_through_the_process_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Popen arm of _terminate must actually kill the process.

    Every fake-child test exercises the duck-typed fallback; the arm production
    takes -- terminate_process_tree on a real Popen -- had never run, and it is
    the one that exists because a bare terminate() left the tools the child
    started still holding the sample. A bare terminate() also kills a childless
    sleeper, so the routing is pinned with a forwarding spy: dropping the Popen
    arm would leave the child just as dead and this test just as red.
    """
    routed: list[int] = []
    real_terminate = terminate_process_tree

    def forwarding_spy(process: Any, *, wait_s: float = 5.0, kill_group: bool = False) -> list[int]:
        routed.append(process.pid)
        return real_terminate(process, wait_s=wait_s, kill_group=kill_group)

    monkeypatch.setattr(supervisor_module, "terminate_process_tree", forwarding_spy)
    spawned: list[subprocess.Popen[bytes]] = []

    def spawn(argv: Any) -> subprocess.Popen[bytes]:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        spawned.append(child)
        return child

    report = Supervisor(
        argv=["unused"],
        ready_url="http://127.0.0.1:1/readyz",
        probe=lambda url, timeout: (False, "http 503"),
        unhealthy_strikes=1,
        check_interval_s=0.01,
        grace_period_s=0.0,
        max_restarts=1,
        spawn=spawn,
        sleep=lambda seconds: time.sleep(min(seconds, 0.01)),
        log=lambda record: None,
    ).run_forever()

    assert report.unhealthy_restarts == 1
    assert report.stopped_reason == "restart_limit"
    assert len(spawned) == 1
    assert routed == [spawned[0].pid], "a real Popen must go through terminate_process_tree"
    assert spawned[0].poll() is not None, "the wedged child must actually be dead"
