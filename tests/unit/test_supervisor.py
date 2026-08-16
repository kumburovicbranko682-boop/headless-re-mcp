from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.supervisor import (
    HEALTHY_UPTIME_S,
    MAX_RAPID_RESTARTS,
    Supervisor,
    build_child_argv,
)


class FakeChild:
    """A child whose lifetime the test controls exactly."""

    def __init__(self, exits_after: int, code: int) -> None:
        self.pid = 4242
        self._ticks_left = exits_after
        self._code = code
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        if self._ticks_left > 0:
            self._ticks_left -= 1
            return None
        return self._code

    def terminate(self) -> None:
        self.terminated = True
        self._ticks_left = 0

    def wait(self, timeout: float | None = None) -> int:
        return self._code

    def kill(self) -> None:
        self.killed = True


class Harness:
    """Drives the supervisor on a virtual clock so nothing actually sleeps."""

    def __init__(
        self,
        children: list[FakeChild],
        probes: list[tuple[bool, str]] | None = None,
    ) -> None:
        self.children = list(children)
        self.probes = list(probes or [])
        self.now = 0.0
        self.spawned = 0
        self.slept: list[float] = []
        self.records: list[dict[str, Any]] = []

    def spawn(self, argv: Any) -> FakeChild:
        self.spawned += 1
        return self.children.pop(0) if self.children else FakeChild(exits_after=0, code=0)

    def probe(self, url: str, timeout: float) -> tuple[bool, str]:
        return self.probes.pop(0) if self.probes else (True, "http 200")

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        # Advance far enough that a child counts as long-lived unless the test
        # made it exit immediately.
        self.now += seconds

    def clock(self) -> float:
        self.now += 1.0
        return self.now

    def log(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def build(self, *, check_interval_s: float = 1.0, **kwargs: Any) -> Supervisor:
        return Supervisor(
            ["python", "-m", "headless_re_mcp", "serve-web"],
            spawn=self.spawn,
            probe=self.probe,
            sleep=self.sleep,
            clock=self.clock,
            log=self.log,
            check_interval_s=check_interval_s,
            grace_period_s=0.0,
            **kwargs,
        )

    def events(self) -> list[str]:
        return [str(record["event"]) for record in self.records]


def test_a_clean_exit_is_not_restarted() -> None:
    """Stopping the service on purpose must not be fought by the supervisor."""
    harness = Harness([FakeChild(exits_after=1, code=0)])

    report = harness.build().run_forever()

    assert harness.spawned == 1
    assert report.stopped_reason == "child_exited_cleanly"
    assert report.crash_restarts == 0
    assert "child.exited" in harness.events()


def test_a_crash_is_restarted() -> None:
    harness = Harness([FakeChild(exits_after=1, code=1), FakeChild(exits_after=1, code=0)])

    report = harness.build().run_forever()

    assert harness.spawned == 2
    assert report.crash_restarts == 1
    assert report.stopped_reason == "child_exited_cleanly"


def test_a_live_but_wedged_child_is_restarted_on_failed_readiness() -> None:
    """Alive is not the same as serving, which is why /readyz exists.

    A process can hold its port open and answer nothing useful; without this the
    supervisor would report perfect uptime for a service doing no work.
    """
    wedged = FakeChild(exits_after=99, code=0)
    harness = Harness(
        [wedged, FakeChild(exits_after=1, code=0)],
        probes=[(False, "http 503"), (False, "http 503"), (False, "http 503")],
    )

    report = harness.build(ready_url="http://127.0.0.1:8765/readyz").run_forever()

    assert report.unhealthy_restarts == 1
    assert wedged.terminated is True
    assert "child.unhealthy" in harness.events()


def test_a_single_failed_probe_does_not_restart_anything() -> None:
    """One slow moment is not a fault; restarting on it would be its own outage."""
    ok = (True, "http 200")
    harness = Harness(
        [FakeChild(exits_after=4, code=0)],
        probes=[(False, "unreachable: TimeoutError"), ok, ok, ok],
    )

    report = harness.build(ready_url="http://127.0.0.1:8765/readyz").run_forever()

    assert report.unhealthy_restarts == 0
    assert report.stopped_reason == "child_exited_cleanly"


def test_readiness_is_not_judged_during_the_grace_period() -> None:
    """A service that is still starting is not a service that has failed."""
    harness = Harness(
        [FakeChild(exits_after=2, code=0)],
        probes=[(False, "unreachable"), (False, "unreachable")],
    )
    supervisor = harness.build(ready_url="http://127.0.0.1:8765/readyz")
    supervisor.grace_period_s = 10_000.0

    report = supervisor.run_forever()

    assert report.unhealthy_restarts == 0
    assert "child.unhealthy" not in harness.events()


def test_a_spawn_that_fails_is_a_failed_start_not_a_dead_supervisor() -> None:
    """Popen fails transiently: on Windows, under memory or handle pressure.

    Raising out of run_forever leaves nothing running and nothing left to
    restart it, which is a worse outcome than the crash loop the backoff exists
    to bound. A shortage at 3am must cost a retry, not the service.
    """
    harness = Harness([])
    attempts: list[int] = []

    def refuse_twice(argv: Any) -> FakeChild:
        attempts.append(1)
        if len(attempts) <= 2:
            raise OSError(12, "Not enough memory resources are available")
        return FakeChild(exits_after=1, code=0)

    supervisor = harness.build()
    supervisor.spawn = refuse_twice

    report = supervisor.run_forever()

    assert len(attempts) == 3, "a failed spawn must be retried, not raised"
    assert report.stopped_reason == "child_exited_cleanly"
    assert "child.spawn_failed" in harness.events()


def test_a_spawn_that_never_works_stops_the_way_a_crash_loop_does() -> None:
    """The bound that applies to a child that keeps dying applies here too."""
    harness = Harness([])

    def always_refuse(argv: Any) -> FakeChild:
        raise OSError(2, "No such file or directory")

    supervisor = harness.build()
    supervisor.spawn = always_refuse

    report = supervisor.run_forever()

    assert report.stopped_reason == "crash_loop"
    assert "supervisor.giving_up" in harness.events()


def test_a_probe_that_raises_is_a_failed_check_not_a_dead_supervisor() -> None:
    """urlopen raises more than probe_ready catches.

    http.client.HTTPException is not an OSError, and a wedged child answering
    with a malformed response produces exactly that -- the case the probe was
    added to catch, killing the supervisor instead of restarting the child.
    """
    wedged = FakeChild(exits_after=99, code=0)
    harness = Harness([wedged, FakeChild(exits_after=1, code=0)])

    def raising_probe(url: str, timeout: float) -> tuple[bool, str]:
        raise RuntimeError("BadStatusLine")

    supervisor = harness.build(ready_url="http://127.0.0.1:8765/readyz")
    supervisor.probe = raising_probe

    report = supervisor.run_forever()

    assert report.unhealthy_restarts == 1, "a probe that raises is a child that is not ready"
    assert wedged.terminated is True


def test_a_log_sink_that_fails_does_not_take_the_supervisor_with_it() -> None:
    """Started detached, the default sink writes to a stdout nobody is reading."""
    harness = Harness([FakeChild(exits_after=1, code=1), FakeChild(exits_after=1, code=0)])

    def broken_log(record: dict[str, Any]) -> None:
        raise OSError(22, "Invalid argument")

    supervisor = harness.build()
    supervisor.log = broken_log

    report = supervisor.run_forever()

    assert report.crash_restarts == 1
    assert report.stopped_reason == "child_exited_cleanly"


def test_an_interrupted_supervisor_does_not_leave_its_child_behind() -> None:
    """Stopping the supervisor is how the whole service is stopped.

    A child outlives its parent on Windows, so an interrupt left a web server
    running -- along with the debuggers and the debuggees it owns -- with
    nothing supervising it. Measured against a real supervise run: killing the
    supervisor left the server up, and the next start would then crash-loop
    against a port the orphan still holds.
    """
    child = FakeChild(exits_after=99, code=0)
    harness = Harness([child])
    supervisor = harness.build()
    sleeps = {"count": 0}

    def interrupt_on_the_second_wait(seconds: float) -> None:
        sleeps["count"] += 1
        if sleeps["count"] >= 2:
            raise KeyboardInterrupt
        harness.sleep(seconds)

    supervisor.sleep = interrupt_on_the_second_wait

    with pytest.raises(KeyboardInterrupt):
        supervisor.run_forever()

    assert child.terminated is True, "the child must go down with the supervisor"


def test_a_clean_exit_still_leaves_nothing_to_terminate() -> None:
    """The guard must not fire on the path where the child already stopped."""
    child = FakeChild(exits_after=1, code=0)
    harness = Harness([child])

    report = harness.build().run_forever()

    assert report.stopped_reason == "child_exited_cleanly"
    assert child.terminated is False, "a child that exited is not terminated again"


def test_a_real_child_is_tied_to_this_process_and_a_fake_one_is_not() -> None:
    """Force-killing the supervisor has to take the server with it.

    TerminateProcess delivers no signal, so the cleanup above cannot run, and
    stopping a scheduled task is exactly that. A job object is what closes it.
    A fake child must be left alone: its pid is invented, and grouping it would
    put whatever really owns that number in line to be killed.
    """
    from headless_re_mcp import process_group
    from headless_re_mcp import supervisor as supervisor_module

    real = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        **no_window_popen_kwargs(),
    )
    try:
        assert process_group.assign_to_process_group(real.pid) is True
        assert process_group.assign_to_process_group(0) is False
    finally:
        real.kill()
        real.wait(timeout=10)

    grouped: list[int] = []
    harness = Harness([FakeChild(exits_after=1, code=0)])
    supervisor = harness.build()
    original = supervisor_module.assign_to_process_group
    supervisor_module.assign_to_process_group = lambda pid: (grouped.append(pid), True)[1]
    try:
        supervisor.run_forever()
    finally:
        supervisor_module.assign_to_process_group = original

    assert grouped == [], "an injected fake child must never be grouped by pid"


def test_a_crash_loop_stops_instead_of_pretending_to_be_uptime() -> None:
    """Restarting forever hides a broken deployment behind a running process."""
    harness = Harness([FakeChild(exits_after=0, code=1) for _ in range(20)])

    report = harness.build().run_forever()

    assert report.stopped_reason == "crash_loop"
    assert harness.spawned == MAX_RAPID_RESTARTS
    assert "supervisor.giving_up" in harness.events()


def test_restart_backoff_grows_and_is_capped() -> None:
    harness = Harness([FakeChild(exits_after=0, code=1) for _ in range(20)])

    # A distinct poll interval so the waits between restarts can be told apart
    # from the waits between health checks; both go through the same sleep.
    harness.build(check_interval_s=0.01).run_forever()

    backoffs = [seconds for seconds in harness.slept if seconds > 0.01]
    assert backoffs, "a restart must wait before respawning"
    assert backoffs == sorted(backoffs), "backoff must not shrink between rapid restarts"
    assert backoffs[0] < backoffs[-1], "backoff must actually grow"
    assert max(backoffs) <= 30.0


def test_an_explicit_restart_limit_is_honoured() -> None:
    children = [FakeChild(exits_after=1, code=1) for _ in range(10)]
    harness = Harness(children)

    report = harness.build(max_restarts=2).run_forever()

    assert report.stopped_reason == "restart_limit"
    assert report.crash_restarts == 2


def test_a_long_lived_child_does_not_count_toward_the_crash_loop() -> None:
    """Two crashes a day apart are two incidents, not a loop."""
    harness = Harness([FakeChild(exits_after=200, code=1), FakeChild(exits_after=1, code=0)])

    report = harness.build().run_forever()

    assert report.crash_restarts == 1
    assert report.stopped_reason == "child_exited_cleanly"
    assert harness.now > HEALTHY_UPTIME_S


def test_child_argv_reuses_this_interpreter_and_carries_the_config() -> None:
    argv = build_child_argv("serve-web", host="127.0.0.1", port=9001, config="C:/cfg.json")

    assert argv[1:3] == ["-m", "headless_re_mcp"]
    assert argv[3:5] == ["--config", "C:/cfg.json"]
    assert argv[5] == "serve-web"
    assert "--host" in argv and "127.0.0.1" in argv
    assert "--port" in argv and "9001" in argv


def test_stdio_child_argv_has_no_http_flags() -> None:
    argv = build_child_argv("serve", host="127.0.0.1", port=9001)
    assert "--host" not in argv and "--port" not in argv

def test_a_child_that_refuses_to_start_is_not_restarted(tmp_path: Path) -> None:
    """A refusal is not a crash, and a retry cannot change it.

    The web console exits 78, the sysexits code for a configuration that
    cannot work, when another instance already holds the artifact root.
    Measured with two supervisors against one root: the second restarted its
    refused child on a 2, 4, 8, 16 second backoff, logging only reason crashed,
    while the reason the child printed went to its own console rather than the
    supervisor's log.
    """
    starts: list[int] = []

    class Refuses:
        def __init__(self) -> None:
            self.pid = 4242
            self._code: int | None = None

        def poll(self) -> int | None:
            self._code = 78
            return self._code

        def terminate(self) -> None:
            return

        def wait(self, timeout: float | None = None) -> int:
            return 78

    def spawn(argv: Sequence[str]) -> Refuses:
        starts.append(1)
        return Refuses()

    records: list[dict[str, object]] = []
    supervisor = Supervisor(
        argv=["x"],
        ready_url=None,
        check_interval_s=0.01,
        grace_period_s=0.0,
        spawn=spawn,
        sleep=lambda _seconds: None,
        log=records.append,
        max_restarts=20,
    )

    report = supervisor.run_forever()

    assert len(starts) == 1, "a refusal must be tried exactly once"
    assert report.stopped_reason == "child_refused_to_start"
    refusal = [item for item in records if item.get("event") == "supervisor.child_refused"]
    assert refusal and refusal[0]["exit_code"] == 78
    assert "restart cannot change" in str(refusal[0]["detail"])


def test_a_child_that_really_crashed_is_still_restarted(tmp_path: Path) -> None:
    """The distinction has to hold the other way, or nothing gets restarted."""
    starts: list[int] = []

    class Crashes:
        def __init__(self) -> None:
            self.pid = 99
            self.terminated = False

        def poll(self) -> int | None:
            return 1

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> int:
            return 1

    def spawn(argv: Sequence[str]) -> Crashes:
        starts.append(1)
        return Crashes()

    supervisor = Supervisor(
        argv=["x"],
        ready_url=None,
        check_interval_s=0.01,
        grace_period_s=0.0,
        spawn=spawn,
        sleep=lambda _seconds: None,
        log=lambda _record: None,
        max_restarts=3,
    )

    report = supervisor.run_forever()

    assert len(starts) > 1, "an ordinary crash must still be restarted"
    assert report.stopped_reason in {"crash_loop", "restart_limit"}


def test_the_real_default_spawn_starts_and_restarts_an_actual_process(
    tmp_path: Path,
) -> None:
    """Exercise the spawn production uses, not an injected fake.

    Every other test here supplies its own `spawn`, so the default -- which is
    also where the console-window suppression lives -- is never executed. A
    mistake in it would leave the supervisor unable to start anything while the
    suite stayed green.
    """
    marker = tmp_path / "starts.txt"
    child = tmp_path / "child.py"
    child.write_text(
        "import sys, time\n"
        "from pathlib import Path\n"
        "p = Path(sys.argv[1])\n"
        "p.write_text((p.read_text() if p.exists() else '') + 'start\\n')\n"
        "time.sleep(0.2)\n"
        "sys.exit(3)\n",
        encoding="utf-8",
    )

    records: list[dict[str, Any]] = []
    supervisor = Supervisor(
        argv=[sys.executable, str(child), str(marker)],
        ready_url=None,
        check_interval_s=0.05,
        grace_period_s=0.0,
        max_restarts=2,
        log=records.append,
        sleep=lambda _seconds: None,  # skip the restart backoff, not the restart
    )

    report = supervisor.run_forever()

    assert marker.exists(), "the child never ran, so the default spawn is broken"
    assert len(marker.read_text().splitlines()) == 2, "the crashed child must be restarted"
    assert report.starts == 2
    assert report.crash_restarts == 2
    assert report.last_exit_code == 3, "the child's real exit code must come back"
    assert [record["event"] for record in records] == [
        "child.started",
        "child.restarting",
        "child.started",
        "supervisor.restart_limit",
    ]


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            return fh.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


def test_supervisor_terminate_kills_the_whole_process_tree(tmp_path: Path) -> None:
    """A restart used to SIGTERM only the service; its workers stayed."""
    import os
    import time
    from contextlib import suppress

    child_file = tmp_path / "child.pid"
    script = tmp_path / "sleeper.py"
    script.write_text(
        "import subprocess, sys\n"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(child_file)!r}, 'w').write(str(c.pid))\n"
        "import time; time.sleep(60)\n"
    )
    parent = subprocess.Popen([sys.executable, str(script)])
    for _ in range(50):
        if child_file.exists():
            break
        time.sleep(0.02)
    child_pid = int(child_file.read_text())
    try:
        assert _alive(parent.pid)
        assert _alive(child_pid)
        Supervisor(["x"])._terminate(parent)
        time.sleep(0.2)
        assert parent.poll() is not None
        assert not _alive(child_pid), f"child {child_pid} still alive after supervisor stop"
    finally:
        with suppress(OSError):
            os.kill(child_pid, 9)
        with suppress(OSError):
            os.kill(parent.pid, 9)