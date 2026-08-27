"""An unusable port number must be refused, not half-served or kill-looped.

``run_web`` validated the host (must parse, must be loopback) but not the
port. Port 0 sailed through: ``port_is_free`` binds 0 successfully (the kernel
assigns an ephemeral port) and uvicorn happily serves on whatever number the
kernel picked -- but the banner, ``app.state.bind_port`` and the supervisor's
readiness URL could only repeat the 0 they were given. Standalone that is a
healthy server nobody can find (uvicorn's own "running on" line is INFO,
suppressed under ``log_level="warning"``); under ``supervise`` it is the worst
case: the probe against ``:0`` can never answer, and unhealthy restarts
deliberately never count toward the crash-loop bound, so the supervisor killed
a healthy child forever. Ports past 65535 died differently: ``socket.bind``
raises ``OverflowError``, which is not ``OSError``, so it escaped
``port_is_free`` as an incident instead of a refusal. Both ends now get the
same fail-closed treatment as a non-loopback host.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.cli as cli_module
from headless_re_mcp.config import Settings
from headless_re_mcp.web.app import run_web


def _settings(tmp_path: Path, http_port: int = 8765) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=http_port,
    )


@pytest.mark.parametrize("port", [0, -1, 65536, 70000])
def test_run_web_refuses_a_port_outside_1_to_65535(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], port: int
) -> None:
    settings = _settings(tmp_path)
    code = run_web(settings, host="127.0.0.1", port=port)
    assert code == 2
    assert "1..65535" in capsys.readouterr().out
    # Refused before any side effect: no artifact root claimed, no token minted.
    assert not settings.artifact_root.exists()


def test_run_web_refuses_a_zero_port_coming_from_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The config file is a boundary too: http_port 0 must not half-start."""
    settings = _settings(tmp_path, http_port=0)
    code = run_web(settings, host="127.0.0.1", port=None)
    assert code == 2
    assert "1..65535" in capsys.readouterr().out


class _FakeReport:
    stopped_reason = "child_exited_cleanly"

    def as_json(self) -> dict[str, Any]:
        return {"stopped_reason": self.stopped_reason}


def _install_fake_supervisor(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    class _FakeSupervisor:
        def __init__(self, argv: Any, **kwargs: Any) -> None:
            seen["constructed"] = True
            seen["argv"] = list(argv)
            seen.update(kwargs)

        def run_forever(self) -> _FakeReport:
            return _FakeReport()

    monkeypatch.setattr("headless_re_mcp.supervisor.Supervisor", _FakeSupervisor)
    return seen


def test_supervise_web_target_refuses_port_zero_before_spawning_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Pre-fix this was the unbounded case: a healthy child killed forever."""
    monkeypatch.setattr(
        Settings, "load", staticmethod(lambda _path=None: _settings(tmp_path))
    )
    seen = _install_fake_supervisor(monkeypatch)
    code = cli_module._main(["supervise", "--target", "serve-web", "--port", "0"])
    assert code == 2
    assert "1..65535" in capsys.readouterr().out
    assert "constructed" not in seen, "the supervisor must not start on a bad port"


def test_supervise_stdio_target_ignores_the_port_it_does_not_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--target serve has no HTTP surface; a port value must not block it."""
    monkeypatch.setattr(
        Settings, "load", staticmethod(lambda _path=None: _settings(tmp_path))
    )
    seen = _install_fake_supervisor(monkeypatch)
    code = cli_module._main(["supervise", "--target", "serve", "--port", "0"])
    assert code == 0
    assert seen["constructed"] is True
    assert seen["ready_url"] is None
    assert "--port" not in seen["argv"]
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_a_valid_port_still_reaches_the_bind_chooser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The guard must reject the range ends, not the ports in between."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()

    import uvicorn

    from headless_re_mcp.web import app as web_app

    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: None)
    code = web_app.run_web(
        _settings(tmp_path), host="127.0.0.1", port=free_port, quiet_banner=True
    )
    assert code == 0
