"""Dispatch coverage for the CLI entry point.

``test_cli`` pins the two gate-xdbg happy paths; this pins the rest of the
command routing in ``_main`` and the supervisor wiring in ``_run_supervisor``.
Every heavy collaborator (doctor, the stdio/web servers, the supervisor, the
config generator, the x64dbg gate) is substituted, so these tests assert the
routing contract -- which command calls what, with which arguments, and what
exit code it maps to -- without starting a server or a subprocess.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.cli as cli_module
from headless_re_mcp.config import Settings


@pytest.fixture(autouse=True)
def _stub_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=tmp_path / "x64.exe",
        x64dbg_headless_x86=tmp_path / "x86.exe",
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )
    monkeypatch.setattr(Settings, "load", staticmethod(lambda _path=None: settings))
    return settings


# --------------------------------------------------------------------------- #
# doctor                                                                      #
# --------------------------------------------------------------------------- #
class _Report:
    def __init__(self, ready: bool) -> None:
        self.ready = ready

    def to_json(self) -> str:
        return json.dumps({"ready": self.ready})


def test_doctor_prints_json_and_returns_zero_when_ready(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli_module, "run_doctor", lambda _s: _Report(ready=True))
    code = cli_module._main(["doctor", "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["ready"] is True


def test_doctor_prints_human_report_by_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli_module, "run_doctor", lambda _s: _Report(ready=True))
    monkeypatch.setattr(cli_module, "format_report", lambda _r: "HUMAN REPORT")
    code = cli_module._main(["doctor"])
    assert code == 0
    assert "HUMAN REPORT" in capsys.readouterr().out


def test_doctor_strict_returns_nonzero_when_not_ready(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli_module, "run_doctor", lambda _s: _Report(ready=False))
    code = cli_module._main(["doctor", "--json", "--strict"])
    assert code == 1


def test_doctor_without_strict_returns_zero_even_when_not_ready(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli_module, "run_doctor", lambda _s: _Report(ready=False))
    code = cli_module._main(["doctor", "--json"])
    assert code == 0


# --------------------------------------------------------------------------- #
# gate-xdbg exception path                                                     #
# --------------------------------------------------------------------------- #
def test_gate_xdbg_reports_a_gate_that_raises(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli_module, "is_windows_host", lambda: True)

    def _boom(executable: Any, architecture: Any, *, timeout: float) -> Any:
        raise OSError("gate crashed")

    monkeypatch.setattr(cli_module, "run_command_loop_gate", _boom)
    code = cli_module._main(["gate-xdbg", "--architecture", "x86"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["ok"] is False
    assert "OSError" in payload["results"][0]["error"]


# --------------------------------------------------------------------------- #
# serve / serve-web                                                           #
# --------------------------------------------------------------------------- #
def test_serve_runs_stdio_with_the_service(
    monkeypatch: pytest.MonkeyPatch, _stub_settings: Settings
) -> None:
    monkeypatch.setattr(cli_module, "_keep_routine_logs_off_the_pipe", lambda: None)
    built: dict[str, Any] = {}

    class _FakeService:
        def __init__(self, settings: Settings) -> None:
            built["settings"] = settings

    served: dict[str, Any] = {}

    def _run_stdio(service: Any) -> None:
        served["service"] = service

    monkeypatch.setattr("headless_re_mcp.core.service.AnalysisService", _FakeService)
    monkeypatch.setattr("headless_re_mcp.mcp.server.run_stdio", _run_stdio)

    code = cli_module._main(["serve"])
    assert code == 0
    assert built["settings"] is _stub_settings
    assert isinstance(served["service"], _FakeService)


def test_serve_web_forwards_host_and_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patching the string target imports headless_re_mcp.web.app, which needs
    # fastapi (the optional ``web`` extra) — exactly what serve-web itself
    # needs. Skip just this test when the extra is absent (skip != pass); the
    # rest of the CLI dispatch coverage runs fine on a bare install.
    pytest.importorskip("fastapi", reason="fastapi (web extra) not installed (skip != pass)")
    captured: dict[str, Any] = {}

    def _run_web(settings: Any, *, host: Any, port: Any) -> int:
        captured["host"] = host
        captured["port"] = port
        return 7

    monkeypatch.setattr("headless_re_mcp.web.app.run_web", _run_web)
    code = cli_module._main(["serve-web", "--host", "127.0.0.1", "--port", "9001"])
    assert code == 7
    assert captured == {"host": "127.0.0.1", "port": 9001}


def test_serve_web_without_the_web_extra_says_what_to_install(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A base install typing serve-web is an expected condition, not an incident.

    ``None`` in ``sys.modules`` makes the deferred ``web.app`` import raise
    ModuleNotFoundError exactly as a machine without the ``web`` extra does, so
    this runs identically whether or not fastapi happens to be installed.
    Before the guard, this surfaced as ``internal_error`` with a minted
    incident id, burying the actionable fix (install the extra).
    """
    monkeypatch.setitem(sys.modules, "headless_re_mcp.web.app", None)
    code = cli_module._main(["serve-web", "--host", "127.0.0.1", "--port", "9001"])
    assert code == 2
    payload = json.loads(capsys.readouterr().err)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "backend_unavailable"
    assert 'pip install "headless-re-mcp[web]"' in payload["error"]["message"]
    assert "incident" not in json.dumps(payload).lower(), (
        "a predictable missing extra must not mint an incident id"
    )


# --------------------------------------------------------------------------- #
# supervise / _run_supervisor                                                 #
# --------------------------------------------------------------------------- #
class _FakeReport:
    def __init__(self, reason: str) -> None:
        self.stopped_reason = reason

    def as_json(self) -> dict[str, Any]:
        return {"stopped_reason": self.stopped_reason}


def _install_fake_supervisor(
    monkeypatch: pytest.MonkeyPatch, *, reason: str
) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    class _FakeSupervisor:
        def __init__(self, argv: Any, **kwargs: Any) -> None:
            seen["argv"] = argv
            seen.update(kwargs)

        def run_forever(self) -> _FakeReport:
            return _FakeReport(reason)

    def _build_child_argv(target: str, *, host: Any, port: Any, config: Any) -> list[str]:
        seen["child"] = {"target": target, "host": host, "port": port, "config": config}
        return ["child", target]

    monkeypatch.setattr("headless_re_mcp.supervisor.Supervisor", _FakeSupervisor)
    monkeypatch.setattr("headless_re_mcp.supervisor.build_child_argv", _build_child_argv)
    return seen


def test_supervise_web_target_builds_a_readiness_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = _install_fake_supervisor(monkeypatch, reason="child_exited_cleanly")
    code = cli_module._main(
        ["supervise", "--target", "serve-web", "--host", "127.0.0.1", "--port", "9100"]
    )
    assert code == 0
    assert seen["ready_url"] == "http://127.0.0.1:9100/readyz"
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_supervise_stdio_target_has_no_readiness_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = _install_fake_supervisor(monkeypatch, reason="child_exited_cleanly")
    code = cli_module._main(["supervise", "--target", "serve"])
    assert code == 0
    assert seen["ready_url"] is None


def test_supervise_no_readiness_flag_disables_the_probe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = _install_fake_supervisor(monkeypatch, reason="child_exited_cleanly")
    code = cli_module._main(["supervise", "--target", "serve-web", "--no-readiness"])
    assert code == 0
    assert seen["ready_url"] is None


def test_supervise_reports_nonzero_on_an_unclean_stop(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install_fake_supervisor(monkeypatch, reason="crash_loop_detected")
    code = cli_module._main(["supervise", "--target", "serve-web"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["ok"] is False
    assert payload["stopped_reason"] == "crash_loop_detected"


def test_supervise_clamps_check_and_grace_intervals(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = _install_fake_supervisor(monkeypatch, reason="child_exited_cleanly")
    cli_module._main(
        [
            "supervise",
            "--target",
            "serve-web",
            "--check-interval",
            "0.1",
            "--grace-period",
            "-5",
        ]
    )
    assert seen["check_interval_s"] == 1.0  # floored at 1.0
    assert seen["grace_period_s"] == 0.0  # floored at 0.0


# --------------------------------------------------------------------------- #
# config generate                                                             #
# --------------------------------------------------------------------------- #
def test_config_generate_writes_to_a_file_when_output_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.generate_config_bundle",
        lambda *a, **k: {"ok": True, "servers": {}},
    )
    out = tmp_path / "nested" / "mcp.json"
    code = cli_module._main(["config", "generate", "--output", str(out)])
    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["ok"] is True


def test_config_generate_returns_nonzero_when_the_bundle_is_not_ok(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.generate_config_bundle",
        lambda *a, **k: {"ok": False, "error": "doctor not ready"},
    )
    code = cli_module._main(["config", "generate"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


# --------------------------------------------------------------------------- #
# _keep_routine_logs_off_the_pipe                                             #
# --------------------------------------------------------------------------- #
def test_routine_logs_go_to_a_file_while_warnings_still_reach_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On stdio, INFO logs on the client's pipe deadlock the server once the
    buffer fills; they must land in a file, with only WARNING+ left on stderr."""
    monkeypatch.setenv("HEADLESS_RE_LOG_DIR", str(tmp_path))
    logger_name = "headless_re_mcp._test_stdio_pipe_logger"
    logger = logging.getLogger(logger_name)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    try:
        cli_module._keep_routine_logs_off_the_pipe(logger_name)
        file_handlers = [
            h for h in logger.handlers if isinstance(h, logging.FileHandler)
        ]
        stream_only = [h for h in logger.handlers if type(h) is logging.StreamHandler]
        assert file_handlers, "routine logs must be routed to a file, not the pipe"
        assert file_handlers[0].baseFilename.endswith("mcp-stdio.log")
        assert any(h.level == logging.WARNING for h in stream_only), (
            "warnings must still surface on stderr"
        )
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
