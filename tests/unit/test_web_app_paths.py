"""run_web refusal exits, banner output and the Windows lock branch."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.web.launch_util as launch_util
from headless_re_mcp.config import Settings
from headless_re_mcp.web import app as web_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=0,
    )


def test_windows_locking_claims_via_msvcrt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    locked: list[tuple[int, int, int]] = []
    fake_msvcrt = SimpleNamespace(
        LK_NBLCK=2,
        locking=lambda handle, mode, size: locked.append((handle, mode, size)),
    )
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)
    monkeypatch.setattr(web_app.os, "name", "nt")

    handle = web_app._claim_artifact_root(tmp_path / "artifacts")

    assert handle is not None
    assert locked == [(handle, 2, 1)]
    web_app.os.close(handle)


def test_run_web_refuses_a_host_that_is_not_an_ip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = web_app.run_web(_settings(tmp_path), host="localhost", port=8765)

    assert code == 2
    assert "不是合法 IP" in capsys.readouterr().out


def test_run_web_refuses_a_busy_port_without_auto_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        launch_util, "choose_bind_port", lambda host, port, span, auto: (port, "busy")
    )

    code = web_app.run_web(_settings(tmp_path), port=8765, auto_port=False)

    assert code == 3
    assert "端口已被占用" in capsys.readouterr().out


def test_run_web_reports_an_exhausted_port_span(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        launch_util,
        "choose_bind_port",
        lambda host, port, span, auto: (port, "exhausted"),
    )

    code = web_app.run_web(_settings(tmp_path), port=8765, port_span=4)

    assert code == 3
    assert "端口区间均不可用" in capsys.readouterr().out


def test_run_web_refuses_an_artifact_root_another_console_holds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(web_app, "_claim_artifact_root", lambda root: None)

    code = web_app.run_web(_settings(tmp_path), port=8765)

    assert code == 78
    assert "另一个控制台" in capsys.readouterr().out


def test_run_web_banner_names_the_fallback_port_and_token_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import uvicorn

    monkeypatch.setattr(
        launch_util,
        "choose_bind_port",
        lambda host, port, span, auto: (18777, "fallback"),
    )
    monkeypatch.setattr(
        web_app,
        "ensure_web_token",
        lambda settings: ("token-value", tmp_path / "web_token.json"),
    )
    served: list[dict[str, Any]] = []
    monkeypatch.setattr(
        uvicorn, "run", lambda app, **kwargs: served.append(kwargs)
    )

    code = web_app.run_web(_settings(tmp_path), port=8765, quiet_banner=False)

    out = capsys.readouterr().out
    assert code == 0
    assert served == [{"host": "127.0.0.1", "port": 18777, "log_level": "warning"}]
    assert "自动改用 18777" in out
    assert "监控台已启动" in out
    assert str(tmp_path / "web_token.json") in out
    assert "仅本机回环可访问" in out


def test_run_web_banner_on_the_preferred_port_has_no_fallback_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import uvicorn

    monkeypatch.setattr(
        launch_util,
        "choose_bind_port",
        lambda host, port, span, auto: (port, "preferred"),
    )
    monkeypatch.setattr(
        web_app,
        "ensure_web_token",
        lambda settings: ("token-value", tmp_path / "web_token.json"),
    )
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: None)

    code = web_app.run_web(_settings(tmp_path), port=8765, quiet_banner=False)

    out = capsys.readouterr().out
    assert code == 0
    assert "自动改用" not in out
    assert "监控台已启动" in out


def test_run_web_releases_the_lock_when_startup_fails_before_the_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_telemetry() -> None:
        raise RuntimeError("telemetry exploded")

    monkeypatch.setattr(web_app, "configure_telemetry_logging", broken_telemetry)
    settings = _settings(tmp_path)

    with pytest.raises(RuntimeError, match="telemetry exploded"):
        web_app.run_web(settings, port=8765, quiet_banner=True)

    reclaimed = web_app._claim_artifact_root(settings.artifact_root)
    assert reclaimed is not None, "a failed start must release the console lock"
    web_app.os.close(reclaimed)
