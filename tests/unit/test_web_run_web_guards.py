"""``run_web`` refuses to start on any binding it cannot own outright.

Each of these is a distinct, early exit code the supervisor reads: a non-IP or
non-loopback host, a preferred port that is busy with auto-port off, a whole
span that is busy, and a second console on the same artifact root. None of them
reach ``uvicorn.run``; the ones that do here have it stubbed so the assertion is
about the code path, not a live server.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.web import app as web_app
from headless_re_mcp.web.app import run_web


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )


def test_run_web_refuses_a_host_that_is_not_an_ip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = run_web(_settings(tmp_path), host="not-an-ip", port=8765)
    assert code == 2
    assert "主机不是合法 IP" in capsys.readouterr().out


def test_run_web_refuses_a_busy_preferred_port_without_auto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda *_a, **_k: (8765, "busy"),
    )
    code = run_web(_settings(tmp_path), host="127.0.0.1", port=8765, auto_port=False)
    assert code == 3
    assert "端口已被占用" in capsys.readouterr().out


def test_run_web_reports_an_exhausted_port_span(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda *_a, **_k: (8765, "exhausted"),
    )
    code = run_web(_settings(tmp_path), host="127.0.0.1", port=8765)
    assert code == 3
    assert "端口区间均不可用" in capsys.readouterr().out


def test_run_web_refuses_a_root_a_second_console_already_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda *_a, **_k: (8765, "preferred"),
    )
    monkeypatch.setattr(web_app, "_claim_artifact_root", lambda _root: None)
    code = run_web(_settings(tmp_path), host="127.0.0.1", port=8765)
    assert code == 78
    assert "另一个控制台已在使用同一制品目录" in capsys.readouterr().out


def test_run_web_announces_a_fallback_port_when_not_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The banner path only runs when a port actually changed and quiet is off."""
    import uvicorn

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts", http_port=0)
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda *_a, **_k: (8799, "fallback"),
    )
    ran: list[dict[str, Any]] = []
    monkeypatch.setattr(
        uvicorn, "run", lambda *_a, **kwargs: ran.append(dict(kwargs))
    )

    code = run_web(settings, host="127.0.0.1", port=8765, quiet_banner=False)

    assert code == 0
    assert ran and ran[0]["port"] == 8799
    out = capsys.readouterr().out
    assert "自动改用 8799" in out
    assert "监控台已启动" in out
    # A normal shutdown must release the single-instance lock it took.
    released = web_app._claim_artifact_root(settings.artifact_root)
    assert released is not None
    os.close(released)


def test_run_web_banner_omits_the_fallback_line_on_the_preferred_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Bound to the preferred port, the banner prints but not the change notice."""
    import uvicorn

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts", http_port=0)
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda *_a, **_k: (8765, "preferred"),
    )
    monkeypatch.setattr(uvicorn, "run", lambda *_a, **_k: None)

    code = run_web(settings, host="127.0.0.1", port=8765, quiet_banner=False)

    assert code == 0
    out = capsys.readouterr().out
    assert "监控台已启动" in out
    assert "自动改用" not in out
    released = web_app._claim_artifact_root(settings.artifact_root)
    assert released is not None
    os.close(released)


def test_run_web_releases_the_lock_when_service_construction_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash before the service exists must still free the artifact-root lock.

    The ``finally`` skips ``close_all`` because there is no session to close, but
    the file lock was already taken and would otherwise leak, blocking the very
    restart the supervisor is about to attempt.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts", http_port=0)
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda *_a, **_k: (8765, "preferred"),
    )

    def boom(_settings: Settings) -> Any:
        raise RuntimeError("service refused to start")

    monkeypatch.setattr(web_app, "AnalysisService", boom)

    with pytest.raises(RuntimeError, match="service refused to start"):
        run_web(settings, host="127.0.0.1", port=8765, quiet_banner=True)

    # The lock was released on the way out, so a replacement can take it.
    released = web_app._claim_artifact_root(settings.artifact_root)
    assert released is not None
    os.close(released)
