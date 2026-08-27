"""run_web refusal paths, banner output, and the Windows lock branch."""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.web import app as web_app
from headless_re_mcp.web import launch_util


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=0,
    )


def test_a_hostname_that_is_not_an_ip_is_refused(
    settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    """`localhost` resolves to loopback but is not verifiable before bind."""
    code = web_app.run_web(settings, host="localhost", port=0)

    assert code == 2
    assert "不是合法 IP" in capsys.readouterr().out


def test_a_busy_port_without_auto_fallback_is_refused(
    settings: Settings, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(launch_util, "choose_bind_port", lambda *a, **k: (8765, "busy"))

    code = web_app.run_web(settings, port=8765, auto_port=False)

    assert code == 3
    assert "端口已被占用" in capsys.readouterr().out


def test_an_exhausted_port_span_is_refused(
    settings: Settings, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(launch_util, "choose_bind_port", lambda *a, **k: (8765, "exhausted"))

    code = web_app.run_web(settings, port=8765, port_span=4)

    assert code == 3
    assert "端口区间均不可用" in capsys.readouterr().out


def test_a_root_already_claimed_returns_the_config_error_sysexit(
    settings: Settings, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """78 tells a supervisor this is a refusal, not a crash to restart."""
    monkeypatch.setattr(web_app, "_claim_artifact_root", lambda root: None)

    code = web_app.run_web(settings, port=0)

    assert code == 78
    assert "另一个控制台已在使用同一制品目录" in capsys.readouterr().out


def test_the_banner_discloses_the_fallback_port_and_token_location(
    settings: Settings, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    monkeypatch.setattr(launch_util, "choose_bind_port", lambda *a, **k: (18766, "fallback"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)

    code = web_app.run_web(settings, port=18765, quiet_banner=False)

    assert code == 0
    out = capsys.readouterr().out
    assert "端口 18765 已被占用，自动改用 18766" in out
    assert "http://127.0.0.1:18766" in out
    assert "Token 文件" in out
    assert "仅本机回环可访问" in out


def test_the_banner_on_the_preferred_port_does_not_mention_a_fallback(
    settings: Settings, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    monkeypatch.setattr(launch_util, "choose_bind_port", lambda *a, **k: (18765, "preferred"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)

    code = web_app.run_web(settings, port=18765, quiet_banner=False)

    assert code == 0
    out = capsys.readouterr().out
    assert "自动改用" not in out
    assert "http://127.0.0.1:18765" in out


def test_a_startup_crash_still_releases_the_single_instance_lock(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No service exists yet, so only the lock handle needs cleaning up."""

    def refuse(_settings: Settings) -> tuple[str, Path]:
        raise RuntimeError("token store unavailable")

    monkeypatch.setattr(web_app, "ensure_web_token", refuse)

    with pytest.raises(RuntimeError, match="token store unavailable"):
        web_app.run_web(settings, port=0, quiet_banner=True)

    reclaimed = web_app._claim_artifact_root(settings.artifact_root)
    assert reclaimed is not None, "the crash leaked the console lock"
    os.close(reclaimed)


def test_the_windows_lock_uses_msvcrt_and_refuses_a_held_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On nt the claim goes through msvcrt.locking, not fcntl."""
    calls: list[tuple[int, int, int]] = []

    def locking(handle: int, mode: int, nbytes: int) -> None:
        calls.append((handle, mode, nbytes))
        if len(calls) > 1:
            raise OSError("already locked")

    fake_msvcrt = SimpleNamespace(locking=locking, LK_NBLCK=2)
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)
    monkeypatch.setattr(os, "name", "nt")

    first = web_app._claim_artifact_root(tmp_path)
    assert first is not None and first >= 0
    second = web_app._claim_artifact_root(tmp_path)
    monkeypatch.undo()
    os.close(first)

    assert second is None
    assert [call[1:] for call in calls] == [(2, 1), (2, 1)]
