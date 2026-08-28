"""run_web's refusal paths, its banner, and the lock cleanup on a failed start.

test_web_launch.py pins the non-loopback refusal and the quiet happy path, and
test_web_single_instance.py pins _claim_artifact_root in isolation. Unexercised
between them: the exit codes an operator's script keys off -- 2 for a host
that is not an IP at all, 3 for a busy port without auto-fallback and for an
exhausted port span, 78 (the sysexits refusal the supervisor stops on) when
another console already holds the artifact root -- plus the fallback banner,
the guarantee that a start that dies before creating its service still
releases the single-instance lock, and the Windows arm of the lock itself.
"""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

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
        http_port=8765,
    )


# --------------------------------------------------------------------------- #
# refusal exit codes: 2 (bad host), 3 (port), 78 (root already claimed)       #
# --------------------------------------------------------------------------- #
def test_a_host_that_is_not_an_ip_is_refused_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """ "localhost" resolves, but the loopback check needs an address literal."""
    code = web_app.run_web(_settings(tmp_path), host="localhost", port=8765)

    assert code == 2
    assert "主机不是合法 IP" in capsys.readouterr().out


def test_a_busy_port_without_auto_fallback_is_refused_with_exit_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "busy"),
    )

    code = web_app.run_web(_settings(tmp_path), port=8765, auto_port=False)

    assert code == 3
    assert "端口已被占用" in capsys.readouterr().out


def test_an_exhausted_port_span_is_refused_with_exit_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "exhausted"),
    )

    code = web_app.run_web(_settings(tmp_path), port=8765, port_span=4)

    assert code == 3
    assert "端口区间均不可用" in capsys.readouterr().out


def test_a_root_held_by_another_console_is_refused_with_exit_78(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """78 is the refusal the supervisor stops on instead of restarting."""
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "preferred"),
    )
    holder = web_app._claim_artifact_root(settings.artifact_root)
    assert holder is not None, "the first console takes the root"
    try:
        code = web_app.run_web(settings, port=8765)
    finally:
        os.close(holder)

    assert code == 78
    assert "另一个控制台已在使用同一制品目录" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# the fallback banner and the lock release on a start that dies early         #
# --------------------------------------------------------------------------- #
def test_the_banner_names_the_fallback_port_and_the_token_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred + 1, "fallback"),
    )
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: None)

    code = web_app.run_web(settings, port=8765, quiet_banner=False)

    out = capsys.readouterr().out
    assert code == 0
    assert "端口 8765 已被占用，自动改用 8766" in out
    assert "监控台已启动：http://127.0.0.1:8766/?token=…" in out
    assert "Token 文件：" in out
    assert "仅本机回环可访问" in out


def test_a_start_that_dies_before_the_service_still_releases_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No service to close, but the claim must not outlive the failed start,
    or the supervisor's restarted child would be refused by its own corpse."""
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.web.launch_util.choose_bind_port",
        lambda host, preferred, *, span, auto: (preferred, "preferred"),
    )

    def broken_token(_settings: Settings) -> tuple[str, Path]:
        raise RuntimeError("token store is unwritable")

    monkeypatch.setattr(web_app, "ensure_web_token", broken_token)

    with pytest.raises(RuntimeError, match="token store"):
        web_app.run_web(settings, port=8765)

    reclaimed = web_app._claim_artifact_root(settings.artifact_root)
    assert reclaimed is not None, "the failed start leaked the single-instance lock"
    os.close(reclaimed)


# --------------------------------------------------------------------------- #
# the Windows arm of the single-instance lock                                 #
# --------------------------------------------------------------------------- #
def test_the_windows_lock_arm_uses_a_non_blocking_msvcrt_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows the claim is msvcrt.locking(LK_NBLCK): non-blocking, so a
    second console is refused immediately rather than queueing behind the
    first. Faked here because the module does not exist off Windows."""
    calls: list[tuple[int, int, int]] = []
    fake_msvcrt = SimpleNamespace(
        LK_NBLCK=2,
        locking=lambda handle, mode, size: calls.append((handle, mode, size)),
    )
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)  # type: ignore[arg-type]
    monkeypatch.setattr(os, "name", "nt")

    handle = web_app._claim_artifact_root(tmp_path)

    assert handle is not None
    try:
        assert calls == [(handle, 2, 1)], "one byte, non-blocking, on the open handle"
    finally:
        os.close(handle)


def test_a_windows_lock_already_held_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def already_locked(handle: int, mode: int, size: int) -> None:
        raise OSError(36, "resource deadlock avoided")

    fake_msvcrt = SimpleNamespace(LK_NBLCK=2, locking=already_locked)
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)  # type: ignore[arg-type]
    monkeypatch.setattr(os, "name", "nt")

    assert web_app._claim_artifact_root(tmp_path) is None
