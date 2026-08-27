"""The subprocess ``_run`` error taxonomy of the JVM-backed backends.

apktool and jadx both launch a JVM through ``run_bounded`` and must translate
its failure modes into structured errors rather than letting a raw exception
escape: an invalid deadline is ``invalid_params``, a blown deadline is
``timeout`` (carrying the pids the launcher had to kill), and a binary that will
not launch is ``backend_error``. jadx's ``_run`` additionally gates on
availability, a missing apk, and -- because jadx exits non-zero on a partial
decompile while still writing usable sources -- only hard-fails when nothing
landed on disk. These paths only ran with a real JVM, so they are pinned here by
driving the launcher through monkeypatch.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.backends.apktool.client as apktool
import headless_re_mcp.backends.jadx.client as jadx
from headless_re_mcp.backends.apktool.client import ApktoolError
from headless_re_mcp.backends.apktool.client import _run as apktool_run
from headless_re_mcp.backends.common.bounded_run import InvalidTimeout, TimedOut
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError


def _raise_invalid_timeout(timeout: float, *, maximum: float) -> float:
    raise InvalidTimeout("timeout must be positive")


def _identity_timeout(timeout: float, *, maximum: float) -> float:
    return timeout


def _make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "x")
    return path


def _jadx_client(tmp_path: Path) -> JadxClient:
    executable = tmp_path / "jadx"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    return JadxClient(executable)


class TestApktoolRun:
    def test_an_invalid_timeout_is_invalid_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(apktool, "clamp_cli_timeout", _raise_invalid_timeout)
        with pytest.raises(ApktoolError) as info:
            apktool_run(["apktool", "d"], timeout=-1)
        assert info.value.code == "invalid_params"

    def test_a_blown_deadline_is_a_timeout_with_killed_pids(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(apktool, "clamp_cli_timeout", _identity_timeout)

        def _times_out(
            cmd: list[str], *, timeout: float, creationflags: int = 0, env: object = None
        ):
            raise TimedOut(timeout, [999])

        monkeypatch.setattr(apktool, "run_bounded", _times_out)
        with pytest.raises(ApktoolError) as info:
            apktool_run(["/usr/bin/apktool", "d"], timeout=5)
        assert info.value.code == "timeout"
        assert info.value.details["killed_pids"] == [999]

    def test_a_launch_failure_is_backend_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(apktool, "clamp_cli_timeout", _identity_timeout)

        def _cannot_launch(
            cmd: list[str], *, timeout: float, creationflags: int = 0, env: object = None
        ):
            raise OSError("no such file")

        monkeypatch.setattr(apktool, "run_bounded", _cannot_launch)
        with pytest.raises(ApktoolError) as info:
            apktool_run(["apktool"], timeout=5)
        assert info.value.code == "backend_error"

    def test_a_clean_run_decodes_the_streams(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(apktool, "clamp_cli_timeout", _identity_timeout)
        monkeypatch.setattr(
            apktool,
            "run_bounded",
            lambda cmd, *, timeout, creationflags=0, env=None: SimpleNamespace(
                stdout=b"out", stderr=b"err", returncode=0
            ),
        )
        assert apktool_run(["apktool"], timeout=5) == ("out", "err", 0)


class TestJadxRun:
    def test_an_invalid_timeout_is_invalid_params(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _jadx_client(tmp_path)
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _raise_invalid_timeout)
        with pytest.raises(JadxError) as info:
            client._run(_make_apk(tmp_path / "a.apk"), [], tmp_path / "out", timeout=-1)
        assert info.value.code == "invalid_params"

    def test_a_missing_executable_is_capability_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = JadxClient(tmp_path / "missing-jadx")
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _identity_timeout)
        with pytest.raises(JadxError) as info:
            client._run(_make_apk(tmp_path / "a.apk"), [], tmp_path / "out", timeout=5)
        assert info.value.code == "capability_unavailable"

    def test_a_missing_apk_is_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _jadx_client(tmp_path)
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _identity_timeout)
        with pytest.raises(JadxError) as info:
            client._run(tmp_path / "nope.apk", [], tmp_path / "out", timeout=5)
        assert info.value.code == "not_found"

    def test_a_blown_deadline_is_a_timeout_with_killed_pids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _jadx_client(tmp_path)
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _identity_timeout)

        def _times_out(cmd: list[str], *, timeout: float, creationflags: int = 0):
            raise TimedOut(timeout, [321])

        monkeypatch.setattr(jadx, "run_bounded", _times_out)
        with pytest.raises(JadxError) as info:
            client._run(_make_apk(tmp_path / "a.apk"), [], tmp_path / "out", timeout=5)
        assert info.value.code == "timeout"
        assert info.value.details["killed_pids"] == [321]

    def test_a_launch_failure_is_backend_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _jadx_client(tmp_path)
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _identity_timeout)

        def _cannot_launch(cmd: list[str], *, timeout: float, creationflags: int = 0):
            raise OSError("no such file")

        monkeypatch.setattr(jadx, "run_bounded", _cannot_launch)
        with pytest.raises(JadxError) as info:
            client._run(_make_apk(tmp_path / "a.apk"), [], tmp_path / "out", timeout=5)
        assert info.value.code == "backend_error"

    def test_a_nonzero_exit_that_still_wrote_sources_is_returned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """jadx choking on some classes while emitting a usable tree is kept, not
        failed -- the exit code rides back for the handler to flag."""
        client = _jadx_client(tmp_path)
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _identity_timeout)
        out = tmp_path / "out"
        out.mkdir()
        (out / "Main.java").write_text("class Main {}", encoding="utf-8")
        monkeypatch.setattr(
            jadx,
            "run_bounded",
            lambda cmd, *, timeout, creationflags=0: SimpleNamespace(
                stdout=b"o", stderr=b"e", returncode=1
            ),
        )
        assert client._run(_make_apk(tmp_path / "a.apk"), [], out, timeout=5) == ("o", "e", 1)

    def test_a_nonzero_exit_with_no_sources_is_backend_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _jadx_client(tmp_path)
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _identity_timeout)
        monkeypatch.setattr(
            jadx,
            "run_bounded",
            lambda cmd, *, timeout, creationflags=0: SimpleNamespace(
                stdout=b"", stderr=b"jadx blew up", returncode=1
            ),
        )
        with pytest.raises(JadxError) as info:
            client._run(_make_apk(tmp_path / "a.apk"), [], tmp_path / "out", timeout=5)
        assert info.value.code == "backend_error"
        assert info.value.details["exit_code"] == 1

    def test_a_clean_run_decodes_the_streams(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _jadx_client(tmp_path)
        monkeypatch.setattr(jadx, "clamp_cli_timeout", _identity_timeout)
        monkeypatch.setattr(
            jadx,
            "run_bounded",
            lambda cmd, *, timeout, creationflags=0: SimpleNamespace(
                stdout=b"ok", stderr=b"", returncode=0
            ),
        )
        assert client._run(_make_apk(tmp_path / "a.apk"), [], tmp_path / "out", timeout=5) == (
            "ok",
            "",
            0,
        )
