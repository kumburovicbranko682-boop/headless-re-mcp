"""The idalib runtime probe must not embed unbounded output in its details.

``_probe_run`` caps each stream at ``run_bounded``'s 8 MiB ceiling, so a broken
or hostile ``idapro`` package that floods stdout/stderr used to push megabytes
straight into the probe details -- and from there into every doctor report
rendered by the CLI, the web setup page and the MCP tool. Every other probe in
``doctor.py`` bounds what it stores; this locks the idalib probe to the same
``_bounded_text`` convention while keeping the readiness decision on the raw
output, so truncation never flips a READY verdict.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import ProbeStatus, probe_ida

_FLOOD = 300_000


def _idalib_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Fake a complete IDA install so probe_ida reaches the runtime probe."""

    monkeypatch.setattr(doctor_module, "find_idalib_library", lambda _home: tmp_path / "libida.so")
    monkeypatch.setattr(doctor_module, "find_ida_executable", lambda _home: tmp_path / "ida")
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str, *args: object, **kwargs: object) -> object:
        if name == "idapro":
            return SimpleNamespace(origin=str(tmp_path / "idapro" / "__init__.py"))
        return real_find_spec(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    return Settings(
        ida_home=tmp_path,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _patch_probe_run(
    monkeypatch: pytest.MonkeyPatch, *, returncode: int, stdout: str, stderr: str
) -> None:
    def fake_run(
        command: list[str], *, timeout: float, env: object = None
    ) -> doctor_module._ProbeOutput:
        del command, timeout, env
        return doctor_module._ProbeOutput(returncode, stdout, stderr)

    monkeypatch.setattr(doctor_module, "_probe_run", fake_run)


def _assert_bounded(value: str) -> None:
    assert len(value) < 8192
    assert value.endswith("...[truncated]")


def test_ready_verdict_survives_flooded_output_with_bounded_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _idalib_environment(tmp_path, monkeypatch)
    _patch_probe_run(
        monkeypatch,
        returncode=0,
        stdout=("x" * _FLOOD) + "\nTrue",
        stderr="w" * _FLOOD,
    )

    probe = probe_ida(settings)

    assert probe.status is ProbeStatus.READY
    _assert_bounded(probe.details["probe_stdout"])
    _assert_bounded(probe.details["probe_stderr"])


def test_blocked_probe_stores_bounded_failure_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _idalib_environment(tmp_path, monkeypatch)
    _patch_probe_run(
        monkeypatch,
        returncode=1,
        stdout="",
        stderr="Traceback: " + "e" * _FLOOD,
    )

    probe = probe_ida(settings)

    assert probe.status is ProbeStatus.BLOCKED
    assert probe.details["probe_exit_code"] == 1
    assert probe.details["probe_stdout"] == ""
    _assert_bounded(probe.details["probe_stderr"])


def test_normal_output_is_stored_verbatim_after_strip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _idalib_environment(tmp_path, monkeypatch)
    _patch_probe_run(
        monkeypatch,
        returncode=0,
        stdout="/opt/ida/idapro/__init__.py\nTrue\n",
        stderr="",
    )

    probe = probe_ida(settings)

    assert probe.status is ProbeStatus.READY
    assert probe.details["probe_stdout"] == "/opt/ida/idapro/__init__.py\nTrue"
    assert probe.details["probe_stderr"] == ""
