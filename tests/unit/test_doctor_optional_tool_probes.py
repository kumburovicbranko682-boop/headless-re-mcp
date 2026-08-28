"""Doctor probes for the optional external CLIs share one honest contract.

de4dot, NETReactorSlayer, XVLKC, VMP dumper and Scylla each report MISSING when
unconfigured, BLOCKED when the configured path is absent or the CLI probe fails,
and READY only when the underlying probe confirms a runnable tool. ``test_doctor``
covers the upx and x64dbg/IDA probes but leaves these five entirely untested;
this pins their three-way verdict (and fills in the two upx branches
``test_doctor`` does not reach). The doctor probes import their CLI probe lazily,
so the underlying seam is patched in its source module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import (
    ProbeStatus,
    probe_de4dot,
    probe_net_reactor_slayer,
    probe_scylla,
    probe_upx,
    probe_vmp_dumper,
    probe_xvlkc,
)

# (doctor probe fn, Settings attr, "module.path.to.underlying_probe", probe name)
_TOOLS = [
    (probe_de4dot, "de4dot", "headless_re_mcp.dotnet.de4dot.probe_de4dot_version", "de4dot"),
    (
        probe_net_reactor_slayer,
        "net_reactor_slayer",
        "headless_re_mcp.dotnet.net_reactor_slayer.probe_net_reactor_slayer",
        "net_reactor_slayer",
    ),
    (probe_xvlkc, "xvlkc", "headless_re_mcp.unpack.xvlkc.probe_xvlkc", "xvlkc"),
    (
        probe_vmp_dumper,
        "vmp_dumper",
        "headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper",
        "vmp_dumper",
    ),
    (probe_scylla, "scylla", "headless_re_mcp.unpack.scylla.probe_scylla", "scylla"),
]

_ProbeFn = Callable[[Settings], Any]


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides) if overrides else base


@pytest.mark.parametrize(
    ("probe_fn", "attr", "_seam", "name"),
    _TOOLS,
    ids=[t[3] for t in _TOOLS],
)
def test_unconfigured_optional_tool_is_missing(
    tmp_path: Path,
    probe_fn: _ProbeFn,
    attr: str,
    _seam: str,
    name: str,
) -> None:
    probe = probe_fn(_settings(tmp_path))
    assert probe.name == name
    assert probe.status == ProbeStatus.MISSING
    assert probe.remediation  # every MISSING probe explains how to configure it


@pytest.mark.parametrize(
    ("probe_fn", "attr", "_seam", "name"),
    _TOOLS,
    ids=[t[3] for t in _TOOLS],
)
def test_configured_but_absent_optional_tool_is_blocked(
    tmp_path: Path,
    probe_fn: _ProbeFn,
    attr: str,
    _seam: str,
    name: str,
) -> None:
    settings = _settings(tmp_path, **{attr: tmp_path / "not_here" / "tool"})
    probe = probe_fn(settings)
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["executable"].endswith("tool")


@pytest.mark.parametrize(
    ("probe_fn", "attr", "seam", "name"),
    _TOOLS,
    ids=[t[3] for t in _TOOLS],
)
def test_a_confirmed_optional_tool_is_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_fn: _ProbeFn,
    attr: str,
    seam: str,
    name: str,
) -> None:
    exe = tmp_path / name
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(seam, lambda executable, **kw: (True, f"{name} v1.2.3 banner"))

    probe = probe_fn(_settings(tmp_path, **{attr: exe}))

    assert probe.status == ProbeStatus.READY
    assert probe.details["executable"] == str(exe)
    assert name in (probe.details["probe_output"] or "")


@pytest.mark.parametrize(
    ("probe_fn", "attr", "seam", "name"),
    _TOOLS,
    ids=[t[3] for t in _TOOLS],
)
def test_a_failing_probe_blocks_the_optional_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_fn: _ProbeFn,
    attr: str,
    seam: str,
    name: str,
) -> None:
    exe = tmp_path / name
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(seam, lambda executable, **kw: (False, ""))

    probe = probe_fn(_settings(tmp_path, **{attr: exe}))

    assert probe.status == ProbeStatus.BLOCKED
    assert probe.remediation


# ---------------------------------------------------------------------------
# upx: fill in the two branches test_doctor does not reach.
# ---------------------------------------------------------------------------


def test_upx_configured_but_absent_is_blocked(tmp_path: Path) -> None:
    settings = _settings(tmp_path, upx=tmp_path / "missing" / "upx")
    probe = probe_upx(settings)
    assert probe.status == ProbeStatus.BLOCKED
    assert probe.details["executable"].endswith("upx")


def test_upx_probe_that_raises_is_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "upx"
    exe.write_text("", encoding="utf-8")

    def boom(command: list[str], *, timeout: float, env: Any = None) -> Any:
        del command, timeout, env
        raise OSError("cannot exec upx")

    monkeypatch.setattr(doctor_module, "_probe_run", boom)
    probe = probe_upx(_settings(tmp_path, upx=exe))
    assert probe.status == ProbeStatus.BLOCKED
    assert "error" in probe.details
