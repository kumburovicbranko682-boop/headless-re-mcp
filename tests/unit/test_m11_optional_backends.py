"""Unit coverage for M11 optional backend invariants (whitelist / kernel gate)."""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.r2.client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import (
    WINDOWS_REQUIRED_PROBES,
    DoctorReport,
    Probe,
    ProbeStatus,
)


def test_r2_rejects_non_whitelisted_command(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    with pytest.raises(R2Error) as exc:
        client.run(binary, ["!cmd"])
    assert exc.value.code == "invalid_params"


def test_configured_but_missing_r2_falls_back_to_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale HEADLESS_RE_R2 must not hide an r2 that is on PATH.

    __init__ kept any truthy configured path verbatim, so a typo'd or stale
    HEADLESS_RE_R2 left available False and every r2.* call
    capability_unavailable even with r2 on PATH -- while doctor's
    probe_optional_tool and the JsClient/WasmClient resolvers fall back to PATH,
    so doctor reported radare2 detected while the tools reported it missing.
    """
    on_path = tmp_path / "path-r2"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(r2_client, "_discover", lambda: on_path)

    client = R2Client(tmp_path / "missing-r2")

    assert client.available is True
    assert client.executable == on_path


def test_missing_r2_everywhere_reports_capability_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(r2_client, "_discover", lambda: None)
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x7fELF")

    client = R2Client(tmp_path / "missing-r2")

    assert client.available is False
    with pytest.raises(R2Error) as info:
        client.run(binary, ["i"])
    assert info.value.code == "capability_unavailable"


def test_configured_r2_that_exists_is_used(tmp_path: Path) -> None:
    tool = tmp_path / "r2"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")

    client = R2Client(tool)

    assert client.available is True
    assert client.executable == tool


def test_windbg_kernel_requires_explicit_allow(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    denied = WindbgClient(cdb=tmp_path / "cdb.exe", allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        denied.open_dump(dump, ["lm"], kernel=True)
    assert exc.value.code == "permission_denied"

    allowed = WindbgClient(cdb=tmp_path / "cdb.exe", allow_kernel=True)
    with pytest.raises(WindbgError) as missing:
        allowed.open_dump(dump, ["lm"], kernel=True)
    assert missing.value.code == "capability_unavailable"


def test_windbg_rejects_non_whitelisted_command(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client.open_dump(dump, ["!analyze -v"])
    assert exc.value.code == "invalid_params"


def test_settings_exposes_cdb_and_kernel_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.delenv("HEADLESS_RE_WINDBG_ALLOW_KERNEL", raising=False)
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path / "art"))
    settings = Settings.load(config_path=tmp_path / "missing.json")
    assert settings.windbg_allow_kernel is False

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"")
    monkeypatch.setenv("HEADLESS_RE_CDB", str(cdb))
    monkeypatch.setenv("HEADLESS_RE_WINDBG_ALLOW_KERNEL", "1")
    settings2 = Settings.load(config_path=tmp_path / "missing.json")
    assert settings2.cdb is not None
    assert Path(settings2.cdb) == cdb.resolve() or Path(settings2.cdb) == cdb
    assert settings2.windbg_allow_kernel is True


def test_doctor_ready_ignores_optional_backend_missing() -> None:
    report = DoctorReport(
        probes=(
            Probe("platform", ProbeStatus.READY, "ok"),
            Probe("python", ProbeStatus.READY, "ok"),
            Probe("ida_idalib", ProbeStatus.READY, "ok"),
            Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ok"),
            Probe("x64dbg_source", ProbeStatus.MISSING, "missing"),
            Probe("native_toolchain", ProbeStatus.MISSING, "missing"),
            Probe("radare2", ProbeStatus.MISSING, "missing"),
            Probe("ghidra", ProbeStatus.MISSING, "missing"),
            Probe("frida", ProbeStatus.MISSING, "missing"),
            Probe("windbg", ProbeStatus.MISSING, "missing"),
        ),
        required_probes=WINDOWS_REQUIRED_PROBES,
    )
    assert report.ready is True


def test_windbg_live_pid_boundary(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client.attach(111, allowed_pid=222)
    assert exc.value.code == "permission_denied"


def test_windbg_live_rejects_non_whitelisted(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client._run_process(1, ["!analyze -v"], allowed_pid=1, timeout=1.0)
    assert exc.value.code == "invalid_params"


def test_windbg_live_missing_cdb(tmp_path: Path) -> None:
    client = WindbgClient(cdb=tmp_path / "missing-cdb.exe", allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client.attach(1, allowed_pid=1)
    assert exc.value.code == "capability_unavailable"
