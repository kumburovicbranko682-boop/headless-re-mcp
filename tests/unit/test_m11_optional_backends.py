"""Unit coverage for M11 optional backend invariants (whitelist / kernel gate)."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import DoctorReport, Probe, ProbeStatus


def test_r2_rejects_non_whitelisted_command(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    with pytest.raises(R2Error) as exc:
        client.run(binary, ["!cmd"])
    assert exc.value.code == "invalid_params"


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
            Probe("python", ProbeStatus.READY, "ok"),
            Probe("ida_idalib", ProbeStatus.READY, "ok"),
            Probe("x64dbg_source", ProbeStatus.READY, "ok"),
            Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ok"),
            Probe("native_toolchain", ProbeStatus.READY, "ok"),
            Probe("radare2", ProbeStatus.MISSING, "missing"),
            Probe("ghidra", ProbeStatus.MISSING, "missing"),
            Probe("frida", ProbeStatus.MISSING, "missing"),
            Probe("windbg", ProbeStatus.MISSING, "missing"),
        )
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
