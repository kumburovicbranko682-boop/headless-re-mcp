"""The doctor's wabt probe must not claim a half-installed wabt is whole.

wabt is two executables: ``wasm.wat`` runs ``wasm2wat`` and ``wasm.info`` runs
``wasm-objdump``. The probe used to look only for ``wasm2wat``, so a config that
resolved one but not the other read as a plain "wabt detected" while
``wasm.info`` answered ``capability_unavailable`` at call time. These pin that
the probe now resolves both -- the same way the client does -- and says which
half is usable.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as jsre_client
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import ProbeStatus, probe_wabt, run_doctor

_EXE = ".exe" if os.name == "nt" else ""


def _settings(tmp_path: Path, *, wabt: Path | None) -> Settings:
    return replace(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        ),
        wabt=wabt,
    )


def _stub(directory: Path, tool: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / f"{tool}{_EXE}"
    binary.write_bytes(b"")
    return binary


def _no_path_wabt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop PATH from resolving a wabt a CI image happens to ship."""
    monkeypatch.setattr(jsre_client.shutil, "which", lambda _tool: None)


def test_wabt_probe_detected_when_both_binaries_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_path_wabt(monkeypatch)
    bin_dir = tmp_path / "wabt"
    _stub(bin_dir, "wasm2wat")
    _stub(bin_dir, "wasm-objdump")

    probe = probe_wabt(_settings(tmp_path, wabt=bin_dir))

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["wasm2wat"] is not None
    assert probe.details["wasm-objdump"] is not None
    assert "partial" not in probe.details


def test_wabt_probe_is_partial_when_objdump_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """wasm2wat alone used to read as a whole wabt; wasm.info would then fail."""
    _no_path_wabt(monkeypatch)
    bin_dir = tmp_path / "wabt"
    _stub(bin_dir, "wasm2wat")

    probe = probe_wabt(_settings(tmp_path, wabt=bin_dir))

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["partial"] is True
    assert probe.details["wasm2wat"] is not None
    assert probe.details["wasm-objdump"] is None
    assert "wasm.info" in probe.summary
    assert "wasm-objdump" in (probe.remediation or "")


def test_wabt_probe_is_partial_when_wasm2wat_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_path_wabt(monkeypatch)
    bin_dir = tmp_path / "wabt"
    _stub(bin_dir, "wasm-objdump")

    probe = probe_wabt(_settings(tmp_path, wabt=bin_dir))

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["partial"] is True
    assert probe.details["wasm-objdump"] is not None
    assert probe.details["wasm2wat"] is None
    assert "wasm.wat" in probe.summary
    assert "wasm2wat" in (probe.remediation or "")


def test_wabt_probe_missing_when_neither_binary_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_path_wabt(monkeypatch)

    probe = probe_wabt(_settings(tmp_path, wabt=None))

    assert probe.status == ProbeStatus.MISSING
    assert "HEADLESS_RE_WABT" in (probe.remediation or "")


def test_wabt_configured_at_the_wasm2wat_binary_reveals_the_missing_objdump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reachable mistake: HEADLESS_RE_WABT points at the wasm2wat file itself.

    A single-path hint naturally lands on one binary. The old probe took that as
    "wabt configured" and stopped; wasm.info then failed with nothing in the
    doctor to have warned. The probe now resolves wasm-objdump the same way the
    client does and flags the gap.
    """
    _no_path_wabt(monkeypatch)
    wasm2wat = _stub(tmp_path / "bin", "wasm2wat")

    probe = probe_wabt(_settings(tmp_path, wabt=wasm2wat))

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["partial"] is True
    assert probe.details["wasm-objdump"] is None


def test_run_doctor_still_emits_a_probe_named_wabt(tmp_path: Path) -> None:
    """The capability catalog keys wasm.wabt on a probe literally named 'wabt'."""
    report = run_doctor(_settings(tmp_path, wabt=None))
    assert any(probe.name == "wabt" for probe in report.probes)
