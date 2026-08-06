"""M6 Gate-first: real de4dot inspect → deobfuscate → verify.

Uses a user-configured ``HEADLESS_RE_DE4DOT`` and an optional sample path.
Default sample preference (never copied into the repo):

1. ``HEADLESS_RE_DOTNET_GATE_BINARY`` if set
2. ``<de4dot_dir>/bin/Test.Rename.exe`` (ships with many de4dot builds)
3. skip if neither is available

Skip is not a pass.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _de4dot_executable() -> Path:
    configured = os.environ.get("HEADLESS_RE_DE4DOT")
    if not configured:
        pytest.skip("HEADLESS_RE_DE4DOT is not configured")
    path = Path(configured)
    if not path.is_file():
        pytest.skip(f"HEADLESS_RE_DE4DOT does not exist: {path}")
    return path


def _gate_sample(de4dot: Path) -> Path:
    configured = os.environ.get("HEADLESS_RE_DOTNET_GATE_BINARY")
    if configured:
        path = Path(configured)
        if not path.is_file():
            pytest.skip(f"HEADLESS_RE_DOTNET_GATE_BINARY missing: {path}")
        return path
    # de4dotEx flat layout has no Test.Rename; older layouts may ship bin/Test.Rename.exe
    for candidate in (
        de4dot.parent / "bin" / "Test.Rename.exe",
        de4dot.parent / "Test.Rename.exe",
    ):
        if candidate.is_file():
            return candidate
    pytest.skip(
        "no .NET Gate sample: set HEADLESS_RE_DOTNET_GATE_BINARY "
        "or provide a de4dot build with Test.Rename.exe"
    )


def _service_data(result: object) -> dict:
    assert getattr(result, "ok", False), result
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


@pytest.mark.integration
def test_dotnet_m6_inspect_deobfuscate_verify_gate(tmp_path: Path) -> None:
    de4dot = _de4dot_executable()
    sample = _gate_sample(de4dot)
    artifact_root = (tmp_path / "artifacts").resolve()
    input_sha = file_sha256(sample)

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            de4dot=de4dot,
        )
    )

    created = _service_data(service.create_session(str(sample)))
    session_id = str(created["session"]["id"])

    inspected = _service_data(service.dotnet_inspect(session_id, require_verified=True))
    assert inspected["is_dotnet"] is True
    assert inspected["verified_clr"] is True
    assert inspected["claims_universal_unpack"] is False
    assert inspected["kind"] in {"pure_managed", "mixed_mode"}

    deob = _service_data(service.dotnet_deobfuscate(session_id, timeout=180.0))
    assert deob["claims_universal_unpack"] is False
    assert deob["input_unchanged"] is True
    assert file_sha256(sample) == input_sha
    out = Path(str(deob["de4dot"]["output_path"]))
    assert out.is_file()
    assert str(artifact_root) in str(out.resolve())
    assert out.resolve() != sample.resolve()
    assert deob["stats"]["before"] is not None or deob["before"].get("metadata_stats") is not None
    # Prefer structured metadata_stats from inspect reports.
    before_stats = deob["before"].get("metadata_stats") or deob["stats"].get("before")
    after_stats = deob["after"].get("metadata_stats") or deob["stats"].get("after")
    assert isinstance(before_stats, dict)
    assert isinstance(after_stats, dict)
    assert "type_count" in before_stats and "method_count" in before_stats

    verified = _service_data(service.dotnet_verify(session_id, str(out)))
    assert verified["ok"] is True
    assert verified["verify"]["verified_clr"] is True
    assert verified["claims_universal_unpack"] is False


@pytest.mark.integration
def test_dotnet_m6_refuse_unverified_hint(tmp_path: Path) -> None:
    de4dot = _de4dot_executable()
    hint = _PROJECT_ROOT / "fixtures" / "dotnet" / "minimal_clr_hint.exe"
    if not hint.is_file():
        pytest.skip(f"missing hint fixture: {hint}")

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            de4dot=de4dot,
        )
    )
    session_id = _service_data(service.create_session(str(hint)))["session"]["id"]
    inspected = service.dotnet_inspect(session_id, require_verified=True)
    assert not inspected.ok
    assert inspected.error is not None
    assert inspected.error.code == "clr_unverified"

    deob = service.dotnet_deobfuscate(session_id)
    assert not deob.ok
    assert deob.error is not None
    assert deob.error.code == "clr_unverified"


@pytest.mark.integration
def test_dotnet_m6_4_enumerate_il_xrefs(tmp_path: Path) -> None:
    """M6.4: bounded metadata enum / IL / weak xrefs on a real assembly."""
    de4dot = _de4dot_executable()
    sample = _gate_sample(de4dot)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            de4dot=de4dot,
        )
    )
    session_id = _service_data(service.create_session(str(sample)))["session"]["id"]
    types_page = _service_data(service.dotnet_enumerate(session_id, "types", limit=16))
    assert types_page["capability"] == "dotnet_metadata"
    assert types_page["not_ida_idalib"] is True
    assert types_page["claims_universal_unpack"] is False
    assert int(types_page["total"]) >= 1
    methods = _service_data(service.dotnet_enumerate(session_id, "methods", limit=64))
    assert int(methods["total"]) >= 1
    token = next(
        (int(item["token"]) for item in methods["items"] if int(item.get("rva") or 0) > 0),
        None,
    )
    assert token is not None
    il = _service_data(service.dotnet_il(session_id, token))
    assert il["backend"] == "dotnet_metadata"
    assert isinstance(il.get("instructions"), list)
    xrefs = _service_data(service.dotnet_xrefs(session_id, limit=16))
    assert xrefs["kind"] == "xrefs"
    assert xrefs["not_ida_idalib"] is True


@pytest.mark.integration
def test_doctor_marks_configured_de4dot_ready() -> None:
    de4dot = _de4dot_executable()
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=_PROJECT_ROOT / "artifacts" / "_doctor_tmp",
            de4dot=de4dot,
        )
    )
    report = _service_data(service.doctor())
    probes = {item["name"]: item for item in report["probes"]}
    assert probes["de4dot"]["status"] == "ready"
    assert Path(probes["de4dot"]["details"]["executable"]) == de4dot
