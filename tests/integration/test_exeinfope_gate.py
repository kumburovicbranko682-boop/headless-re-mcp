"""Live Gate for optional Exeinfo PE second-opinion detect.

Requires ``HEADLESS_RE_EXEINFOPE`` pointing at a user-supplied Exeinfo PE binary.
skip ≠ pass.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeGuiWindowError,
    scan_with_exeinfope,
)
from headless_re_mcp.doctor import ProbeStatus, probe_exeinfope

_REPO = Path(__file__).resolve().parents[2]
_UPX_FIXTURE = _REPO / "fixtures" / "upx" / "console_fixture-x64.upx.exe"


def _resolve_exeinfope() -> Path:
    configured = os.environ.get("HEADLESS_RE_EXEINFOPE")
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()
    pytest.skip("HEADLESS_RE_EXEINFOPE not configured")


@pytest.mark.integration
def test_exeinfope_live_upx_second_opinion(tmp_path: Path) -> None:
    executable = _resolve_exeinfope()
    if not _UPX_FIXTURE.is_file():
        pytest.skip(f"UPX fixture missing: {_UPX_FIXTURE}")

    log_path = tmp_path / "live-exeinfope.log"
    try:
        result = scan_with_exeinfope(
            executable,
            _UPX_FIXTURE,
            log_path=log_path,
            timeout=30.0,
        )
    except ExeinfopeGuiWindowError as exc:
        pytest.fail(f"visible analyzer window during silent scan: {exc.details}")

    assert result.returncode == 0
    assert result.claims_universal_unpack is False
    assert result.findings
    assert any(
        "upx" in finding.summary.casefold() or finding.name.casefold() == "upx"
        for finding in result.findings
    )
    # Main form / modal must not have been visible; invisible Delphi forms may exist.
    assert log_path.is_file()


@pytest.mark.integration
def test_exeinfope_detect_scan_service_live(tmp_path: Path) -> None:
    executable = _resolve_exeinfope()
    if not _UPX_FIXTURE.is_file():
        pytest.skip(f"UPX fixture missing: {_UPX_FIXTURE}")

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        exeinfope=executable,
    )
    service = AnalysisService(settings)
    created = service.create_session(str(_UPX_FIXTURE))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    scanned = service.detect_scan(
        session_id,
        use_die=False,
        use_exeinfope=True,
        timeout=30.0,
    )
    assert scanned.ok and scanned.data is not None
    assert scanned.data["claims_universal_unpack"] is False
    assert scanned.data["exeinfope_enabled"] is True
    report = scanned.data["report"]
    sources = {item["name"]: item for item in report["sources"]}
    assert sources["exeinfope"]["status"] == "completed"
    assert any(item["source"] == "exeinfope" for item in report["findings"])
    assert any("upx" in item["summary"].casefold() for item in report["findings"])


@pytest.mark.integration
def test_exeinfope_doctor_live(tmp_path: Path) -> None:
    executable = _resolve_exeinfope()
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        exeinfope=executable,
    )
    probe = probe_exeinfope(settings)
    assert probe.status == ProbeStatus.READY
    assert probe.details.get("claims_universal_unpack") is False
