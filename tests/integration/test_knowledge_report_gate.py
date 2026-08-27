"""Knowledge/report gate: the analysis-capstone workflow on a non-PE session.

``knowledge.record`` / ``knowledge.query`` / ``report.generate`` are how an agent
accumulates findings and renders them at the end of *any* analysis, yet the only
integration coverage is in the composite-tools gate, which needs a real IDA +
x64dbg backend and so runs on Windows alone. On Linux CI -- and for every non-PE
target -- this cross-cutting surface was never exercised end to end, leaving room
for a PE-shaped assumption in the report renderer to break Android/Web/ELF
reports unseen.

This drives the whole loop on a synthetic APK session (classification needs no
external tool, so the gate always runs, never skips): it records two kinds of
fact, updates one in place, reads them back filtered and whole, then generates
the report and proves the recorded facts -- including the *updated* value, not
the original -- actually land in the rendered Markdown.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _build_synthetic_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
    return path


@pytest.mark.integration
def test_knowledge_and_report_on_a_non_pe_session(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "apk"
        session_id = created.data["session"]["id"]

        first = service.knowledge_record(
            session_id, "api", "getDeviceId", {"module": "TelephonyManager"}
        )
        assert first.ok, first.error
        assert first.data["replaced"] is False

        recorded = service.knowledge_record(
            session_id, "finding", "hardcoded_key", {"value": "AES_KEY_ALPHA"}
        )
        assert recorded.ok, recorded.error

        # Same kind+key must update in place, not append a duplicate.
        updated = service.knowledge_record(
            session_id, "finding", "hardcoded_key", {"value": "AES_KEY_BRAVO"}
        )
        assert updated.ok, updated.error
        assert updated.data["replaced"] is True

        everything = service.knowledge_query(session_id)
        assert everything.ok, everything.error
        assert everything.data["total"] == 2
        assert everything.data["kinds"] == {"api": 1, "finding": 1}

        findings = service.knowledge_query(session_id, kind="finding")
        assert findings.ok, findings.error
        assert findings.data["total"] == 1

        report = service.report_generate(session_id, title="APK Report Gate")
        assert report.ok, report.error
        assert report.data["findings"] == 2
        path = Path(report.data["path"])
        assert path.is_file()
        markdown = path.read_text(encoding="utf-8")
        assert markdown.startswith("# APK Report Gate")
        # The recorded facts must surface in the rendered report...
        assert "getDeviceId" in markdown
        # ...and specifically the updated value, proving the in-place update flows
        # through to the report rather than the stale original.
        assert "AES_KEY_BRAVO" in markdown
        assert "AES_KEY_ALPHA" not in markdown
    finally:
        service.close_all()
