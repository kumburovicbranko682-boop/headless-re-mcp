"""Android decompile gate: real jadx against the committed APK fixture.

Decompilation is the core Android RE operation, yet apk_export_sources and
apk_decompile had only unit coverage (path safety, partial-failure shaping) --
no test ever ran jadx end to end, so a break in the adapter or in how a class's
source is located and read would pass CI unseen. This gate runs the configured
jadx on the committed one-class APK (fixtures/android/build_minimal_apk.py) and
asserts the decompiled source. jadx is auto-discovered from PATH by
Settings.load(); skip != pass -- it skips only when jadx is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"


@pytest.mark.integration
def test_android_jadx_decompiles_the_fixture() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    settings = Settings.load()
    if settings.jadx is None:
        pytest.skip("jadx not installed — decompile gate not run (skip != pass)")

    service = AnalysisService(settings=settings)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id, timeout=180.0)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        assert any(
            name.endswith("com/example/headless/Sample.java")
            for name in exported.data["java_files"]
        )

        decompiled = service.apk_decompile(
            session_id, "com.example.headless.Sample", timeout=180.0
        )
        assert decompiled.ok, decompiled.error
        source = decompiled.data["source"]
        assert "getSecret" in source
        # The const-string the method returns must survive decompilation: this
        # is the round trip from our hand-built DEX through jadx's output.
        assert "flag{headless-re}" in source
        assert decompiled.data["class_name"] == "com.example.headless.Sample"
    finally:
        service.close_all()
