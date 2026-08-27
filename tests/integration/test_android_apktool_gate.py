"""Live apktool gate: an APK survives a decode -> rebuild round-trip.

This covers the Android repack line's tooling (``apk.decode`` / ``apk.repack``):
apktool baksmali's the DEX and decodes the manifest, then rebuilds an installable
APK from that tree. Both are bounded subprocesses into a per-session artifact
dir with no live coverage, so a break in argv assembly or the session-path guard
would only show up on a real machine. The proof is end to end: the rebuilt APK
is handed back to androguard and must still parse to the same package and
components -- a rebuild that silently corrupted the archive would be caught.

The sign step (``apk.sign``) is deliberately not gated here: apksigner ships
only in the Android SDK build-tools, which is too heavy for a hosted runner, and
that path already has unit coverage (password kept off argv). skip != pass when
apktool (or its JRE) or androguard is absent.
"""

from __future__ import annotations

import importlib.util
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURE_BUILDER = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "apk_fixture.py"


def _load_fixture_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("apk_fixture", _FIXTURE_BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.integration
def test_apktool_decode_then_repack_yields_a_parseable_apk(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    if not ApktoolClient(settings.apktool, settings.apksigner).available:
        pytest.skip("apktool not installed — apktool Gate not run (skip != pass)")
    if not ApkClient().available:
        pytest.skip("androguard not installed — cannot verify rebuilt APK (skip != pass)")
    fx = _load_fixture_builder()
    apk = fx.build_apk(tmp_path / "gate.apk")

    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id)
        assert decoded.ok, decoded.error
        assert decoded.data["smali_dirs"], "apktool produced no smali tree"
        decoded_dir = Path(decoded.data["decoded_dir"])
        assert (decoded_dir / "AndroidManifest.xml").is_file()
        # The DEX must really have been baksmali'd into a per-class file.
        smali = next(decoded_dir.rglob("Gate.smali"), None)
        assert smali is not None, "Gate class was not disassembled to smali"
        assert "leaf" in smali.read_text(encoding="utf-8", errors="replace")

        repacked = service.apk_repack(session_id)
        assert repacked.ok, repacked.error
        rebuilt = Path(repacked.data["apk"])
        assert rebuilt.is_file()
        assert repacked.data["signed"] is False

        # The whole point: androguard must still parse the rebuilt archive and
        # recover the identity apktool was given.
        reopened = ApkClient().open(rebuilt)
        assert reopened["package"] == fx.PACKAGE
        assert reopened["main_activity"] == fx.MAIN_ACTIVITY
        assert reopened["native_abis"] == ["arm64-v8a"]
    finally:
        service.close_all()
