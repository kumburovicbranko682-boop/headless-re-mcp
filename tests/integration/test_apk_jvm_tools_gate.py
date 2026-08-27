"""APK JVM-tool gate: apktool decode/repack/sign and jadx end to end on Linux.

The apk.* surface splits in two. The androguard half (parsing) is covered by
test_androguard_apk_gate.py; this gate covers the JVM-subprocess half, which had
no test that runs the real tools anywhere. The unit tests all stub run_bounded,
so nothing had ever driven a real apktool decode -> repack, a real apksigner
signature, or a real jadx decompile -- the parts most likely to break against a
new tool version or a fixture quirk (and one did: a resource-table-less APK does
not round-trip through apktool, which this fixture now avoids).

It reuses the committed signed APK (fixtures/android/gate_fixture.apk) and drives
AnalysisService:

  * apk.decode -> apktool d: a smali tree and a decoded manifest land on disk.
  * apk.repack -> apktool b: the decoded tree rebuilds into a valid (unsigned)
    zip, which only works because the fixture carries a resources.arsc so
    apktool records the framework and aapt2 can resolve android:* attributes.
  * apk.sign -> apksigner: the rebuild is signed with the Android debug keystore
    and the output verifies under an independent apksigner invocation.
  * apk.export_sources / apk.decompile -> jadx: the DEX decompiles back to Java
    that names MainActivity and contains getMarker()'s marker string.

Each real-tool test skips with an explicit "skip != pass" when its tool is not
configured (HEADLESS_RE_APKTOOL / _APKSIGNER / _JADX), and the sign test also
skips when the debug keystore is absent. The closed-session guard and the
not-configured degradation test need no tool and always run. Verified against
apktool 3.0.3, apksigner 31.0.2 and jadx 1.5.6 on OpenJDK 21, Linux.
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.backends.jadx import JadxClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "gate_fixture.apk"
_MAIN_CLASS_DOTTED = "com.headlessre.gatefixture.MainActivity"
_MARKER = "headless-re apk gate fixture"
_DEBUG_KEYSTORE = Path.home() / ".android" / "debug.keystore"
_TIMEOUT_S = 600.0


def _settings() -> Settings:
    return Settings.load()


def _apktool() -> ApktoolClient:
    settings = _settings()
    return ApktoolClient(settings.apktool, settings.apksigner)


def _jadx() -> JadxClient:
    return JadxClient(_settings().jadx)


def _skip_without_apktool() -> None:
    if not _apktool().available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL) — Gate not run (skip != pass)")


def _skip_without_apksigner() -> None:
    if not _apktool().signer_available:
        pytest.skip(
            "apksigner not configured (HEADLESS_RE_APKSIGNER) — Gate not run (skip != pass)"
        )


def _skip_without_jadx() -> None:
    if not _jadx().available:
        pytest.skip("jadx not configured (HEADLESS_RE_JADX) — Gate not run (skip != pass)")


def _apk_session(service: AnalysisService) -> str:
    created = service.create_session(str(_APK_FIXTURE))
    assert created.ok, created.error
    assert created.data["session"]["target"] == "apk"
    return str(created.data["session"]["id"])


@pytest.mark.integration
def test_apk_decode_emits_smali_and_manifest() -> None:
    """apktool d turns the APK back into an editable smali + manifest tree."""
    _skip_without_apktool()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        decoded = service.apk_decode(session_id, timeout=_TIMEOUT_S)
        assert decoded.ok, decoded.error
        assert decoded.data["smali_dirs"] == ["smali"]
        assert decoded.data["has_resources"] is True

        decoded_dir = Path(decoded.data["decoded_dir"])
        assert decoded_dir.is_dir()
        manifest = Path(decoded.data["manifest"])
        assert manifest.is_file() and manifest.name == "AndroidManifest.xml"
        # The recovered smali carries the fixture's one class and its marker.
        smali = decoded_dir / "smali" / "com" / "headlessre" / "gatefixture" / "MainActivity.smali"
        assert smali.is_file()
        assert _MARKER in smali.read_text(encoding="utf-8")
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_repack_rebuilds_a_valid_unsigned_zip() -> None:
    """apktool b rebuilds the decoded tree into a real (unsigned) APK.

    This is the round trip the resource-table-less fixture used to fail: with no
    resources.arsc apktool omits the framework and aapt2 cannot resolve the
    manifest. A valid zip out the far side proves the whole decode->build path.
    """
    _skip_without_apktool()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        assert service.apk_decode(session_id, timeout=_TIMEOUT_S).ok

        repacked = service.apk_repack(session_id, timeout=_TIMEOUT_S)
        assert repacked.ok, repacked.error
        assert repacked.data["signed"] is False
        assert "sign" in repacked.data["note"]
        out_apk = Path(repacked.data["apk"])
        assert out_apk.is_file()
        assert repacked.data["size"] == out_apk.stat().st_size > 0
        # A rebuilt APK is a zip that still carries the manifest and the DEX.
        assert zipfile.is_zipfile(out_apk)
        names = set(zipfile.ZipFile(out_apk).namelist())
        assert "AndroidManifest.xml" in names
        assert "classes.dex" in names
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_sign_signs_the_repack_and_verifies() -> None:
    """apk.sign signs the rebuild with the debug keystore; the output verifies.

    apk.sign's default source is the session's repacked.apk, so the chain must
    be decode -> repack -> sign in one session. The service runs apksigner
    verify internally; this test also re-verifies with an independent apksigner
    invocation so a broken signature cannot pass as signed.
    """
    _skip_without_apktool()
    _skip_without_apksigner()
    if not _DEBUG_KEYSTORE.is_file():
        pytest.skip(f"Android debug keystore absent at {_DEBUG_KEYSTORE} — skip != pass")
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        assert service.apk_decode(session_id, timeout=_TIMEOUT_S).ok
        assert service.apk_repack(session_id, timeout=_TIMEOUT_S).ok

        signed = service.apk_sign(session_id, timeout=_TIMEOUT_S)
        assert signed.ok, signed.error
        assert signed.data["signed"] is True
        assert signed.data["debug_keystore"] is True
        signed_apk = Path(signed.data["apk"])
        assert signed_apk.is_file()
        assert signed.data["size"] == signed_apk.stat().st_size > 0
        assert zipfile.is_zipfile(signed_apk)

        apksigner = _settings().apksigner
        assert apksigner is not None
        verify = subprocess.run(
            [str(apksigner), "verify", str(signed_apk)],
            capture_output=True,
            timeout=120,
        )
        assert verify.returncode == 0, verify.stderr.decode("utf-8", "replace")
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_export_sources_decompiles_to_java() -> None:
    """jadx decompiles the whole APK into a Java tree that names the class."""
    _skip_without_jadx()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        exported = service.apk_export_sources(session_id, timeout=_TIMEOUT_S)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        # A clean run, not a partial one: the marker is the whole point.
        assert exported.data.get("tool_failed") in (None, False)
        java_files = exported.data["java_files"]
        assert any("MainActivity.java" in name for name in java_files), java_files
        assert exported.data["sources_dir"] is not None
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_decompile_returns_the_class_source() -> None:
    """apk.decompile returns MainActivity's Java, and refuses an unknown class.

    The recovered source must be the fixture's class, proved by its method and
    the marker string it returns -- not just any non-empty file.
    """
    _skip_without_jadx()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        decompiled = service.apk_decompile(session_id, _MAIN_CLASS_DOTTED, timeout=_TIMEOUT_S)
        assert decompiled.ok, decompiled.error
        assert Path(decompiled.data["path"]).name == "MainActivity.java"
        source = decompiled.data["source"]
        assert "class MainActivity" in source
        assert "getMarker" in source
        assert _MARKER in source
        assert decompiled.data["truncated"] is False

        missing = service.apk_decompile(session_id, "com.does.not.Exist", timeout=_TIMEOUT_S)
        assert not missing.ok
        assert missing.error is not None
        assert missing.error.code == "not_found"
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_jvm_tools_refuse_a_closed_session() -> None:
    """The session-state guard fires before any JVM launches.

    Needs no tool: the refusal comes from the service, so this always runs and
    pins the invalid_request mapping for the decode path.
    """
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        assert service.close_session(session_id).ok

        refused = service.apk_decode(session_id)
        assert not refused.ok
        assert refused.error is not None
        assert refused.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_jvm_tools_degrade_when_unconfigured(tmp_path: Path) -> None:
    """No apktool/apksigner/jadx degrades to capability_unavailable, not a crash.

    Always runs: it pins the tool paths to None, so even a machine with the CLIs
    installed exercises the absent-tool branch and proves the service maps it to
    capability_unavailable rather than raising.
    """
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        apktool=None,
        apksigner=None,
        jadx=None,
        health_check_interval_s=0.0,
    )
    service = AnalysisService(settings)
    try:
        session_id = _apk_session(service)

        decoded = service.apk_decode(session_id)
        assert not decoded.ok
        assert decoded.error is not None
        assert decoded.error.code == "capability_unavailable"

        decompiled = service.apk_decompile(session_id, _MAIN_CLASS_DOTTED)
        assert not decompiled.ok
        assert decompiled.error is not None
        assert decompiled.error.code == "capability_unavailable"
    finally:
        service.close_all()
