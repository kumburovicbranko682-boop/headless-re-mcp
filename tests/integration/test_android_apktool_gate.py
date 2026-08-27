"""Android apktool gate: proof that apktool disassembles and rebuilds an APK.

apktool (``apk.decode`` / ``apk.repack``) had no live coverage here -- the
Android RE gate only ever asked it to degrade cleanly. This gate closes that hole
with no Android SDK: it reuses the hand-encoded, valid ``classes.dex`` the
androguard static gate builds and drives the real service surface, asserting the
*disassembled smali* and a genuinely rebuilt archive, not merely that a call
returned:

  * ``apk.decode`` (``--no-res``, since the fixture's ``resources.arsc`` is a
    placeholder) writes a ``smali/`` tree whose ``Gate.smali`` carries the class,
    both methods, the ``const-string`` marker apktool preserves verbatim, and the
    ``invoke-static`` call edge from ``gateCaller`` to ``gateSecret`` -- proof
    apktool baksmali'd the DEX rather than that files appeared;
  * ``apk.repack`` rebuilds a valid (unsigned) zip APK from that tree that still
    contains ``classes.dex``.

skip != pass: with apktool (a JRE plus the apktool CLI) absent the gate skips
loudly.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

import pytest
from test_android_static_gate import (
    _DEX_CALLER,
    _DEX_CLASS,
    _DEX_METHOD,
    _DEX_STRING,
    _build_valid_apk,
)

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _apktool_executable() -> Path | None:
    """Resolve apktool the way config does: env override, then PATH."""
    env = os.environ.get("HEADLESS_RE_APKTOOL")
    if env and Path(env).is_file():
        return Path(env)
    found = shutil.which("apktool") or shutil.which("apktool.bat")
    return Path(found) if found else None


def _service(tmp_path: Path, apktool: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        apktool=apktool,
    )
    return AnalysisService(settings)


@pytest.mark.integration
def test_apktool_decodes_the_dex_to_smali_and_rebuilds(tmp_path: Path) -> None:
    apktool = _apktool_executable()
    if apktool is None:
        pytest.skip("apktool not installed — Android apktool Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "gate.apk")
    assert classify_target(apk) is TargetKind.APK

    service = _service(tmp_path, apktool)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        # --no-res: the fixture's resources.arsc is a placeholder, and the smali
        # round trip is what this gate proves, not resource decoding.
        decoded = service.apk_decode(session_id, no_resources=True)
        assert decoded.ok, decoded.error
        data = decoded.data
        assert data["manifest"] is not None
        assert "smali" in data["smali_dirs"], data["smali_dirs"]

        smali = Path(data["decoded_dir"]) / "smali" / "com" / "gate" / "sample" / "Gate.smali"
        assert smali.is_file(), f"expected {smali} to exist"
        text = smali.read_text()
        assert _DEX_CLASS in text
        assert f"{_DEX_METHOD}()V" in text
        assert f"{_DEX_CALLER}()V" in text
        # apktool preserves the string constant jadx elides as dead code ...
        assert f'const-string v0, "{_DEX_STRING}"' in text
        # ... and the invoke-static call edge from gateCaller to gateSecret.
        assert f"invoke-static {{}}, {_DEX_CLASS}->{_DEX_METHOD}()V" in text

        repacked = service.apk_repack(session_id)
        assert repacked.ok, repacked.error
        rebuilt = Path(repacked.data["apk"])
        assert rebuilt.is_file()
        assert repacked.data["size"] > 0
        assert repacked.data["signed"] is False
        assert zipfile.is_zipfile(rebuilt)
        with zipfile.ZipFile(rebuilt) as archive:
            assert "classes.dex" in archive.namelist()
    finally:
        service.close_all()


@pytest.mark.integration
def test_apktool_repack_without_a_decode_is_a_clean_error(tmp_path: Path) -> None:
    """Repack before any decode must be a structured error, not a crash."""
    apktool = _apktool_executable()
    if apktool is None:
        pytest.skip("apktool not installed — Android apktool Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "gate.apk")
    service = _service(tmp_path, apktool)
    try:
        created = service.create_session(str(apk))
        session_id = created.data["session"]["id"]
        repacked = service.apk_repack(session_id)
        assert repacked.ok is False
        assert repacked.error is not None
        assert repacked.error.code in {"not_found", "invalid_params"}
    finally:
        service.close_all()
