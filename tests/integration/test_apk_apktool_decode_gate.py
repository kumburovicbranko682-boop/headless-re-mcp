"""apktool live gate: real APK decode, not just structured degradation.

Nothing in the suite drives apktool against a real APK -- the Android RE gate
only asserts a structured envelope when apktool is absent. apktool is an external
CLI (bundling aapt2) whose flags and output layout drift across releases (the
runtime-only class of break): ``d -o -f`` / ``-r`` could change, or the decoded
tree could stop containing ``AndroidManifest.xml`` / ``smali*/``, and every
fake-based unit test would still pass.

This gate discovers apktool exactly as ``config.py`` does (``HEADLESS_RE_APKTOOL``
or ``apktool`` on PATH) and drives ``ApktoolClient`` end to end against the
committed real APK, pinning that decode recovers the AXML manifest back to text
(package + declared permission) and disassembles the DEX into smali. Skipped when
apktool is not installed; skip is not pass.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient

_FIXTURE_APK = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "fixture.apk"


def _discover_apktool() -> Path | None:
    # The same resolution order config.py uses to populate settings.apktool.
    candidate = (
        os.environ.get("HEADLESS_RE_APKTOOL")
        or shutil.which("apktool")
        or shutil.which("apktool.bat")
    )
    return Path(candidate) if candidate else None


@pytest.mark.integration
def test_apktool_decodes_a_real_apk(tmp_path: Path) -> None:
    apktool = _discover_apktool()
    if apktool is None or not apktool.is_file():
        pytest.skip("apktool not installed — apktool decode Gate not run (skip != pass)")
    if not _FIXTURE_APK.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_APK}")

    client = ApktoolClient(apktool=apktool)
    assert client.available

    result = client.decode(_FIXTURE_APK, tmp_path / "decoded", timeout=180.0)

    # The AXML manifest must be decoded back to text carrying the real package
    # and permission -- proof apktool parsed the binary manifest, not just copied
    # bytes.
    manifest = Path(result["manifest"])
    assert manifest.is_file()
    manifest_text = manifest.read_text(encoding="utf-8", errors="replace")
    assert "com.example.fixture" in manifest_text
    assert "android.permission.INTERNET" in manifest_text

    # classes.dex must be disassembled into a smali tree with our class.
    assert result["smali_dirs"], "apktool produced no smali output"
    decoded_root = tmp_path / "decoded"
    smali_files = list(decoded_root.rglob("MainActivity.smali"))
    assert smali_files, "MainActivity.smali not found in decoded tree"
    assert "decryptSecret" in smali_files[0].read_text(encoding="utf-8", errors="replace")
