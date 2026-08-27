"""Android repack gate: real apktool decode + rebuild of the committed APK.

apk_decode / apk_repack had only unit coverage (path safety, empty-rebuild
rejection, closed-session guards) -- nothing ran apktool end to end, so a break
in the decode/build adapters or in how the decoded tree is located and rebuilt
would pass CI unseen. This gate decodes the committed APK, checks apktool's own
baksmali really disassembled the fixture's class, then rebuilds a valid APK.

Decode runs with no_resources: the fixture carries a placeholder resources.arsc
(a valid ARSC is a separate hand-built binary format, out of scope), and the
manifest uses only inline attribute values, so full-resource decoding is not
needed to exercise the smali + manifest + rebuild path. apktool is
auto-discovered from PATH by Settings.load(); skip != pass -- the gate skips
only when apktool is not installed.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"


@pytest.mark.integration
def test_android_apktool_decode_and_repack() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    settings = Settings.load()
    if settings.apktool is None:
        pytest.skip("apktool not installed — repack gate not run (skip != pass)")

    service = AnalysisService(settings=settings)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=180.0, no_resources=True)
        assert decoded.ok, decoded.error
        assert decoded.data["smali_dirs"], "apktool produced no smali directory"
        decoded_dir = Path(decoded.data["decoded_dir"])
        assert (decoded_dir / "AndroidManifest.xml").is_file()

        # apktool's own baksmali must have disassembled the fixture's class: the
        # method and the string it returns have to survive DEX -> smali.
        smali_files = list(decoded_dir.rglob("Sample.smali"))
        assert smali_files, "Sample.smali not found in the decoded tree"
        smali = smali_files[0].read_text(encoding="utf-8", errors="replace")
        assert "getSecret" in smali
        assert "flag{headless-re}" in smali

        repacked = service.apk_repack(session_id, timeout=180.0)
        assert repacked.ok, repacked.error
        out_apk = Path(repacked.data["apk"])
        assert out_apk.is_file()
        assert repacked.data["size"] > 0
        assert repacked.data["signed"] is False
        # The rebuild must be a real archive, not an empty/truncated file that
        # happens to exist -- the same contract apk.sign/install depend on.
        assert zipfile.is_zipfile(out_apk)
        with zipfile.ZipFile(out_apk) as archive:
            names = set(archive.namelist())
        assert "AndroidManifest.xml" in names
        assert "classes.dex" in names
    finally:
        service.close_all()
