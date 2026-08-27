"""Android repack gate: apktool decode + build round-trip through the service.

The apktool adapter had no live coverage -- decode / build, the session
artifact-tree wiring (_repack_dir, _require_session_path), the oversized-tree
guard, and build's empty/invalid-apk detection ran only against a stubbed
subprocess in unit tests. apktool bundles its default AOSP framework and
auto-installs it on first build, so a manifest with no android:-namespaced
attributes compiles with nothing beyond apktool and a JRE -- no Android SDK.
This uses apktool's own build path to compile a minimal text manifest into a
real APK (the fixture, like compiling the ELF fixture with gcc), then drives
the service decode -> repack round-trip on it and proves the package name
survives the binary-AXML round trip (skip != pass when apktool is absent).
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.gate.repack"

# A manifest with zero android:-namespaced attributes: aapt2 resolves android:
# attributes against the framework, and keeping them out means the build needs
# only apktool's bundled default framework, never an external SDK.
_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n'
    "    <application/>\n"
    "</manifest>\n"
)
# The minimal apktool.yml apktool 3.x's own YAML reader accepts. Numeric fields
# would fail Integer.parseInt if quoted, so version info is omitted entirely
# (without it apktool passes no --version-code/--min-sdk-version to aapt2, which
# is what would otherwise inject android: attributes that need the framework).
_APKTOOL_YML = (
    "!!brut.androlib.meta.MetaInfo\n"
    "apkFileName: gate.apk\n"
    "isFrameworkApk: false\n"
    "version: 3.0.3\n"
    "doNotCompress: []\n"
)


def _apktool_client() -> ApktoolClient:
    return ApktoolClient(getattr(Settings.load(), "apktool", None))


def _seed_apk(client: ApktoolClient, work_dir: Path) -> Path:
    """Compile a minimal text manifest into a real APK via apktool build."""
    tree = work_dir / "seed"
    tree.mkdir(parents=True)
    (tree / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (tree / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    apk = work_dir / "seed.apk"
    built = client.build(tree, apk, timeout=180.0)
    # build's own contract: a real, non-empty zip flagged unsigned.
    assert built["signed"] is False
    assert built["size"] > 0
    assert zipfile.is_zipfile(apk)
    return apk


@pytest.mark.integration
def test_apktool_decode_and_repack_round_trip(tmp_path: Path) -> None:
    client = _apktool_client()
    if not client.available:
        pytest.skip("apktool not configured — APK repack Gate not run (skip != pass)")
    seed = _seed_apk(client, tmp_path / "fixture")

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        created = service.create_session(str(seed))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "apk"
        session_id = created.data["session"]["id"]

        # decode: the binary AXML apktool produced must decode back to a text
        # tree with a manifest -- the client's manifest-presence check passing
        # on a real decode, not a stubbed one.
        decoded = service.apk_decode(session_id, timeout=180.0)
        assert decoded.ok, decoded.error
        manifest = Path(decoded.data["manifest"])
        assert manifest.is_file()
        assert _PACKAGE in manifest.read_text(encoding="utf-8")

        # repack: rebuild from that decoded tree back into the session artifact
        # tree. Exercises _require_session_path plus build's empty/invalid guard.
        repacked = service.apk_repack(session_id, timeout=180.0)
        assert repacked.ok, repacked.error
        assert repacked.data["signed"] is False
        out_apk = Path(repacked.data["apk"])
        assert out_apk.is_file()
        assert zipfile.is_zipfile(out_apk)

        # The rebuilt APK must itself decode again with the package intact --
        # proof the round trip produced a genuine binary manifest, not a stub.
        reout = tmp_path / "verify"
        verified = client.decode(out_apk, reout, timeout=180.0)
        assert Path(verified["manifest"]).is_file()
        assert _PACKAGE in (reout / "AndroidManifest.xml").read_text(encoding="utf-8")
    finally:
        service.close_all()
