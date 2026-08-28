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
survives the binary-AXML round trip (skip != pass when apktool is absent). A
second gate signs the rebuilt APK with the debug keystore and proves apksigner
accepts the result -- covering the sign path's env-var password handoff.
"""

from __future__ import annotations

import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.gate.repack"
# The client's default when apk.sign is handed no keystore. apk.sign confines a
# *custom* keystore to the session artifact tree (a path-escape guard), so the
# debug default is the only keystore the gate can use without planting a file
# inside the session dir; the gate only reads it, never writes it.
_DEBUG_KEYSTORE = Path.home() / ".android" / "debug.keystore"

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
    settings = Settings.load()
    return ApktoolClient(getattr(settings, "apktool", None), getattr(settings, "apksigner", None))


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


@pytest.mark.integration
def test_apktool_sign_produces_a_verifiable_apk(tmp_path: Path) -> None:
    """apk.sign signs a rebuilt APK with the debug keystore and it verifies.

    The apksigner path had no live coverage: sign's env-var password handoff
    (apksigner reads env:APKSIGNER_KS_PASS, never argv, so the secret stays off
    the world-readable process table), the follow-up apksigner verify the client
    runs before declaring success, and the debug-keystore defaulting all ran
    only against a stubbed subprocess. This builds and repacks a real APK, signs
    it through the service with the default debug keystore, and proves the result
    is genuinely signed -- v1 signature files land in the zip and a fresh,
    independent ``apksigner verify`` accepts it. It needs apktool, apksigner, and
    the standard ~/.android/debug.keystore; any absent, it skips (skip != pass).
    """
    client = _apktool_client()
    if not client.available:
        pytest.skip("apktool not configured — APK sign Gate not run (skip != pass)")
    if not client.signer_available:
        pytest.skip("apksigner not configured — APK sign Gate not run (skip != pass)")
    if not _DEBUG_KEYSTORE.is_file():
        pytest.skip("android debug keystore absent — APK sign Gate not run (skip != pass)")
    seed = _seed_apk(client, tmp_path / "fixture")

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        created = service.create_session(str(seed))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        assert service.apk_decode(session_id, timeout=180.0).ok
        assert service.apk_repack(session_id, timeout=180.0).ok

        # No keystore argument -> the client's debug-keystore default path, which
        # also runs apksigner verify internally before returning ok.
        signed = service.apk_sign(session_id, timeout=180.0)
        assert signed.ok, signed.error
        assert signed.data["signed"] is True
        assert signed.data["debug_keystore"] is True
        out_apk = Path(signed.data["apk"])
        assert out_apk.is_file()

        # Concrete proof it is really signed, independent of the tool's own word:
        # v1 signing writes a <ALIAS>.(RSA|DSA|EC) block and MANIFEST.MF into the
        # zip's META-INF, neither of which the unsigned repack produced.
        with zipfile.ZipFile(out_apk) as archive:
            names = archive.namelist()
        assert any(
            n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in names
        ), names
        assert "META-INF/MANIFEST.MF" in names, names

        # And a fresh apksigner process -- not the one the client already ran --
        # must accept the signature.
        assert client.apksigner is not None
        verify = subprocess.run(
            [str(client.apksigner), "verify", str(out_apk)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert verify.returncode == 0, verify.stderr or verify.stdout
    finally:
        service.close_all()
