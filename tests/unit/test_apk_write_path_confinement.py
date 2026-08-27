"""apk.repack / apk.sign must confine caller-supplied paths to the session tree.

_session_owns_artifact_path is exhaustively unit-tested (traversal, symlink
smuggling, cross-session, hostile ids) in test_session_artifact_ownership.py --
but that proves only that the helper is correct, not that the apk write tools
actually route their caller-supplied paths through it. These two are the only
non-PE tools that accept a filesystem path from the caller (decoded_dir for
repack; apk_path and keystore for sign), so a regression that stopped calling
_require_session_path would let an agent read a keystore from /etc or rebuild
from an arbitrary directory, and no test of the helper alone would notice.

The confinement check runs before apktool/apksigner are invoked, so these
assert the rejection with androguard-only fixtures and no JVM backends: the
happy path (a real decode -> repack -> sign inside the tree) is the
android_re integration gate's job. skip is never used -- this is a pure
service-layer guard that runs everywhere.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _apk_session(service: AnalysisService, tmp_path: Path) -> str:
    """A minimal APK-target session; parsing never happens (no backend is hit
    before the path guard), so the archive only has to classify as an apk."""
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


@pytest.mark.parametrize("hostile", ["../../elsewhere", "/etc", "/tmp/outside-the-tree"])
def test_repack_refuses_a_decoded_dir_outside_the_session_tree(
    tmp_path: Path, hostile: str
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        result = service.apk_repack(session_id, decoded_dir=hostile)
        assert not result.ok, hostile
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "decoded_dir" in result.error.message
    finally:
        service.close_all()


@pytest.mark.parametrize("hostile", ["/etc/passwd", "../../x.apk", "/tmp/evil.apk"])
def test_sign_refuses_an_apk_path_outside_the_session_tree(tmp_path: Path, hostile: str) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        result = service.apk_sign(session_id, apk_path=hostile)
        assert not result.ok, hostile
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "apk_path" in result.error.message
    finally:
        service.close_all()


@pytest.mark.parametrize("hostile", ["/etc/keystore", "../../secret.jks"])
def test_sign_refuses_a_keystore_outside_the_session_tree(tmp_path: Path, hostile: str) -> None:
    """A keystore read is the higher-value target: a traversal here would let an
    agent hand any file on the host to apksigner as a signing key."""
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        result = service.apk_sign(session_id, keystore=hostile)
        assert not result.ok, hostile
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "keystore" in result.error.message
    finally:
        service.close_all()
