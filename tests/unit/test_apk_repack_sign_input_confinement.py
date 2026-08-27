"""apk.repack / apk.sign must confine caller-supplied paths to the session tree.

``apk.repack`` takes a ``decoded_dir`` and ``apk.sign`` takes an ``apk_path`` and
a ``keystore`` -- all on-disk paths the caller chooses. Left unchecked they would
let a caller point apktool/apksigner at anything on the box: rebuild from an
arbitrary directory, sign an APK outside the workspace, or read a keystore that
is none of the tool's business. The service confines each through
``_require_session_path`` -> ``_session_owns_artifact_path`` and refuses
(``invalid_params``) anything that does not resolve under THIS session's artifact
tree, before apktool or apksigner is ever launched.

``test_session_artifact_ownership.py`` pins the ``_session_owns_artifact_path``
helper in isolation (owned / another session / outside-root / dotted id /
symlink-out). What nothing pinned is that ``apk.repack`` and ``apk.sign`` actually
*call* it on their inputs. That is the same split the frida boundary had: the
predicate was tested, the service wiring that must invoke it was not. Drop the
``_require_session_path`` call -- or resolve the path after handing it to the
tool -- and the isolated helper test keeps passing while apktool/apksigner would
run against an attacker-named path. These tests close that: an outside (or
another session's) path is refused with ``invalid_params`` and the stubbed
tool is never called, so the refusal provably happens before any subprocess.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _TrackingApktool:
    """Records every build/sign so a test can prove the tool was never reached.

    A successful build/sign leaves a real zip behind, matching the client's
    contract, so if a confinement regression *did* let the call through the rest
    of the service path would behave normally -- the test then fails on the
    recorded call, not on some incidental downstream error.
    """

    def __init__(self) -> None:
        self.builds: list[Path] = []
        self.signs: list[tuple[Path, Path | None]] = []

    def build(self, source: Path, out_apk: Path, *, timeout: float = 600.0) -> dict[str, Any]:
        del timeout
        self.builds.append(source)
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out_apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"m")
        return {"apk": str(out_apk), "size": out_apk.stat().st_size, "signed": False}

    def sign(
        self,
        apk: Path,
        out_apk: Path,
        *,
        keystore: Path | None = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        del keystore_password, key_alias, timeout
        self.signs.append((apk, keystore))
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out_apk, "w") as archive:
            archive.writestr("META-INF/CERT.RSA", b"sig")
        return {"apk": str(out_apk), "size": out_apk.stat().st_size, "signed": True}


def _service_with_apk_session(tmp_path: Path) -> tuple[AnalysisService, str, _TrackingApktool]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    tracker = _TrackingApktool()
    service._apktool_client = lambda: tracker  # type: ignore[method-assign]
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], tracker


def test_repack_refuses_a_decoded_dir_outside_the_session_tree(tmp_path: Path) -> None:
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    outside = tmp_path / "outside_decoded"
    outside.mkdir()
    (outside / "AndroidManifest.xml").write_text("manifest", encoding="utf-8")
    try:
        result = service.apk_repack(session_id, decoded_dir=str(outside))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "decoded_dir must be inside the session artifact tree" in result.error.message
        # The refusal must precede apktool: nothing was built from the outside dir.
        assert tracker.builds == []
    finally:
        service.close_all()


def test_repack_refuses_another_sessions_decoded_dir(tmp_path: Path) -> None:
    """"Inside the artifact root" is not enough -- it must be THIS session's tree.

    Point session A's repack at a decoded dir that lives under session B's own
    apktool tree. It is inside artifact_root, so a containment check that forgot
    to scope by session id would allow it; ownership must still refuse it.
    """
    service, session_a, tracker = _service_with_apk_session(tmp_path)
    try:
        apk_b = _write_minimal_apk(tmp_path / "b.apk")
        created_b = service.create_session(str(apk_b), target="apk")
        assert created_b.ok and created_b.data is not None, created_b.error
        session_b = created_b.data["session"]["id"]
        b_decoded = service._repack_dir(session_b) / "decoded"
        b_decoded.mkdir(parents=True, exist_ok=True)
        (b_decoded / "AndroidManifest.xml").write_text("manifest", encoding="utf-8")

        result = service.apk_repack(session_a, decoded_dir=str(b_decoded))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert tracker.builds == []
    finally:
        service.close_all()


def test_sign_refuses_an_apk_path_outside_the_session_tree(tmp_path: Path) -> None:
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    outside_apk = _write_minimal_apk(tmp_path / "outside.apk")
    try:
        result = service.apk_sign(session_id, apk_path=str(outside_apk))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "apk_path must be inside the session artifact tree" in result.error.message
        assert tracker.signs == []
    finally:
        service.close_all()


def test_sign_refuses_a_keystore_outside_the_session_tree(tmp_path: Path) -> None:
    """With a valid in-tree apk_path, the keystore is the path that must be caught.

    apk_path is confined first; giving it a legitimate in-tree value proves the
    refusal here is the keystore check specifically, not the apk_path one, and
    that a caller cannot smuggle an arbitrary keystore past a valid APK argument.
    """
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    inside_apk = service._repack_dir(session_id) / "repacked.apk"
    with zipfile.ZipFile(inside_apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"m")
    outside_keystore = tmp_path / "outside.keystore"
    outside_keystore.write_bytes(b"ks")
    try:
        result = service.apk_sign(
            session_id, apk_path=str(inside_apk), keystore=str(outside_keystore)
        )
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "keystore must be inside the session artifact tree" in result.error.message
        assert tracker.signs == []
    finally:
        service.close_all()
