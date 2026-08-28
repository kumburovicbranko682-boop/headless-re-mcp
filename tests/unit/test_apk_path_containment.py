"""Service-level path containment for apk.repack / apk.sign.

apktool and apksigner act on caller-supplied paths -- ``decoded_dir`` for the
rebuild, ``apk_path`` and ``keystore`` for the signing. Without a containment
check the model could point them anywhere on disk: sign an arbitrary file, read
a keystore from outside the workspace, or rebuild from another session's tree.
The service routes every such path through ``_require_session_path``, so a path
outside *this* session's artifact tree is refused as ``invalid_params`` (naming
the field) before the tool is ever built, while a legitimate in-tree path is
accepted and the tool runs.

The client payload/scrub/verify contracts are covered elsewhere
(test_apk_sign_fields.py); the closed-session and mid-run guards in
test_apk_repack_closed_session.py / test_apk_sign_closed_session.py. This pins
the containment boundary itself -- the security decision -- at the service
layer, device-free: a stub apktool proves whether the tool was reached, so no
real apktool/apksigner is needed.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _TrackingApktool:
    """Records whether the service ever reached the tool for a given path."""

    def __init__(self) -> None:
        self.builds: list[Path] = []
        self.signs: list[Path] = []

    def build(self, source: Path, out_apk: Path, *, timeout: float = 600.0) -> dict[str, Any]:
        del timeout
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PK")
        self.builds.append(Path(source))
        return {"apk": str(out_apk), "size": 2, "signed": False, "note": "unsigned"}

    def sign(
        self,
        source: Path,
        out_apk: Path,
        *,
        keystore: Path | None = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        del keystore, keystore_password, key_alias, timeout
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PKSIGN")
        self.signs.append(Path(source))
        return {"apk": str(out_apk), "size": 6, "signed": True, "debug_keystore": True}


def _service_with_apk_session(tmp_path: Path) -> tuple[AnalysisService, str, _TrackingApktool]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    tracker = _TrackingApktool()
    service._apktool_client = lambda: tracker  # type: ignore[method-assign]
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    return service, session_id, tracker


def _apktool_tree(service: AnalysisService, session_id: str) -> Path:
    return service.settings.artifact_root.expanduser().resolve() / "apktool" / session_id


def _artifact_tree(root: Path) -> set[str]:
    if not root.exists():
        return set()
    return {str(path.relative_to(root)) for path in root.rglob("*")}


def test_apk_path_builders_refuse_traversal_shaped_session_ids(tmp_path: Path) -> None:
    """The path builders must be self-guarding, not lean on a prior registry.get.

    apk.decode/decompile/repack/sign all call registry.get(session_id) at the
    top of the public method, so a "." or ".." fails as session_not_found before
    ever reaching these builders today. But each builder turns the id into a
    filesystem path -- and _repack_dir mkdir()s it and hands it back as the
    containment base that repack/sign then trust -- so a bare ".." collapsing
    "<cat>"/".." to the artifact root would let one caller own every session's
    tree if that call ordering ever changed. Pin the builders directly: every
    path-escape shape is refused as invalid_params before any mkdir, and the
    artifact root is left untouched. A plain id still builds an in-tree path, so
    this is a shape gate, not a blanket refusal.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    root = settings.artifact_root.expanduser().resolve()
    hostile_ids = ["", ".", "..", "../../etc", "a/b", "apktool/../../secret", "/etc/passwd"]
    try:
        baseline = _artifact_tree(root)
        for session_id in hostile_ids:
            for builder in (service._jadx_out_dir, service._repack_dir):
                with pytest.raises(ApkError) as caught:
                    builder(session_id)
                assert caught.value.code == "invalid_params", (session_id, builder.__name__)
                assert "session id" in caught.value.message, (session_id, builder.__name__)
        assert _artifact_tree(root) == baseline
        assert not (tmp_path / "etc").exists()
        assert not (root.parent / "secret").exists()

        good = uuid4().hex
        assert service._jadx_out_dir(good) == root / "jadx" / good
        assert service._repack_dir(good) == root / "apktool" / good
    finally:
        service.close_all()


def test_apk_repack_refuses_a_decoded_dir_outside_the_session_tree(tmp_path: Path) -> None:
    """A decoded_dir anywhere off the session tree is refused before apktool runs.

    Both an absolute path outside artifact_root entirely and a path under a
    *different* session's apktool tree must be rejected as invalid_params naming
    the field, and the rebuild must never start.
    """
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    other_session = uuid4().hex
    outside_root = service.settings.artifact_root.expanduser().resolve()
    off_tree = tmp_path / "elsewhere" / "decoded"
    cross_session = outside_root / "apktool" / other_session / "decoded"
    try:
        for decoded_dir in (str(off_tree), str(cross_session)):
            result = service.apk_repack(session_id, decoded_dir=decoded_dir)
            assert result.ok is False, decoded_dir
            assert result.error is not None
            assert result.error.code == "invalid_params", result.error
            assert "decoded_dir" in result.error.message
            assert "inside the session artifact tree" in result.error.message
        assert tracker.builds == []
    finally:
        service.close_all()


def test_apk_repack_accepts_a_decoded_dir_inside_the_session_tree(tmp_path: Path) -> None:
    """The boundary is containment, not a blanket refusal: an in-tree dir runs.

    Proves the negative tests above reject because the path is out of tree, not
    because apk.repack refuses every explicit decoded_dir.
    """
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    in_tree = _apktool_tree(service, session_id) / "decoded"
    in_tree.mkdir(parents=True, exist_ok=True)
    (in_tree / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    try:
        result = service.apk_repack(session_id, decoded_dir=str(in_tree))
        assert result.ok and result.data is not None, result.error
        assert len(tracker.builds) == 1
        assert tracker.builds[0] == in_tree.expanduser().resolve()
    finally:
        service.close_all()


def test_apk_sign_refuses_an_apk_path_outside_the_session_tree(tmp_path: Path) -> None:
    """apk.sign will not sign a file the session does not own."""
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    off_tree = tmp_path / "victim.apk"
    off_tree.write_bytes(b"PK")
    try:
        result = service.apk_sign(session_id, apk_path=str(off_tree))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params", result.error
        assert "apk_path" in result.error.message
        assert "inside the session artifact tree" in result.error.message
        assert tracker.signs == []
    finally:
        service.close_all()


def test_apk_sign_refuses_a_keystore_outside_the_session_tree(tmp_path: Path) -> None:
    """A keystore path is caller-supplied too, so it gets the same boundary.

    The apk_path is left default (in-tree), so the only thing that can fail is
    the out-of-tree keystore -- proving the keystore is gated independently.
    """
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    off_tree_keystore = tmp_path / "secrets" / "release.keystore"
    off_tree_keystore.parent.mkdir(parents=True, exist_ok=True)
    off_tree_keystore.write_bytes(b"ks")
    # apk_path default resolves to <tree>/repacked.apk; create it so only the
    # keystore containment can be the cause of the refusal.
    tree = _apktool_tree(service, session_id)
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "repacked.apk").write_bytes(b"PK")
    try:
        result = service.apk_sign(session_id, keystore=str(off_tree_keystore))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params", result.error
        assert "keystore" in result.error.message
        assert "inside the session artifact tree" in result.error.message
        assert tracker.signs == []
    finally:
        service.close_all()


def test_apk_sign_accepts_in_tree_apk_and_keystore(tmp_path: Path) -> None:
    """An in-tree apk_path and keystore are accepted and apksigner is reached."""
    service, session_id, tracker = _service_with_apk_session(tmp_path)
    tree = _apktool_tree(service, session_id)
    tree.mkdir(parents=True, exist_ok=True)
    apk_in_tree = tree / "repacked.apk"
    apk_in_tree.write_bytes(b"PK")
    keystore_in_tree = tree / "debug.keystore"
    keystore_in_tree.write_bytes(b"ks")
    try:
        result = service.apk_sign(
            session_id,
            apk_path=str(apk_in_tree),
            keystore=str(keystore_in_tree),
            keystore_password="android",
            key_alias="androiddebugkey",
        )
        assert result.ok and result.data is not None, result.error
        assert len(tracker.signs) == 1
        assert tracker.signs[0] == apk_in_tree.expanduser().resolve()
    finally:
        service.close_all()
