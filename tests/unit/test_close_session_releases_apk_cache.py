"""Closing an APK session must drop its cached DEX analysis.

AnalysisService caches androguard's full-APK analysis -- the parse that
apk.methods / apk.xrefs / apk.classes / apk.strings all share -- keyed by
path+mtime. One such analysis is tens to hundreds of megabytes resident, and the
cache is only count-capped, so an unattended run that opens many APKs would sit
on every one of them until eviction rather than the moment its session ended.
close_session releases the cache for that session's binary, best-effort and right
beside the browser/proxy teardown, so the memory goes back when the session that
needed it closes.

Nothing pinned this: it is a bare ``ApkClient.release(session.binary)`` on the
close path that a refactor could drop or misplace, and the leak only shows after
hours of real APK churn -- exactly the class of "survives the night" property the
web/proxy teardown next to it is pinned for. These pin that close drives the
release for an APK session's binary (and only that binary), and does not reach
for it at all on a non-APK session, where there is nothing to release.
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


def _write_minimal_pe(path: Path) -> Path:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)
    return path


def test_close_session_releases_the_apk_dex_cache(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from headless_re_mcp.backends.apk.client import ApkClient

    released: list[Path] = []

    def _spy(path: Path) -> bool:
        released.append(Path(path))
        return True

    # release is a classmethod called as ApkClient.release(binary); a plain
    # function set on the class is invoked with the single path argument.
    monkeypatch.setattr(ApkClient, "release", _spy)

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        binary = service.registry.get(session_id).binary

        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        # Exactly this session's binary was released, once -- the cache the DEX
        # analysis lives under is dropped when the session that filled it ends.
        assert released == [Path(binary)]
    finally:
        service.close_all()


def test_close_session_does_not_release_the_apk_cache_for_a_non_apk_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A PE session has no androguard cache, so close must not reach for it.

    The release is guarded by ``session.target is APK``. Pinning the negative
    keeps a future change from calling release() unconditionally -- harmless in
    effect but a sign the target guard was lost, which is the same guard that
    keeps PE/web closes off the Android code path.
    """
    from headless_re_mcp.backends.apk.client import ApkClient

    released: list[Path] = []
    monkeypatch.setattr(ApkClient, "release", lambda path: released.append(Path(path)))

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = _write_minimal_pe(tmp_path / "sample.exe")
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        assert released == []
    finally:
        service.close_all()
