"""_apk_package_name reads a bounded prefix of AndroidManifest.xml.

device.install reads the package id back from the session's APK to verify the
install. The old ``archive.read(name)[:65536]`` decompressed the whole manifest
member first, so a bomb-compressed AndroidManifest.xml -- a few KiB on disk that
inflates to gigabytes -- would exhaust memory before the slice ran. The read is
now streamed and capped; these tests hold it to that bound while proving the
package id is still parsed.
"""

from __future__ import annotations

import tracemalloc
import zipfile
from pathlib import Path

from headless_re_mcp.backends.adb.client import _MAX_MANIFEST_BYTES, _apk_package_name


def _write_apk(path: Path, manifest: bytes) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)


def test_reads_the_package_from_a_normal_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk(apk, b'<manifest package="com.example.app"> ... </manifest>')
    assert _apk_package_name(apk) == "com.example.app"


def test_a_bomb_compressed_manifest_stays_bounded(tmp_path: Path) -> None:
    """A manifest that inflates far past the cap must not decompress in full."""
    inflated = 32 * 1024 * 1024  # 32 MiB of a single byte compresses to a few KiB
    manifest = b'<manifest package="com.example.bomb">' + b"A" * inflated
    apk = tmp_path / "bomb.apk"
    _write_apk(apk, manifest)
    # On disk the whole thing is tiny; the danger is only realised on read.
    assert apk.stat().st_size < 1 * 1024 * 1024
    # Drop our own copy so tracemalloc measures only what the read allocates.
    del manifest

    tracemalloc.start()
    try:
        package = _apk_package_name(apk)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert package == "com.example.bomb"
    # The old read()[:n] would have allocated the full 32 MiB member; the
    # streamed read keeps peak near the cap plus decode copies.
    assert peak < 8 * 1024 * 1024, f"peak {peak} suggests the whole member inflated"


def test_the_cap_only_sees_the_prefix(tmp_path: Path) -> None:
    """A package attribute past the cap is not read, same as the old slice."""
    padding = b"<x>" + b" " * (_MAX_MANIFEST_BYTES + 4096) + b"</x>"
    manifest = padding + b'<manifest package="com.example.late">'
    apk = tmp_path / "late.apk"
    _write_apk(apk, manifest)
    # Nothing valid in the first cap bytes, so the best-effort read finds none.
    assert _apk_package_name(apk) is None


def test_a_missing_manifest_returns_none(tmp_path: Path) -> None:
    apk = tmp_path / "nomanifest.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("classes.dex", b"not a manifest")
    assert _apk_package_name(apk) is None
