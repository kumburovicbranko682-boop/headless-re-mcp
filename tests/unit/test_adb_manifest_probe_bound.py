"""device.install's package probe must not inflate the whole manifest into RAM.

``_apk_package_name`` used ``archive.read("AndroidManifest.xml")[:65536]``,
which materialises the entire member as a bytes object before slicing. A
malicious APK whose manifest entry is a decompression bomb (tiny compressed,
tens of MiB uncompressed) would balloon this probe's memory during
``device.install`` -- the probe runs after the install to report the package
id. The fix streams a bounded prefix via ``open(...).read(n)``. The old and
new code return the same prefix, so the bug is invisible to output alone;
what changes is peak allocation, which is what these tests pin.
"""

from __future__ import annotations

import tracemalloc
import zipfile
from pathlib import Path

from headless_re_mcp.backends.adb.client import _MANIFEST_PROBE_BYTES, _apk_package_name


def _apk_with_manifest(path: Path, manifest: bytes) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    return path


def test_probe_finds_a_package_marker_inside_the_prefix(tmp_path: Path) -> None:
    manifest = b'<manifest package="com.example.app">' + b"A" * (_MANIFEST_PROBE_BYTES * 4)
    apk = _apk_with_manifest(tmp_path / "front.apk", manifest)
    assert _apk_package_name(apk) == "com.example.app"


def test_probe_does_not_inflate_the_whole_manifest_into_ram(tmp_path: Path) -> None:
    """A decompression-bomb-shaped manifest must cost the prefix, not the member.

    The package marker sits in the prefix so the probe still succeeds; the
    16 MiB of highly compressible filler behind it is what a full
    ``archive.read`` would allocate. Peak tracked allocation staying far under
    that size is the proof the read is bounded -- the old code would spike to
    the whole uncompressed length here.
    """
    filler = b"A" * (_MANIFEST_PROBE_BYTES * 256)  # 16 MiB uncompressed
    manifest = b'<manifest package="com.example.app">' + filler
    apk = _apk_with_manifest(tmp_path / "bomb.apk", manifest)

    with zipfile.ZipFile(apk) as archive:
        info = archive.getinfo("AndroidManifest.xml")
    assert info.file_size > _MANIFEST_PROBE_BYTES * 200
    # The bomb shape: it compresses to a tiny fraction of its member size.
    assert info.compress_size < info.file_size // 100

    tracemalloc.start()
    try:
        package = _apk_package_name(apk)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert package == "com.example.app"
    # A full inflate would push peak past the 16 MiB member. 4 MiB leaves ample
    # room for interpreter noise while still failing loudly on an unbounded read.
    assert peak < 4 * 1024 * 1024, peak
