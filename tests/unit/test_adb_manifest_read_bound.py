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


def test_reads_the_package_from_a_compiled_binary_manifest(tmp_path: Path) -> None:
    """A real APK ships a compiled AXML manifest, not the plaintext XML above.

    aapt stores manifest strings in a UTF-16-LE string pool, so the literal
    ``package="..."`` the UTF-8 regex looks for never appears in a shipped APK
    -- the plaintext test is only the source-form case. The load-bearing path
    for ``device.install``'s package readback is the UTF-16-LE fallback, and it
    must clear two hazards a compiled manifest always presents:

      * the binary chunk headers hold bytes (the 0xFFFFFFFF sentinels here)
        that make the UTF-8 decode raise, which must be swallowed so the
        fallback still runs rather than aborting the whole read; and
      * the string pool lists framework strings -- the android namespace URI,
        an ``android.permission.*`` value -- that also look like dotted package
        ids. The ``android.``/``com.android.`` skip is what stops the readback
        naming ``android.permission.INTERNET`` as the installed package; drop
        it and this manifest resolves to the permission, not the real id.

    The member models exactly what the fallback decodes: binary sentinels
    (invalid UTF-8) followed by a UTF-16-LE run of pool strings ordered as aapt
    emits them -- URI and attribute names first, then the ``package`` attribute
    name, an ``android.permission`` value, and finally the real package.
    """
    pool = "\x00".join(
        [
            "manifest",
            "http://schemas.android.com/apk/res/android",
            "versionCode",
            "package",
            "android.permission.INTERNET",
            "com.example.app",
        ]
    )
    manifest = b"\x03\x00\x08\x00" + b"\xff\xff\xff\xff" + pool.encode("utf-16-le")
    apk = tmp_path / "compiled.apk"
    _write_apk(apk, manifest)

    assert _apk_package_name(apk) == "com.example.app"


def test_reads_the_package_from_a_utf8_string_pool(tmp_path: Path) -> None:
    """Modern aapt2 emits a UTF-8 string pool, which the UTF-16 scan misses.

    An AXML string pool is UTF-16-LE on older aapt but UTF-8 on aapt2 (the
    pool's UTF8 flag, default for years) -- so a current APK, the common case,
    stores ``package`` and the id as UTF-8. The readback used to decode only as
    UTF-16-LE, which turns those UTF-8 bytes into CJK-range garbage: the
    ``package`` marker never appears and no dotted id survives, so the scan
    returned None and device.install/uninstall could never verify a modern APK
    (installed/uninstalled came back None, "package name not readable"). The
    android RE gate cross-checks this against androguard on a genuinely valid
    aapt2-shaped AXML; here the same UTF-8 pool is modelled directly, including
    the framework strings (the namespace URI, an android.permission value) the
    android-skip must step over to reach the real id.

    The chunk begins with binary header bytes that make a strict UTF-8 decode
    raise (0xA8 is not a valid start byte), the same hazard the compiled UTF-16
    case presents, so the fallback must decode with errors ignored and still
    recover the id.
    """
    pool_strings = [
        "manifest",
        "http://schemas.android.com/apk/res/android",
        "versionCode",
        "package",
        "android.permission.INTERNET",
        "com.example.app",
    ]
    # A byte that is not a valid UTF-8 start byte, standing in for the binary
    # AXML chunk header a real manifest opens with, then the UTF-8 pool run.
    manifest = b"\x03\x00\x08\x00\xa8\xff" + "\x00".join(pool_strings).encode("utf-8")
    apk = tmp_path / "aapt2.apk"
    _write_apk(apk, manifest)

    assert _apk_package_name(apk) == "com.example.app"


def test_namespace_uri_host_is_not_mistaken_for_the_package(tmp_path: Path) -> None:
    """The AXML namespace URI host must never be returned as the app package.

    Every manifest carries the namespace URI http://schemas.android.com/apk/res/
    android, whose host "schemas.android.com" is a dotted id the package regex
    matches and which is not android./com.android.-prefixed. The scan prefers the
    id within 400 chars of the "package" marker, but aapt2 sorts the string pool,
    so on a real manifest the package value can sit farther than that -- and then
    the whole-manifest fallback would return the URI host. That is worse than
    returning nothing: "schemas.android.com" is not a real package, so the install
    readback's pm-path check finds no such package and reports a successfully
    installed APK as installed=False. Model exactly that layout -- the URI before
    the "package" marker, the real id padded well past the window -- and pin that
    the real package still wins.
    """
    pool = [
        "manifest",
        "http://schemas.android.com/apk/res/android",
        "package",
        *[f"attr_{i}_name" for i in range(80)],
        "com.example.realapp",
    ]
    manifest = b"\x03\x00\x08\x00\xa8\xff" + "\x00".join(pool).encode("utf-8")
    apk = tmp_path / "faraway.apk"
    _write_apk(apk, manifest)

    assert _apk_package_name(apk) == "com.example.realapp"
