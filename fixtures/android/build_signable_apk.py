"""Build a minimal, real APK that apksigner will sign, for the sign live gate.

The sign gate needs an APK apksigner will actually accept, and apksigner refuses
to sign a package whose ``minSdkVersion`` it cannot read: it parses the *binary*
``AndroidManifest.xml`` for that field before signing anything. A placeholder
(non-AXML) manifest -- fine for jadx or an ``apktool d -r`` -- fails here with
``Failed to determine APK's minimum supported platform version``. So this
fixture emits a genuine binary AXML manifest via ``pyaxml`` declaring
``minSdkVersion``; that (in a zip) is the whole APK, because apksigner signs a
zip and needs no ``classes.dex`` or resources to do it.

``pyaxml`` (and ``lxml``) are the only non-stdlib requirement, so a machine
without them cannot build the fixture and the gate skips rather than pretends to
pass. Nothing is committed: the gate builds these bytes in a temp dir.

Regenerate the standalone APK with ``python fixtures/android/build_signable_apk.py``;
it prints the path and byte size.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

PACKAGE = "com.example.signable"
MIN_SDK = 21
# The smallest manifest apksigner is happy with: a package and a readable
# minSdkVersion. A trivial <application> keeps it recognisable as a real app.
MANIFEST_XML = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{PACKAGE}"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="{MIN_SDK}" android:targetSdkVersion="33"/>
    <application android:label="SignableApp"/>
</manifest>
"""


def build_manifest() -> bytes:
    """Pack the manifest XML into binary AXML apksigner can parse."""
    import pyaxml
    from lxml import etree

    root = etree.fromstring(MANIFEST_XML.encode("utf-8"))
    axml = pyaxml.AXML()
    axml.from_xml(root)
    return bytes(axml.pack())


def _add(archive: zipfile.ZipFile, name: str, payload: bytes) -> None:
    # A fixed timestamp keeps the archive byte-for-byte reproducible so a
    # regeneration never shows a spurious diff.
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, payload)


def build_apk(out_path: Path) -> Path:
    """Write a single binary AXML manifest into an APK zip apksigner will sign."""
    manifest = build_manifest()
    with zipfile.ZipFile(out_path, "w") as archive:
        _add(archive, "AndroidManifest.xml", manifest)
    return out_path


if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "signable.apk"
    build_apk(target)
    print(f"wrote {target} ({target.stat().st_size} bytes)")
