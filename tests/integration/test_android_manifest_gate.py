"""Live androguard gate: manifest triage over a real APK.

The DEX gate drives androguard's class/method/string/xref surface but builds a
manifest with no permissions and no components, and the RE gate only feeds a
synthetic (invalid) APK. So androguard's manifest-level triage -- the first
questions asked of an unknown app: what does it request, what does it expose,
what native code does it ship -- is never proven end to end. That path parses
the *binary* AndroidManifest (AXML), not the text skeleton, so a regression in
androguard's AXML decode or the ApkClient mapping would silently misreport an
app's permissions and attack surface while the DEX gate stayed green.

This gate assembles a real APK with three requested permissions, one activity /
one service / one receiver, and native libraries in two ABIs (apktool compiles
the android:* attributes against its bundled framework, so no Android SDK is
needed), confirms from the zip that the manifest really compiled to binary AXML,
then asserts ApkClient recovers the permission set exactly, buckets each
component under the correct type (and only that type), and lists both native
libraries with their ABIs.

Skips honestly when apktool (needs a JRE) or androguard is missing. skip != pass.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.config import Settings

_PACKAGE = "com.headlessre.manifestgate"
_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
}
_ACTIVITY = f"{_PACKAGE}.MainActivity"
_SERVICE = f"{_PACKAGE}.SyncService"
_RECEIVER = f"{_PACKAGE}.BootReceiver"
_ABIS = {"arm64-v8a", "x86_64"}

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n'
    '    <uses-permission android:name="android.permission.INTERNET"/>\n'
    '    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>\n'
    '    <uses-permission android:name="android.permission.CAMERA"/>\n'
    '    <application android:label="MG">\n'
    '        <activity android:name=".MainActivity" android:exported="true"/>\n'
    '        <service android:name=".SyncService" android:exported="false"/>\n'
    '        <receiver android:name=".BootReceiver" android:exported="true"/>\n'
    "    </application>\n"
    "</manifest>\n"
)
# usesFramework id 1 links apktool's bundled framework table so aapt2 can resolve
# android:name / android:exported without an installed Android SDK.
_APKTOOL_YML = (
    "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\nusesFramework:\n  ids:\n  - 1\n"
)
_SMALI = """.class public Lcom/headlessre/manifestgate/MainActivity;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
"""
# An AXML document starts with chunk type 0x0003 / header size 0x0008.
_AXML_MAGIC = (0x0003, 0x0008)


def _chunk_magic(blob: bytes) -> tuple[int, int]:
    kind, header_size = struct.unpack_from("<HH", blob, 0)
    return (int(kind), int(header_size))


def _build_manifest_apk(client: ApktoolClient, tmp_path: Path) -> Path:
    skeleton = tmp_path / "skeleton"
    smali_dir = skeleton / "smali" / "com" / "headlessre" / "manifestgate"
    smali_dir.mkdir(parents=True)
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    (smali_dir / "MainActivity.smali").write_text(_SMALI, encoding="utf-8")
    for abi in _ABIS:
        lib_dir = skeleton / "lib" / abi
        lib_dir.mkdir(parents=True)
        (lib_dir / "libgate.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
    out = tmp_path / "out.apk"
    built = client.build(skeleton, out)
    assert Path(built["apk"]).is_file()
    return out


@pytest.mark.integration
def test_android_manifest_permissions_components_and_native_libs(tmp_path: Path) -> None:
    settings = Settings.load()
    apktool = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not apktool.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    apk_client = ApkClient()
    if not apk_client.available:
        pytest.skip("androguard not installed — manifest Gate not run (skip != pass)")

    apk = _build_manifest_apk(apktool, tmp_path)

    # Independent evidence: the manifest androguard will read really is binary
    # AXML, not the text skeleton (read straight from the zip).
    with zipfile.ZipFile(apk) as zf:
        raw_manifest = zf.read("AndroidManifest.xml")
    assert not raw_manifest.startswith(b"<?xml"), "manifest was not compiled to AXML"
    assert _chunk_magic(raw_manifest) == _AXML_MAGIC, raw_manifest[:8].hex()

    # open(): the light metadata path counts permissions and native ABIs.
    opened = apk_client.open(apk)
    assert opened["opened"] is True
    assert opened["package"] == _PACKAGE
    assert opened["permission_count"] == len(_PERMISSIONS)
    assert set(opened["native_abis"]) == _ABIS, opened["native_abis"]

    # permissions(): the exact requested set is recovered from AXML.
    permissions = apk_client.permissions(apk)
    assert set(permissions["permissions"]) == _PERMISSIONS, permissions
    assert set(permissions["requested_permissions"]) == _PERMISSIONS, permissions
    assert permissions["count"] == len(_PERMISSIONS)

    # components(): each declared component is bucketed under its own type, with
    # fully-qualified names resolved from the relative android:name.
    components = apk_client.components(apk)
    activities = set(components["activities"])
    services = set(components["services"])
    receivers = set(components["receivers"])
    assert _ACTIVITY in activities, components
    assert _SERVICE in services, components
    assert _RECEIVER in receivers, components
    assert components["providers"] == [], components
    # Buckets are mutually exclusive: a service is not mis-filed as an activity.
    assert _SERVICE not in activities and _RECEIVER not in activities, components
    assert _ACTIVITY not in services and _ACTIVITY not in receivers, components

    # native_libs(): both bundled libraries are listed under their ABIs.
    native = apk_client.native_libs(apk)
    assert set(native["abis"]) == _ABIS, native
    assert native["count"] == 2, native
    lib_paths = set(native["native_libs"])
    assert {f"lib/{abi}/libgate.so" for abi in _ABIS} == lib_paths, native
