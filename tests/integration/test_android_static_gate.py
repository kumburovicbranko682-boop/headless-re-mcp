"""Android static gate: proof that androguard decodes a real binary manifest.

The existing Android gate builds a *synthetic* APK whose ``AndroidManifest.xml``
is not valid AXML, so it can only assert that androguard degrades cleanly on
garbage -- ``apk.open`` returns an envelope rather than crashing. That leaves the
thing the Android static line exists for unproven: that androguard actually
parses a compiled Android manifest and reports the package, version, SDK levels,
declared permissions and launcher activity a real APK carries.

This gate closes that hole without an Android SDK. It hand-encodes a valid
binary ``AndroidManifest.xml`` (the AOSP ``ResXMLTree`` chunk format: an XML
resource header, a UTF-16 string pool, a resource-map that binds the framework
attribute names to their resource IDs, and the namespace/element/attribute
chunks) and zips it into an APK with two native ABIs. Then it drives the real
tool surface (``apk.open`` / ``apk.manifest`` / ``apk.permissions`` /
``apk.components`` / ``apk.native_libs``) and asserts the decoded values, not
merely that a call returned. The DEX-analysis tools (classes/methods/strings)
need a real ``classes.dex`` and are out of scope here.

skip != pass: with androguard absent the gate skips loudly.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

# The one source of truth the fixture is built from and the gate asserts against.
_PACKAGE = "com.gate.sample"
_VERSION_NAME = "1.2.3"
_VERSION_CODE = 7
_MIN_SDK = 21
_TARGET_SDK = 33
_PERMISSION = "android.permission.INTERNET"
_ACTIVITY = "com.gate.sample.MainActivity"
_ABIS = ("arm64-v8a", "x86_64")

_ANDROID_URI = "http://schemas.android.com/apk/res/android"
# Framework attribute name -> resource id. androguard resolves an android:*
# attribute name from its resource id via the resource map, so these strings
# must be the first entries in the pool and line up positionally with it.
_RES_IDS = {
    "name": 0x01010003,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270,
    "label": 0x01010001,
}

_RES_XML_TYPE = 0x0003
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_RESOURCE_MAP_TYPE = 0x0180
_RES_XML_START_NAMESPACE = 0x0100
_RES_XML_END_NAMESPACE = 0x0101
_RES_XML_START_ELEMENT = 0x0102
_RES_XML_END_ELEMENT = 0x0103
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_NO_ENTRY = 0xFFFFFFFF


class _StringPool:
    """An AOSP ``ResStringPool`` of UTF-16 strings, resource-mapped ones first."""

    def __init__(self, mapped_first: list[str]) -> None:
        self._strings: list[str] = list(mapped_first)
        self._index = {s: i for i, s in enumerate(self._strings)}

    def add(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self._strings)
            self._strings.append(value)
        return self._index[value]

    def encode(self) -> bytes:
        offsets: list[int] = []
        data = bytearray()
        for text in self._strings:
            offsets.append(len(data))
            data += struct.pack("<H", len(text))
            data += text.encode("utf-16-le")
            data += b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        header_size = 28
        strings_start = header_size + 4 * len(self._strings)
        out = bytearray()
        out += struct.pack("<HH", _RES_STRING_POOL_TYPE, header_size)
        out += struct.pack("<I", strings_start + len(data))
        out += struct.pack("<I", len(self._strings))
        out += struct.pack("<I", 0)  # styleCount
        out += struct.pack("<I", 0)  # flags: 0 -> UTF-16
        out += struct.pack("<I", strings_start)
        out += struct.pack("<I", 0)  # stylesStart
        for off in offsets:
            out += struct.pack("<I", off)
        out += data
        return bytes(out)


def _xml_node(chunk_type: int, body: bytes) -> bytes:
    header_size = 16  # ResChunk_header(8) + lineNumber(4) + comment(4)
    out = bytearray()
    out += struct.pack("<HH", chunk_type, header_size)
    out += struct.pack("<I", header_size + len(body))
    out += struct.pack("<I", _NO_ENTRY)  # lineNumber
    out += struct.pack("<I", _NO_ENTRY)  # comment
    out += body
    return bytes(out)


def _attribute(ns: int, name: int, value_str: int, vtype: int, data: int) -> bytes:
    # The typed value packs as size(2)=8 | res0(1)=0 | dataType(1) into one u32.
    return struct.pack(
        "<LLLLL",
        ns & 0xFFFFFFFF,
        name,
        value_str & 0xFFFFFFFF,
        8 | (vtype << 24),
        data & 0xFFFFFFFF,
    )


def _start_element(name: int, attrs: bytes, count: int) -> bytes:
    body = struct.pack("<LL", _NO_ENTRY, name)  # element namespace, name
    body += struct.pack("<HH", 0x14, 0x14)  # attributeStart, attributeSize
    body += struct.pack("<I", count)  # low16 count; high16 idIndex+1 = 0 -> -1
    body += struct.pack("<I", 0)  # class/style indices -> none
    body += attrs
    return _xml_node(_RES_XML_START_ELEMENT, body)


def _end_element(name: int) -> bytes:
    return _xml_node(_RES_XML_END_ELEMENT, struct.pack("<LL", _NO_ENTRY, name))


def _build_manifest_axml() -> bytes:
    pool = _StringPool(list(_RES_IDS))
    uri = pool.add(_ANDROID_URI)
    prefix = pool.add("android")
    tag = {
        t: pool.add(t)
        for t in (
            "manifest",
            "uses-sdk",
            "uses-permission",
            "application",
            "activity",
            "intent-filter",
            "action",
            "category",
        )
    }
    i_package = pool.add("package")
    v_pkg = pool.add(_PACKAGE)
    v_ver = pool.add(_VERSION_NAME)
    v_perm = pool.add(_PERMISSION)
    v_activity = pool.add(_ACTIVITY)
    v_main = pool.add("android.intent.action.MAIN")
    v_launcher = pool.add("android.intent.category.LAUNCHER")
    v_label = pool.add("Gate")
    attr = {name: idx for idx, name in enumerate(_RES_IDS)}

    nodes = bytearray()
    nodes += _xml_node(_RES_XML_START_NAMESPACE, struct.pack("<LL", prefix, uri))

    nodes += _start_element(
        tag["manifest"],
        _attribute(_NO_ENTRY, i_package, v_pkg, _TYPE_STRING, v_pkg)
        + _attribute(uri, attr["versionCode"], _NO_ENTRY, _TYPE_INT_DEC, _VERSION_CODE)
        + _attribute(uri, attr["versionName"], v_ver, _TYPE_STRING, v_ver),
        3,
    )

    nodes += _start_element(
        tag["uses-sdk"],
        _attribute(uri, attr["minSdkVersion"], _NO_ENTRY, _TYPE_INT_DEC, _MIN_SDK)
        + _attribute(uri, attr["targetSdkVersion"], _NO_ENTRY, _TYPE_INT_DEC, _TARGET_SDK),
        2,
    )
    nodes += _end_element(tag["uses-sdk"])

    nodes += _start_element(
        tag["uses-permission"],
        _attribute(uri, attr["name"], v_perm, _TYPE_STRING, v_perm),
        1,
    )
    nodes += _end_element(tag["uses-permission"])

    nodes += _start_element(
        tag["application"],
        _attribute(uri, attr["label"], v_label, _TYPE_STRING, v_label),
        1,
    )
    nodes += _start_element(
        tag["activity"],
        _attribute(uri, attr["name"], v_activity, _TYPE_STRING, v_activity),
        1,
    )
    nodes += _start_element(tag["intent-filter"], b"", 0)
    nodes += _start_element(
        tag["action"],
        _attribute(uri, attr["name"], v_main, _TYPE_STRING, v_main),
        1,
    )
    nodes += _end_element(tag["action"])
    nodes += _start_element(
        tag["category"],
        _attribute(uri, attr["name"], v_launcher, _TYPE_STRING, v_launcher),
        1,
    )
    nodes += _end_element(tag["category"])
    nodes += _end_element(tag["intent-filter"])
    nodes += _end_element(tag["activity"])
    nodes += _end_element(tag["application"])
    nodes += _end_element(tag["manifest"])
    nodes += _xml_node(_RES_XML_END_NAMESPACE, struct.pack("<LL", prefix, uri))

    resmap = bytearray()
    resmap += struct.pack("<HH", _RES_XML_RESOURCE_MAP_TYPE, 8)
    resmap += struct.pack("<I", 8 + 4 * len(_RES_IDS))
    for rid in _RES_IDS.values():
        resmap += struct.pack("<I", rid)

    payload = pool.encode() + bytes(resmap) + bytes(nodes)
    header = struct.pack("<HH", _RES_XML_TYPE, 8) + struct.pack("<I", 8 + len(payload))
    return header + payload


def _build_valid_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", _build_manifest_axml())
        for abi in _ABIS:
            archive.writestr(f"lib/{abi}/libgate.so", b"\x7fELF" + b"\x00" * 60)
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 60)
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 8)
    return path


def _androguard_available() -> bool:
    return ApkClient().available


@pytest.mark.integration
def test_androguard_reports_the_real_manifest_identity(tmp_path: Path) -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — Android static Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "gate.apk")
    assert classify_target(apk) is TargetKind.APK

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        data = opened.data
        assert data["opened"] is True
        assert data["package"] == _PACKAGE
        assert data["version_name"] == _VERSION_NAME
        assert str(data["version_code"]) == str(_VERSION_CODE)
        assert str(data["min_sdk"]) == str(_MIN_SDK)
        assert str(data["target_sdk"]) == str(_TARGET_SDK)
        assert data["main_activity"] == _ACTIVITY
        assert data["permission_count"] == 1
        assert data["native_abis"] == list(_ABIS)

        # The decoded manifest must be real XML, not the raw AXML bytes.
        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        xml = manifest.data["manifest_xml"]
        assert manifest.data["package"] == _PACKAGE
        assert f'package="{_PACKAGE}"' in xml
        assert _ACTIVITY in xml
        assert _PERMISSION in xml
    finally:
        service.close_all()


@pytest.mark.integration
def test_androguard_enumerates_permissions_components_and_libs(tmp_path: Path) -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — Android static Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "gate.apk")
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert _PERMISSION in permissions.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == [_ACTIVITY]
        assert components.data["main_activity"] == _ACTIVITY
        assert components.data["services"] == []

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert libs.data["abis"] == list(_ABIS)
        assert libs.data["count"] == len(_ABIS)
    finally:
        service.close_all()
