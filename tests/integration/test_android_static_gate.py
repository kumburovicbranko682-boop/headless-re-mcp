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
chunks) *and* a valid ``classes.dex`` (a header with the mandatory Adler32
checksum, a map_list, and the string/type/proto/method/class tables plus one
method whose bytecode loads a marker string), then zips both into an APK with
two native ABIs. It drives the real tool surface and asserts the decoded values,
not merely that a call returned:

  * manifest half -- ``apk.open`` / ``apk.manifest`` / ``apk.permissions`` /
    ``apk.components`` / ``apk.native_libs``;
  * DEX half -- ``apk.classes`` finds the internal class, ``apk.methods`` lists
    its method with the right descriptor and access, and ``apk.strings`` returns
    the marker constant the method loads.

skip != pass: with androguard absent the gate skips loudly.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
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

# What the hand-built classes.dex carries, asserted by the DEX-half tests.
_DEX_CLASS = "Lcom/gate/sample/Gate;"
_DEX_METHOD = "gateSecret"
_DEX_STRING = "gate-secret-marker"

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


# --- classes.dex ------------------------------------------------------------
# A minimal but valid DEX (format 035): one public class with one direct method
# whose bytecode is ``const-string v0, "gate-secret-marker"; return-void``. That
# is enough for androguard to enumerate the class, list the method and surface
# the string, which is what the DEX-half tools read. String indices are explicit
# throughout, so the tables need not be sorted for androguard to resolve them.
_DEX_STRINGS = [
    _DEX_CLASS,  # 0: the class descriptor
    "Ljava/lang/Object;",  # 1: superclass
    "V",  # 2: void, reused as the proto shorty
    _DEX_STRING,  # 3: the constant the method loads
    _DEX_METHOD,  # 4: the method name
]
_DEX_TYPES = [0, 1, 2]  # type index -> string index
_T_CLASS, _T_OBJECT, _T_VOID = range(3)


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def _align4(buf: bytearray) -> None:
    while len(buf) % 4:
        buf.append(0)


def _build_classes_dex() -> bytes:
    header_size = 0x70
    body = bytearray()

    string_ids_off = header_size
    body += b"\x00" * (4 * len(_DEX_STRINGS))  # patched once data is placed

    _align4(body)
    type_ids_off = header_size + len(body)
    for string_index in _DEX_TYPES:
        body += struct.pack("<I", string_index)

    _align4(body)
    proto_ids_off = header_size + len(body)
    body += struct.pack("<III", 2, _T_VOID, 0)  # shorty "V", return void, no params

    _align4(body)
    method_ids_off = header_size + len(body)
    body += struct.pack("<HHI", _T_CLASS, 0, 4)  # class, proto 0, name "gateSecret"

    _align4(body)
    code_off = header_size + len(body)
    insns = struct.pack("<BBH", 0x1A, 0x00, 3)  # const-string v0, string@3
    insns += struct.pack("<BB", 0x0E, 0x00)  # return-void
    body += struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(insns) // 2)
    body += insns

    _align4(body)
    class_data_off = header_size + len(body)
    body += _uleb128(0)  # static fields
    body += _uleb128(0)  # instance fields
    body += _uleb128(1)  # direct methods
    body += _uleb128(0)  # virtual methods
    body += _uleb128(0)  # first method_idx_diff
    body += _uleb128(0x9)  # access: public | static
    body += _uleb128(code_off)

    _align4(body)
    class_defs_off = header_size + len(body)
    body += struct.pack(
        "<IIIIIIII",
        _T_CLASS,  # class_idx
        0x1,  # access: public
        _T_OBJECT,  # superclass_idx
        0,  # interfaces_off
        0xFFFFFFFF,  # source_file_idx: NO_INDEX
        0,  # annotations_off
        class_data_off,
        0,  # static_values_off
    )

    string_data_offsets: list[int] = []
    for text in _DEX_STRINGS:
        string_data_offsets.append(header_size + len(body))
        body += _uleb128(len(text))
        body += text.encode("utf-8")  # MUTF-8 == UTF-8 for ASCII
        body += b"\x00"
    for i, off in enumerate(string_data_offsets):
        pos = string_ids_off - header_size + 4 * i
        body[pos : pos + 4] = struct.pack("<I", off)

    _align4(body)
    map_off = header_size + len(body)
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(_DEX_STRINGS), string_ids_off),
        (0x0002, len(_DEX_TYPES), type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 1, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2000, 1, class_data_off),
        (0x2001, 1, code_off),
        (0x2002, len(_DEX_STRINGS), string_data_offsets[0]),
        (0x1000, 1, map_off),
    ]
    body += struct.pack("<I", len(map_items))
    for type_code, size, off in map_items:
        body += struct.pack("<HHII", type_code, 0, size, off)

    file_size = header_size + len(body)
    header = bytearray()
    header += b"dex\n035\x00"
    header += b"\x00" * 4  # checksum (Adler32), patched below
    header += b"\x00" * 20  # signature (SHA-1), patched below
    header += struct.pack("<I", file_size)
    header += struct.pack("<I", header_size)
    header += struct.pack("<I", 0x12345678)  # little-endian tag
    header += struct.pack("<II", 0, 0)  # link
    header += struct.pack("<I", map_off)
    header += struct.pack("<II", len(_DEX_STRINGS), string_ids_off)
    header += struct.pack("<II", len(_DEX_TYPES), type_ids_off)
    header += struct.pack("<II", 1, proto_ids_off)
    header += struct.pack("<II", 0, 0)  # field ids
    header += struct.pack("<II", 1, method_ids_off)
    header += struct.pack("<II", 1, class_defs_off)
    header += struct.pack("<II", file_size - code_off, code_off)  # data section

    dex = bytearray(header + body)
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    dex[8:12] = struct.pack("<I", zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF)
    return bytes(dex)


def _build_valid_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", _build_manifest_axml())
        archive.writestr("classes.dex", _build_classes_dex())
        for abi in _ABIS:
            archive.writestr(f"lib/{abi}/libgate.so", b"\x7fELF" + b"\x00" * 60)
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


@pytest.mark.integration
def test_androguard_analyzes_the_dex_classes_methods_and_strings(tmp_path: Path) -> None:
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

        # apk.classes runs the full DEX analysis; the internal class must appear
        # (framework types like Object are external and filtered out).
        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["classes"] == [_DEX_CLASS]

        # apk.methods must decode the one method with its real descriptor/access.
        methods = service.apk_methods(session_id, _DEX_CLASS)
        assert methods.ok, methods.error
        names = {m["name"] for m in methods.data["methods"]}
        assert _DEX_METHOD in names
        method = next(m for m in methods.data["methods"] if m["name"] == _DEX_METHOD)
        assert method["descriptor"] == "()V"
        assert "static" in method["access"]

        # apk.strings must surface the constant the method loads.
        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert _DEX_STRING in strings.data["strings"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_methods_rejects_an_unknown_class(tmp_path: Path) -> None:
    """A class the DEX does not define must be a clean not_found, not a crash."""
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
        session_id = created.data["session"]["id"]
        missing = service.apk_methods(session_id, "Lcom/gate/sample/DoesNotExist;")
        assert missing.ok is False
        assert missing.error is not None
        assert missing.error.code == "not_found"
    finally:
        service.close_all()
