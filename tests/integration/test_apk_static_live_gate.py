"""APK static-analysis gate over a real, androguard-parseable DEX.

The sibling ``test_android_re_gate`` builds a synthetic archive whose manifest
and ``classes.dex`` are placeholders, so androguard's DEX analysis (the path
behind ``apk.classes`` / ``apk.methods`` / ``apk.strings`` / ``apk.xrefs``) was
never actually run against a parseable APK anywhere -- every unit test stubs
``AnalyzeAPK`` out. This gate assembles a minimal but valid DEX (one class, one
method, one data string) in memory, wraps it in an APK, and drives the real
androguard-backed service methods end to end, so a regression in the analysis
path or its pagination is caught rather than mocked over.

The manifest stays a placeholder on purpose: it exercises the second half of the
contract, that ``apk.open`` degrades to null identity fields on a manifest
androguard cannot parse rather than filing an ``internal_error`` incident.

skip != pass: without androguard the gate skips instead of asserting a pass.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_NO_INDEX = 0xFFFFFFFF
_HEADER_SIZE = 0x70
_DATA_STRING = "hello_dex_string"


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _build_minimal_dex() -> bytes:
    """Assemble a valid DEX 035 with class ``LFoo;``, method ``bar()V``, one string.

    Hand-built rather than compiled because the box has no Android toolchain;
    every offset, the map list, the sha1 signature and the adler32 checksum are
    what androguard validates, so a wrong one fails loudly at parse time.
    """
    # ASCII strings only, sorted as the format requires (by code point).
    strings = sorted(["LFoo;", "Ljava/lang/Object;", "V", "bar", _DATA_STRING])
    sidx = {name: index for index, name in enumerate(strings)}
    type_names = sorted(["LFoo;", "Ljava/lang/Object;", "V"], key=lambda name: sidx[name])
    tidx = {name: index for index, name in enumerate(type_names)}

    n_strings, n_types, n_protos, n_methods, n_classes = len(strings), len(type_names), 1, 1, 1

    offset = _HEADER_SIZE
    string_ids_off = offset
    offset += n_strings * 4
    type_ids_off = offset
    offset += n_types * 4
    proto_ids_off = offset
    offset += n_protos * 12
    method_ids_off = offset
    offset += n_methods * 8
    class_defs_off = offset
    offset += n_classes * 32
    data_off = offset

    data = io.BytesIO()

    def align4() -> None:
        while data.tell() % 4:
            data.write(b"\x00")

    string_data_offsets: dict[str, int] = {}
    for name in strings:
        string_data_offsets[name] = data_off + data.tell()
        data.write(_uleb128(len(name.encode("utf-8"))))
        data.write(name.encode("utf-8"))
        data.write(b"\x00")

    align4()
    code_off = data_off + data.tell()
    data.write(struct.pack("<HHHH", 1, 0, 0, 0))  # registers, ins, outs, tries
    data.write(struct.pack("<I", 0))  # debug_info_off
    insns = struct.pack("<H", 0x000E)  # return-void (10x)
    data.write(struct.pack("<I", len(insns) // 2))
    data.write(insns)

    class_data_off = data_off + data.tell()
    class_data = io.BytesIO()
    class_data.write(_uleb128(0))  # static_fields
    class_data.write(_uleb128(0))  # instance_fields
    class_data.write(_uleb128(1))  # direct_methods
    class_data.write(_uleb128(0))  # virtual_methods
    class_data.write(_uleb128(0))  # method_idx_diff -> method 0
    class_data.write(_uleb128(0x1 | 0x8))  # public static
    class_data.write(_uleb128(code_off))
    data.write(class_data.getvalue())

    align4()
    map_off = data_off + data.tell()
    map_items = [
        (0x0000, 1, 0),  # header
        (0x0001, n_strings, string_ids_off),  # string ids
        (0x0002, n_types, type_ids_off),  # type ids
        (0x0003, n_protos, proto_ids_off),  # proto ids
        (0x0005, n_methods, method_ids_off),  # method ids
        (0x0006, n_classes, class_defs_off),  # class defs
        (0x2002, n_strings, string_data_offsets[strings[0]]),  # string data
        (0x2001, 1, code_off),  # code items
        (0x2000, 1, class_data_off),  # class data
        (0x1000, 1, map_off),  # map list
    ]
    map_items.sort(key=lambda item: item[2])
    data.write(struct.pack("<I", len(map_items)))
    for type_code, size, item_off in map_items:
        data.write(struct.pack("<HHII", type_code, 0, size, item_off))

    data_bytes = data.getvalue()

    body = io.BytesIO()
    body.write(b"\x00" * _HEADER_SIZE)
    for name in strings:
        body.write(struct.pack("<I", string_data_offsets[name]))
    for name in type_names:
        body.write(struct.pack("<I", sidx[name]))
    body.write(struct.pack("<III", sidx["V"], tidx["V"], 0))  # proto ()V
    body.write(struct.pack("<HHI", tidx["LFoo;"], 0, sidx["bar"]))  # method bar
    body.write(
        struct.pack(
            "<IIIIIIII",
            tidx["LFoo;"],
            0x1,
            tidx["Ljava/lang/Object;"],
            0,
            _NO_INDEX,
            0,
            class_data_off,
            0,
        )
    )
    body.write(data_bytes)

    blob = bytearray(body.getvalue())
    struct.pack_into("<8s", blob, 0, b"dex\n035\x00")
    struct.pack_into("<I", blob, 0x20, len(blob))
    struct.pack_into("<I", blob, 0x24, _HEADER_SIZE)
    struct.pack_into("<I", blob, 0x28, 0x12345678)
    struct.pack_into("<I", blob, 0x34, map_off)
    struct.pack_into("<I", blob, 0x38, n_strings)
    struct.pack_into("<I", blob, 0x3C, string_ids_off)
    struct.pack_into("<I", blob, 0x40, n_types)
    struct.pack_into("<I", blob, 0x44, type_ids_off)
    struct.pack_into("<I", blob, 0x48, n_protos)
    struct.pack_into("<I", blob, 0x4C, proto_ids_off)
    struct.pack_into("<I", blob, 0x50, 0)  # field_ids_size
    struct.pack_into("<I", blob, 0x54, 0)  # field_ids_off
    struct.pack_into("<I", blob, 0x58, n_methods)
    struct.pack_into("<I", blob, 0x5C, method_ids_off)
    struct.pack_into("<I", blob, 0x60, n_classes)
    struct.pack_into("<I", blob, 0x64, class_defs_off)
    struct.pack_into("<I", blob, 0x68, len(data_bytes))
    struct.pack_into("<I", blob, 0x6C, data_off)

    struct.pack_into("<20s", blob, 0x0C, hashlib.sha1(blob[0x20:]).digest())
    struct.pack_into("<I", blob, 0x08, zlib.adler32(blob[0x0C:]) & 0xFFFFFFFF)
    return bytes(blob)


def _build_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        # Placeholder manifest: present so the archive classifies as an APK, but
        # not valid AXML, which is what exercises apk.open's degrade path.
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", _build_minimal_dex())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
    return path


@pytest.mark.integration
def test_apk_static_analysis_runs_against_a_real_dex(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")

    apk = _build_apk(tmp_path / "sample.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        assert created.data["session"]["target"] == "apk"

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert "LFoo;" in classes.data["classes"]
        assert classes.data["total"] >= 1
        assert classes.data["has_more"] is False

        # Both the smali and dotted spellings must resolve to the same class.
        for spelling in ("LFoo;", "Foo"):
            methods = service.apk_methods(session_id, spelling)
            assert methods.ok, methods.error
            assert methods.data["class_name"] == "LFoo;"
            assert [m["name"] for m in methods.data["methods"]] == ["bar"]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert _DATA_STRING in strings.data["strings"]

        # bar has no callers; the envelope must say so rather than crash.
        xrefs = service.apk_xrefs(session_id, "bar")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["method_name"] == "bar"
        assert xrefs.data["callers"] == []
        assert xrefs.data["has_more"] is False

        # Paging past the only class yields an empty, terminal page.
        empty_page = service.apk_classes(session_id, offset=1, limit=100)
        assert empty_page.ok, empty_page.error
        assert empty_page.data["classes"] == []
        assert empty_page.data["has_more"] is False

        # The manifest is not valid AXML; open must degrade, not file an incident.
        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True
        assert opened.data["version_name"] is None
        assert opened.data["native_abis"] == ["arm64-v8a"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_manifest_readers_degrade_on_an_unparseable_manifest(tmp_path: Path) -> None:
    """Every manifest reader must degrade, not file an internal_error incident.

    apk.open was fixed to null its identity fields when androguard cannot parse
    the manifest rather than letting a getter's KeyError reach the envelope as an
    incident. The sibling readers share that hazard -- androguard's getters raise
    on some malformed manifests and return empty on others -- so this pins the
    whole surface against the same invalid-AXML APK: permissions / components /
    certificates return empty-but-ok, native_libs still reads the abis off the
    lib/ paths (which do not depend on the manifest), and manifest fails with the
    clean backend_error it raises for an undecodable file, never internal_error.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")

    apk = _build_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert permissions.data["permissions"] == []
        assert permissions.data["count"] == 0

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == []
        assert components.data["services"] == []
        # get_main_activity is called raw here (open guards it with _safe); on an
        # unparseable manifest it must yield None, not raise.
        assert components.data["main_activity"] is None

        certificates = service.apk_certificates(session_id)
        assert certificates.ok, certificates.error
        assert certificates.data["certificates"] == []

        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert native.data["abis"] == ["arm64-v8a"]
        assert native.data["count"] == 1

        manifest = service.apk_manifest(session_id)
        assert not manifest.ok
        assert manifest.error is not None
        assert manifest.error.code == "backend_error"
    finally:
        service.close_all()
