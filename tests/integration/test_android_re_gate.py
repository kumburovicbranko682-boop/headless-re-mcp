"""Android RE gate: session classification, real APK parsing, and degradation.

Runs without a device or extra tools by building a genuinely valid APK in a
temp dir: a compiled binary AndroidManifest (AXML) that declares a package, and
a valid classes.dex that defines one class. That makes the gate drive the real
androguard backend end to end -- manifest parse and DEX analysis -- rather than
only the stdlib zip classification, so a regression in the androguard
integration fails here instead of hiding behind a "structured envelope" check.
Parts that need a real device / jadx / adbutils still degrade to an envelope
(skip != pass for the live-device parts, which have their own explicit skips).

The APK is assembled by hand rather than committed as a binary so every byte is
transparent and the fixture cannot silently rot; both formats are simple enough
that a few dozen lines produce something androguard validates as a real app.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_PACKAGE = "com.example.gate"
_CLASS_SMALI = "Lcom/example/Gate;"


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


def _build_one_class_dex() -> bytes:
    """A valid DEX (v035) that defines one class with no methods.

    Only the sections a lone class needs are emitted: two strings (the class and
    its ``java.lang.Object`` superclass descriptors), the two matching type ids,
    one class_def, and the map list. The header's checksum (adler32 over
    everything after it) and signature (sha1 over everything after the
    signature) are filled in last, exactly as the format requires, so
    androguard's validator accepts it.
    """
    strings = [_CLASS_SMALI, "Ljava/lang/Object;"]
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    class_defs_off = type_ids_off + 4 * len(strings)
    data_off = class_defs_off + 32

    string_data = bytearray()
    string_offsets: list[int] = []
    for text in strings:
        string_offsets.append(data_off + len(string_data))
        string_data += _uleb128(len(text)) + text.encode("ascii") + b"\x00"

    map_off = data_off + len(string_data)
    pad = (-map_off) % 4
    map_off += pad
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(strings), type_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, len(strings), data_off),
        (0x1000, 1, map_off),
    ]
    map_list = struct.pack("<I", len(map_items))
    for type_code, size, offset in map_items:
        map_list += struct.pack("<HHII", type_code, 0, size, offset)

    file_size = map_off + len(map_list)
    header = bytearray()
    header += b"dex\n035\x00" + b"\x00" * 4 + b"\x00" * 20
    header += struct.pack("<I", file_size)
    header += struct.pack("<I", header_size)
    header += struct.pack("<I", 0x12345678)
    header += struct.pack("<I", 0) + struct.pack("<I", 0)  # link size/off
    header += struct.pack("<I", map_off)
    header += struct.pack("<I", len(strings)) + struct.pack("<I", string_ids_off)
    header += struct.pack("<I", len(strings)) + struct.pack("<I", type_ids_off)
    header += struct.pack("<I", 0) + struct.pack("<I", 0)  # proto ids
    header += struct.pack("<I", 0) + struct.pack("<I", 0)  # field ids
    header += struct.pack("<I", 0) + struct.pack("<I", 0)  # method ids
    header += struct.pack("<I", 1) + struct.pack("<I", class_defs_off)
    header += struct.pack("<I", file_size - data_off) + struct.pack("<I", data_off)

    body = bytearray(header)
    body += b"".join(struct.pack("<I", offset) for offset in string_offsets)
    body += struct.pack("<I", 0) + struct.pack("<I", 1)  # type ids -> string ids
    # class_def: class=type0, public, super=type1, no interfaces/source/data.
    body += struct.pack("<IIIIIIII", 0, 0x1, 1, 0, 0xFFFFFFFF, 0, 0, 0)
    body += string_data + b"\x00" * pad + map_list

    body[12:32] = hashlib.sha1(bytes(body[32:])).digest()
    body[8:12] = struct.pack("<I", zlib.adler32(bytes(body[12:])) & 0xFFFFFFFF)
    return bytes(body)


def _build_two_method_dex() -> bytes:
    """A valid DEX (v035) whose ``caller()`` invokes ``callee()`` in one class.

    The one-class fixture above has no methods, so it cannot exercise call-graph
    analysis. This adds two static methods to ``com.example.Gate`` and a real
    ``invoke-static`` from caller to callee, giving androguard a genuine
    cross-reference edge for the apk.xrefs gate to recover. The section layout
    mirrors the no-method fixture but adds the proto_ids / method_ids /
    class_data / code_item sections a method-bearing class requires; checksum
    and signature are filled in last so androguard validates it. The bytes were
    verified end to end -- androguard reports callee's only caller as caller.
    """
    strings = [_CLASS_SMALI, "Ljava/lang/Object;", "V", "callee", "caller"]
    assert strings == sorted(strings)
    s_class, s_super, s_void, s_callee, s_caller = range(5)
    type_ids = [s_class, s_super, s_void]
    t_class, t_super, t_void = 0, 1, 2

    n = len(strings)
    header_size = 0x70
    string_ids_off = header_size
    proto_ids_off = string_ids_off + 4 * n
    method_ids_off = proto_ids_off + 12  # one proto
    type_ids_off = method_ids_off + 8 * 2  # two methods
    class_defs_off = type_ids_off + 4 * len(type_ids)
    data_off = class_defs_off + 32

    data = bytearray()

    def emit(chunk: bytes) -> int:
        offset = data_off + len(data)
        data.extend(chunk)
        return offset

    def pad_to(boundary: int) -> None:
        while (data_off + len(data)) % boundary:
            data.append(0)

    string_offsets: list[int] = []
    for text in strings:
        string_offsets.append(emit(_uleb128(len(text)) + text.encode("ascii") + b"\x00"))

    pad_to(4)
    # callee: return-void (one code unit).
    callee_code_off = emit(struct.pack("<HHHHII", 0, 0, 0, 0, 0, 1) + bytes([0x0E, 0x00]))
    pad_to(4)
    # caller: invoke-static {}, meth@0 (callee); return-void (four code units).
    caller_insns = bytes([0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00])
    caller_code_off = emit(struct.pack("<HHHHII", 1, 0, 0, 0, 0, 4) + caller_insns)

    class_data = bytearray()
    class_data += _uleb128(0)  # static fields
    class_data += _uleb128(0)  # instance fields
    class_data += _uleb128(2)  # direct methods
    class_data += _uleb128(0)  # virtual methods
    # Direct methods, encoded as method_idx deltas: callee is method 0, caller 1.
    class_data += _uleb128(0) + _uleb128(0x9) + _uleb128(callee_code_off)
    class_data += _uleb128(1) + _uleb128(0x9) + _uleb128(caller_code_off)
    class_data_off = emit(bytes(class_data))

    pad_to(4)
    map_off = data_off + len(data)
    map_items = [
        (0x0000, 1, 0),
        (0x0001, n, string_ids_off),
        (0x0002, len(type_ids), type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 2, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2000, 1, class_data_off),
        (0x2001, 2, callee_code_off),
        (0x2002, n, string_offsets[0]),
        (0x1000, 1, map_off),
    ]
    map_items.sort(key=lambda item: item[2])
    map_blob = struct.pack("<I", len(map_items))
    for type_code, size, offset in map_items:
        map_blob += struct.pack("<HHII", type_code, 0, size, offset)
    emit(map_blob)

    file_size = data_off + len(data)

    proto_ids = struct.pack("<III", s_void, t_void, 0)  # shorty "V", returns void
    method_ids = struct.pack("<HHI", t_class, 0, s_callee)  # callee
    method_ids += struct.pack("<HHI", t_class, 0, s_caller)  # caller
    type_ids_blob = b"".join(struct.pack("<I", value) for value in type_ids)
    class_def = struct.pack(
        "<IIIIIIII", t_class, 0x1, t_super, 0, 0xFFFFFFFF, 0, class_data_off, 0
    )

    header = bytearray()
    header += b"dex\n035\x00" + b"\x00" * 4 + b"\x00" * 20
    header += struct.pack("<I", file_size)
    header += struct.pack("<I", header_size)
    header += struct.pack("<I", 0x12345678)
    header += struct.pack("<I", 0) + struct.pack("<I", 0)  # link size/off
    header += struct.pack("<I", map_off)
    header += struct.pack("<I", n) + struct.pack("<I", string_ids_off)
    header += struct.pack("<I", len(type_ids)) + struct.pack("<I", type_ids_off)
    header += struct.pack("<I", 1) + struct.pack("<I", proto_ids_off)
    header += struct.pack("<I", 0) + struct.pack("<I", 0)  # field ids
    header += struct.pack("<I", 2) + struct.pack("<I", method_ids_off)
    header += struct.pack("<I", 1) + struct.pack("<I", class_defs_off)
    header += struct.pack("<I", file_size - data_off) + struct.pack("<I", data_off)

    body = bytearray(header)
    body += b"".join(struct.pack("<I", offset) for offset in string_offsets)
    body += proto_ids + method_ids + type_ids_blob + class_def + bytes(data)
    assert len(body) == file_size, (len(body), file_size)

    body[12:32] = hashlib.sha1(bytes(body[32:])).digest()
    body[8:12] = struct.pack("<I", zlib.adler32(bytes(body[12:])) & 0xFFFFFFFF)
    return bytes(body)


def _build_axml_manifest(package: str = _PACKAGE) -> bytes:
    """A compiled AndroidManifest (AXML) of ``<manifest package="...">``.

    No android-namespace attributes are used, so no resource map is needed: a
    UTF-8 string pool plus one start/end element pair with a single plain-string
    ``package`` attribute is enough for androguard to report the package.
    """
    strings = ["manifest", "package", package]

    def _encode(text: str) -> bytes:
        raw = text.encode("utf-8")
        return bytes([len(text), len(raw)]) + raw + b"\x00"

    string_data = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(len(string_data))
        string_data += _encode(text)
    while len(string_data) % 4:
        string_data.append(0)

    offset_array = b"".join(struct.pack("<I", offset) for offset in offsets)
    strings_start = 28 + len(offset_array)
    pool_size = strings_start + len(string_data)
    pool = struct.pack("<HHI", 0x0001, 28, pool_size)
    pool += struct.pack("<IIIII", len(strings), 0, 0x00000100, strings_start, 0)
    pool += offset_array + bytes(string_data)

    start = struct.pack("<HHI", 0x0102, 16, 56)
    start += struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)  # line, comment
    start += struct.pack("<II", 0xFFFFFFFF, 0)  # ns=-1, name="manifest"
    start += struct.pack("<HHHHHH", 0x14, 0x14, 1, 0, 0, 0)
    start += struct.pack("<III", 0xFFFFFFFF, 1, 2)  # attr ns=-1, name, rawValue
    start += struct.pack("<HBBI", 8, 0, 0x03, 2)  # typed value: TYPE_STRING -> "..."
    end = struct.pack("<HHI", 0x0103, 16, 24)
    end += struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, 0)

    body = pool + start + end
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _build_valid_apk(path: Path, *, dex: bytes | None = None) -> Path:
    """Assemble a real, androguard-parseable APK with native libs and a v1 sig.

    ``dex`` overrides the packed classes.dex; it defaults to the no-method
    fixture so existing callers are unchanged, and the xrefs gate passes the
    two-method fixture instead.
    """
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", _build_axml_manifest())
        archive.writestr("classes.dex", dex if dex is not None else _build_one_class_dex())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return path


@pytest.mark.integration
def test_android_session_classification_and_metadata(tmp_path: Path) -> None:
    apk = _build_valid_apk(tmp_path / "sample.apk")

    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        meta = session["metadata"]["apk"]
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True

        session_id = session["id"]

        # Real androguard manifest parse: the package comes from the AXML we
        # compiled, and the native ABIs from the committed lib/ entries.
        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == _PACKAGE
        assert set(opened.data["native_abis"]) == {"arm64-v8a", "x86_64"}

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == _PACKAGE
        assert "manifest" in manifest.data["manifest_xml"]

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert permissions.data["permissions"] == []

        # Real DEX analysis: the defined class is enumerated with a real page.
        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert _CLASS_SMALI in classes.data["classes"]
        assert classes.data["count"] >= 1
        assert classes.data["has_more"] is False

        # The class defines no methods, so a real (empty) page comes back, not
        # a not_found: enumeration succeeded and simply found nothing.
        methods = service.apk_methods(session_id, _CLASS_SMALI)
        assert methods.ok, methods.error
        assert methods.data["count"] == 0
        assert methods.data["methods"] == []

        # The DEX string table is read for real: the class/superclass
        # descriptors are the strings this app contains.
        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert _CLASS_SMALI in strings.data["strings"]

        # Native libraries come straight from the zip entries androguard lists.
        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert set(native.data["abis"]) == {"arm64-v8a", "x86_64"}
        assert native.data["count"] == 2

        # Components are declared by none of this minimal manifest, so every
        # list is empty -- but the call succeeds against the real parser.
        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == []
        assert components.data["services"] == []

        # Certificates parse without raising even though the placeholder v1
        # signature is partial; v1_signed is a real boolean either way.
        certificates = service.apk_certificates(session_id)
        assert certificates.ok, certificates.error
        assert isinstance(certificates.data["v1_signed"], bool)
        assert isinstance(certificates.data["certificates"], list)

        # Device enumeration degrades cleanly when adbutils / adb is absent.
        listed = service.device_list()
        assert isinstance(listed.ok, bool)
        assert listed.ok or listed.error is not None

        # Frida device enumeration returns an envelope (frida may be present).
        devices = service.frida_devices()
        assert isinstance(devices.ok, bool)
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_jadx_decompiles_the_valid_apk(tmp_path: Path) -> None:
    """Drive the real jadx CLI over the built APK: export tree + one class.

    jadx is the flagship Android decompiler behind apk.export_sources and
    apk.decompile, yet it had no live coverage -- only stubbed unit tests. The
    built DEX defines one class, so jadx has real work: it must emit a Java tree
    and decompile ``com.example.Gate`` to a class declaration. skip != pass: it
    skips only when jadx is not installed (resolved the way the service does,
    via settings/PATH), never masking a jadx failure.
    """
    if Settings.load().jadx is None:
        pytest.skip("jadx is not installed — live Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        assert any(str(path).endswith("Gate.java") for path in exported.data["java_files"])

        decompiled = service.apk_decompile(session_id, "com.example.Gate")
        assert decompiled.ok, decompiled.error
        assert decompiled.data["class_name"] == "com.example.Gate"
        source = decompiled.data["source"]
        assert "class Gate" in source
        assert "package com.example" in source
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apktool_decodes_and_repacks_the_valid_apk(tmp_path: Path) -> None:
    """Round-trip the built APK through the real apktool: decode then rebuild.

    apktool decode/build back apk.decode and apk.repack but had no live
    coverage -- only stubbed unit tests -- so an apktool CLI or output-layout
    change would slip through. Decode runs with ``no_resources`` because the
    built APK carries a placeholder resources.arsc; that still exercises the
    real work -- decoding the binary AndroidManifest to text and the DEX to a
    ``smali`` tree -- and rebuild then repackages that tree into a fresh zip
    (asserted a valid, non-empty, unsigned APK). skip != pass: skips only when
    apktool is not installed, resolved the way the service does.
    """
    if Settings.load().apktool is None:
        pytest.skip("apktool is not installed — live Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        decoded = service.apk_decode(session_id, no_resources=True)
        assert decoded.ok, decoded.error
        assert "smali" in decoded.data["smali_dirs"]
        assert decoded.data["manifest"] is not None

        repacked = service.apk_repack(session_id)
        assert repacked.ok, repacked.error
        assert repacked.data["signed"] is False
        assert repacked.data["size"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apksigner_signs_the_repacked_apk(tmp_path: Path) -> None:
    """Sign a freshly rebuilt APK with the real apksigner and let it verify.

    apk.sign shells out to apksigner (sign, then a verify pass) but had no live
    coverage. This decodes and rebuilds with apktool, then signs the rebuilt
    APK against the standard Android debug keystore; apk.sign only returns ok
    after apksigner's own verify confirms the signature, so a green result is a
    genuinely signed, verifiable APK. skip != pass: skips when apktool or
    apksigner is absent, or when no debug keystore exists to sign against.
    """
    settings = Settings.load()
    if settings.apktool is None or settings.apksigner is None:
        pytest.skip("apktool/apksigner not installed — live Gate not run (skip != pass)")
    debug_keystore = Path.home() / ".android" / "debug.keystore"
    if not debug_keystore.is_file():
        pytest.skip("no Android debug keystore to sign against (skip != pass)")
    apk = _build_valid_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]
        assert service.apk_decode(session_id, no_resources=True).ok
        assert service.apk_repack(session_id).ok

        signed = service.apk_sign(session_id)
        assert signed.ok, signed.error
        assert signed.data["signed"] is True
        assert signed.data["debug_keystore"] is True
        assert signed.data["size"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apk_xrefs_finds_the_real_caller(tmp_path: Path) -> None:
    """apk.methods lists both methods and apk.xrefs recovers the call edge.

    The default fixture has no methods, so call-graph analysis -- apk.xrefs,
    the capability an agent uses to answer "who calls this?" -- had no
    executable coverage. This packs a two-method DEX whose ``caller`` invokes
    ``callee`` and asserts androguard's real cross-reference analysis reports
    ``caller`` as the one caller of ``callee`` (and nothing calls ``caller``),
    so a regression that returned an empty or wrong caller set fails here
    instead of passing on a fixture with no edges to get wrong.
    """
    apk = _build_valid_apk(tmp_path / "xrefs.apk", dex=_build_two_method_dex())
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        methods = service.apk_methods(session_id, _CLASS_SMALI)
        assert methods.ok, methods.error
        names = {method["name"] for method in methods.data["methods"]}
        assert {"caller", "callee"} <= names, methods.data["methods"]

        callers_of_callee = service.apk_xrefs(session_id, "callee")
        assert callers_of_callee.ok, callers_of_callee.error
        caller_names = {row["method"] for row in callers_of_callee.data["callers"]}
        assert caller_names == {"caller"}, callers_of_callee.data
        assert callers_of_callee.data["count"] == 1
        assert callers_of_callee.data["has_more"] is False

        # callee makes no calls, so nothing cross-references caller: the empty
        # result must come back as a real (successful) empty page.
        callers_of_caller = service.apk_xrefs(session_id, "caller")
        assert callers_of_caller.ok, callers_of_caller.error
        assert callers_of_caller.data["callers"] == []
        assert callers_of_caller.data["count"] == 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_pe_tool_rejects_apk_session(tmp_path: Path) -> None:
    apk = _build_valid_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        session_id = created.data["session"]["id"]
        # A PE-only tool must refuse an APK session with target_mismatch, not crash.
        opened = service.open_static(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code in {"target_mismatch", "invalid_request", "backend_unavailable"}
    finally:
        service.close_all()
