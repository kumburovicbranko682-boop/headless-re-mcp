"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _build_synthetic_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        # Minimal (not AXML-valid) manifest is enough for stdlib classification.
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return path


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
    """Assemble a valid classes.dex by hand -- no Android SDK on the runner.

    One class ``LCrackme;`` extends ``Ljava/lang/Object;`` with one direct,
    ``public static`` method ``secret()V`` whose body is
    ``const-string v0, "s3cr3t"; return-void``. That is the smallest DEX that
    exercises the four DEX-analysis tools with real androguard: a defined class
    (``apk.classes``), a method with descriptor/access (``apk.methods``), and a
    referenced string literal (``apk.strings``). Building it here rather than
    shipping a binary blob keeps the fixture auditable, and hand-crafting is the
    only option without d8/dx on the machine.
    """
    strings = ["LCrackme;", "Ljava/lang/Object;", "V", "s3cr3t", "secret"]
    assert strings == sorted(strings)  # DEX requires string_ids sorted
    s_idx = {s: i for i, s in enumerate(strings)}
    types = ["LCrackme;", "Ljava/lang/Object;", "V"]
    t_idx = {t: i for i, t in enumerate(types)}

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + len(types) * 4
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    data_off = class_defs_off + 32

    cursor = data_off
    string_data_off: dict[str, int] = {}
    string_data = bytearray()
    for text in strings:
        string_data_off[text] = cursor
        chunk = _uleb128(len(text)) + text.encode("utf-8") + b"\x00"
        string_data += chunk
        cursor += len(chunk)

    while cursor % 4:  # code_item is 4-byte aligned
        string_data += b"\x00"
        cursor += 1
    code_off = cursor
    insns = struct.pack("<BBH", 0x1A, 0x00, s_idx["s3cr3t"])  # const-string v0
    insns += struct.pack("<BB", 0x0E, 0x00)  # return-void
    code_item = struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(insns) // 2) + insns
    cursor += len(code_item)

    class_data_off = cursor
    class_data = bytearray(
        _uleb128(0)  # static_fields_size
        + _uleb128(0)  # instance_fields_size
        + _uleb128(1)  # direct_methods_size
        + _uleb128(0)  # virtual_methods_size
        + _uleb128(0)  # method_idx_diff -> method 0
        + _uleb128(0x9)  # public | static
        + _uleb128(code_off)
    )
    cursor += len(class_data)

    while cursor % 4:  # map_list is 4-byte aligned
        class_data += b"\x00"
        cursor += 1
    map_off = cursor
    entries = [
        (0x0000, 1, 0x00),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(types), type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 1, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, len(strings), data_off),
        (0x2001, 1, code_off),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    map_blob = struct.pack("<I", len(entries))
    for type_code, size, off in entries:
        map_blob += struct.pack("<HHII", type_code, 0, size, off)
    cursor += len(map_blob)

    file_size = cursor
    string_ids = b"".join(struct.pack("<I", string_data_off[s]) for s in strings)
    type_ids = b"".join(struct.pack("<I", s_idx[t]) for t in types)
    proto_ids = struct.pack("<III", s_idx["V"], t_idx["V"], 0)
    method_ids = struct.pack("<HHI", t_idx["LCrackme;"], 0, s_idx["secret"])
    class_def = struct.pack(
        "<IIIIIIII",
        t_idx["LCrackme;"],
        0x1,
        t_idx["Ljava/lang/Object;"],
        0,
        0xFFFFFFFF,
        0,
        class_data_off,
        0,
    )

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, file_size)
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x34, map_off)
    struct.pack_into("<II", header, 0x38, len(strings), string_ids_off)
    struct.pack_into("<II", header, 0x40, len(types), type_ids_off)
    struct.pack_into("<II", header, 0x48, 1, proto_ids_off)
    struct.pack_into("<II", header, 0x58, 1, method_ids_off)
    struct.pack_into("<II", header, 0x60, 1, class_defs_off)
    struct.pack_into("<II", header, 0x68, file_size - data_off, data_off)

    data = bytearray()
    data += header
    data += string_ids
    data += type_ids
    data += proto_ids
    data += method_ids
    data += class_def
    data += string_data
    data += code_item
    data += class_data
    data += map_blob
    assert len(data) == file_size
    struct.pack_into("<20s", data, 0x0C, hashlib.sha1(data[0x20:]).digest())
    struct.pack_into("<I", data, 0x08, zlib.adler32(data[0x0C:]) & 0xFFFFFFFF)
    return bytes(data)


def _build_real_dex_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", _build_minimal_dex())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
    return path


@pytest.mark.integration
def test_android_session_classification_and_metadata(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")

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

        # androguard opens a real APK; on the synthetic archive its manifest is
        # not AXML-valid, which is exactly the corrupted/obfuscated case seen in
        # the wild. It must still answer with a structured envelope rather than
        # raising -- and never as internal_error, which would file our own code
        # as broken (and mint an incident) for a merely malformed input.
        from headless_re_mcp.backends.apk.client import ApkClient

        opened = service.apk_open(session_id)
        assert isinstance(opened.ok, bool)
        if ApkClient().available:
            # Real androguard: the ZIP parses, the version getters raise
            # KeyError internally and degrade to None, and the file-derived
            # facts (native ABIs) still come back. Before the open() guard this
            # was ok=False / internal_error.
            assert opened.ok, opened.error
            assert set(opened.data["native_abis"]) == {"arm64-v8a", "x86_64"}
            assert opened.data["version_name"] is None
        else:
            assert opened.ok is False
            assert opened.error is not None
            assert opened.error.code == "capability_unavailable"

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
def test_android_dex_analysis_on_a_real_dex(tmp_path: Path) -> None:
    """The DEX-analysis tools, run against a hand-built but valid classes.dex.

    The synthetic APK above has a placeholder DEX, so androguard's full analysis
    (apk.classes/methods/strings/xrefs) only ever exercised its clean-failure
    path there. This builds a real DEX so the four tools are proven end to end
    against live androguard: a defined class, a method with its descriptor and
    access, the referenced string literal, and the empty-but-structured xrefs
    answer for a method nothing calls. Unit tests cover the field shaping with
    fakes; this is what would catch androguard changing get_classes /
    get_methods / get_strings / get_xref_from out from under the fakes.
    """
    from headless_re_mcp.backends.apk.client import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — DEX analysis Gate not run (skip != pass)")

    apk = _build_real_dex_apk(tmp_path / "real.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["classes"] == ["LCrackme;"]
        assert classes.data["total"] == 1

        # Both the smali form and the dotted form must resolve the same class.
        for name in ("LCrackme;", "Crackme"):
            methods = service.apk_methods(session_id, name)
            assert methods.ok, (name, methods.error)
            assert methods.data["count"] == 1
            method = methods.data["methods"][0]
            assert method["name"] == "secret"
            assert method["descriptor"] == "()V"
            assert "static" in method["access"]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert "s3cr3t" in strings.data["strings"]

        # secret() is never invoked, so its caller set is empty -- but the
        # answer must still be a structured, has_more-bearing envelope, not a
        # "no such method" error.
        xrefs = service.apk_xrefs(session_id, "secret")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["callers"] == []
        assert xrefs.data["has_more"] is False

        # A class that does not exist is a not_found, not a crash.
        missing = service.apk_methods(session_id, "does.not.Exist")
        assert missing.ok is False
        assert missing.error is not None
        assert missing.error.code == "not_found"
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_pe_tool_rejects_apk_session(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
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
