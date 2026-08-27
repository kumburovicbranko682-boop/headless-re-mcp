"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import importlib.util
import shutil
import struct
import subprocess
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_ANDROID_URI = "http://schemas.android.com/apk/res/android"
_APK_PACKAGE = "com.example.gate"
_APK_PERMISSION = "android.permission.INTERNET"
_APK_ACTIVITY = "com.example.gate.MainActivity"
_DEX_CLASS = "Lcom/example/gate/Sample;"
_DEX_METHOD = "helper"
_DEX_STRING = "gate-secret-marker"
_CERT_SERIAL = 0x0A11CE
_CERT_CN = "Gate Test Cert"


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


# --- Minimal *valid* binary AndroidManifest (AXML) -------------------------
#
# The synthetic APK above is enough for stdlib classification, but its manifest
# is not real AXML, so androguard cannot read a single fact from it. To give the
# androguard static line genuine live coverage we need a manifest androguard
# actually parses -- and building one normally needs the Android SDK (aapt).
# Instead we hand-encode the AXML binary format directly: it is self-contained
# (stdlib struct + zipfile), so the gate builds a real, parseable APK in CI
# without any Android toolchain. Attribute names are encoded as literal strings
# (e.g. "name") rather than the resource-id form aapt emits, which is exactly
# the form androguard resolves by (namespace, name) without a resource map.
_RES_STRING_POOL = 0x0001
_RES_XML = 0x0003
_RES_XML_START_NS = 0x0100
_RES_XML_END_NS = 0x0101
_RES_XML_START_ELEM = 0x0102
_RES_XML_END_ELEM = 0x0103
_UTF8_FLAG = 0x00000100
_TYPE_STRING = 0x03
_NIL = 0xFFFFFFFF


class _AxmlStrings:
    """Interning UTF-8 string pool for the AXML chunk."""

    def __init__(self) -> None:
        self._list: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self._list)
            self._list.append(value)
        return self._index[value]

    def encode(self) -> bytes:
        offsets: list[int] = []
        data = bytearray()
        for value in self._list:
            offsets.append(len(data))
            raw = value.encode("utf-8")
            # Single-byte lengths: every string here is short ASCII (< 0x80).
            assert len(value) < 0x80 and len(raw) < 0x80
            data.append(len(value))
            data.append(len(raw))
            data += raw
            data.append(0x00)
        while len(data) % 4 != 0:
            data.append(0x00)
        header_size = 28
        strings_start = header_size + 4 * len(self._list)
        chunk_size = strings_start + len(data)
        out = bytearray()
        out += struct.pack("<HHI", _RES_STRING_POOL, header_size, chunk_size)
        out += struct.pack("<III", len(self._list), 0, _UTF8_FLAG)
        out += struct.pack("<II", strings_start, 0)
        for offset in offsets:
            out += struct.pack("<I", offset)
        out += data
        return bytes(out)


def _axml_node_header(node_type: int, size: int) -> bytes:
    return struct.pack("<HHIII", node_type, 16, size, 1, 0xFFFFFFFF)


def _axml_start_elem(name: int, attrs: list[tuple[int, int, int]]) -> bytes:
    size = 16 + 20 + 20 * len(attrs)
    out = bytearray()
    out += _axml_node_header(_RES_XML_START_ELEM, size)
    out += struct.pack("<II", _NIL, name)  # element namespace, name
    out += struct.pack("<HHH", 20, 20, len(attrs))  # attr start, size, count
    out += struct.pack("<HHH", 0, 0, 0)  # id, class, style index (none)
    for a_ns, a_name, a_value in attrs:
        out += struct.pack("<III", a_ns, a_name, a_value)
        out += struct.pack("<HBBI", 8, 0, _TYPE_STRING, a_value)
    return bytes(out)


def _axml_end_elem(name: int) -> bytes:
    return _axml_node_header(_RES_XML_END_ELEM, 24) + struct.pack("<II", _NIL, name)


def _build_axml_manifest() -> bytes:
    s = _AxmlStrings()
    i_android = s.add("android")
    i_uri = s.add(_ANDROID_URI)
    i_package = s.add("package")
    i_pkg = s.add(_APK_PACKAGE)
    i_manifest = s.add("manifest")
    i_uses_perm = s.add("uses-permission")
    i_name = s.add("name")
    i_perm = s.add(_APK_PERMISSION)
    i_application = s.add("application")
    i_activity = s.add("activity")
    i_activity_val = s.add(_APK_ACTIVITY)
    i_intent = s.add("intent-filter")
    i_action = s.add("action")
    i_action_val = s.add("android.intent.action.MAIN")
    i_category = s.add("category")
    i_category_val = s.add("android.intent.category.LAUNCHER")

    body = bytearray()
    body += _axml_node_header(_RES_XML_START_NS, 24) + struct.pack("<II", i_android, i_uri)
    body += _axml_start_elem(i_manifest, [(_NIL, i_package, i_pkg)])
    body += _axml_start_elem(i_uses_perm, [(i_uri, i_name, i_perm)])
    body += _axml_end_elem(i_uses_perm)
    body += _axml_start_elem(i_application, [])
    body += _axml_start_elem(i_activity, [(i_uri, i_name, i_activity_val)])
    body += _axml_start_elem(i_intent, [])
    body += _axml_start_elem(i_action, [(i_uri, i_name, i_action_val)])
    body += _axml_end_elem(i_action)
    body += _axml_start_elem(i_category, [(i_uri, i_name, i_category_val)])
    body += _axml_end_elem(i_category)
    body += _axml_end_elem(i_intent)
    body += _axml_end_elem(i_activity)
    body += _axml_end_elem(i_application)
    body += _axml_end_elem(i_manifest)
    body += _axml_node_header(_RES_XML_END_NS, 24) + struct.pack("<II", i_android, i_uri)

    pool = _AxmlStrings.encode(s)
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", _RES_XML, 8, total) + pool + bytes(body)


def _build_valid_apk(path: Path) -> Path:
    """A minimal APK androguard fully parses (package/permission/activity)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", _build_axml_manifest())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)
        archive.writestr("resources.arsc", b"")
    return path


# --- Minimal *valid* classes.dex ------------------------------------------
#
# The valid manifest above lets androguard read the metadata, but the whole DEX
# side of the static line -- classes/methods/strings/xrefs -- still had no live
# coverage, because none of the fixtures carry a real DEX. Compiling one
# normally needs the Android build tools (d8/dx); to stay self-contained we
# hand-encode the DEX container the same way we do the AXML manifest. The result
# is one class (Lcom/example/gate/Sample;) with one static method helper()V
# whose body is `const-string v0, "gate-secret-marker"; return-void`, so
# androguard's analysis has a class to list, a method to enumerate, a string to
# surface and a call graph to walk. The Adler-32 checksum and SHA-1 signature
# are computed over the finished bytes exactly as the format requires, so a
# strict parser accepts it.
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


def _build_classes_dex() -> bytes:
    # DEX requires string_ids sorted by code point; keep the source list sorted.
    strings = [_DEX_CLASS, "Ljava/lang/Object;", "V", _DEX_STRING, _DEX_METHOD]
    assert strings == sorted(strings)
    s_void, s_marker, s_name = 2, 3, 4  # indices into `strings`
    # type_ids -> string index, itself sorted by string index: Sample, Object, V.
    type_to_str = [0, 1, 2]
    t_sample, t_object, t_void = 0, 1, 2

    header_size = 112
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    proto_ids_off = type_ids_off + 4 * len(type_to_str)
    method_ids_off = proto_ids_off + 12  # one proto ()V
    class_defs_off = method_ids_off + 8  # one method
    data_off = class_defs_off + 32  # one class_def

    def align4(pos: int) -> tuple[bytes, int]:
        pad = (-pos) % 4
        return b"\x00" * pad, pos + pad

    cursor = data_off
    string_data_offsets: list[int] = []
    string_data = bytearray()
    for value in strings:
        string_data_offsets.append(cursor)
        chunk = _uleb128(len(value)) + value.encode("utf-8") + b"\x00"
        string_data += chunk
        cursor += len(chunk)

    pad, cursor = align4(cursor)
    string_data += pad
    code_off = cursor
    # const-string v0, string@marker ; return-void  (3 code units)
    insns = struct.pack("<HHH", 0x001A, s_marker, 0x000E)
    code_item = struct.pack("<HHHH", 1, 0, 0, 0) + struct.pack("<II", 0, 3) + insns
    cursor += len(code_item)

    class_data_off = cursor
    class_data = (
        _uleb128(0) + _uleb128(0) + _uleb128(1) + _uleb128(0)  # static/instance/direct/virtual
        + _uleb128(0) + _uleb128(0x9) + _uleb128(code_off)  # method_idx_diff, public|static, code
    )
    cursor += len(class_data)

    map_pad, cursor = align4(cursor)
    map_off = cursor
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(type_to_str), type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 1, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, len(strings), data_off),
        (0x2001, 1, code_off),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    map_list = struct.pack("<I", len(map_items))
    for mtype, count, off in map_items:
        map_list += struct.pack("<HHII", mtype, 0, count, off)
    cursor += len(map_list)

    file_size = cursor
    string_ids = b"".join(struct.pack("<I", off) for off in string_data_offsets)
    type_ids = b"".join(struct.pack("<I", idx) for idx in type_to_str)
    proto_ids = struct.pack("<III", s_void, t_void, 0)
    method_ids = struct.pack("<HHI", t_sample, 0, s_name)
    class_defs = struct.pack(
        "<IiIIiIII", t_sample, 0x1, t_object, 0, -1, 0, class_data_off, 0
    )

    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    fields = [
        (32, file_size), (36, header_size), (40, 0x12345678), (44, 0), (48, 0),
        (52, map_off), (56, len(strings)), (60, string_ids_off),
        (64, len(type_to_str)), (68, type_ids_off), (72, 1), (76, proto_ids_off),
        (80, 0), (84, 0), (88, 1), (92, method_ids_off), (96, 1), (100, class_defs_off),
        (104, file_size - data_off), (108, data_off),
    ]
    for pos, val in fields:
        struct.pack_into("<I", header, pos, val)

    body = bytearray(
        bytes(header) + string_ids + type_ids + proto_ids + method_ids + class_defs
        + bytes(string_data) + code_item + bytes(class_data) + map_pad + map_list
    )
    assert len(body) == file_size, (len(body), file_size)
    body[12:32] = hashlib.sha1(bytes(body[32:])).digest()
    struct.pack_into("<I", body, 8, zlib.adler32(bytes(body[12:])) & 0xFFFFFFFF)
    return bytes(body)


def _build_apk_with_dex(path: Path) -> Path:
    """A valid APK carrying a real, analyzable classes.dex."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", _build_axml_manifest())
        archive.writestr("classes.dex", _build_classes_dex())
        archive.writestr("resources.arsc", b"")
    return path


# --- Minimal *valid* v1 (JAR) signature -----------------------------------
#
# apk.certificates only ever ran on the synthetic archive's failure path; the
# success path (androguard reading a real signer certificate) had no coverage
# and no fixture carried a signature. Signing normally needs the Java toolchain
# (apksigner/jarsigner); to keep this self-contained we hand-build the classic
# v1 JAR signature -- META-INF/MANIFEST.MF, CERT.SF and a PKCS#7 CERT.RSA over a
# throwaway self-signed cert -- with the `cryptography` library androguard
# already pulls in. androguard extracts the embedded X.509 without a JRE.
def _b64_sha256(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _build_v1_signed_apk(path: Path) -> Path:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    from cryptography.x509.oid import NameOID

    entries = {
        "AndroidManifest.xml": _build_axml_manifest(),
        "classes.dex": _build_classes_dex(),
    }
    manifest = "Manifest-Version: 1.0\r\nCreated-By: gate\r\n\r\n"
    sections: dict[str, str] = {}
    for name, data in entries.items():
        section = f"Name: {name}\r\nSHA-256-Digest: {_b64_sha256(data)}\r\n\r\n"
        sections[name] = section
        manifest += section
    manifest_bytes = manifest.encode("utf-8")

    sf = (
        "Signature-Version: 1.0\r\nCreated-By: gate\r\n"
        f"SHA-256-Digest-Manifest: {_b64_sha256(manifest_bytes)}\r\n\r\n"
    )
    for name, section in sections.items():
        sf += f"Name: {name}\r\nSHA-256-Digest: {_b64_sha256(section.encode('utf-8'))}\r\n\r\n"
    sf_bytes = sf.encode("utf-8")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CERT_CN)])
    not_before = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_CERT_SERIAL)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    pkcs7_der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(sf_bytes)
        .add_signer(cert, key, hashes.SHA256())
        .sign(
            Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.NoAttributes],
        )
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", manifest_bytes)
        archive.writestr("META-INF/CERT.SF", sf_bytes)
        archive.writestr("META-INF/CERT.RSA", pkcs7_der)
        for name_, data in entries.items():
            archive.writestr(name_, data)
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
        # not valid AXML, so apk.open must fail with a *structured* backend_error
        # -- androguard's constructor does not raise but leaves getters that do,
        # which used to fall through to the service's BaseException handler as an
        # internal_error with a logged incident (a bad APK misreported as a
        # server defect).
        opened = service.apk_open(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code == "backend_error"

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
def test_valid_apk_androguard_reads_real_static_facts(tmp_path: Path) -> None:
    """Live androguard coverage: a real, parseable APK, not just degradation.

    Every other Android assertion runs against the synthetic archive whose
    manifest is not valid AXML, so androguard could only ever be exercised on
    its failure path. This builds a genuine APK (hand-encoded binary manifest,
    no Android SDK needed) and asserts androguard extracts the package,
    permission and launcher activity that were actually encoded -- the
    in-process static line proving it works, not merely that it fails cleanly.
    """
    from headless_re_mcp.backends.apk import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "valid.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == _APK_PACKAGE
        assert opened.data["main_activity"] == _APK_ACTIVITY
        assert opened.data["permission_count"] >= 1
        assert "arm64-v8a" in opened.data["native_abis"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == _APK_PACKAGE
        assert "uses-permission" in manifest.data["manifest_xml"]

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert _APK_PERMISSION in perms.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert _APK_ACTIVITY in components.data["activities"]
        assert components.data["main_activity"] == _APK_ACTIVITY
    finally:
        service.close_all()


@pytest.mark.integration
def test_valid_apk_androguard_analyzes_the_dex(tmp_path: Path) -> None:
    """Live DEX coverage: androguard lists the class, method and string we encoded.

    The metadata gate proves the manifest side; this one drives the DEX side of
    the same static line (apk.classes / apk.methods / apk.strings / apk.xrefs),
    which had no live coverage because no fixture carried a real DEX. The APK
    embeds a hand-encoded classes.dex (no Android build tools) whose single class
    Lcom/example/gate/Sample; has one method helper() that references the string
    "gate-secret-marker", and we assert androguard's analysis surfaces exactly
    those facts rather than merely failing cleanly.
    """
    from headless_re_mcp.backends.apk import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — APK DEX gate not run (skip != pass)")
    apk = _build_apk_with_dex(tmp_path / "withdex.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert _DEX_CLASS in classes.data["classes"]
        assert classes.data["total"] >= 1

        methods = service.apk_methods(session_id, _DEX_CLASS)
        assert methods.ok, methods.error
        assert _DEX_METHOD in [m["name"] for m in methods.data["methods"]]

        # A dotted class name resolves the same class as the smali descriptor.
        dotted = service.apk_methods(session_id, "com.example.gate.Sample")
        assert dotted.ok, dotted.error
        assert dotted.data["class_name"] == _DEX_CLASS

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert _DEX_STRING in strings.data["strings"]

        # xrefs of an uncalled method is a structured, empty result, not a crash.
        xrefs = service.apk_xrefs(session_id, _DEX_METHOD)
        assert xrefs.ok, xrefs.error
        assert xrefs.data["method_name"] == _DEX_METHOD
        assert xrefs.data["has_more"] is False
        assert isinstance(xrefs.data["callers"], list)
    finally:
        service.close_all()


def _jadx_available() -> bool:
    from headless_re_mcp.backends.jadx import JadxClient

    return JadxClient(Settings.load().jadx).available


@pytest.mark.integration
def test_valid_apk_jadx_decompiles_the_dex(tmp_path: Path) -> None:
    """Live jadx coverage: the Java toolchain decompiles our real DEX in CI.

    jadx (and the Java toolchain generally) had no CI coverage — it needs a JRE
    and the jadx CLI, which the linux-integration job now installs. This drives
    the same hand-encoded DEX fixture through the decompiler: apk.export_sources
    must emit the one Java file for our class, apk.decompile must return its
    source carrying the package, class and method we encoded, and a class that
    was never compiled in must come back as a structured not_found rather than a
    crash. The output lands under a temp artifact root so nothing leaks. Skips
    only when jadx is genuinely absent (skip != pass).
    """
    if not _jadx_available():
        pytest.skip("jadx not configured — Java decompiler gate not run (skip != pass)")
    apk = _build_apk_with_dex(tmp_path / "withdex.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        exported = service.apk_export_sources(session_id, timeout=240.0)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        assert "sources/com/example/gate/Sample.java" in exported.data["java_files"]

        decompiled = service.apk_decompile(session_id, "com.example.gate.Sample", timeout=240.0)
        assert decompiled.ok, decompiled.error
        source = decompiled.data["source"]
        assert "package com.example.gate;" in source
        assert "class Sample" in source
        assert _DEX_METHOD in source

        missing = service.apk_decompile(session_id, "com.example.gate.DoesNotExist", timeout=240.0)
        assert missing.ok is False
        assert missing.error is not None
        assert missing.error.code == "not_found"
    finally:
        service.close_all()


def _apktool_available() -> bool:
    from headless_re_mcp.backends.apktool import ApktoolClient

    settings = Settings.load()
    return ApktoolClient(settings.apktool, settings.apksigner).available


@pytest.mark.integration
def test_valid_apk_apktool_decodes_and_repacks(tmp_path: Path) -> None:
    """Live apktool coverage: decode our real DEX to smali, then rebuild.

    apktool is the other half of the Java toolchain that had no CI coverage. It
    disassembles classes.dex to smali (where jadx recovers Java, apktool keeps
    the raw bytecode) and rebuilds an APK from an edited tree — the decode/repack
    loop RE workflows lean on. This drives the real DEX fixture through it:
    apk.decode must emit a smali tree containing our class (with the exact method
    and the const-string jadx folds away), and apk.repack must rebuild an APK
    from it. no_resources skips the hand-built empty resources.arsc; the DEX
    disassembly is the point. Skips only when apktool is absent (skip != pass).
    """
    if not _apktool_available():
        pytest.skip("apktool not configured — decode/repack gate not run (skip != pass)")
    apk = _build_apk_with_dex(tmp_path / "withdex.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=240.0, no_resources=True)
        assert decoded.ok, decoded.error
        assert "smali" in decoded.data["smali_dirs"]
        manifest = decoded.data["manifest"]
        assert manifest is not None and Path(manifest).is_file()

        smali = (
            Path(decoded.data["decoded_dir"])
            / "smali" / "com" / "example" / "gate" / "Sample.smali"
        )
        assert smali.is_file()
        body = smali.read_text(encoding="utf-8")
        assert ".class public Lcom/example/gate/Sample;" in body
        assert "helper()V" in body
        assert _DEX_STRING in body

        repacked = service.apk_repack(session_id, timeout=240.0)
        assert repacked.ok, repacked.error
        assert Path(repacked.data["apk"]).is_file()
        assert repacked.data["signed"] is False
    finally:
        service.close_all()


def _apksigner_available() -> bool:
    from headless_re_mcp.backends.apktool import ApktoolClient

    settings = Settings.load()
    return ApktoolClient(settings.apktool, settings.apksigner).signer_available


@pytest.mark.integration
def test_valid_apk_apksigner_signs_and_verifies_a_repack(tmp_path: Path) -> None:
    """Live apksigner coverage: sign a repacked APK and have apksigner verify it.

    apk.sign was the last Android Java-toolchain tool with no CI coverage. This
    closes the modify -> repack -> sign loop: decode the real DEX, rebuild the
    APK, generate a throwaway RSA keystore inside the session artifact tree with
    keytool, then sign against it. The backend runs `apksigner verify` right
    after signing, so a green envelope means the output really carries a valid
    signature -- we assert it reports signed with our (non-debug) keystore and
    that the signed APK landed on disk. Needs apktool + apksigner + keytool;
    skips cleanly otherwise (skip != pass).
    """
    if not (_apktool_available() and _apksigner_available()):
        pytest.skip("apktool/apksigner not configured — sign gate not run (skip != pass)")
    if shutil.which("keytool") is None:
        pytest.skip("keytool not available — sign gate not run (skip != pass)")
    apk = _build_apk_with_dex(tmp_path / "withdex.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        # apk.sign requires the keystore to live inside the session-owned artifact
        # tree; the apktool subtree (root/apktool/<id>) is one such owned root.
        keystore_dir = tmp_path / "artifacts" / "apktool" / session_id
        keystore_dir.mkdir(parents=True, exist_ok=True)
        keystore = keystore_dir / "signing.keystore"
        generated = subprocess.run(
            [
                "keytool", "-genkeypair", "-keystore", str(keystore),
                "-storepass", "testpass", "-keypass", "testpass",
                "-alias", "testkey", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "365", "-dname", "CN=Gate Test,O=Test,C=US",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert generated.returncode == 0, generated.stderr

        assert service.apk_decode(session_id, timeout=240.0, no_resources=True).ok
        assert service.apk_repack(session_id, timeout=240.0).ok

        signed = service.apk_sign(
            session_id,
            keystore=str(keystore),
            keystore_password="testpass",
            key_alias="testkey",
            timeout=240.0,
        )
        assert signed.ok, signed.error
        assert signed.data["signed"] is True
        assert signed.data["debug_keystore"] is False
        assert Path(signed.data["apk"]).is_file()
    finally:
        service.close_all()


def _cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


@pytest.mark.integration
def test_v1_signed_apk_androguard_reads_the_certificate(tmp_path: Path) -> None:
    """Live apk.certificates success path: androguard reads a real signer cert.

    Every other apk.certificates assertion runs on the synthetic archive, where
    it can only fail cleanly -- androguard reading an actual certificate had no
    coverage. Build an APK with a hand-crafted v1 JAR signature (self-signed
    cert, no JRE needed) and assert androguard reports it v1-signed, names the
    signature file, and returns the certificate with the exact serial we minted.
    Skips only if androguard or cryptography is missing (skip != pass).
    """
    from headless_re_mcp.backends.apk import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — certificate gate not run (skip != pass)")
    if not _cryptography_available():
        pytest.skip("cryptography not installed — certificate gate not run (skip != pass)")
    apk = _build_v1_signed_apk(tmp_path / "signed.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        certs = service.apk_certificates(session_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is True
        assert "META-INF/CERT.RSA" in certs.data["signature_files"]
        assert len(certs.data["certificates"]) >= 1
        first = certs.data["certificates"][0]
        assert first["serial"] == str(_CERT_SERIAL)
        assert first["sha256"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_malformed_apk_yields_structured_errors_not_incidents(tmp_path: Path) -> None:
    """A malformed APK is bad input, never a server defect.

    androguard is lenient: APK() does not raise on a broken manifest, so every
    apk.* method has to defend its own getters. Any that lets an androguard
    exception escape surfaces as internal_error with a logged incident, telling
    an unattended caller the server is broken when the sample is. Pin that none
    of them do that on the synthetic (invalid-AXML) archive.
    """
    from headless_re_mcp.backends.apk import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]
        calls = {
            "apk_open": lambda: service.apk_open(session_id),
            "apk_manifest": lambda: service.apk_manifest(session_id),
            "apk_permissions": lambda: service.apk_permissions(session_id),
            "apk_components": lambda: service.apk_components(session_id),
            "apk_native_libs": lambda: service.apk_native_libs(session_id),
            "apk_certificates": lambda: service.apk_certificates(session_id),
        }
        for name, call in calls.items():
            result = call()
            assert isinstance(result.ok, bool), name
            if not result.ok:
                assert result.error is not None, name
                assert result.error.code != "internal_error", (
                    f"{name} reported a malformed APK as a server incident"
                )
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
