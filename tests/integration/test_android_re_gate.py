"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.backends.jadx import JadxClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _string_data(text: str) -> bytes:
    # string_data_item: uleb128 UTF-16 length + MUTF-8 bytes + NUL (all ASCII here).
    return _uleb128(len(text)) + text.encode("utf-8") + b"\x00"


def _build_minimal_dex() -> bytes:
    """Assemble the smallest structurally valid classes.dex, byte by byte.

    One class Lcom/gate/Sample; extending Object, with two public-static
    methods: secret()V is [const-string v0, "gate-secret"; return-void] and
    caller()V is [invoke-static {} secret; return-void]. That is exactly enough
    for androguard's AnalyzeAPK to build its real object graph: a defined
    (non-external) ClassAnalysis, EncodedMethods with descriptors and access
    flags, a referenced StringAnalysis, and -- through the invoke-static -- a
    non-empty xref table, so xrefs can prove the caller-rendering loop and not
    just the found-but-uncalled answer. Same in-process-fixture approach as the
    hand-assembled WASM module and the compiled ELF fixture: no binary blob
    checked in, every byte explained here. DEX rules honored: string_ids sorted
    by content, type_ids by string index, method_ids by (class, name), adler32
    checksum over bytes[12:] and SHA-1 signature over bytes[32:].
    """
    strings = ["Lcom/gate/Sample;", "Ljava/lang/Object;", "V", "caller", "gate-secret", "secret"]
    s_caller, s_gate, s_secret = 3, 4, 5  # indices into the sorted pool used below

    header_size = 112
    string_ids_off = header_size  # 6 * 4 bytes
    type_ids_off = string_ids_off + 24  # 3 * 4 bytes
    proto_ids_off = type_ids_off + 12  # 1 * 12 bytes
    method_ids_off = proto_ids_off + 12  # 2 * 8 bytes
    class_defs_off = method_ids_off + 16  # 1 * 32 bytes
    data_off = class_defs_off + 32

    # --- data section: string_data, code_items, class_data, map_list ---
    data = bytearray()
    offset = data_off
    string_offsets = []
    for text in strings:
        string_offsets.append(offset)
        chunk = _string_data(text)
        data += chunk
        offset += len(chunk)
    while offset % 4:  # code_item is 4-byte aligned
        data += b"\x00"
        offset += 1
    caller_code_off = offset
    # invoke-static {} method#1 (secret, format 35c with zero args); return-void.
    insns = bytes([0x71, 0x00]) + struct.pack("<H", 1) + b"\x00\x00" + bytes([0x0E, 0x00])
    code_item = struct.pack("<HHHHII", 0, 0, 0, 0, 0, len(insns) // 2) + insns
    data += code_item
    offset += len(code_item)
    while offset % 4:
        data += b"\x00"
        offset += 1
    secret_code_off = offset
    # const-string v0, "gate-secret" (format 21c); return-void.
    insns = bytes([0x1A, 0x00]) + struct.pack("<H", s_gate) + bytes([0x0E, 0x00])
    code_item = struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(insns) // 2) + insns
    data += code_item
    offset += len(code_item)
    class_data_off = offset
    # 0 static fields, 0 instance fields, 2 direct methods, 0 virtual methods;
    # per method: uleb method_idx_diff, access=public|static (0x9), code_off.
    class_data = bytes([0, 0, 2, 0])
    class_data += _uleb128(0) + _uleb128(0x9) + _uleb128(caller_code_off)  # method 0: caller
    class_data += _uleb128(1) + _uleb128(0x9) + _uleb128(secret_code_off)  # method 1: secret
    data += class_data
    offset += len(class_data)
    while offset % 4:  # map_list is 4-byte aligned
        data += b"\x00"
        offset += 1
    map_off = offset
    map_items = [  # (TYPE_*_ITEM code, item count, section offset), ordered by offset
        (0x0000, 1, 0),
        (0x0001, 6, string_ids_off),
        (0x0002, 3, type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 2, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, 6, data_off),
        (0x2001, 2, caller_code_off),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    map_list = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", kind, 0, count, item_off) for kind, count, item_off in map_items
    )
    data += map_list
    offset += len(map_list)
    file_size = offset

    # --- fixed index tables ---
    string_ids = b"".join(struct.pack("<I", o) for o in string_offsets)
    type_ids = b"".join(struct.pack("<I", i) for i in (0, 1, 2))  # Sample, Object, V
    proto_ids = struct.pack("<III", 2, 2, 0)  # shorty "V", return type V, no params
    method_ids = struct.pack("<HHI", 0, 0, s_caller) + struct.pack("<HHI", 0, 0, s_secret)
    class_defs = struct.pack(
        "<IIIIIIII", 0, 0x1, 1, 0, 0xFFFFFFFF, 0, class_data_off, 0
    )  # public Sample extends Object, no source file / annotations / static values

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<II", header, 56, 6, string_ids_off)
    struct.pack_into("<II", header, 64, 3, type_ids_off)
    struct.pack_into("<II", header, 72, 1, proto_ids_off)
    struct.pack_into("<II", header, 88, 2, method_ids_off)
    struct.pack_into("<II", header, 96, 1, class_defs_off)
    struct.pack_into("<II", header, 104, file_size - data_off, data_off)

    dex = header + string_ids + type_ids + proto_ids + method_ids + class_defs + data
    assert len(dex) == file_size
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    struct.pack_into("<I", dex, 8, zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF)
    return bytes(dex)


def _build_dex_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", _build_minimal_dex())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
    return path


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

        # androguard opens a real APK; on the synthetic archive it must still
        # answer with a structured envelope rather than raising.
        opened = service.apk_open(session_id)
        assert isinstance(opened.ok, bool)
        if ApkClient().available:
            # Real androguard tolerates the unparseable synthetic manifest and
            # opens the zip, but its package name comes back empty. apk.open
            # refuses that with a *structured* backend_error -- it will not
            # answer {opened: True} for a zip that is not really an APK, nor leak
            # a raw KeyError from get_androidversion_name/code that the service
            # would file as an internal_error incident.
            assert opened.ok is False
            assert opened.error is not None
            assert opened.error.code == "backend_error"
        else:
            # No androguard: a clean capability_unavailable, not a crash.
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
def test_android_dex_operations_parse_a_real_dex(tmp_path: Path) -> None:
    """classes / methods / strings / xrefs against androguard's real DEX parse.

    The synthetic APK above carries a junk classes.dex, so on it every DEX op
    can only exercise the backend_error path -- AnalyzeAPK rejects the file
    before any analysis object exists. The successful path (get_classes with
    is_external filtering, get_methods with descriptor/access rendering,
    get_strings, and the xref scan with its caller-rendering loop) therefore ran
    only against fake objects in unit tests. androguard needs no external tool,
    just a structurally valid .dex, so this hand-assembles the smallest real one
    and drives all four operations through the service on it (skip != pass when
    androguard is absent).
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK DEX Gate not run (skip != pass)")
    apk = _build_dex_apk(tmp_path / "real.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["classes"] == ["Lcom/gate/Sample;"]
        assert classes.data["total"] == 1
        assert classes.data["has_more"] is False

        methods = service.apk_methods(session_id, "Lcom/gate/Sample;")
        assert methods.ok, methods.error
        assert methods.data["methods"] == [
            {"name": "caller", "descriptor": "()V", "access": "public static"},
            {"name": "secret", "descriptor": "()V", "access": "public static"},
        ]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        # The const-string operand must surface among the pool entries.
        assert "gate-secret" in strings.data["strings"]

        # The invoke-static in caller() must land in androguard's xref table, so
        # the caller-rendering loop -- not just the found-but-uncalled branch --
        # runs against a real analysis.
        xrefs = service.apk_xrefs(session_id, "secret")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["method_name"] == "secret"
        assert xrefs.data["callers"] == [{"class": "Lcom/gate/Sample;", "method": "caller"}]
        assert xrefs.data["count"] == 1

        # And the uncalled method still gets the honest empty answer, not an
        # error envelope.
        uncalled = service.apk_xrefs(session_id, "caller")
        assert uncalled.ok, uncalled.error
        assert uncalled.data["callers"] == []
        assert uncalled.data["count"] == 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_native_libs_answer_despite_an_unparseable_manifest(tmp_path: Path) -> None:
    """apk.native_libs against androguard's real zip walk, junk manifest and all.

    native_libs reads the archive listing (apk.get_files), not the manifest, so
    it must keep answering on an APK whose AndroidManifest.xml androguard cannot
    parse -- the exact archive apk.open refuses with backend_error. That split
    (metadata ops refuse, content ops still work) only ever ran against stubs;
    real androguard logs a manifest parse error while still serving the file
    list, which is the behavior this pins (skip != pass without androguard).
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — native_libs Gate not run (skip != pass)")
    apk = _build_dex_apk(tmp_path / "real.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert libs.data["native_libs"] == ["lib/arm64-v8a/libnative.so"]
        assert libs.data["abis"] == ["arm64-v8a"]
        assert libs.data["count"] == 1
        assert libs.data["has_more"] is False
    finally:
        service.close_all()


def _sign_v1_in_place(apk: Path, workdir: Path) -> None:
    """JAR-sign the APK with a throwaway debug key (keytool + jarsigner)."""
    store = ["-keystore", str(workdir / "debug.keystore")]
    store += ["-storepass", "android", "-keypass", "android"]
    keytool = ["keytool", "-genkeypair", *store, "-alias", "androiddebugkey"]
    keytool += ["-keyalg", "RSA", "-keysize", "2048", "-validity", "10000"]
    keytool += ["-dname", "CN=Android Debug,O=Android,C=US"]
    subprocess.run(keytool, check=True, capture_output=True, timeout=120)
    jarsigner = ["jarsigner", *store, "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256"]
    jarsigner += [str(apk), "androiddebugkey"]
    subprocess.run(jarsigner, check=True, capture_output=True, timeout=120)


@pytest.mark.integration
def test_apk_certificates_parse_a_real_v1_signature(tmp_path: Path) -> None:
    """apk.certificates against a genuinely signed APK, and the unsigned negative.

    The certificate op walks androguard's PKCS7 parse -- get_signature_names,
    get_certificates, then per-certificate attribute extraction whose object
    shape (subject/issuer/serial_number/sha256_fingerprint) varies by androguard
    version, exactly the client-library drift that broke frida 17. It only ever
    ran against hand-rolled fakes; the apksigner gate verifies its own signature
    with apksigner, never through this op. A JAR (v1) signature from the JDK's
    own keytool+jarsigner is precisely the META-INF/*.RSA layout the op reads,
    so this signs the hand-assembled DEX APK with a throwaway debug key and
    asserts the real parse: the .RSA signature file is found, v1_signed flips
    true, and the one certificate comes back with its debug subject, serial and
    fingerprint. The unsigned twin must answer the honest empty shape -- not an
    error -- and the session metadata's stdlib signed_v1 sniff must agree with
    androguard on both (skip != pass without androguard or a JDK).
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — certificates Gate not run (skip != pass)")
    if not (shutil.which("keytool") and shutil.which("jarsigner")):
        pytest.skip("JDK keytool/jarsigner missing — certificates Gate not run (skip != pass)")

    unsigned = _build_dex_apk(tmp_path / "unsigned.apk")
    signed = _build_dex_apk(tmp_path / "signed.apk")
    _sign_v1_in_place(signed, tmp_path)

    service = AnalysisService()
    try:
        created = service.create_session(str(signed))
        assert created.ok, created.error
        assert created.data["session"]["metadata"]["apk"]["signed_v1"] is True
        signed_id = created.data["session"]["id"]

        certs = service.apk_certificates(signed_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is True
        assert len(certs.data["signature_files"]) == 1
        assert certs.data["signature_files"][0].startswith("META-INF/")
        assert certs.data["signature_files"][0].endswith(".RSA")
        assert len(certs.data["certificates"]) == 1
        cert = certs.data["certificates"][0]
        # Self-signed debug key: the CN appears in both subject and issuer.
        assert "Android Debug" in cert["subject"]
        assert "Android Debug" in cert["issuer"]
        assert cert["serial"].strip()
        assert cert["sha256"].strip()
        assert certs.data["has_more"] is False

        created = service.create_session(str(unsigned))
        assert created.ok, created.error
        assert created.data["session"]["metadata"]["apk"]["signed_v1"] is False
        plain = service.apk_certificates(created.data["session"]["id"])
        assert plain.ok, plain.error
        assert plain.data["v1_signed"] is False
        assert plain.data["signature_files"] == []
        assert plain.data["certificates"] == []
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_jadx_decompiles_the_real_dex(tmp_path: Path) -> None:
    """apk.export_sources and apk.decompile against a real jadx run.

    The jadx adapter had no live coverage at all -- export_sources / decompile,
    the _class_to_java_path mapping, the sources-root escape guards, and the
    _capped_java_listing tree summary were exercised only against a stubbed
    subprocess in unit tests. jadx is a real Java decompiler that turns the same
    hand-assembled DEX into Java, so this drives both service ops on it: export
    must summarise a tree containing com/gate/Sample.java, and decompile of
    Lcom/gate/Sample; must return source with the class and both methods (skip
    != pass when jadx is not configured on this machine).
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    if not JadxClient(getattr(settings, "jadx", None)).available:
        pytest.skip("jadx not configured — APK decompile Gate not run (skip != pass)")
    apk = _build_dex_apk(tmp_path / "real.apk")
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id, timeout=120.0)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        assert exported.data["sources_dir"] is not None
        # The tree summary must name the class jadx recovered from the DEX.
        assert any(
            str(name).endswith("com/gate/Sample.java") for name in exported.data["java_files"]
        ), exported.data["java_files"]

        decompiled = service.apk_decompile(session_id, "Lcom/gate/Sample;", timeout=120.0)
        assert decompiled.ok, decompiled.error
        assert decompiled.data["path"].endswith("Sample.java")
        assert decompiled.data["truncated"] is False
        source = decompiled.data["source"]
        # jadx reconstructs the class and both public-static methods; the
        # invoke-static shows up as the secret() call inside caller().
        assert "class Sample" in source
        assert "secret" in source
        assert "caller" in source
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
