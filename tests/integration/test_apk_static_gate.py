"""APK static-analysis gate: real androguard parsing, end to end.

The unit tests mock androguard's parse results, so an API break in a new
androguard release (methods removed or renamed, a changed manifest decode) would
pass every unit test and only fail in production -- exactly how the frida
``Memory.read*`` removal slipped through. There was no APK fixture to parse, so
this gate builds a minimal but genuinely valid APK in pure Python (a compiled
binary ``AndroidManifest.xml`` plus a real zip layout) and drives the whole
manifest-level surface through the service: package, version, permissions, all
four component kinds, the launcher activity, native ABIs, certificates, and the
DEX-analysis pipeline. It skips with an explicit "skip != pass" when androguard
is not installed.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.core.service import AnalysisService

_ANDROID_URI = "http://schemas.android.com/apk/res/android"
_DEX_CLASS = "Lcom/example/headlessre/Secret;"
_DEX_SUPER = "Ljava/lang/Object;"
_DEX_METHOD = "decrypt"


class _StringPool:
    """The AXML string pool: dedup, then emit a UTF-8 ResStringPool chunk."""

    def __init__(self) -> None:
        self._items: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str | None) -> int:
        if value is None:
            return 0xFFFFFFFF
        if value not in self._index:
            self._index[value] = len(self._items)
            self._items.append(value)
        return self._index[value]

    def build(self) -> bytes:
        data = b""
        offsets: list[int] = []
        for item in self._items:
            offsets.append(len(data))
            encoded = item.encode("utf-8")
            # Only short ASCII strings are used here, so a single length byte
            # (utf-16 units, then utf-8 bytes) is always enough.
            assert len(item) < 128 and len(encoded) < 128
            data += bytes([len(item), len(encoded)]) + encoded + b"\x00"
        while len(data) % 4:
            data += b"\x00"
        count = len(self._items)
        strings_start = 0x1C + 4 * count
        body = struct.pack("<IIIII", count, 0, 0x100, strings_start, 0)
        body += b"".join(struct.pack("<I", off) for off in offsets)
        body += data
        return struct.pack("<HHI", 0x0001, 0x1C, 8 + len(body)) + body


def _node(node_type: int, payload: bytes) -> bytes:
    body = struct.pack("<II", 1, 0xFFFFFFFF) + payload
    return struct.pack("<HHI", node_type, 0x10, 8 + len(body)) + body


def _build_manifest_axml() -> bytes:
    """A compiled binary AndroidManifest.xml androguard parses like aapt's."""
    pool = _StringPool()
    android = _ANDROID_URI
    prefix_idx = pool.add("android")
    uri_idx = pool.add(android)

    # (kind, name, attrs) where attrs is [(ns, name, value)].
    tree: list[tuple[str, str, list[tuple[str | None, str, str]]]] = [
        ("start", "manifest", [
            (None, "package", "com.example.headlessre"),
            (android, "versionCode", "7"),
            (android, "versionName", "1.2.3"),
        ]),
        ("start", "uses-permission", [(android, "name", "android.permission.INTERNET")]),
        ("end", "uses-permission", []),
        ("start", "uses-permission", [(android, "name", "android.permission.CAMERA")]),
        ("end", "uses-permission", []),
        ("start", "application", [(android, "label", "HeadlessRE Test")]),
        ("start", "activity", [(android, "name", "com.example.headlessre.MainActivity")]),
        ("start", "intent-filter", []),
        ("start", "action", [(android, "name", "android.intent.action.MAIN")]),
        ("end", "action", []),
        ("start", "category", [(android, "name", "android.intent.category.LAUNCHER")]),
        ("end", "category", []),
        ("end", "intent-filter", []),
        ("end", "activity", []),
        ("start", "service", [(android, "name", "com.example.headlessre.SyncService")]),
        ("end", "service", []),
        ("start", "receiver", [(android, "name", "com.example.headlessre.BootReceiver")]),
        ("end", "receiver", []),
        ("start", "provider", [(android, "name", "com.example.headlessre.DataProvider")]),
        ("end", "provider", []),
        ("end", "application", []),
        ("end", "manifest", []),
    ]

    # Register every string first so pool indices are stable before emitting.
    for _kind, name, attrs in tree:
        pool.add(name)
        for a_ns, a_name, a_val in attrs:
            pool.add(a_ns)
            pool.add(a_name)
            pool.add(a_val)

    nodes = [_node(0x0100, struct.pack("<II", prefix_idx, uri_idx))]
    for kind, name, attrs in tree:
        if kind == "start":
            payload = struct.pack("<II", 0xFFFFFFFF, pool.add(name))
            payload += struct.pack("<HH", 0x14, 0x14)
            payload += struct.pack("<I", len(attrs))
            payload += struct.pack("<I", 0)
            for a_ns, a_name, a_val in attrs:
                value_idx = pool.add(a_val)
                payload += struct.pack("<I", pool.add(a_ns))
                payload += struct.pack("<I", pool.add(a_name))
                payload += struct.pack("<I", value_idx)
                payload += struct.pack("<I", 8 | (0x03 << 24))
                payload += struct.pack("<I", value_idx)
            nodes.append(_node(0x0102, payload))
        else:
            nodes.append(_node(0x0103, struct.pack("<II", 0xFFFFFFFF, pool.add(name))))
    nodes.append(_node(0x0101, struct.pack("<II", prefix_idx, uri_idx)))

    rest = pool.build() + b"".join(nodes)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(rest)) + rest


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


def _mutf8(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _uleb128(len(text)) + encoded + b"\x00"


def _build_classes_dex() -> bytes:
    """A minimal but valid classes.dex: one class with one native method.

    Enough for the analysis pipeline to return real data -- a class name, a
    method, and the DEX string pool -- with correct adler32 checksum and SHA-1
    signature so androguard accepts it. No code item is needed to list them.
    """
    strings = sorted({_DEX_CLASS, _DEX_SUPER, "V", _DEX_METHOD})
    sidx = {value: i for i, value in enumerate(strings)}
    type_descs = sorted({_DEX_CLASS, _DEX_SUPER, "V"}, key=lambda d: sidx[d])
    tidx = {value: i for i, value in enumerate(type_descs)}

    n_str, n_type, n_proto, n_method, n_class = len(strings), len(type_descs), 1, 1, 1
    off = 0x70
    string_ids_off = off
    off += 4 * n_str
    type_ids_off = off
    off += 4 * n_type
    proto_ids_off = off
    off += 12 * n_proto
    method_ids_off = off
    off += 8 * n_method
    class_defs_off = off
    off += 32 * n_class
    data_off = off

    data = bytearray()

    def emit(chunk: bytes) -> int:
        pos = data_off + len(data)
        data.extend(chunk)
        return pos

    class_data = bytearray()
    class_data += _uleb128(0) + _uleb128(0) + _uleb128(1) + _uleb128(0)
    class_data += _uleb128(0) + _uleb128(0x101) + _uleb128(0)  # public|native, no code
    class_data_off = emit(bytes(class_data))

    string_data_offs = [emit(_mutf8(value)) for value in strings]

    while (data_off + len(data)) % 4:
        data.extend(b"\x00")
    map_off = data_off + len(data)
    map_items = [
        (0x0000, 1, 0),
        (0x0001, n_str, string_ids_off),
        (0x0002, n_type, type_ids_off),
        (0x0003, n_proto, proto_ids_off),
        (0x0005, n_method, method_ids_off),
        (0x0006, n_class, class_defs_off),
        (0x2000, 1, class_data_off),
        (0x2002, n_str, string_data_offs[0]),
        (0x1000, 1, map_off),
    ]
    map_bytes = bytearray(struct.pack("<I", len(map_items)))
    for kind, size, offset in map_items:
        map_bytes += struct.pack("<HHII", kind, 0, size, offset)
    emit(bytes(map_bytes))
    data_size = len(data)

    string_ids = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_ids = b"".join(struct.pack("<I", sidx[d]) for d in type_descs)
    proto_ids = struct.pack("<III", sidx["V"], tidx["V"], 0)
    method_ids = struct.pack("<HHI", tidx[_DEX_CLASS], 0, sidx[_DEX_METHOD])
    class_defs = struct.pack(
        "<IIIIIIII",
        tidx[_DEX_CLASS], 0x1, tidx[_DEX_SUPER], 0, 0xFFFFFFFF, 0, class_data_off, 0,
    )
    body = string_ids + type_ids + proto_ids + method_ids + class_defs + bytes(data)

    header = bytearray()
    header += b"dex\n035\x00"
    header += b"\x00\x00\x00\x00"  # checksum, filled below
    header += b"\x00" * 20  # signature, filled below
    header += struct.pack("<I", 0x70 + len(body))
    header += struct.pack("<I", 0x70)
    header += struct.pack("<I", 0x12345678)
    header += struct.pack("<II", 0, 0)
    header += struct.pack("<I", map_off)
    header += struct.pack("<II", n_str, string_ids_off)
    header += struct.pack("<II", n_type, type_ids_off)
    header += struct.pack("<II", n_proto, proto_ids_off)
    header += struct.pack("<II", 0, 0)
    header += struct.pack("<II", n_method, method_ids_off)
    header += struct.pack("<II", n_class, class_defs_off)
    header += struct.pack("<II", data_size, data_off)

    dex = bytearray(bytes(header) + body)
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    dex[8:12] = struct.pack("<I", zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF)
    return bytes(dex)


def _build_apk(dest: Path) -> Path:
    axml = _build_manifest_axml()
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", axml)
        zf.writestr("classes.dex", _build_classes_dex())
        zf.writestr("resources.arsc", b"")
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("lib/x86_64/libnative.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("assets/config.json", b'{"k":1}')
    return dest


# --- A second, apksigner-parseable manifest ------------------------------
# apksigner (unlike androguard) needs a real <uses-sdk minSdkVersion> to pick a
# JAR-signature digest: with no minSdkVersion it assumes API 1 and then rejects
# its own SHA-256 v1 signature as unsupported below API 18. apksig finds that
# attribute *by resource id* (0x0101020c) via the XML resource-map chunk, not by
# name, and the value must be an int -- so this builds a minimal manifest with
# "minSdkVersion" at string index 0, a resource map pointing index 0 at the
# framework attribute id, and the value typed as TYPE_INT_DEC.
_MIN_SDK_ATTR_ID = 0x0101020C
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10


def _attr(pool: _StringPool, ns: str | None, name: str, *, data_type: int, data: int) -> bytes:
    raw = 0xFFFFFFFF if data_type != _TYPE_STRING else data
    return (
        struct.pack("<I", pool.add(ns))
        + struct.pack("<I", pool.add(name))
        + struct.pack("<I", raw)
        + struct.pack("<I", 8 | (data_type << 24))
        + struct.pack("<I", data)
    )


def _start(pool: _StringPool, name: str, attrs: bytes, count: int) -> bytes:
    payload = struct.pack("<II", 0xFFFFFFFF, pool.add(name))
    payload += struct.pack("<HH", 0x14, 0x14)
    payload += struct.pack("<I", count)
    payload += struct.pack("<I", 0)
    return _node(0x0102, payload + attrs)


def _end(pool: _StringPool, name: str) -> bytes:
    return _node(0x0103, struct.pack("<II", 0xFFFFFFFF, pool.add(name)))


def _build_signable_manifest_axml() -> bytes:
    pool = _StringPool()
    # index 0 must be minSdkVersion so resource_map[0] carries its attribute id.
    assert pool.add("minSdkVersion") == 0
    android = _ANDROID_URI
    prefix_idx = pool.add("android")
    uri_idx = pool.add(android)

    pkg = pool.add("com.example.headlessre")
    manifest = _start(
        pool, "manifest", _attr(pool, None, "package", data_type=_TYPE_STRING, data=pkg), 1
    )
    uses_sdk = _start(
        pool,
        "uses-sdk",
        _attr(pool, android, "minSdkVersion", data_type=_TYPE_INT_DEC, data=21),
        1,
    )
    application = _start(pool, "application", b"", 0)

    resource_map = struct.pack("<HHI", 0x0180, 8, 8 + 4) + struct.pack("<I", _MIN_SDK_ATTR_ID)

    nodes = [
        _node(0x0100, struct.pack("<II", prefix_idx, uri_idx)),
        manifest,
        uses_sdk,
        _end(pool, "uses-sdk"),
        application,
        _end(pool, "application"),
        _end(pool, "manifest"),
        _node(0x0101, struct.pack("<II", prefix_idx, uri_idx)),
    ]
    rest = pool.build() + resource_map + b"".join(nodes)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(rest)) + rest


def _build_signable_apk(dest: Path) -> Path:
    """A minimal APK whose binary manifest apksigner can actually parse."""
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", _build_signable_manifest_axml())
        zf.writestr("classes.dex", _build_classes_dex())
    return dest


def _androguard_available() -> bool:
    try:
        import androguard.core.apk  # noqa: F401
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_apk_static_pipeline_parses_a_real_manifest(tmp_path: Path) -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — APK static Gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        assert created.data["session"].get("target") == "apk"
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == "com.example.headlessre"
        assert opened.data["version_code"] == "7"
        assert opened.data["version_name"] == "1.2.3"
        assert opened.data["main_activity"] == "com.example.headlessre.MainActivity"
        assert sorted(opened.data["native_abis"]) == ["arm64-v8a", "x86_64"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.headlessre"
        assert "<manifest" in manifest.data["manifest_xml"]
        assert "com.example.headlessre.MainActivity" in manifest.data["manifest_xml"]

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert "android.permission.INTERNET" in perms.data["permissions"]
        assert "android.permission.CAMERA" in perms.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == ["com.example.headlessre.MainActivity"]
        assert components.data["services"] == ["com.example.headlessre.SyncService"]
        assert components.data["receivers"] == ["com.example.headlessre.BootReceiver"]
        assert components.data["providers"] == ["com.example.headlessre.DataProvider"]
        assert components.data["main_activity"] == "com.example.headlessre.MainActivity"

        # The launcher activity carries an intent-filter and no explicit flag,
        # so it reads as exported; the other components declare neither, so the
        # attack-surface map lists only the activity. This is the whole reason
        # to parse the manifest tree rather than just enumerate names.
        details = components.data["details"]
        main_detail = next(
            row
            for row in details["activities"]
            if row["name"] == "com.example.headlessre.MainActivity"
        )
        assert main_detail["exported"] is True
        assert main_detail["exported_explicit"] is None
        assert main_detail["has_intent_filter"] is True
        # The launcher filter's action/category must round-trip out of the real
        # binary manifest, not just the has_intent_filter boolean.
        assert main_detail["intent_filters"] == [
            {
                "actions": ["android.intent.action.MAIN"],
                "categories": ["android.intent.category.LAUNCHER"],
            }
        ]
        svc_detail = details["services"][0]
        assert svc_detail["exported"] is False
        assert svc_detail["has_intent_filter"] is False
        # The fixture declares no uses-sdk, so androguard resolves the effective
        # targetSdk to 1; below API 17 a filterless provider is exported by
        # default. That the DataProvider lands in the exported map -- while the
        # service/receiver do not -- proves the API-17 provider rule fires on a
        # real binary manifest, not just in the unit stubs.
        prov_detail = details["providers"][0]
        assert prov_detail["exported"] is True
        assert prov_detail["exported_explicit"] is None
        assert prov_detail["has_intent_filter"] is False
        assert components.data["exported"] == {
            "activities": ["com.example.headlessre.MainActivity"],
            "services": [],
            "receivers": [],
            "providers": ["com.example.headlessre.DataProvider"],
        }

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert sorted(libs.data["abis"]) == ["arm64-v8a", "x86_64"]
        assert libs.data["count"] == 2

        certs = service.apk_certificates(session_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is False
        assert certs.data["v2_signed"] is False
        assert certs.data["v3_signed"] is False
        assert certs.data["signed"] is False
        assert certs.data["certificates"] == []

        # The DEX-analysis pipeline (AnalyzeAPK, Analysis, get_classes,
        # klass.get_methods, get_strings, get_xref_from) is the API surface a
        # version bump could break; drive it against a real classes.dex.
        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["total"] == 1
        assert _DEX_CLASS in classes.data["classes"]
        assert classes.data["scan_capped"] is False

        # A dotted class name must resolve to the smali descriptor internally.
        methods = service.apk_methods(session_id, "com.example.headlessre.Secret")
        assert methods.ok, methods.error
        assert methods.data["total"] == 1
        method = methods.data["methods"][0]
        assert method["name"] == _DEX_METHOD
        assert method["descriptor"] == "()V"

        strings = service.apk_strings(session_id, limit=50)
        assert strings.ok, strings.error
        assert _DEX_METHOD in strings.data["strings"]
        assert _DEX_CLASS in strings.data["strings"]

        # xrefs must traverse the analysis graph and return cleanly even when
        # the target method has no callers.
        xrefs = service.apk_xrefs(session_id, _DEX_METHOD)
        assert xrefs.ok, xrefs.error
        assert xrefs.data["callers"] == []
    finally:
        service.close_all()


def _jadx_available() -> bool:
    return AnalysisService().settings.jadx is not None


def _build_resourceless_apk(dest: Path) -> Path:
    """An APK with no resources.arsc, which apktool decodes and rebuilds cleanly.

    apktool refuses to decode a placeholder/empty resources.arsc, and its build
    step only recompiles the manifest to binary when a framework is installed;
    a resource-free tree sidesteps both and still exercises the smali round trip.
    """
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", _build_manifest_axml())
        zf.writestr("classes.dex", _build_classes_dex())
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("assets/config.json", b'{"k":1}')
    return dest


def _apktool_available() -> bool:
    return AnalysisService().settings.apktool is not None


def _apksigner_available() -> bool:
    return AnalysisService().settings.apksigner is not None


@pytest.mark.integration
def test_apk_apktool_decode_and_repack(tmp_path: Path) -> None:
    """The apktool resource line -- decode to smali, then rebuild -- had no test.

    Both are thin subprocess wrappers over apktool whose contract (the ``d``/``b``
    argument vectors, the decoded-tree shape, and the "AndroidManifest.xml must
    exist" success check) only shows up against a real apktool. Drive both
    through the service and assert the decode yields a text manifest plus a smali
    directory and that the rebuild produces an unsigned APK.
    """
    if not _apktool_available():
        pytest.skip("apktool not configured — APK apktool Gate not run (skip != pass)")
    apk = _build_resourceless_apk(tmp_path / "resourceless.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=180.0)
        assert decoded.ok, decoded.error
        assert decoded.data["smali_dirs"], "apktool produced no smali directory"
        assert decoded.data["has_resources"] is False
        manifest_text = Path(decoded.data["manifest"]).read_text(encoding="utf-8")
        assert manifest_text.lstrip().startswith("<?xml")
        assert "com.example.headlessre" in manifest_text

        repacked = service.apk_repack(session_id, timeout=180.0)
        assert repacked.ok, repacked.error
        rebuilt = Path(repacked.data["apk"])
        assert rebuilt.is_file() and rebuilt.stat().st_size > 0
        assert repacked.data["signed"] is False
        with zipfile.ZipFile(rebuilt) as zf:
            assert "classes.dex" in zf.namelist()
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_sign_produces_a_verifiable_apk(tmp_path: Path) -> None:
    """apk.sign wraps apksigner's sign+verify; nothing exercised the real CLI.

    The wrapper builds an argument vector with four password-bearing flags, then
    re-invokes apksigner to verify its own output and only reports success when
    that verify passes. apksigner's flag names and its refusal to sign an APK
    whose manifest lacks a parseable minSdkVersion are exactly the kind of
    contract a mock can't hold, so sign a real (freshly generated) keystore over
    an APK with a genuine binary manifest and confirm the output verifies.
    """
    if not _apksigner_available():
        pytest.skip("apksigner not configured — APK sign Gate not run (skip != pass)")
    keytool = shutil.which("keytool")
    if keytool is None:
        pytest.skip("keytool not installed — cannot mint a test keystore (skip != pass)")

    keystore = tmp_path / "test.jks"
    generated = subprocess.run(
        [
            keytool, "-genkeypair", "-keystore", str(keystore),
            "-storepass", "storepass", "-keypass", "storepass",
            "-alias", "gatekey", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "365", "-dname", "CN=headless-re gate,O=test,C=US",
        ],
        capture_output=True,
        timeout=120,
    )
    assert generated.returncode == 0, generated.stderr.decode("utf-8", "replace")

    apk = _build_signable_apk(tmp_path / "signable.apk")
    out_apk = tmp_path / "signed.apk"
    settings = AnalysisService().settings
    client = ApktoolClient(settings.apktool, settings.apksigner)

    result = client.sign(
        apk,
        out_apk,
        keystore=keystore,
        keystore_password="storepass",
        key_alias="gatekey",
        timeout=180.0,
    )
    assert result["signed"] is True
    assert result["debug_keystore"] is False
    assert out_apk.is_file() and out_apk.stat().st_size > apk.stat().st_size
    with zipfile.ZipFile(out_apk) as zf:
        names = zf.namelist()
        assert any(n.startswith("META-INF/") and n.endswith(".RSA") for n in names), (
            "the signed APK carries no v1 JAR signature block"
        )
    # The wrapper already ran apksigner verify internally (it raises otherwise);
    # re-run it here so the gate fails loudly if that contract ever regresses.
    verified = subprocess.run(
        [str(settings.apksigner), "verify", str(out_apk)],
        capture_output=True,
        timeout=120,
    )
    assert verified.returncode == 0, verified.stderr.decode("utf-8", "replace")

    # apksigner adds an APK Signing Block (v2) alongside the v1 block, so the
    # scheme detection has a genuinely v2-signed artifact to read back -- the
    # modern case v1_signed alone would misreport. Only when androguard is here.
    if _androguard_available():
        service = AnalysisService()
        try:
            created = service.create_session(str(out_apk))
            assert created.ok, created.error
            session_id = created.data["session"]["id"]
            certs = service.apk_certificates(session_id)
            assert certs.ok, certs.error
            assert certs.data["v2_signed"] is True
            assert certs.data["signed"] is True
            assert certs.data["certificates"], "signed APK reported no certificates"
        finally:
            service.close_all()


@pytest.mark.integration
def test_apk_jadx_decompiles_the_dex(tmp_path: Path) -> None:
    """jadx is a thin subprocess wrapper whose CLI contract had no live test.

    Drive the real decompiler against the fixture DEX and assert the two things
    an analyst depends on: export_sources produces the expected sources tree,
    and decompile returns one class's Java text -- proving the --output-dir /
    sources/ layout, the single-class path resolution, and the exit-code
    handling all still hold against a real jadx.
    """
    if not _androguard_available():
        pytest.skip("androguard not installed — APK jadx Gate not run (skip != pass)")
    if not _jadx_available():
        pytest.skip("jadx not configured — APK jadx Gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id, timeout=180.0)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        assert any(
            str(name).endswith("Secret.java") for name in exported.data["java_files"]
        )

        decompiled = service.apk_decompile(
            session_id, "com.example.headlessre.Secret", timeout=180.0
        )
        assert decompiled.ok, decompiled.error
        assert decompiled.data["class_name"] == "com.example.headlessre.Secret"
        assert str(decompiled.data["path"]).endswith("Secret.java")
        source = decompiled.data["source"]
        assert "class Secret" in source
        assert "decrypt" in source
    finally:
        service.close_all()
