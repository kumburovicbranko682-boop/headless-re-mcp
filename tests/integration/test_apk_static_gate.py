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
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

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

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert sorted(libs.data["abis"]) == ["arm64-v8a", "x86_64"]
        assert libs.data["count"] == 2

        certs = service.apk_certificates(session_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is False
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
