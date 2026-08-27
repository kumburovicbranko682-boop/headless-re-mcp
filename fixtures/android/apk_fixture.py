"""Deterministic, valid APK fixture built in pure Python -- no Android SDK.

The Android gate used to feed androguard a zip of placeholder bytes and could
therefore only assert "returns an envelope, not a crash"; the success path of
every ``apk.*`` tool (manifest decode, permissions, components, DEX classes /
methods / strings / xrefs) had no live coverage at all. Building a real APK
normally needs aapt + a Java toolchain, which CI and dev machines do not have,
so this module emits the two binary formats androguard actually parses:

- ``build_manifest_axml``: an Android binary XML (AXML) document -- string
  pool, resource map (attribute names that carry AOSP resource ids must be the
  pool's first strings, in map order), namespace and element chunks -- for a
  manifest with a launcher activity, service, receiver, provider, one
  ``uses-permission`` and sdk/version attributes.
- ``build_classes_dex``: a DEX file with one class ``Lcom/headlessre/gate/Gate;``
  holding two static methods, where ``entry()`` loads ``STRING_PAYLOAD`` via
  ``const-string`` and calls ``leaf()`` via ``invoke-static`` -- so string
  extraction and xref analysis have something real to find. Section offsets,
  the map_list, adler32 checksum and SHA-1 signature are computed, not copied
  from a binary blob.

Everything is generated at call time from these ~300 lines of struct packing;
no opaque binary is committed. The same philosophy as the r2 gate compiling
its ELF fixture with the system C compiler.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

# ---- facts the gate asserts against -------------------------------------
PACKAGE = "com.headlessre.gate"
VERSION_CODE = 7
VERSION_NAME = "1.7"
MIN_SDK = 21
TARGET_SDK = 34
PERMISSION = "android.permission.INTERNET"
MAIN_ACTIVITY = f"{PACKAGE}.MainActivity"
SERVICE = f"{PACKAGE}.SyncService"
RECEIVER = f"{PACKAGE}.BootReceiver"
PROVIDER = f"{PACKAGE}.DataProvider"
NATIVE_LIB = "lib/arm64-v8a/libgate.so"
CLASS_SMALI = "Lcom/headlessre/gate/Gate;"
CLASS_DOTTED = f"{PACKAGE}.Gate"
METHOD_ENTRY = "entry"
METHOD_LEAF = "leaf"
STRING_PAYLOAD = "gate-strings-live"

# ==========================================================================
# AXML (Android binary XML) encoding
# ==========================================================================

# AOSP attribute resource ids (frameworks/base public.xml). Attribute names
# that carry a resource id must be the first strings in the pool, in exactly
# this order, so the resource map chunk can pair them positionally.
_ATTR_IDS: list[tuple[str, int]] = [
    ("versionCode", 0x0101021B),
    ("versionName", 0x0101021C),
    ("minSdkVersion", 0x0101020C),
    ("targetSdkVersion", 0x01010270),
    ("name", 0x01010003),
    ("label", 0x01010001),
    ("exported", 0x01010010),
    ("authorities", 0x01010018),
]

_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_BOOLEAN = 0x12
_NO_ENTRY = 0xFFFFFFFF

# ns-uri (None = no namespace), name, rawValue string idx, dataType, data
_Attr = tuple[str | None, str, int, int, int]


class _StringPool:
    def __init__(self) -> None:
        self.values: list[str] = [name for name, _ in _ATTR_IDS]

    def index(self, value: str) -> int:
        if value not in self.values:
            self.values.append(value)
        return self.values.index(value)

    def chunk(self) -> bytes:
        """UTF-16 pool: u16 char count, UTF-16LE data, u16 terminator each."""
        offsets: list[int] = []
        blob = bytearray()
        for value in self.values:
            offsets.append(len(blob))
            blob += struct.pack("<H", len(value)) + value.encode("utf-16-le") + b"\x00\x00"
        while len(blob) % 4:
            blob += b"\x00"
        header_size = 28
        strings_start = header_size + 4 * len(self.values)
        head = struct.pack(
            "<HHIIIIII",
            0x0001,  # RES_STRING_POOL_TYPE
            header_size,
            strings_start + len(blob),
            len(self.values),
            0,  # styleCount
            0,  # flags (UTF-16)
            strings_start,
            0,  # stylesStart
        )
        return head + b"".join(struct.pack("<I", off) for off in offsets) + bytes(blob)


def _resource_map() -> bytes:
    ids = [rid for _, rid in _ATTR_IDS]
    head = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ids))  # RES_XML_RESOURCE_MAP_TYPE
    return head + b"".join(struct.pack("<I", rid) for rid in ids)


def _start_element(pool: _StringPool, name: str, attrs: list[_Attr]) -> bytes:
    body = struct.pack(
        "<IIIIHHHHHH",
        1,  # lineNumber
        _NO_ENTRY,  # comment
        _NO_ENTRY,  # element namespace
        pool.index(name),
        20,  # attributeStart
        20,  # attributeSize
        len(attrs),
        0,  # idIndex
        0,  # classIndex
        0,  # styleIndex
    )
    for ns, attr_name, raw, dtype, data in attrs:
        body += struct.pack(
            "<IIIHBBI",
            _NO_ENTRY if ns is None else pool.index(ns),
            pool.index(attr_name),
            raw,
            8,  # Res_value size
            0,  # res0
            dtype,
            data,
        )
    return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body  # RES_XML_START_ELEMENT


def _end_element(pool: _StringPool, name: str) -> bytes:
    return struct.pack("<HHIIIII", 0x0103, 16, 24, 1, _NO_ENTRY, _NO_ENTRY, pool.index(name))


def _namespace_chunk(pool: _StringPool, chunk_type: int) -> bytes:
    return struct.pack(
        "<HHIIIII",
        chunk_type,  # 0x0100 start / 0x0101 end
        16,
        24,
        1,
        _NO_ENTRY,
        pool.index("android"),
        pool.index(_ANDROID_NS),
    )


def build_manifest_axml() -> bytes:
    pool = _StringPool()

    def s_attr(ns: str | None, name: str, value: str) -> _Attr:
        idx = pool.index(value)
        return (ns, name, idx, _TYPE_STRING, idx)

    def i_attr(ns: str | None, name: str, value: int) -> _Attr:
        return (ns, name, _NO_ENTRY, _TYPE_INT_DEC, value)

    def b_attr(ns: str | None, name: str, value: bool) -> _Attr:
        return (ns, name, _NO_ENTRY, _TYPE_BOOLEAN, _NO_ENTRY if value else 0)

    ns = _ANDROID_NS
    doc = bytearray()
    doc += _namespace_chunk(pool, 0x0100)
    doc += _start_element(
        pool,
        "manifest",
        [
            i_attr(ns, "versionCode", VERSION_CODE),
            s_attr(ns, "versionName", VERSION_NAME),
            s_attr(None, "package", PACKAGE),
        ],
    )
    doc += _start_element(
        pool,
        "uses-sdk",
        [i_attr(ns, "minSdkVersion", MIN_SDK), i_attr(ns, "targetSdkVersion", TARGET_SDK)],
    )
    doc += _end_element(pool, "uses-sdk")
    doc += _start_element(pool, "uses-permission", [s_attr(ns, "name", PERMISSION)])
    doc += _end_element(pool, "uses-permission")
    doc += _start_element(pool, "application", [s_attr(ns, "label", "Headless Gate")])
    doc += _start_element(
        pool, "activity", [s_attr(ns, "name", MAIN_ACTIVITY), b_attr(ns, "exported", True)]
    )
    doc += _start_element(pool, "intent-filter", [])
    doc += _start_element(pool, "action", [s_attr(ns, "name", "android.intent.action.MAIN")])
    doc += _end_element(pool, "action")
    doc += _start_element(
        pool, "category", [s_attr(ns, "name", "android.intent.category.LAUNCHER")]
    )
    doc += _end_element(pool, "category")
    doc += _end_element(pool, "intent-filter")
    doc += _end_element(pool, "activity")
    doc += _start_element(pool, "service", [s_attr(ns, "name", SERVICE)])
    doc += _end_element(pool, "service")
    doc += _start_element(pool, "receiver", [s_attr(ns, "name", RECEIVER)])
    doc += _end_element(pool, "receiver")
    doc += _start_element(
        pool,
        "provider",
        [s_attr(ns, "name", PROVIDER), s_attr(ns, "authorities", f"{PACKAGE}.provider")],
    )
    doc += _end_element(pool, "provider")
    doc += _end_element(pool, "application")
    doc += _end_element(pool, "manifest")
    doc += _namespace_chunk(pool, 0x0101)

    # The pool is serialized after the document (interning happens while the
    # document is built) but placed before it in the file.
    pool_chunk = pool.chunk()
    rmap = _resource_map()
    total = 8 + len(pool_chunk) + len(rmap) + len(doc)
    return struct.pack("<HHI", 0x0003, 8, total) + pool_chunk + rmap + bytes(doc)


# ==========================================================================
# DEX encoding
# ==========================================================================

_DEX_NO_INDEX = 0xFFFFFFFF
_ACC_PUBLIC = 0x0001
_ACC_PUBLIC_STATIC = 0x0009

# string_ids must be sorted by UTF-16 code point order (all ASCII here).
_DEX_STRINGS = [
    "()V",
    CLASS_SMALI,
    "Ljava/lang/Object;",
    "V",
    METHOD_ENTRY,
    STRING_PAYLOAD,
    METHOD_LEAF,
]
_DEX_STR = {value: index for index, value in enumerate(_DEX_STRINGS)}
_DEX_TYPES = [CLASS_SMALI, "Ljava/lang/Object;", "V"]
_DEX_TYPE = {value: index for index, value in enumerate(_DEX_TYPES)}


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


def _code_item(registers: int, insns: bytes) -> bytes:
    # registers/ins/outs/tries u16 each, debug_info_off u32, insns_size in
    # 16-bit units.
    return struct.pack("<HHHHII", registers, 0, 0, 0, 0, len(insns) // 2) + insns


def build_classes_dex() -> bytes:
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(_DEX_STRINGS)
    proto_ids_off = type_ids_off + 4 * len(_DEX_TYPES)
    method_ids_off = proto_ids_off + 12  # one proto: ()V
    class_defs_off = method_ids_off + 8 * 2  # entry, leaf
    data_off = class_defs_off + 32  # one class_def

    data = bytearray()

    def here() -> int:
        return data_off + len(data)

    def align4() -> None:
        while here() % 4:
            data.append(0)

    # entry(): const-string v0, STRING_PAYLOAD; invoke-static {}, leaf; return-void
    align4()
    entry_code_off = here()
    entry_insns = (
        struct.pack("<BBH", 0x1A, 0x00, _DEX_STR[STRING_PAYLOAD])  # const-string (21c)
        + struct.pack("<BBHH", 0x71, 0x00, 1, 0)  # invoke-static (35c), method@1 = leaf
        + b"\x0e\x00"  # return-void (10x)
    )
    data += _code_item(1, entry_insns)

    # leaf(): return-void
    align4()
    leaf_code_off = here()
    data += _code_item(0, b"\x0e\x00")

    string_data_offs: list[int] = []
    for value in _DEX_STRINGS:
        string_data_offs.append(here())
        # uleb128 UTF-16 length, MUTF-8 bytes (== UTF-8 for ASCII), NUL.
        data += _uleb128(len(value)) + value.encode("utf-8") + b"\x00"

    class_data_off = here()
    data += _uleb128(0) + _uleb128(0) + _uleb128(2) + _uleb128(0)
    data += _uleb128(0) + _uleb128(_ACC_PUBLIC_STATIC) + _uleb128(entry_code_off)
    data += _uleb128(1) + _uleb128(_ACC_PUBLIC_STATIC) + _uleb128(leaf_code_off)

    align4()
    map_off = here()
    map_entries = [
        (0x0000, 1, 0),  # header_item
        (0x0001, len(_DEX_STRINGS), string_ids_off),  # string_id_item
        (0x0002, len(_DEX_TYPES), type_ids_off),  # type_id_item
        (0x0003, 1, proto_ids_off),  # proto_id_item
        (0x0005, 2, method_ids_off),  # method_id_item
        (0x0006, 1, class_defs_off),  # class_def_item
        (0x2001, 2, entry_code_off),  # code_item
        (0x2002, len(_DEX_STRINGS), string_data_offs[0]),  # string_data_item
        (0x2000, 1, class_data_off),  # class_data_item
        (0x1000, 1, map_off),  # map_list
    ]
    data += struct.pack("<I", len(map_entries))
    for item_type, count, offset in map_entries:
        data += struct.pack("<HHII", item_type, 0, count, offset)

    file_size = data_off + len(data)

    string_ids = b"".join(struct.pack("<I", off) for off in string_data_offs)
    type_ids = b"".join(struct.pack("<I", _DEX_STR[desc]) for desc in _DEX_TYPES)
    proto_ids = struct.pack("<III", _DEX_STR["V"], _DEX_TYPE["V"], 0)
    method_ids = struct.pack(
        "<HHI", _DEX_TYPE[CLASS_SMALI], 0, _DEX_STR[METHOD_ENTRY]
    ) + struct.pack("<HHI", _DEX_TYPE[CLASS_SMALI], 0, _DEX_STR[METHOD_LEAF])
    class_defs = struct.pack(
        "<IIIIIIII",
        _DEX_TYPE[CLASS_SMALI],
        _ACC_PUBLIC,
        _DEX_TYPE["Ljava/lang/Object;"],
        0,  # interfaces_off
        _DEX_NO_INDEX,  # source_file_idx
        0,  # annotations_off
        class_data_off,
        0,  # static_values_off
    )

    header = struct.pack(
        "<8sI20sIIIII",
        b"dex\n035\x00",
        0,  # checksum, patched below
        b"\x00" * 20,  # signature, patched below
        file_size,
        header_size,
        0x12345678,  # endian_tag
        0,  # link_size
        0,  # link_off
    )
    header += struct.pack("<I", map_off)
    header += struct.pack("<II", len(_DEX_STRINGS), string_ids_off)
    header += struct.pack("<II", len(_DEX_TYPES), type_ids_off)
    header += struct.pack("<II", 1, proto_ids_off)
    header += struct.pack("<II", 0, 0)  # field_ids
    header += struct.pack("<II", 2, method_ids_off)
    header += struct.pack("<II", 1, class_defs_off)
    header += struct.pack("<II", len(data), data_off)

    blob = bytearray(header + string_ids + type_ids + proto_ids + method_ids + class_defs + data)
    if len(blob) != file_size:
        raise AssertionError(f"dex layout drifted: {len(blob)} != {file_size}")

    blob[12:32] = hashlib.sha1(blob[32:]).digest()
    blob[8:12] = struct.pack("<I", zlib.adler32(bytes(blob[12:])) & 0xFFFFFFFF)
    return bytes(blob)


# ==========================================================================
# APK assembly
# ==========================================================================


def build_apk(path: Path) -> Path:
    """Write a valid (unsigned) APK androguard fully parses and analyzes."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", build_manifest_axml())
        archive.writestr("classes.dex", build_classes_dex())
        archive.writestr(NATIVE_LIB, b"\x7fELF-placeholder")
        archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
    return path
