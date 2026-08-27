"""Build a minimal, real APK for the jadx live decompile gate.

The jadx gate needs an APK that the jadx CLI can actually decompile into
recognisable Java, so the assertions can check real decompiler output rather
than a mock. Hosted CI has no Android SDK (no d8/aapt2), so the DEX is
hand-assembled here with the standard library only -- the same technique the
androguard static fixture uses -- and wrapped in a zip at runtime by the gate.

Unlike the static-analysis fixture, this one does **not** need a binary
AndroidManifest.xml: jadx decompiles ``classes.dex`` regardless of the manifest,
so a placeholder keeps the builder dependency-free (no pyaxml) and the gate
needs nothing but jadx and a JRE.

The DEX describes one public class::

    package com.example.gate;
    public class Secret {
        public static String decrypt() { return "gate-secret-string"; }
        public static void   caller()  { decrypt(); }
    }

``caller`` invokes ``decrypt`` and ``decrypt`` returns the literal
``"gate-secret-string"``, so the decompiled Java the gate reads back contains
both methods, the call, and the string -- each of which the gate asserts.

Regenerate the standalone APK with ``python fixtures/android/build_min_apk.py``;
it prints the path and byte size. The gate builds the same bytes in a temp dir,
so there is no committed binary to drift.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

PACKAGE = "com.example.gate"
SECRET_CLASS = "Lcom/example/gate/Secret;"
SECRET_STRING = "gate-secret-string"
# A placeholder manifest: jadx reads the DEX, not this, so it need not be valid
# binary AXML. Kept non-empty so the archive looks like an APK to a human.
PLACEHOLDER_MANIFEST = b"jadx-live-gate placeholder manifest; see build_min_apk.py"


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


def _string_data(text: str) -> bytes:
    # ASCII only, so MUTF-8 equals ASCII and the utf16 length equals len().
    return _uleb128(len(text)) + text.encode("ascii") + b"\x00"


def build_dex() -> bytes:
    """Assemble a minimal but valid DEX v035 (little-endian throughout)."""
    strings = sorted(
        {
            SECRET_CLASS,
            "Ljava/lang/Object;",
            "Ljava/lang/String;",
            "V",
            "L",
            "decrypt",
            "caller",
            SECRET_STRING,
            "Secret.java",
        }
    )
    sidx = {text: index for index, text in enumerate(strings)}

    type_descs = sorted(
        [SECRET_CLASS, "Ljava/lang/Object;", "Ljava/lang/String;", "V"],
        key=lambda desc: sidx[desc],
    )
    tidx = {desc: index for index, desc in enumerate(type_descs)}

    # Protos sort by (return type idx, params). String return sorts before void.
    proto_str = ("L", "Ljava/lang/String;")
    proto_void = ("V", "V")
    protos = sorted([proto_str, proto_void], key=lambda proto: tidx[proto[1]])
    pidx = {proto: index for index, proto in enumerate(protos)}

    # Methods sort by (class idx, name idx, proto idx); "caller" < "decrypt".
    m_decrypt = (SECRET_CLASS, "decrypt", proto_str)
    m_caller = (SECRET_CLASS, "caller", proto_void)
    methods = sorted(
        [m_decrypt, m_caller],
        key=lambda method: (tidx[method[0]], sidx[method[1]], pidx[method[2]]),
    )
    midx = {method: index for index, method in enumerate(methods)}

    n_strings, n_types, n_protos, n_methods, n_classes = (
        len(strings),
        len(type_descs),
        len(protos),
        len(methods),
        1,
    )

    header_size = 0x70
    cursor = header_size
    string_ids_off = cursor
    cursor += n_strings * 4
    type_ids_off = cursor
    cursor += n_types * 4
    proto_ids_off = cursor
    cursor += n_protos * 12
    method_ids_off = cursor
    cursor += n_methods * 8
    class_defs_off = cursor
    cursor += n_classes * 32
    data_off = cursor

    data = bytearray()

    def pos() -> int:
        return data_off + len(data)

    def align4() -> None:
        while pos() % 4 != 0:
            data.append(0)

    string_data_off: dict[str, int] = {}
    for text in strings:
        string_data_off[text] = pos()
        data += _string_data(text)

    align4()
    decrypt_code_off = pos()
    insns = (
        bytes([0x1A, 0x00])
        + struct.pack("<H", sidx[SECRET_STRING])
        + bytes([0x11, 0x00])
    )
    data += struct.pack("<HHHH", 1, 0, 0, 0)
    data += struct.pack("<I", 0)
    data += struct.pack("<I", len(insns) // 2)
    data += insns

    align4()
    caller_code_off = pos()
    insns2 = (
        bytes([0x71, 0x00])
        + struct.pack("<H", midx[m_decrypt])
        + bytes([0x00, 0x00, 0x0E, 0x00])
    )
    data += struct.pack("<HHHH", 1, 0, 0, 0)
    data += struct.pack("<I", 0)
    data += struct.pack("<I", len(insns2) // 2)
    data += insns2

    code_off = {m_decrypt: decrypt_code_off, m_caller: caller_code_off}

    class_data_off = pos()
    data += _uleb128(0)  # static fields
    data += _uleb128(0)  # instance fields
    data += _uleb128(2)  # direct methods
    data += _uleb128(0)  # virtual methods
    prev = 0
    for method in sorted([m_decrypt, m_caller], key=lambda method: midx[method]):
        index = midx[method]
        data += _uleb128(index - prev)
        prev = index
        data += _uleb128(0x9)  # ACC_PUBLIC | ACC_STATIC
        data += _uleb128(code_off[method])

    align4()
    map_off = pos()
    map_items = [
        (0x0000, 1, 0),
        (0x0001, n_strings, string_ids_off),
        (0x0002, n_types, type_ids_off),
        (0x0003, n_protos, proto_ids_off),
        (0x0005, n_methods, method_ids_off),
        (0x0006, n_classes, class_defs_off),
        (0x2002, n_strings, string_data_off[strings[0]]),
        (0x2001, 2, decrypt_code_off),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    map_items.sort(key=lambda item: item[2])
    data += struct.pack("<I", len(map_items))
    for type_code, count, offset in map_items:
        data += struct.pack("<HHII", type_code, 0, count, offset)

    data_size = len(data)
    file_size = data_off + data_size

    string_ids = b"".join(struct.pack("<I", string_data_off[s]) for s in strings)
    type_ids = b"".join(struct.pack("<I", sidx[d]) for d in type_descs)
    proto_ids = b"".join(
        struct.pack("<III", sidx[shorty], tidx[ret], 0) for (shorty, ret) in protos
    )
    method_ids = b"".join(
        struct.pack("<HHI", tidx[cls], pidx[proto], sidx[name])
        for (cls, name, proto) in methods
    )
    class_defs = struct.pack(
        "<IIIIIIII",
        tidx[SECRET_CLASS],
        0x1,
        tidx["Ljava/lang/Object;"],
        0,
        sidx["Secret.java"],
        0,
        class_data_off,
        0,
    )

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    fields = [
        (0x20, file_size),
        (0x24, header_size),
        (0x28, 0x12345678),
        (0x2C, 0),
        (0x30, 0),
        (0x34, map_off),
        (0x38, n_strings),
        (0x3C, string_ids_off),
        (0x40, n_types),
        (0x44, type_ids_off),
        (0x48, n_protos),
        (0x4C, proto_ids_off),
        (0x50, 0),
        (0x54, 0),
        (0x58, n_methods),
        (0x5C, method_ids_off),
        (0x60, n_classes),
        (0x64, class_defs_off),
        (0x68, data_size),
        (0x6C, data_off),
    ]
    for offset, value in fields:
        struct.pack_into("<I", header, offset, value)

    blob = bytearray()
    blob += header
    blob += string_ids
    blob += type_ids
    blob += proto_ids
    blob += method_ids
    blob += class_defs
    blob += data
    if len(blob) != file_size:
        raise AssertionError((len(blob), file_size))

    blob[0x0C:0x20] = hashlib.sha1(bytes(blob[0x20:])).digest()
    struct.pack_into("<I", blob, 0x08, zlib.adler32(bytes(blob[0x0C:])) & 0xFFFFFFFF)
    return bytes(blob)


def _add(archive: zipfile.ZipFile, name: str, payload: bytes) -> None:
    # A fixed timestamp keeps the archive byte-for-byte reproducible so a
    # regeneration never shows a spurious diff.
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, payload)


def build_apk(out_path: Path) -> Path:
    """Write ``classes.dex`` plus a placeholder manifest into an APK zip."""
    dex = build_dex()
    with zipfile.ZipFile(out_path, "w") as archive:
        _add(archive, "AndroidManifest.xml", PLACEHOLDER_MANIFEST)
        _add(archive, "classes.dex", dex)
    return out_path


if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "min.apk"
    build_apk(target)
    print(f"wrote {target} ({target.stat().st_size} bytes)")
