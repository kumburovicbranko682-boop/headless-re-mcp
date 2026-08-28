"""APK static analysis proven against real androguard, not just degradation.

``test_android_re_gate.py`` builds a deliberately *invalid* APK (its manifest is
not real AXML) and only asserts that every reader degrades to a clean envelope.
That never exercises the happy path, so a version-drift bug in how the
``ApkClient`` calls androguard 4.x -- the same class of break that silently
disabled ``frida.memory.read`` -- would pass every test.

This gate builds a genuinely parseable APK entirely in-process: a hand-encoded
binary ``AndroidManifest.xml`` (AXML) with a package, versions, a uses-sdk, a
permission and an activity, plus a real ``classes.dex``. Two DEX shapes are
built: an empty one (proving the empty/absent cases stay on the structured
contract) and a *populated* one -- a class with two methods where ``main`` calls
``onCreate`` and loads a string constant -- so the DEX readers are proven to
decode real classes, methods, string constants and a resolved xref, not merely
to return zero. It then drives the real service entry points an agent uses and
asserts the decoded values, so the Android static line is proven end to end.
skip != pass when androguard is absent; no external tool or device is required.
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

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.backends.apktool.client import (
    _DEBUG_ALIAS,
    _DEBUG_KEYSTORE,
    _DEBUG_PASSWORD,
)
from headless_re_mcp.backends.jadx import JadxClient
from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_NO = 0xFFFFFFFF
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_ANDROID_URI = "http://schemas.android.com/apk/res/android"
_PACKAGE = "com.example.headless"
_PERMISSION = "android.permission.INTERNET"

_STRINGS = [
    "android",
    _ANDROID_URI,
    "package",
    "versionCode",
    "versionName",
    "name",
    "minSdkVersion",
    "targetSdkVersion",
    "manifest",
    "uses-sdk",
    "uses-permission",
    "application",
    "activity",
    _PACKAGE,
    "1.4",
    _PERMISSION,
    ".MainActivity",
]
_IDX = {text: index for index, text in enumerate(_STRINGS)}

# Populated-DEX expectations: one class, two static methods where main calls
# onCreate and loads a string constant.
_DEX_CLASS_SMALI = "Lcom/example/App;"
_DEX_METHODS = ("main", "onCreate")
_DEX_STRING = "hello world"
_DEX_CALLER = "main"
_DEX_CALLEE = "onCreate"

# Two-class-DEX expectations: App.run invoke-virtuals Helper.greet, so the xref
# crosses a class boundary (the populated DEX above only proves the same-class
# case).
_DEX_APP_SMALI = "Lcom/example/App;"
_DEX_HELPER_SMALI = "Lcom/example/Helper;"
_DEX_CROSS_CALLER = "run"
_DEX_CROSS_CALLEE = "greet"

# Field-DEX expectations: Store.save() writes the static field `secret` that
# Store.load() reads, so read and write xrefs land on different methods -- the
# edges apk.field_xrefs must resolve in each direction.
_DEX_STORE_SMALI = "Lcom/example/Store;"
_DEX_FIELD_NAME = "secret"
_DEX_FIELD_READER = "load"
_DEX_FIELD_WRITER = "save"


def _s(text: str) -> int:
    return _IDX[text]


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


def _string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    data = bytearray()
    for text in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    count = len(strings)
    strings_start = 28 + 4 * count
    out = bytearray()
    out += struct.pack("<HHI", 0x0001, 28, strings_start + len(data))
    out += struct.pack("<IIII", count, 0, 0, strings_start)  # flags=0 => UTF-16
    out += struct.pack("<I", 0)
    for off in offsets:
        out += struct.pack("<I", off)
    out += data
    return bytes(out)


def _start_ns(prefix: int, uri: int) -> bytes:
    body = struct.pack("<IIII", 1, _NO, prefix, uri)
    return struct.pack("<HHI", 0x0100, 16, 8 + len(body)) + body


def _end_ns(prefix: int, uri: int) -> bytes:
    body = struct.pack("<IIII", 1, _NO, prefix, uri)
    return struct.pack("<HHI", 0x0101, 16, 8 + len(body)) + body


def _start_el(name: int, attrs: list[tuple[int, int, int, int, int]]) -> bytes:
    body = bytearray()
    body += struct.pack("<II", 1, _NO)
    body += struct.pack("<II", _NO, name)
    body += struct.pack("<HHH", 20, 20, len(attrs))
    body += struct.pack("<HHH", 0, 0, 0)
    for a_ns, a_name, a_raw, a_type, a_data in attrs:
        body += struct.pack("<III", a_ns, a_name, a_raw)
        body += struct.pack("<HBBI", 8, 0, a_type, a_data)
    return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + bytes(body)


def _end_el(name: int) -> bytes:
    body = struct.pack("<IIII", 1, _NO, _NO, name)
    return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body


def _build_manifest_axml() -> bytes:
    uri = _s(_ANDROID_URI)
    chunks = [
        _start_ns(_s("android"), uri),
        _start_el(
            _s("manifest"),
            [
                (_NO, _s("package"), _s(_PACKAGE), _TYPE_STRING, _s(_PACKAGE)),
                (uri, _s("versionCode"), _NO, _TYPE_INT_DEC, 42),
                (uri, _s("versionName"), _s("1.4"), _TYPE_STRING, _s("1.4")),
            ],
        ),
        _start_el(
            _s("uses-sdk"),
            [
                (uri, _s("minSdkVersion"), _NO, _TYPE_INT_DEC, 21),
                (uri, _s("targetSdkVersion"), _NO, _TYPE_INT_DEC, 33),
            ],
        ),
        _end_el(_s("uses-sdk")),
        _start_el(
            _s("uses-permission"),
            [(uri, _s("name"), _s(_PERMISSION), _TYPE_STRING, _s(_PERMISSION))],
        ),
        _end_el(_s("uses-permission")),
        _start_el(_s("application"), []),
        _start_el(
            _s("activity"),
            [(uri, _s("name"), _s(".MainActivity"), _TYPE_STRING, _s(".MainActivity"))],
        ),
        _end_el(_s("activity")),
        _end_el(_s("application")),
        _end_el(_s("manifest")),
        _end_ns(_s("android"), uri),
    ]
    payload = _string_pool(_STRINGS) + b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _build_empty_dex() -> bytes:
    """A valid DEX 035 with zero classes: enough to prove the analysis path."""
    header_size = 0x70
    map_off = header_size
    entries = [(0x0000, 1, 0), (0x1000, 1, map_off)]  # HEADER_ITEM, MAP_LIST
    map_list = struct.pack("<I", len(entries))
    for typ, count, off in entries:
        map_list += struct.pack("<HHII", typ, 0, count, off)
    file_size = header_size + len(map_list)

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)  # endian tag
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 104, len(map_list))  # data_size
    struct.pack_into("<I", header, 108, map_off)  # data_off

    body = bytearray(bytes(header) + map_list)
    body[12:32] = hashlib.sha1(bytes(body[32:])).digest()  # noqa: S324 - DEX spec uses SHA-1
    struct.pack_into("<I", body, 8, zlib.adler32(bytes(body[12:])) & 0xFFFFFFFF)
    return bytes(body)


def _build_populated_dex() -> bytes:
    """A valid DEX 035 with one class and two methods, one calling the other.

    ``com.example.App`` has two static ``()V`` methods. ``main`` loads the string
    constant "hello world" and ``invoke-static``s ``onCreate``; ``onCreate`` is
    ``return-void``. That gives the analysis a real class list, a real method
    list, a string constant, and exactly one resolvable xref (onCreate <- main),
    so the DEX readers are proven to decode non-empty results -- the version-drift
    surface an empty DEX can never touch. Every id table is emitted in the sorted
    order the DEX spec mandates so androguard's parser accepts it as-is.
    """
    strings = [
        "App.java",  # 0
        "Lcom/example/App;",  # 1  App type descriptor
        "Ljava/lang/Object;",  # 2  superclass descriptor
        "V",  # 3  void / shorty
        _DEX_STRING,  # 4  string constant loaded by main
        "main",  # 5
        "onCreate",  # 6
    ]
    s_app_java, s_app, s_obj, s_v, s_hello, s_main, s_oncreate = range(7)
    type_to_str = [s_app, s_obj, s_v]  # type0=App, type1=Object, type2=V
    t_app, t_obj, t_v = 0, 1, 2
    n_str, n_type, n_proto, n_method, n_class = len(strings), 3, 1, 2, 1

    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * n_str
    proto_ids_off = type_ids_off + 4 * n_type
    method_ids_off = proto_ids_off + 12 * n_proto
    class_defs_off = method_ids_off + 8 * n_method
    data_off = class_defs_off + 32 * n_class

    data = bytearray()

    def cursor() -> int:
        return data_off + len(data)

    def align4() -> None:
        while (data_off + len(data)) % 4:
            data.append(0)

    str_data_off: list[int] = []
    for text in strings:
        str_data_off.append(cursor())
        data += _uleb128(len(text)) + text.encode("ascii") + b"\x00"

    align4()
    code_oncreate = cursor()
    data += struct.pack("<HHHHII", 0, 0, 0, 0, 0, 1) + struct.pack("<H", 0x000E)  # return-void

    align4()
    code_main = cursor()
    # const-string v0, "hello world"; invoke-static {} App.onCreate; return-void
    insns = [0x001A, s_hello, 0x0071, 1, 0x0000, 0x000E]
    data += struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(insns))
    data += b"".join(struct.pack("<H", unit) for unit in insns)

    class_data_off = cursor()
    data += _uleb128(0) + _uleb128(0) + _uleb128(2) + _uleb128(0)  # 0 fields, 2 direct methods
    data += _uleb128(0) + _uleb128(0x9) + _uleb128(code_main)  # main (idx 0), public static
    data += _uleb128(1) + _uleb128(0x9) + _uleb128(code_oncreate)  # onCreate (idx 1)

    align4()
    map_off = cursor()
    entries = [
        (0x0000, 1, 0),
        (0x0001, n_str, string_ids_off),
        (0x0002, n_type, type_ids_off),
        (0x0003, n_proto, proto_ids_off),
        (0x0005, n_method, method_ids_off),
        (0x0006, n_class, class_defs_off),
        (0x2002, n_str, str_data_off[0]),
        (0x2001, 2, code_oncreate),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    data += struct.pack("<I", len(entries))
    for typ, count, off in entries:
        data += struct.pack("<HHII", typ, 0, count, off)

    data_size = len(data)
    file_size = data_off + data_size

    buf = bytearray(data_off)
    for i, off in enumerate(str_data_off):
        struct.pack_into("<I", buf, string_ids_off + 4 * i, off)
    for i, si in enumerate(type_to_str):
        struct.pack_into("<I", buf, type_ids_off + 4 * i, si)
    struct.pack_into("<III", buf, proto_ids_off, s_v, t_v, 0)  # shorty "V", return V, no params
    struct.pack_into("<HHI", buf, method_ids_off, t_app, 0, s_main)  # method 0: App.main()V
    struct.pack_into("<HHI", buf, method_ids_off + 8, t_app, 0, s_oncreate)  # method 1: onCreate()V
    struct.pack_into(
        "<IIIIIIII", buf, class_defs_off, t_app, 0x1, t_obj, 0, s_app_java, 0, class_data_off, 0
    )
    buf += data

    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, file_size)
    struct.pack_into("<I", buf, 36, 0x70)
    struct.pack_into("<I", buf, 40, 0x12345678)  # endian tag
    struct.pack_into("<I", buf, 52, map_off)
    struct.pack_into("<II", buf, 56, n_str, string_ids_off)
    struct.pack_into("<II", buf, 64, n_type, type_ids_off)
    struct.pack_into("<II", buf, 72, n_proto, proto_ids_off)
    struct.pack_into("<II", buf, 80, 0, 0)  # no fields
    struct.pack_into("<II", buf, 88, n_method, method_ids_off)
    struct.pack_into("<II", buf, 96, n_class, class_defs_off)
    struct.pack_into("<II", buf, 104, data_size, data_off)
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()  # noqa: S324 - DEX spec uses SHA-1
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def _build_two_class_dex() -> bytes:
    """A valid DEX 035 with two classes where one virtual-calls the other.

    ``com.example.App.run`` (static) does ``invoke-virtual`` on
    ``com.example.Helper.greet`` (a virtual method), so the analysis has to
    resolve a call whose callee lives in a *different* class. That is the xref
    edge the single-class populated DEX cannot exercise: same-class resolution
    can succeed even if cross-class method-id resolution is broken. All id tables
    stay in the DEX-mandated sorted order so androguard parses it as-is.
    """
    no_index = 0xFFFFFFFF
    strings = [
        "Lcom/example/App;",  # 0  App descriptor
        "Lcom/example/Helper;",  # 1  Helper descriptor
        "Ljava/lang/Object;",  # 2  shared superclass
        "V",  # 3  void / shorty
        "greet",  # 4  Helper's virtual method
        "run",  # 5  App's caller
    ]
    s_app, s_helper, s_obj, s_v, s_greet, s_run = range(6)
    type_to_str = [s_app, s_helper, s_obj, s_v]
    t_app, t_helper, t_obj, t_v = 0, 1, 2, 3
    n_str, n_type, n_proto, n_method, n_class = len(strings), 4, 1, 2, 2

    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * n_str
    proto_ids_off = type_ids_off + 4 * n_type
    method_ids_off = proto_ids_off + 12 * n_proto
    class_defs_off = method_ids_off + 8 * n_method
    data_off = class_defs_off + 32 * n_class

    data = bytearray()

    def cursor() -> int:
        return data_off + len(data)

    def align4() -> None:
        while (data_off + len(data)) % 4:
            data.append(0)

    str_data_off: list[int] = []
    for text in strings:
        str_data_off.append(cursor())
        data += _uleb128(len(text)) + text.encode("ascii") + b"\x00"

    align4()
    code_run = cursor()
    # const/4 v0, 0; invoke-virtual {v0}, Helper.greet (method 1); return-void
    run_insns = [0x0012, 0x106E, 1, 0x0000, 0x000E]
    data += struct.pack("<HHHHII", 1, 0, 1, 0, 0, len(run_insns))
    data += b"".join(struct.pack("<H", unit) for unit in run_insns)

    align4()
    code_greet = cursor()
    data += struct.pack("<HHHHII", 0, 0, 0, 0, 0, 1) + struct.pack("<H", 0x000E)  # return-void

    class_data_app = cursor()
    data += _uleb128(0) + _uleb128(0) + _uleb128(1) + _uleb128(0)  # 1 direct method
    data += _uleb128(0) + _uleb128(0x9) + _uleb128(code_run)  # run (method 0), public static
    class_data_helper = cursor()
    data += _uleb128(0) + _uleb128(0) + _uleb128(0) + _uleb128(1)  # 1 virtual method
    data += _uleb128(1) + _uleb128(0x1) + _uleb128(code_greet)  # greet (method 1), public

    align4()
    map_off = cursor()
    entries = [
        (0x0000, 1, 0),
        (0x0001, n_str, string_ids_off),
        (0x0002, n_type, type_ids_off),
        (0x0003, n_proto, proto_ids_off),
        (0x0005, n_method, method_ids_off),
        (0x0006, n_class, class_defs_off),
        (0x2002, n_str, str_data_off[0]),
        (0x2001, 2, code_run),
        (0x2000, 2, class_data_app),
        (0x1000, 1, map_off),
    ]
    data += struct.pack("<I", len(entries))
    for typ, count, off in entries:
        data += struct.pack("<HHII", typ, 0, count, off)

    data_size = len(data)
    file_size = data_off + data_size

    buf = bytearray(data_off)
    for i, off in enumerate(str_data_off):
        struct.pack_into("<I", buf, string_ids_off + 4 * i, off)
    for i, si in enumerate(type_to_str):
        struct.pack_into("<I", buf, type_ids_off + 4 * i, si)
    struct.pack_into("<III", buf, proto_ids_off, s_v, t_v, 0)
    struct.pack_into("<HHI", buf, method_ids_off, t_app, 0, s_run)  # method 0: App.run()V
    struct.pack_into("<HHI", buf, method_ids_off + 8, t_helper, 0, s_greet)  # method 1: greet()V
    struct.pack_into(
        "<IIIIIIII",
        buf,
        class_defs_off,
        t_app,
        0x1,
        t_obj,
        0,
        no_index,
        0,
        class_data_app,
        0,
    )
    struct.pack_into(
        "<IIIIIIII",
        buf,
        class_defs_off + 32,
        t_helper,
        0x1,
        t_obj,
        0,
        no_index,
        0,
        class_data_helper,
        0,
    )
    buf += data

    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, file_size)
    struct.pack_into("<I", buf, 36, 0x70)
    struct.pack_into("<I", buf, 40, 0x12345678)  # endian tag
    struct.pack_into("<I", buf, 52, map_off)
    struct.pack_into("<II", buf, 56, n_str, string_ids_off)
    struct.pack_into("<II", buf, 64, n_type, type_ids_off)
    struct.pack_into("<II", buf, 72, n_proto, proto_ids_off)
    struct.pack_into("<II", buf, 80, 0, 0)  # no fields
    struct.pack_into("<II", buf, 88, n_method, method_ids_off)
    struct.pack_into("<II", buf, 96, n_class, class_defs_off)
    struct.pack_into("<II", buf, 104, data_size, data_off)
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()  # noqa: S324 - DEX spec uses SHA-1
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def _build_single_class_dex(
    *,
    class_desc: str,
    method_name: str,
    method_is_static: bool,
    calls: tuple[str, str] | None = None,
) -> bytes:
    """A valid DEX 035 defining exactly one class with one method.

    If ``calls`` is given, the method ``invoke-virtual``s that (class, method)
    reference -- whose target class need NOT be defined in this DEX. That is what
    lets a caller DEX live in ``classes.dex`` while its callee is defined in
    ``classes2.dex``: the reference is a method-id, resolved across DEX files by
    androguard's merged analysis. String/type/method tables are emitted in the
    sorted order the DEX spec mandates so androguard parses it as-is.
    """
    no_index = 0xFFFFFFFF
    obj_desc = "Ljava/lang/Object;"
    void = "V"
    type_descs = {class_desc, obj_desc, void}
    names = {method_name}
    if calls is not None:
        type_descs.add(calls[0])
        names.add(calls[1])
    all_strings = sorted(type_descs | names)  # DEX orders strings by code point
    sidx = {text: i for i, text in enumerate(all_strings)}
    n_str = len(all_strings)

    types_sorted = sorted(type_descs, key=lambda d: sidx[d])  # and type-ids by string idx
    tidx = {desc: i for i, desc in enumerate(types_sorted)}
    n_type = len(types_sorted)

    methods = [(class_desc, method_name)]
    if calls is not None:
        methods.append(calls)
    methods_sorted = sorted(methods, key=lambda cm: (tidx[cm[0]], sidx[cm[1]]))  # (class,name)
    midx = {cm: i for i, cm in enumerate(methods_sorted)}
    n_method = len(methods_sorted)
    n_proto = 1
    n_class = 1

    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * n_str
    proto_ids_off = type_ids_off + 4 * n_type
    method_ids_off = proto_ids_off + 12 * n_proto
    class_defs_off = method_ids_off + 8 * n_method
    data_off = class_defs_off + 32 * n_class

    data = bytearray()

    def cursor() -> int:
        return data_off + len(data)

    def align4() -> None:
        while (data_off + len(data)) % 4:
            data.append(0)

    str_data_off: list[int] = []
    for text in all_strings:
        str_data_off.append(cursor())
        data += _uleb128(len(text)) + text.encode("ascii") + b"\x00"

    align4()
    code_off = cursor()
    if calls is not None:
        # const/4 v0, 0; invoke-virtual {v0}, <callee>; return-void
        insns = [0x0012, 0x106E, midx[calls], 0x0000, 0x000E]
        registers, outs = 1, 1
    else:
        insns = [0x000E]  # return-void
        registers, outs = 0, 0
    data += struct.pack("<HHHHII", registers, 0, outs, 0, 0, len(insns))
    data += b"".join(struct.pack("<H", unit) for unit in insns)

    class_data_off = cursor()
    defined = _uleb128(midx[(class_desc, method_name)])
    if method_is_static:
        data += _uleb128(0) + _uleb128(0) + _uleb128(1) + _uleb128(0)  # 1 direct method
        data += defined + _uleb128(0x9) + _uleb128(code_off)  # public static
    else:
        data += _uleb128(0) + _uleb128(0) + _uleb128(0) + _uleb128(1)  # 1 virtual method
        data += defined + _uleb128(0x1) + _uleb128(code_off)  # public

    align4()
    map_off = cursor()
    entries = [
        (0x0000, 1, 0),
        (0x0001, n_str, string_ids_off),
        (0x0002, n_type, type_ids_off),
        (0x0003, n_proto, proto_ids_off),
        (0x0005, n_method, method_ids_off),
        (0x0006, n_class, class_defs_off),
        (0x2002, n_str, str_data_off[0]),
        (0x2001, 1, code_off),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    data += struct.pack("<I", len(entries))
    for typ, count, off in entries:
        data += struct.pack("<HHII", typ, 0, count, off)

    data_size = len(data)
    file_size = data_off + data_size

    buf = bytearray(data_off)
    for i, off in enumerate(str_data_off):
        struct.pack_into("<I", buf, string_ids_off + 4 * i, off)
    for i, desc in enumerate(types_sorted):
        struct.pack_into("<I", buf, type_ids_off + 4 * i, sidx[desc])
    struct.pack_into("<III", buf, proto_ids_off, sidx[void], tidx[void], 0)
    for i, (cls, name) in enumerate(methods_sorted):
        struct.pack_into("<HHI", buf, method_ids_off + 8 * i, tidx[cls], 0, sidx[name])
    struct.pack_into(
        "<IIIIIIII",
        buf,
        class_defs_off,
        tidx[class_desc],
        0x1,
        tidx[obj_desc],
        0,
        no_index,
        0,
        class_data_off,
        0,
    )
    buf += data

    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, file_size)
    struct.pack_into("<I", buf, 36, 0x70)
    struct.pack_into("<I", buf, 40, 0x12345678)  # endian tag
    struct.pack_into("<I", buf, 52, map_off)
    struct.pack_into("<II", buf, 56, n_str, string_ids_off)
    struct.pack_into("<II", buf, 64, n_type, type_ids_off)
    struct.pack_into("<II", buf, 72, n_proto, proto_ids_off)
    struct.pack_into("<II", buf, 80, 0, 0)  # no fields
    struct.pack_into("<II", buf, 88, n_method, method_ids_off)
    struct.pack_into("<II", buf, 96, n_class, class_defs_off)
    struct.pack_into("<II", buf, 104, data_size, data_off)
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()  # noqa: S324 - DEX spec uses SHA-1
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def _build_field_dex() -> bytes:
    """A valid DEX 035 with one static field written by one method, read by another.

    ``com.example.Store`` has a static int field ``secret``; ``save`` writes it
    (``sput``) and ``load`` reads it (``sget``). That gives androguard a field
    with exactly one write xref (save) and one read xref (load), the two edges
    ``apk.field_xrefs`` resolves per direction -- a surface neither a class,
    method nor string fixture exercises, since none of them carries a field or a
    field-access instruction. Every id table is emitted in the DEX-mandated
    sorted order so androguard parses it as-is.
    """
    strings = [
        "I",  # 0  int descriptor / field type
        "Lcom/example/Store;",  # 1
        "Ljava/lang/Object;",  # 2
        "V",  # 3  void / shorty
        "load",  # 4  reads the field
        "save",  # 5  writes the field
        "secret",  # 6  the field
    ]
    s_int, s_store, s_obj, s_v, s_load, s_save, s_secret = range(7)
    type_to_str = [s_int, s_store, s_obj, s_v]  # type-ids sorted by string idx
    t_int, t_store, t_obj, t_v = 0, 1, 2, 3
    n_str, n_type, n_proto, n_field, n_method, n_class = len(strings), 4, 1, 1, 2, 1

    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * n_str
    proto_ids_off = type_ids_off + 4 * n_type
    field_ids_off = proto_ids_off + 12 * n_proto
    method_ids_off = field_ids_off + 8 * n_field
    class_defs_off = method_ids_off + 8 * n_method
    data_off = class_defs_off + 32 * n_class

    data = bytearray()

    def cursor() -> int:
        return data_off + len(data)

    def align4() -> None:
        while (data_off + len(data)) % 4:
            data.append(0)

    str_data_off: list[int] = []
    for text in strings:
        str_data_off.append(cursor())
        data += _uleb128(len(text)) + text.encode("ascii") + b"\x00"

    align4()
    code_load = cursor()
    # sget v0, Store.secret (field 0); return-void
    load_insns = [0x0060, 0x0000, 0x000E]
    data += struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(load_insns))
    data += b"".join(struct.pack("<H", unit) for unit in load_insns)

    align4()
    code_save = cursor()
    # const/4 v0, 0; sput v0, Store.secret (field 0); return-void
    save_insns = [0x0012, 0x0067, 0x0000, 0x000E]
    data += struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(save_insns))
    data += b"".join(struct.pack("<H", unit) for unit in save_insns)

    class_data_off = cursor()
    # 1 static field, 0 instance fields, 2 direct methods, 0 virtual methods
    data += _uleb128(1) + _uleb128(0) + _uleb128(2) + _uleb128(0)
    data += _uleb128(0) + _uleb128(0x9)  # secret (field 0), public static
    data += _uleb128(0) + _uleb128(0x9) + _uleb128(code_load)  # load (method 0)
    data += _uleb128(1) + _uleb128(0x9) + _uleb128(code_save)  # save (method 1)

    align4()
    map_off = cursor()
    entries = [
        (0x0000, 1, 0),
        (0x0001, n_str, string_ids_off),
        (0x0002, n_type, type_ids_off),
        (0x0003, n_proto, proto_ids_off),
        (0x0004, n_field, field_ids_off),
        (0x0005, n_method, method_ids_off),
        (0x0006, n_class, class_defs_off),
        (0x2002, n_str, str_data_off[0]),
        (0x2001, 2, code_load),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    data += struct.pack("<I", len(entries))
    for typ, count, off in entries:
        data += struct.pack("<HHII", typ, 0, count, off)

    data_size = len(data)
    file_size = data_off + data_size

    buf = bytearray(data_off)
    for i, off in enumerate(str_data_off):
        struct.pack_into("<I", buf, string_ids_off + 4 * i, off)
    for i, si in enumerate(type_to_str):
        struct.pack_into("<I", buf, type_ids_off + 4 * i, si)
    struct.pack_into("<III", buf, proto_ids_off, s_v, t_v, 0)  # shorty V, return V, no params
    struct.pack_into("<HHI", buf, field_ids_off, t_store, t_int, s_secret)  # Store.secret:I
    struct.pack_into("<HHI", buf, method_ids_off, t_store, 0, s_load)  # load()V
    struct.pack_into("<HHI", buf, method_ids_off + 8, t_store, 0, s_save)  # save()V
    struct.pack_into(
        "<IIIIIIII", buf, class_defs_off, t_store, 0x1, t_obj, 0, _NO, 0, class_data_off, 0
    )
    buf += data

    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, file_size)
    struct.pack_into("<I", buf, 36, 0x70)
    struct.pack_into("<I", buf, 40, 0x12345678)  # endian tag
    struct.pack_into("<I", buf, 52, map_off)
    struct.pack_into("<II", buf, 56, n_str, string_ids_off)
    struct.pack_into("<II", buf, 64, n_type, type_ids_off)
    struct.pack_into("<II", buf, 72, n_proto, proto_ids_off)
    struct.pack_into("<II", buf, 80, n_field, field_ids_off)
    struct.pack_into("<II", buf, 88, n_method, method_ids_off)
    struct.pack_into("<II", buf, 96, n_class, class_defs_off)
    struct.pack_into("<II", buf, 104, data_size, data_off)
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()  # noqa: S324 - DEX spec uses SHA-1
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def _build_apk(
    path: Path,
    *,
    dex: bytes | None = None,
    extra_dexes: dict[str, bytes] | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", _build_manifest_axml())
        archive.writestr("classes.dex", dex if dex is not None else _build_empty_dex())
        for name, payload in (extra_dexes or {}).items():
            archive.writestr(name, payload)
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libhello.so", b"\x7fELFplaceholder")
        # A real native library (an ELF shared object) can be embedded here so the
        # extract -> native-analysis handoff gate has genuine bytes to pull out.
        for name, payload in (extra_files or {}).items():
            archive.writestr(name, payload)
    return path


@pytest.mark.integration
def test_apk_manifest_readers_decode_real_values(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok and opened.data is not None, opened.error
        assert opened.data["package"] == _PACKAGE
        assert str(opened.data["version_code"]) == "42"
        assert opened.data["version_name"] == "1.4"
        assert str(opened.data["min_sdk"]) == "21"
        assert str(opened.data["target_sdk"]) == "33"
        assert opened.data["permission_count"] == 1
        assert set(opened.data["native_abis"]) == {"arm64-v8a", "x86_64"}

        perms = service.apk_permissions(session_id)
        assert perms.ok and perms.data is not None, perms.error
        assert _PERMISSION in perms.data["permissions"]

        comps = service.apk_components(session_id)
        assert comps.ok and comps.data is not None, comps.error
        assert f"{_PACKAGE}.MainActivity" in comps.data["activities"]

        libs = service.apk_native_libs(session_id)
        assert libs.ok and libs.data is not None, libs.error
        assert set(libs.data["abis"]) == {"arm64-v8a", "x86_64"}
        assert libs.data["count"] == 2

        manifest = service.apk_manifest(session_id)
        assert manifest.ok and manifest.data is not None, manifest.error
        assert _PACKAGE in manifest.data["manifest_xml"]

        certs = service.apk_certificates(session_id)
        assert certs.ok and certs.data is not None, certs.error
        # Unsigned fixture: no scheme signed it, and the schemes list is empty.
        assert certs.data["v1_signed"] is False
        assert certs.data["v2_signed"] is False
        assert certs.data["v3_signed"] is False
        assert certs.data["signing_schemes"] == []
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_dex_readers_run_against_real_analysis(tmp_path: Path) -> None:
    """DEX-backed readers must run the real androguard analysis, not just skip.

    The fixture DEX is valid but empty, so classes/strings/xrefs return zero and
    a method lookup misses cleanly -- proving the analysis path (AnalyzeAPK,
    get_classes, get_strings, xref walk) works and its empty/absent cases stay
    on the structured contract.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id, limit=50)
        assert classes.ok and classes.data is not None, classes.error
        assert classes.data["total"] == 0
        assert classes.data["classes"] == []

        strings = service.apk_strings(session_id, limit=50)
        assert strings.ok and strings.data is not None, strings.error
        assert strings.data["total"] == 0

        xrefs = service.apk_xrefs(session_id, "onCreate")
        assert xrefs.ok and xrefs.data is not None, xrefs.error
        assert xrefs.data["callers"] == []

        missing = service.apk_methods(session_id, "com.example.DoesNotExist")
        assert not missing.ok and missing.error is not None
        assert missing.error.code == "not_found", missing.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_dex_readers_decode_a_populated_dex(tmp_path: Path) -> None:
    """The DEX readers must decode real classes/methods/strings and a live xref.

    The empty-DEX case above only proves the analysis runs and its zero cases
    stay on contract. This one drives a DEX with an actual class, two methods and
    an intra-class call, so a drift in how ``ApkClient`` reads androguard's class,
    method, string and xref accessors -- the exact silent-break class that hit
    ``frida.memory.read`` -- fails here instead of shipping. Both the dotted and
    the smali spelling of the class must resolve, since agents pass either.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "populated.apk", dex=_build_populated_dex())
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id, limit=50)
        assert classes.ok and classes.data is not None, classes.error
        assert classes.data["total"] == 1
        assert classes.data["classes"] == [_DEX_CLASS_SMALI]

        # androguard accepts the dotted name too; both spellings must land on the
        # same class and list both methods.
        for spelling in (_DEX_CLASS_SMALI, "com.example.App"):
            methods = service.apk_methods(session_id, spelling)
            assert methods.ok and methods.data is not None, (spelling, methods.error)
            assert methods.data["total"] == 2, spelling
            names = sorted(m["name"] for m in methods.data["methods"])
            assert names == sorted(_DEX_METHODS), spelling
            assert all(m["descriptor"] == "()V" for m in methods.data["methods"]), spelling

        # Filtered listing over the real analysis: a name substring picks one
        # method, and the access substring slices by modifier. total narrows to
        # the matches and the applied filter is echoed, so a filtered page is
        # never read as the whole class.
        only_create = service.apk_methods(session_id, "com.example.App", name_contains="Create")
        assert only_create.ok and only_create.data is not None, only_create.error
        assert [m["name"] for m in only_create.data["methods"]] == ["onCreate"], only_create.data
        assert only_create.data["total"] == 1
        assert only_create.data["filter"] == {"name_contains": "create"}, only_create.data
        # Both methods are public static, so the static slice keeps both...
        statics = service.apk_methods(session_id, "com.example.App", access="static")
        assert statics.ok and statics.data is not None, statics.error
        assert statics.data["total"] == 2, statics.data
        # ...and a modifier none of them carries narrows to nothing, cleanly.
        privates = service.apk_methods(session_id, "com.example.App", access="private")
        assert privates.ok and privates.data is not None, privates.error
        assert privates.data["total"] == 0 and privates.data["methods"] == [], privates.data

        strings = service.apk_strings(session_id, limit=100)
        assert strings.ok and strings.data is not None, strings.error
        assert _DEX_STRING in strings.data["strings"]
        assert strings.data["total"] >= 1

        # The whole point of the call: onCreate has exactly one caller, main.
        xrefs = service.apk_xrefs(session_id, _DEX_CALLEE)
        assert xrefs.ok and xrefs.data is not None, xrefs.error
        assert xrefs.data["count"] == 1, xrefs.data
        caller = xrefs.data["callers"][0]
        assert caller["method"] == _DEX_CALLER
        assert caller["class"] == _DEX_CLASS_SMALI

        # A method with no callers stays a clean, empty enumeration -- not a miss.
        no_callers = service.apk_xrefs(session_id, _DEX_CALLER)
        assert no_callers.ok and no_callers.data is not None, no_callers.error
        assert no_callers.data["callers"] == []

        # The forward direction: main's only callee is onCreate (same class).
        callees = service.apk_xrefs(session_id, _DEX_CALLER, direction="callees")
        assert callees.ok and callees.data is not None, callees.error
        assert callees.data["direction"] == "callees"
        assert callees.data["count"] == 1, callees.data
        callee = callees.data["callees"][0]
        assert callee["class"] == _DEX_CLASS_SMALI, callee
        assert callee["method"] == _DEX_CALLEE, callee

        # onCreate calls nothing, so its callee list is a clean empty enumeration.
        leaf = service.apk_xrefs(session_id, _DEX_CALLEE, direction="callees")
        assert leaf.ok and leaf.data is not None, leaf.error
        assert leaf.data["callees"] == []

        # Pivot from the string constant to the code that loads it: "hello world"
        # is referenced only by main.
        str_refs = service.apk_string_xrefs(session_id, _DEX_STRING)
        assert str_refs.ok and str_refs.data is not None, str_refs.error
        assert str_refs.data["found"] is True, str_refs.data
        assert str_refs.data["total"] == 1, str_refs.data
        ref = str_refs.data["xrefs"][0]
        assert ref["class"] == _DEX_CLASS_SMALI, ref
        assert ref["method"] == _DEX_CALLER, ref

        # A constant the DEX never defines is found False -- not an empty hit on a
        # string that is present but unreferenced.
        absent = service.apk_string_xrefs(session_id, "no-such-constant-zzz")
        assert absent.ok and absent.data is not None, absent.error
        assert absent.data["found"] is False, absent.data
        assert absent.data["xrefs"] == []

        # Method bytecode: apk.methods named main; this reads what it does. main is
        # const-string "hello world"; invoke-static onCreate; return-void -- the
        # exact three ops _build_populated_dex emits. This is the seam from
        # "list a class's methods" to "disassemble one", and the version-drift
        # surface (androguard's instruction decoder) an empty method can't touch.
        for spelling in (_DEX_CLASS_SMALI, "com.example.App"):
            bc = service.apk_method_bytecode(session_id, spelling, _DEX_CALLER)
            assert bc.ok and bc.data is not None, (spelling, bc.error)
            assert bc.data["class_name"] == _DEX_CLASS_SMALI, spelling
            assert bc.data["method"] == _DEX_CALLER, spelling
            assert bc.data["descriptor"] == "()V", spelling
            assert bc.data["has_code"] is True, spelling
            assert bc.data["overloads"] == 1, spelling
            ins = bc.data["instructions"]
            assert [i["mnemonic"] for i in ins] == [
                "const-string",
                "invoke-static",
                "return-void",
            ], (spelling, ins)
            # The point of bytecode over a method list: the operand resolves the
            # target. The invoke names onCreate; the const-string names the literal.
            invoke = next(i for i in ins if i["mnemonic"] == "invoke-static")
            assert _DEX_CALLEE in invoke["operands"], invoke
            const = next(i for i in ins if i["mnemonic"] == "const-string")
            assert _DEX_STRING in const["operands"], const
            # addr is the byte offset within the method; ops decode to real bytes.
            assert [i["addr"] for i in ins] == [0, 4, 10], ins
            assert all(i["bytes"] for i in ins), ins
            assert bc.data["total"] == 3 and bc.data["has_more"] is False, bc.data

        # onCreate is return-void only -- a one-instruction method still reads cleanly.
        leaf_bc = service.apk_method_bytecode(session_id, _DEX_CLASS_SMALI, _DEX_CALLEE)
        assert leaf_bc.ok and leaf_bc.data is not None, leaf_bc.error
        assert [i["mnemonic"] for i in leaf_bc.data["instructions"]] == ["return-void"]

        # Method refs: the same main, summarised. Where the bytecode leg reads the
        # instruction stream, this abstracts it -- main calls onCreate once and
        # loads "hello world" once, and touches no field. That is the triage view
        # (what does this routine reach) built from the resolved references, not a
        # raw opcode dump.
        refs = service.apk_method_refs(session_id, "com.example.App", _DEX_CALLER)
        assert refs.ok and refs.data is not None, refs.error
        assert refs.data["class_name"] == _DEX_CLASS_SMALI, refs.data
        assert refs.data["has_code"] is True, refs.data
        assert refs.data["calls"] == [{"target": "Lcom/example/App;->onCreate()V", "count": 1}]
        assert refs.data["strings"] == [{"value": _DEX_STRING, "count": 1}]
        assert refs.data["fields"] == [], refs.data
        assert refs.data["call_count"] == 1 and refs.data["string_count"] == 1
        assert refs.data["calls_truncated"] is False

        # onCreate reaches nothing, so all three lists are clean empties.
        leaf_refs = service.apk_method_refs(session_id, _DEX_CLASS_SMALI, _DEX_CALLEE)
        assert leaf_refs.ok and leaf_refs.data is not None, leaf_refs.error
        assert leaf_refs.data["calls"] == []
        assert leaf_refs.data["fields"] == []
        assert leaf_refs.data["strings"] == []

        # A method the class does not declare is a clean not_found, not a crash.
        missing = service.apk_method_bytecode(session_id, _DEX_CLASS_SMALI, "noSuchMethod")
        assert not missing.ok
        assert missing.error is not None and missing.error.code == "not_found", missing.error

        # Class summary: the header of the same class, without paging its members.
        # App extends Object, implements nothing, and declares the two methods the
        # method list enumerated and no fields -- the counts and the recovered
        # superclass are the version-drift surface a name-only listing never hits.
        for spelling in (_DEX_CLASS_SMALI, "com.example.App"):
            summary = service.apk_class_summary(session_id, spelling)
            assert summary.ok and summary.data is not None, (spelling, summary.error)
            assert summary.data["class_name"] == _DEX_CLASS_SMALI, spelling
            assert summary.data["superclass"] == "Ljava/lang/Object;", summary.data
            assert summary.data["interfaces"] == [], summary.data
            assert summary.data["method_count"] == 2, summary.data
            assert summary.data["field_count"] == 0, summary.data
            assert summary.data["is_external"] is False, summary.data
            assert "public" in summary.data["access"], summary.data

        # A class the DEX does not carry is a clean not_found, not a crash.
        no_class = service.apk_class_summary(session_id, "com.example.Nope")
        assert not no_class.ok
        assert no_class.error is not None and no_class.error.code == "not_found", no_class.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_dex_readers_resolve_a_cross_class_xref(tmp_path: Path) -> None:
    """A call whose callee lives in another class must resolve to its caller.

    The populated-DEX test above proves same-class xref resolution, which can
    keep working even if cross-class method-id resolution regresses. Here
    App.run invoke-virtuals Helper.greet, so greet's only caller is a method in
    a *different* class; that edge is the one an agent relies on to trace a call
    graph across an app, and it fails here if androguard's class/method wiring
    drifts under ApkClient.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "two_class.apk", dex=_build_two_class_dex())
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id, limit=50)
        assert classes.ok and classes.data is not None, classes.error
        assert classes.data["total"] == 2
        assert set(classes.data["classes"]) == {_DEX_APP_SMALI, _DEX_HELPER_SMALI}

        # The whole point: greet is called only from App.run, a different class.
        cross = service.apk_xrefs(session_id, _DEX_CROSS_CALLEE)
        assert cross.ok and cross.data is not None, cross.error
        assert cross.data["count"] == 1, cross.data
        caller = cross.data["callers"][0]
        assert caller["class"] == _DEX_APP_SMALI, caller
        assert caller["method"] == _DEX_CROSS_CALLER, caller

        # run itself is never called back.
        back = service.apk_xrefs(session_id, _DEX_CROSS_CALLER)
        assert back.ok and back.data is not None, back.error
        assert back.data["callers"] == []

        # The forward direction across the class boundary: run's callee is greet,
        # defined in a different class -- the mirror of the caller edge above.
        forward = service.apk_xrefs(session_id, _DEX_CROSS_CALLER, direction="callees")
        assert forward.ok and forward.data is not None, forward.error
        assert forward.data["direction"] == "callees"
        assert any(
            edge["class"] == _DEX_HELPER_SMALI and edge["method"] == _DEX_CROSS_CALLEE
            for edge in forward.data["callees"]
        ), forward.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_readers_merge_classes_across_secondary_dex(tmp_path: Path) -> None:
    """Classes and xrefs must span classes.dex + classes2.dex, not just the first.

    Real apps routinely exceed one DEX's 64K method limit and ship
    classes.dex/classes2.dex/... A reader that analysed only the primary DEX
    would silently miss every class and call in the secondaries. Here App (in
    classes.dex) calls Helper.greet, but Helper is defined only in classes2.dex,
    so both the merged class list and the cross-DEX xref prove the whole-APK
    analysis path an agent depends on.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    caller_dex = _build_single_class_dex(
        class_desc=_DEX_APP_SMALI,
        method_name=_DEX_CROSS_CALLER,
        method_is_static=True,
        calls=(_DEX_HELPER_SMALI, _DEX_CROSS_CALLEE),
    )
    callee_dex = _build_single_class_dex(
        class_desc=_DEX_HELPER_SMALI,
        method_name=_DEX_CROSS_CALLEE,
        method_is_static=False,
    )
    apk = _build_apk(
        tmp_path / "multidex.apk", dex=caller_dex, extra_dexes={"classes2.dex": callee_dex}
    )
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id, limit=50)
        assert classes.ok and classes.data is not None, classes.error
        # App lives in classes.dex, Helper only in classes2.dex; both must appear.
        assert set(classes.data["classes"]) == {_DEX_APP_SMALI, _DEX_HELPER_SMALI}

        # The callee is defined in the secondary DEX yet its caller is in the
        # primary one -- the xref only resolves if the analysis merged both.
        cross = service.apk_xrefs(session_id, _DEX_CROSS_CALLEE)
        assert cross.ok and cross.data is not None, cross.error
        assert cross.data["count"] == 1, cross.data
        caller = cross.data["callers"][0]
        assert caller["class"] == _DEX_APP_SMALI, caller
        assert caller["method"] == _DEX_CROSS_CALLER, caller

        # And the caller's own methods are reachable from the primary DEX.
        methods = service.apk_methods(session_id, "com.example.App")
        assert methods.ok and methods.data is not None, methods.error
        assert [m["name"] for m in methods.data["methods"]] == [_DEX_CROSS_CALLER]
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_field_xrefs_resolve_read_and_write_sites(tmp_path: Path) -> None:
    """A field's read and write xrefs must land on the right methods.

    Store.save writes the static field secret (sput) and Store.load reads it
    (sget), so the write direction resolves to save and the read direction to
    load -- distinct methods, the way an agent tells "who sets this key" from
    "who uses it". A field untouched in a direction stays found True with an
    empty list, not a miss, and a field that is not there is found False; the
    two must not look alike. This exercises androguard's FieldAnalysis
    read/write xref accessors, the drift surface no class/method/string fixture
    touches. skip != pass when androguard is absent.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "field.apk", dex=_build_field_dex())
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        # The write site: secret is written only by save.
        writes = service.apk_field_xrefs(session_id, _DEX_FIELD_NAME, direction="write")
        assert writes.ok and writes.data is not None, writes.error
        assert writes.data["found"] is True, writes.data
        assert writes.data["direction"] == "write"
        assert writes.data["total"] == 1, writes.data
        writer = writes.data["xrefs"][0]
        assert writer["class"] == _DEX_STORE_SMALI, writer
        assert writer["method"] == _DEX_FIELD_WRITER, writer

        # The read site: secret is read only by load (the default direction).
        reads = service.apk_field_xrefs(session_id, _DEX_FIELD_NAME)
        assert reads.ok and reads.data is not None, reads.error
        assert reads.data["direction"] == "read"
        assert reads.data["total"] == 1, reads.data
        reader = reads.data["xrefs"][0]
        assert reader["class"] == _DEX_STORE_SMALI, reader
        assert reader["method"] == _DEX_FIELD_READER, reader

        # A field the DEX never defines is found False, not an empty hit.
        absent = service.apk_field_xrefs(session_id, "no_such_field")
        assert absent.ok and absent.data is not None, absent.error
        assert absent.data["found"] is False, absent.data
        assert absent.data["xrefs"] == []

        # apk.fields is the inventory side of the same field: list Store's fields
        # and secret must be there with its Dalvik type (I = int) and access, so
        # the "spot the interesting field, then field_xrefs its name" loop starts
        # from a real listing rather than a guessed name. Both class spellings
        # resolve, as with apk.methods.
        for spelling in (_DEX_STORE_SMALI, "com.example.Store"):
            listed = service.apk_fields(session_id, spelling)
            assert listed.ok and listed.data is not None, (spelling, listed.error)
            assert listed.data["class_name"] == _DEX_STORE_SMALI, spelling
            secret = next(
                (f for f in listed.data["fields"] if f["name"] == _DEX_FIELD_NAME), None
            )
            assert secret is not None, listed.data
            assert secret["type"] == "I", secret
            assert "static" in secret["access"], secret
            # The name it lists is exactly what field_xrefs pivots on.
            back = service.apk_field_xrefs(session_id, secret["name"], direction="write")
            assert back.ok and back.data is not None, back.error
            assert back.data["found"] is True, back.data

        # The same name/access filter apk.methods has: secret is static, so the
        # static slice keeps it and a name substring isolates it, while a modifier
        # it lacks narrows to nothing.
        static_fields = service.apk_fields(session_id, "com.example.Store", access="static")
        assert static_fields.ok and static_fields.data is not None, static_fields.error
        assert any(f["name"] == _DEX_FIELD_NAME for f in static_fields.data["fields"])
        assert static_fields.data["filter"] == {"access": "static"}, static_fields.data
        named = service.apk_fields(session_id, "com.example.Store", name_contains="secret")
        assert named.ok and named.data is not None, named.error
        assert [f["name"] for f in named.data["fields"]] == [_DEX_FIELD_NAME], named.data
        volatile = service.apk_fields(session_id, "com.example.Store", access="volatile")
        assert volatile.ok and volatile.data is not None, volatile.error
        assert volatile.data["total"] == 0 and volatile.data["fields"] == [], volatile.data

        # apk.method_refs is the per-method view of the same field access: the same
        # secret that field_xrefs traces globally shows up as a read in load and a
        # write in save, keyed to each method. The field ref carries its declared
        # type, so a caller sees "Store.secret : I", not a bare name.
        field_ref = f"{_DEX_STORE_SMALI}->{_DEX_FIELD_NAME} I"
        load_refs = service.apk_method_refs(session_id, "com.example.Store", _DEX_FIELD_READER)
        assert load_refs.ok and load_refs.data is not None, load_refs.error
        assert load_refs.data["fields"] == [
            {"field": field_ref, "reads": 1, "writes": 0}
        ], load_refs.data
        assert load_refs.data["calls"] == [] and load_refs.data["strings"] == []

        save_refs = service.apk_method_refs(session_id, "com.example.Store", _DEX_FIELD_WRITER)
        assert save_refs.ok and save_refs.data is not None, save_refs.error
        assert save_refs.data["fields"] == [
            {"field": field_ref, "reads": 0, "writes": 1}
        ], save_refs.data

        # Class summary counts the same one field the field readers pivot on, plus
        # the load/save pair, without paging either member list.
        cls_summary = service.apk_class_summary(session_id, "com.example.Store")
        assert cls_summary.ok and cls_summary.data is not None, cls_summary.error
        assert cls_summary.data["class_name"] == _DEX_STORE_SMALI, cls_summary.data
        assert cls_summary.data["field_count"] == 1, cls_summary.data
        assert cls_summary.data["method_count"] == 2, cls_summary.data
        assert cls_summary.data["superclass"] == "Ljava/lang/Object;", cls_summary.data

        # A class the DEX does not declare is a clean not_found, not a crash.
        missing = service.apk_fields(session_id, "com.example.Nope")
        assert not missing.ok
        assert missing.error is not None and missing.error.code == "not_found", missing.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_dex_readers_fail_soft_on_a_corrupt_dex(tmp_path: Path) -> None:
    """A parseable APK with a garbage classes.dex must fault, not crash.

    The manifest is valid AXML but classes.dex is truncated/garbage, so the
    androguard analysis pass (AnalyzeAPK / get_classes) blows up. That raw
    exception must be wrapped into the structured backend_error envelope every
    DEX reader shares -- never surface as internal_error (a logged server defect)
    and never escape as an uncaught traceback. The failure must also stay scoped
    to the DEX line: the manifest readers, which never touch the DEX, still
    decode the package, so an agent learns the APK is readable but its code is
    not, rather than losing the whole session.

    This is the Android sibling of the r2/Ghidra fail-soft gates: the same fault
    contract, exercised against adversarial bytes an agent will encounter in the
    wild (obfuscated, packed, or partially downloaded apps).
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")

    corrupt_dexes = {
        "magic-only": b"dex\n035\x00" + b"\x00" * 8,
        "not-a-dex": b"\x7fELF this is not dalvik bytecode at all" * 4,
        "random-tail": b"dex\n035\x00" + bytes(range(200)),
    }
    for label, payload in corrupt_dexes.items():
        apk = _build_apk(tmp_path / f"corrupt-{label}.apk", dex=payload)
        service = AnalysisService()
        try:
            created = service.create_session(str(apk))
            assert created.ok and created.data is not None, created.error
            session_id = created.data["session"]["id"]

            # The DEX-backed readers must every one fail closed with a structured,
            # non-internal_error code rather than leaking the androguard exception.
            dex_results = {
                "apk_classes": service.apk_classes(session_id, limit=50),
                "apk_strings": service.apk_strings(session_id, limit=50),
                "apk_xrefs": service.apk_xrefs(session_id, "onCreate"),
                "apk_string_xrefs": service.apk_string_xrefs(session_id, "onCreate"),
                "apk_field_xrefs": service.apk_field_xrefs(session_id, "secret"),
                "apk_methods": service.apk_methods(session_id, "com.example.App"),
            }
            for name, result in dex_results.items():
                assert not result.ok and result.error is not None, (label, name, result)
                assert result.error.code != "internal_error", (label, name, result.error)
                assert result.error.code == "backend_error", (label, name, result.error)

            # The fault is scoped to the DEX: the manifest still decodes, so the
            # session is usable for everything that does not need the bytecode.
            opened = service.apk_open(session_id)
            assert opened.ok and opened.data is not None, (label, opened.error)
            assert opened.data["package"] == _PACKAGE, (label, opened.data)
        finally:
            service.close_all()


@pytest.mark.integration
def test_apk_decompile_and_export_sources_with_jadx(tmp_path: Path) -> None:
    """The jadx decompile path must round-trip a real class to Java source.

    androguard covers the in-process readers, but apk.decompile / apk.export_sources
    shell out to jadx and had no end-to-end coverage at all -- the whole path
    (settings discovery, the bounded subprocess, reading the tree back, and the
    class-name -> file mapping with its traversal guards) went unproven, exactly
    the version-drift blind spot that hid the frida and wasm-objdump breaks. Here
    a populated DEX (App.main calls App.onCreate) is decompiled through the real
    service, so a green proves jadx actually produced the named class's source.
    skip != pass when jadx is absent; the in-process APK/DEX builders need no
    device or external sample.
    """
    settings = Settings.load()
    if not JadxClient(settings.jadx).available:
        pytest.skip("jadx not configured (HEADLESS_RE_JADX / PATH) — Gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "decompile.apk", dex=_build_populated_dex())
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id, timeout=240.0)
        assert exported.ok and exported.data is not None, exported.error
        assert exported.data["java_file_count"] >= 1
        assert any(name.endswith("com/example/App.java") for name in exported.data["java_files"])

        decompiled = service.apk_decompile(session_id, "com.example.App", timeout=240.0)
        assert decompiled.ok and decompiled.data is not None, decompiled.error
        source = decompiled.data["source"]
        # jadx recovered the class and both of the methods the DEX defined.
        assert "class App" in source
        assert decompiled.data["path"].endswith("com/example/App.java")
        for method in _DEX_METHODS:
            assert method in source, (method, source)
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_decompile_missing_class_is_a_clean_not_found(tmp_path: Path) -> None:
    """Decompiling a class jadx never emitted must be a structured not_found.

    An agent will ask for classes that are not there (renamed, stripped, or
    guessed). The service walks jadx's output tree for the named file and, on a
    miss, must return not_found -- not internal_error and not the first
    same-named file it stumbles across -- so the caller can branch on it.
    """
    settings = Settings.load()
    if not JadxClient(settings.jadx).available:
        pytest.skip("jadx not configured (HEADLESS_RE_JADX / PATH) — Gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "missing.apk", dex=_build_populated_dex())
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = service.apk_decompile(session_id, "com.example.NoSuchClass", timeout=240.0)
        assert not result.ok and result.error is not None
        assert result.error.code != "internal_error", result.error
        assert result.error.code == "not_found", result.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_decode_and_repack_round_trip_with_apktool(tmp_path: Path) -> None:
    """apktool decode -> repack must round-trip a real APK to smali and back.

    apk.decode and apk.repack shell out to apktool and, like jadx, had no
    end-to-end coverage: decode's smali/resource split, the ``-r`` no-resources
    switch, and repack's rebuild all went unproven against a real apktool. Decode
    a populated DEX (no_resources, since the synthetic APK carries no
    resources.arsc), assert apktool recovered the App class's smali with both its
    methods, then rebuild the tree and assert an unsigned APK lands on disk.
    Decoding smali is the deliverable; with ``-r`` apktool leaves the manifest as
    the original binary AXML, so this asserts on the smali, not the manifest text.
    skip != pass when apktool is absent.
    """
    settings = Settings.load()
    if not ApktoolClient(settings.apktool, settings.apksigner).available:
        pytest.skip(
            "apktool not configured (HEADLESS_RE_APKTOOL / PATH) — Gate not run (skip != pass)"
        )
    apk = _build_apk(tmp_path / "rebuild.apk", dex=_build_populated_dex())
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=300.0, no_resources=True)
        assert decoded.ok and decoded.data is not None, decoded.error
        assert "smali" in decoded.data["smali_dirs"], decoded.data
        decoded_dir = Path(decoded.data["decoded_dir"])
        app_smali = decoded_dir / "smali" / "com" / "example" / "App.smali"
        assert app_smali.is_file(), sorted(str(p) for p in decoded_dir.rglob("*.smali"))
        smali = app_smali.read_text(encoding="utf-8", errors="replace")
        assert ".class" in smali
        for method in _DEX_METHODS:
            assert method in smali, (method, smali)

        repacked = service.apk_repack(session_id, timeout=300.0)
        assert repacked.ok and repacked.data is not None, repacked.error
        assert repacked.data["signed"] is False
        rebuilt = Path(repacked.data["apk"])
        assert rebuilt.is_file() and rebuilt.stat().st_size > 0, repacked.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_repack_rejects_a_directory_that_is_not_a_decode_output(tmp_path: Path) -> None:
    """Repacking a tree with no AndroidManifest.xml must be invalid_params.

    apk.repack is destructive tooling pointed at a caller-influenced directory.
    A path that is not an apktool decode output (no manifest) has to be refused
    up front with a structured invalid_params, never handed to apktool to fail
    opaquely or crash as internal_error.
    """
    settings = Settings.load()
    if not ApktoolClient(settings.apktool, settings.apksigner).available:
        pytest.skip(
            "apktool not configured (HEADLESS_RE_APKTOOL / PATH) — Gate not run (skip != pass)"
        )
    apk = _build_apk(tmp_path / "norepack.apk", dex=_build_populated_dex())
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        # Decode first so a real (owned) session artifact directory exists, then
        # point repack at an empty subdir of it: inside the artifact tree (passes
        # the ownership guard) but not an apktool output (no manifest).
        decoded = service.apk_decode(session_id, timeout=300.0, no_resources=True)
        assert decoded.ok and decoded.data is not None, decoded.error
        empty = Path(decoded.data["decoded_dir"]).parent / "not-a-decode"
        empty.mkdir(parents=True, exist_ok=True)

        result = service.apk_repack(session_id, decoded_dir=str(empty), timeout=300.0)
        assert not result.ok and result.error is not None
        assert result.error.code != "internal_error", result.error
        assert result.error.code == "invalid_params", result.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_decode_repack_sign_round_trip_with_apksigner(tmp_path: Path) -> None:
    """The full patch workflow -- decode, rebuild, sign -- must produce a
    verifiably signed APK.

    apk.sign shells out to apksigner and is the step that makes a rebuilt APK
    installable, closing the decode -> edit -> build -> sign loop. It had no
    end-to-end coverage: keystore discovery (the standard Android debug keystore
    by default), the apksigner invocation with its password argument, and the
    post-sign ``apksigner verify`` step all went unproven. Drive the whole chain
    through the real service and assert the signed APK lands on disk marked
    signed with the debug keystore -- signed is only True because the service's
    own verify pass accepted the output, so a green means apksigner actually
    verified the signature. skip != pass when apktool, apksigner, or the debug
    keystore is absent.
    """
    settings = Settings.load()
    client = ApktoolClient(settings.apktool, settings.apksigner)
    if not client.available:
        pytest.skip(
            "apktool not configured (HEADLESS_RE_APKTOOL / PATH) — Gate not run (skip != pass)"
        )
    if not client.signer_available:
        pytest.skip(
            "apksigner not configured (HEADLESS_RE_APKSIGNER / PATH) — Gate not run (skip != pass)"
        )
    if not _DEBUG_KEYSTORE.is_file():
        pytest.skip(
            f"debug keystore missing at {_DEBUG_KEYSTORE} — Gate not run (skip != pass)"
        )
    apk = _build_apk(tmp_path / "sign.apk", dex=_build_populated_dex())
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=300.0, no_resources=True)
        assert decoded.ok, decoded.error
        repacked = service.apk_repack(session_id, timeout=300.0)
        assert repacked.ok, repacked.error

        signed = service.apk_sign(session_id, timeout=300.0)
        assert signed.ok and signed.data is not None, signed.error
        assert signed.data["signed"] is True, signed.data
        assert signed.data["debug_keystore"] is True, signed.data
        out = Path(signed.data["apk"])
        assert out.is_file() and out.stat().st_size > 0, signed.data
    finally:
        service.close_all()


def _apksigner_sign_scheme(
    apksigner: Path,
    src: Path,
    out: Path,
    *,
    v1: bool,
    v2: bool,
    v3: bool,
) -> None:
    """Sign ``src`` into ``out`` with exactly the requested schemes enabled."""
    subprocess.run(
        [
            str(apksigner),
            "sign",
            "--ks",
            str(_DEBUG_KEYSTORE),
            "--ks-pass",
            f"pass:{_DEBUG_PASSWORD}",
            "--ks-key-alias",
            _DEBUG_ALIAS,
            "--key-pass",
            f"pass:{_DEBUG_PASSWORD}",
            "--v1-signing-enabled",
            "true" if v1 else "false",
            "--v2-signing-enabled",
            "true" if v2 else "false",
            "--v3-signing-enabled",
            "true" if v3 else "false",
            "--out",
            str(out),
            str(src),
        ],
        check=True,
        capture_output=True,
        timeout=180.0,
    )


@pytest.mark.integration
def test_apk_certificates_report_the_actual_signing_scheme(tmp_path: Path) -> None:
    """apk.certificates must name which signature scheme really signed the APK.

    v1_signed alone (inferred from META-INF signature files) cannot tell a
    tamperable v1 JAR signature from the whole-file v2/v3 APK Signature Schemes
    a modern build carries -- and a v2/v3-only APK leaves no META-INF files at
    all, so the old bool(names) inference would call a properly signed app
    "unsigned". This signs the same fixture two ways with the real apksigner --
    v2-only, then v1+v3 -- and asserts the reader reports exactly the enabled
    schemes each time, discriminating them rather than collapsing to a single
    "has a certificate" bit. skip != pass when apksigner or the debug keystore
    is absent.
    """
    settings = Settings.load()
    client = ApktoolClient(settings.apktool, settings.apksigner)
    if not client.signer_available or settings.apksigner is None:
        pytest.skip(
            "apksigner not configured (HEADLESS_RE_APKSIGNER / PATH) — Gate not run (skip != pass)"
        )
    if not _DEBUG_KEYSTORE.is_file():
        pytest.skip(f"debug keystore missing at {_DEBUG_KEYSTORE} — Gate not run (skip != pass)")

    unsigned = _build_apk(tmp_path / "scheme.apk", dex=_build_populated_dex())
    cases = {
        "v2-only": (False, True, False, ["v2"]),
        "v1+v3": (True, False, True, ["v1", "v3"]),
    }
    for label, (v1, v2, v3, expected) in cases.items():
        out = tmp_path / f"signed-{label}.apk"
        try:
            _apksigner_sign_scheme(settings.apksigner, unsigned, out, v1=v1, v2=v2, v3=v3)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            stderr = getattr(exc, "stderr", b"") or b""
            pytest.skip(f"apksigner could not sign the {label} fixture ({stderr[:160]!r})")

        service = AnalysisService(settings)
        try:
            created = service.create_session(str(out))
            assert created.ok and created.data is not None, (label, created.error)
            session_id = created.data["session"]["id"]

            certs = service.apk_certificates(session_id)
            assert certs.ok and certs.data is not None, (label, certs.error)
            assert certs.data["v1_signed"] is v1, (label, certs.data)
            assert certs.data["v2_signed"] is v2, (label, certs.data)
            assert certs.data["v3_signed"] is v3, (label, certs.data)
            assert certs.data["signing_schemes"] == expected, (label, certs.data)
            # A real signature also yields at least one certificate to inspect.
            assert certs.data["certificates"], (label, certs.data)
        finally:
            service.close_all()


# The extract -> native-analysis handoff: a real ELF shared object embedded in
# the APK, carrying an exported function and a marker string r2 must recover.
_NATIVE_LIB_ENTRY = "lib/x86_64/libre_mcp.so"
_NATIVE_FUNC = "re_mcp_triple"
_NATIVE_MARKER = "re_mcp_native_marker_9449"
_NATIVE_SO_SOURCE = (
    f"int {_NATIVE_FUNC}(int x) {{ return x * 3 + 1; }}\n"
    f'const char re_mcp_marker[] = "{_NATIVE_MARKER}";\n'
)


def _build_elf_so(tmp_path: Path) -> bytes:
    """Compile a tiny ELF shared object, or skip (skip != pass).

    A shared object (not the placeholder ``\\x7fELF`` bytes the other fixtures
    embed) is what proves the extracted library is a genuine native binary the
    portable backend can analyse: it carries an exported function and a marker
    string in .rodata, both of which r2 must recover from the pulled-out file.
    """
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — native-lib handoff Gate not run (skip != pass)")
    source = tmp_path / "re_mcp_lib.c"
    source.write_text(_NATIVE_SO_SOURCE, encoding="utf-8")
    out = tmp_path / "libre_mcp.so"
    try:
        completed = subprocess.run(
            [compiler, "-shared", "-fPIC", "-O0", "-o", str(out), str(source)],
            capture_output=True,
            timeout=120.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover - host dependent
        pytest.skip(f"C compiler unusable ({exc}) — native-lib handoff Gate not run (skip != pass)")
    if completed.returncode != 0 or not out.is_file():
        pytest.skip(
            "C compiler produced no shared object "
            f"({completed.stderr.decode('utf-8', 'replace')[:200]}) — skip != pass"
        )
    return out.read_bytes()


@pytest.mark.integration
def test_apk_extract_native_lib_feeds_the_native_analysis_line(tmp_path: Path) -> None:
    """An embedded .so must extract to a file the native RE backend can analyse.

    apk.native_libs could list an app's native libraries but nothing could hand
    one to r2/Ghidra -- jadx and apktool only touch Java/smali, so native crypto,
    DRM and anti-tamper code was a dead end. This embeds a real ELF shared object
    in the APK, extracts it through apk.extract_native_lib (exact bytes, an
    artifact id), then opens the pulled-out file as a native session and proves r2
    recovers the exported function and the marker string. That is the seam from
    the Android line to the native line. skip != pass without androguard, a C
    compiler, or radare2.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    so_bytes = _build_elf_so(tmp_path)
    apk = _build_apk(
        tmp_path / "native.apk",
        dex=_build_populated_dex(),
        extra_files={_NATIVE_LIB_ENTRY: so_bytes},
    )
    service = AnalysisService(Settings.load())
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        # The library is listed, then extracted to disk with the exact bytes.
        libs = service.apk_native_libs(session_id)
        assert libs.ok and libs.data is not None, libs.error
        assert _NATIVE_LIB_ENTRY in libs.data["native_libs"], libs.data["native_libs"]

        extracted = service.apk_extract_native_lib(session_id, _NATIVE_LIB_ENTRY)
        assert extracted.ok and extracted.data is not None, extracted.error
        assert extracted.data["abi"] == "x86_64", extracted.data
        assert extracted.data["sha256"] == hashlib.sha256(so_bytes).hexdigest()
        assert extracted.data["size"] == len(so_bytes)
        # It is registered, so an agent has a handle to read it back.
        assert extracted.data.get("artifact_id"), extracted.data
        lib_path = Path(extracted.data["path"])
        assert lib_path.is_file()
        on_disk = lib_path.read_bytes()
        assert on_disk == so_bytes
        assert on_disk[:4] == b"\x7fELF", on_disk[:8]

        # Asking for a real archive entry that is not a native library is refused,
        # so this is not an arbitrary zip extractor.
        not_a_lib = service.apk_extract_native_lib(session_id, "classes.dex")
        assert not not_a_lib.ok and not_a_lib.error is not None
        assert not_a_lib.error.code == "invalid_params", not_a_lib.error

        # A .so name absent from the archive is a clean not_found.
        ghost = service.apk_extract_native_lib(session_id, "lib/x86_64/ghost.so")
        assert not ghost.ok and ghost.error is not None
        assert ghost.error.code == "not_found", ghost.error

        # The seam: the extracted file opens as a native session and r2 analyses
        # it -- the whole reason to pull the library out of the APK.
        if not R2Client().available:
            pytest.skip("radare2 not installed — native handoff leg not run (skip != pass)")
        native = service.create_session(str(lib_path))
        assert native.ok and native.data is not None, native.error
        nsession = native.data["session"]
        assert nsession.get("target") == "native", nsession
        assert nsession.get("metadata", {}).get("native", {}).get("format") == "elf", nsession
        nsid = str(nsession["id"])

        assert service.r2_open(nsid, timeout=60.0).ok

        # The exported function must come back from the extracted library, named.
        exports = service.r2_exports(nsid, timeout=60.0)
        assert exports.ok and exports.data is not None, exports.error
        symbols = service.r2_symbols(nsid, timeout=60.0)
        assert symbols.ok and symbols.data is not None, symbols.error
        names = {item.get("name") for item in exports.data.get("items", [])}
        names |= {item.get("name") for item in symbols.data.get("items", [])}
        assert any(_NATIVE_FUNC in (n or "") for n in names), sorted(n for n in names if n)

        # The marker string in .rodata proves r2 read the real library bytes.
        strings = service.r2_strings(nsid, timeout=60.0)
        assert strings.ok and strings.data is not None, strings.error
        literals = strings.data.get("items") or []
        assert any(
            _NATIVE_MARKER in (s.get("string") or "") for s in literals
        ), [s.get("string") for s in literals]
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_sign_before_repack_is_a_clean_not_found(tmp_path: Path) -> None:
    """Signing before anything was rebuilt must be a structured not_found.

    apk.sign defaults its input to the session's repacked.apk. Calling it before
    apk.repack (that file does not exist yet) has to surface not_found so the
    caller learns "build first", never internal_error from an apksigner run on a
    missing path. Only apksigner is needed to reach this branch -- it fires
    before any keystore work -- so the gate does not depend on apktool.
    """
    settings = Settings.load()
    if not ApktoolClient(settings.apktool, settings.apksigner).signer_available:
        pytest.skip(
            "apksigner not configured (HEADLESS_RE_APKSIGNER / PATH) — Gate not run (skip != pass)"
        )
    apk = _build_apk(tmp_path / "nosign.apk", dex=_build_populated_dex())
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = service.apk_sign(session_id, timeout=300.0)
        assert not result.ok and result.error is not None
        assert result.error.code != "internal_error", result.error
        assert result.error.code == "not_found", result.error
    finally:
        service.close_all()
