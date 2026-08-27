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
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
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


def _build_apk(
    path: Path, *, dex: bytes | None = None, extra_dexes: dict[str, bytes] | None = None
) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", _build_manifest_axml())
        archive.writestr("classes.dex", dex if dex is not None else _build_empty_dex())
        for name, payload in (extra_dexes or {}).items():
            archive.writestr(name, payload)
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libhello.so", b"\x7fELFplaceholder")
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
        assert certs.data["v1_signed"] is False  # unsigned fixture
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
            dex_calls = {
                "apk_classes": lambda: service.apk_classes(session_id, limit=50),
                "apk_strings": lambda: service.apk_strings(session_id, limit=50),
                "apk_xrefs": lambda: service.apk_xrefs(session_id, "onCreate"),
                "apk_methods": lambda: service.apk_methods(session_id, "com.example.App"),
            }
            for name, call in dex_calls.items():
                result = call()
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
