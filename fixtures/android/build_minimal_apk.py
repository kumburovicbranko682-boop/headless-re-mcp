"""Build the committed ``minimal.apk`` Android fixture from scratch.

There is no Android SDK on the machines that run this suite (no ``aapt2`` /
``d8`` / ``apksigner`` / ``smali``), so every part is emitted here by tiny
purpose-built encoders:

* the manifest as compiled binary XML (AXML) -- enough for androguard to read
  the package, versions, SDK levels, one permission, two shared-library
  dependencies (<uses-library>), one launcher activity (which also handles two
  deep links through an ACTION_VIEW filter: an https host/pathPrefix and a bare
  custom scheme), and a mix of exported and private components (an exported
  service, a private receiver, an exported provider) that exercise every
  export rule;
* ``classes.dex`` as a valid DEX carrying one class
  (``com.example.headless.Sample``) with one static method (``getSecret``) that
  returns the string ``flag{headless-re}`` -- enough for androguard's full
  ``AnalyzeAPK`` to enumerate the class, its method, and its strings.

The APK is then v1 (JAR) signed with the JDK's ``keytool`` and ``jarsigner`` so
certificate parsing is exercised too.

The committed ``minimal.apk`` is the artifact the gate consumes; this script is
its provenance. Re-running it produces an equivalent APK (the embedded manifest
and DEX are byte-identical; the signature differs because a fresh throwaway key
is generated each time).

Usage::

    python fixtures/android/build_minimal_apk.py            # writes minimal.apk
    python fixtures/android/build_minimal_apk.py --unsigned  # skip JDK signing
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"
PACKAGE = "com.example.headless"
# The custom Application subclass (<application android:name>): instantiated
# before any component runs -- the app's code-before-main -- so the reader's
# application_name fact and the apktool/androguard cross-checks have a real
# declared class to agree on.
APPLICATION_NAME = "com.example.headless.HeadlessApp"
MAIN_ACTIVITY = "com.example.headless.MainActivity"
PERMISSION = "android.permission.INTERNET"
# Device shared-library dependencies (<uses-library>): one hard requirement
# (no android:required attribute, which defaults to true) and one optional,
# so the reader's default handling and the explicit-false encoding are both
# exercised and cross-checkable against apktool/androguard.
USES_LIBRARY_REQUIRED = "org.apache.http.legacy"
USES_LIBRARY_OPTIONAL = "androidx.window.extensions"
# Extra components exercising every export rule the reader applies, so the
# apktool/androguard gate cross-checks a non-trivial attack surface: a service
# exported by an explicit android:exported="true" (no intent-filter), a
# receiver an explicit "false" closes despite carrying an intent-filter, and a
# provider exported explicitly. Together with the launcher activity (exported
# implicitly through its MAIN/LAUNCHER filter) that is one of each kind.
EXPORTED_SERVICE = "com.example.headless.ExportedService"
PRIVATE_RECEIVER = "com.example.headless.PrivateReceiver"
EXPORTED_PROVIDER = "com.example.headless.SharedProvider"
PROVIDER_AUTHORITY = "com.example.headless.provider"
CUSTOM_ACTION = "com.example.headless.action.PING"
# The deep links the launcher activity handles: a second intent-filter with
# ACTION_VIEW (BROWSABLE/DEFAULT, as a real link handler declares) whose two
# <data> elements bind an https://deeplink.example.com/open prefix and a bare
# custom scheme -- one web link and one app scheme, so the reader's URI-part
# handling and the multi-<data> case are both exercised and cross-checkable
# against apktool/androguard.
DEEP_LINK_SCHEME_WEB = "https"
DEEP_LINK_HOST = "deeplink.example.com"
DEEP_LINK_PATH_PREFIX = "/open"
DEEP_LINK_SCHEME_APP = "headless"

# Framework attribute resource ids for the android:* attributes we emit. The
# string-pool entries for these names must lead the pool so their indices line
# up with the resource-map array below.
ATTR_RES_IDS = {
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270,
    "name": 0x01010003,
    "label": 0x01010001,
    "debuggable": 0x0101000F,
    "allowBackup": 0x01010280,
    "usesCleartextTraffic": 0x010104EC,
    "required": 0x0101028E,
    "exported": 0x01010010,
    "authorities": 0x01010018,
    "scheme": 0x01010027,
    "host": 0x01010028,
    "pathPrefix": 0x0101002B,
}
ATTR_NAMES = list(ATTR_RES_IDS)


class StringPool:
    def __init__(self) -> None:
        self._strings: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self._strings)
            self._strings.append(value)
        return self._index[value]

    def index(self, value: str) -> int:
        return self._index[value]

    def encode(self) -> bytes:
        offsets: list[int] = []
        data = bytearray()
        for value in self._strings:
            offsets.append(len(data))
            data += struct.pack("<H", len(value))
            data += value.encode("utf-16-le")
            data += b"\x00\x00"
        while len(data) % 4 != 0:
            data += b"\x00"
        count = len(self._strings)
        strings_start = 28 + count * 4
        header = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL_TYPE,
            28,
            strings_start + len(data),
            count,
            0,
            0,
            strings_start,
            0,
        )
        offset_array = b"".join(struct.pack("<I", off) for off in offsets)
        return header + offset_array + bytes(data)


class Attr:
    def __init__(
        self,
        ns: str | None,
        name: str,
        value: str | int | bool,
        *,
        is_int: bool = False,
        is_bool: bool = False,
    ) -> None:
        self.ns = ns
        self.name = name
        self.value = value
        self.is_int = is_int
        self.is_bool = is_bool


def _resource_map() -> bytes:
    body = b"".join(struct.pack("<I", ATTR_RES_IDS[name]) for name in ATTR_NAMES)
    return struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + len(body)) + body


def _namespace(pool: StringPool, chunk_type: int) -> bytes:
    body = struct.pack(
        "<IIii", 0xFFFFFFFF, 0xFFFFFFFF, pool.index("android"), pool.index(ANDROID_NS)
    )
    return struct.pack("<HHI", chunk_type, 16, 8 + len(body)) + body


def _start_element(pool: StringPool, name: str, attrs: list[Attr]) -> bytes:
    attr_bytes = bytearray()
    for attr in attrs:
        ns = pool.index(attr.ns) if attr.ns else -1
        if attr.is_bool:
            raw, data_type, data = -1, TYPE_INT_BOOLEAN, (0xFFFFFFFF if attr.value else 0)
        elif attr.is_int:
            raw, data_type, data = -1, TYPE_INT_DEC, int(attr.value) & 0xFFFFFFFF
        else:
            raw = data = pool.index(str(attr.value))
            data_type = TYPE_STRING
        attr_bytes += struct.pack(
            "<iiiHBBI", ns, pool.index(attr.name), raw, 8, 0, data_type, data
        )
    ext = struct.pack(
        "<IIiIHHHHHH",
        0xFFFFFFFF,
        0xFFFFFFFF,
        -1,
        pool.index(name),
        20,
        20,
        len(attrs),
        0,
        0,
        0,
    )
    chunk = ext + bytes(attr_bytes)
    return struct.pack("<HHI", RES_XML_START_ELEMENT_TYPE, 16, 8 + len(chunk)) + chunk


def _end_element(pool: StringPool, name: str) -> bytes:
    body = struct.pack("<IIiI", 0xFFFFFFFF, 0xFFFFFFFF, -1, pool.index(name))
    return struct.pack("<HHI", RES_XML_END_ELEMENT_TYPE, 16, 8 + len(body)) + body


def build_manifest() -> bytes:
    pool = StringPool()
    for name in ATTR_NAMES:
        pool.add(name)
    for value in (
        "android",
        ANDROID_NS,
        "package",
        "manifest",
        "uses-sdk",
        "uses-permission",
        "uses-library",
        "application",
        "activity",
        "service",
        "receiver",
        "provider",
        "intent-filter",
        "action",
        "category",
        "data",
        PACKAGE,
        "1.0",
        APPLICATION_NAME,
        MAIN_ACTIVITY,
        PERMISSION,
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
        "android.intent.action.VIEW",
        "android.intent.category.DEFAULT",
        "android.intent.category.BROWSABLE",
        "Headless",
        USES_LIBRARY_REQUIRED,
        USES_LIBRARY_OPTIONAL,
        EXPORTED_SERVICE,
        PRIVATE_RECEIVER,
        EXPORTED_PROVIDER,
        PROVIDER_AUTHORITY,
        CUSTOM_ACTION,
        DEEP_LINK_SCHEME_WEB,
        DEEP_LINK_HOST,
        DEEP_LINK_PATH_PREFIX,
        DEEP_LINK_SCHEME_APP,
    ):
        pool.add(value)

    body = bytearray()
    body += _resource_map()
    body += _namespace(pool, RES_XML_START_NAMESPACE_TYPE)
    body += _start_element(pool, "manifest", [
        Attr(None, "package", PACKAGE),
        Attr(ANDROID_NS, "versionCode", 1, is_int=True),
        Attr(ANDROID_NS, "versionName", "1.0"),
    ])
    body += _start_element(pool, "uses-sdk", [
        Attr(ANDROID_NS, "minSdkVersion", 21, is_int=True),
        Attr(ANDROID_NS, "targetSdkVersion", 33, is_int=True),
    ])
    body += _end_element(pool, "uses-sdk")
    body += _start_element(pool, "uses-permission", [Attr(ANDROID_NS, "name", PERMISSION)])
    body += _end_element(pool, "uses-permission")
    body += _start_element(pool, "application", [
        # The custom Application class, run before any component -- the fact
        # the reader reports as application_name.
        Attr(ANDROID_NS, "name", APPLICATION_NAME),
        Attr(ANDROID_NS, "label", "Headless"),
        # Declared security-posture flags the stdlib AXML reader surfaces and
        # the apktool gate cross-checks against apktool's decoded manifest:
        # a debuggable, cleartext-permitting build whose data is shielded from
        # `adb backup` -- one true, one false, so both encodings are exercised.
        Attr(ANDROID_NS, "debuggable", True, is_bool=True),
        Attr(ANDROID_NS, "allowBackup", False, is_bool=True),
        Attr(ANDROID_NS, "usesCleartextTraffic", True, is_bool=True),
    ])
    body += _start_element(
        pool, "uses-library", [Attr(ANDROID_NS, "name", USES_LIBRARY_REQUIRED)]
    )
    body += _end_element(pool, "uses-library")
    body += _start_element(pool, "uses-library", [
        Attr(ANDROID_NS, "name", USES_LIBRARY_OPTIONAL),
        Attr(ANDROID_NS, "required", False, is_bool=True),
    ])
    body += _end_element(pool, "uses-library")
    body += _start_element(pool, "activity", [Attr(ANDROID_NS, "name", MAIN_ACTIVITY)])
    body += _start_element(pool, "intent-filter", [])
    body += _start_element(pool, "action", [Attr(ANDROID_NS, "name", "android.intent.action.MAIN")])
    body += _end_element(pool, "action")
    body += _start_element(
        pool, "category", [Attr(ANDROID_NS, "name", "android.intent.category.LAUNCHER")]
    )
    body += _end_element(pool, "category")
    body += _end_element(pool, "intent-filter")
    # The deep-link filter: ACTION_VIEW + BROWSABLE/DEFAULT with two <data>
    # elements, exactly how a real link handler declares an https prefix and a
    # bare custom scheme side by side.
    body += _start_element(pool, "intent-filter", [])
    body += _start_element(pool, "action", [Attr(ANDROID_NS, "name", "android.intent.action.VIEW")])
    body += _end_element(pool, "action")
    body += _start_element(
        pool, "category", [Attr(ANDROID_NS, "name", "android.intent.category.DEFAULT")]
    )
    body += _end_element(pool, "category")
    body += _start_element(
        pool, "category", [Attr(ANDROID_NS, "name", "android.intent.category.BROWSABLE")]
    )
    body += _end_element(pool, "category")
    body += _start_element(pool, "data", [
        Attr(ANDROID_NS, "scheme", DEEP_LINK_SCHEME_WEB),
        Attr(ANDROID_NS, "host", DEEP_LINK_HOST),
        Attr(ANDROID_NS, "pathPrefix", DEEP_LINK_PATH_PREFIX),
    ])
    body += _end_element(pool, "data")
    body += _start_element(pool, "data", [Attr(ANDROID_NS, "scheme", DEEP_LINK_SCHEME_APP)])
    body += _end_element(pool, "data")
    body += _end_element(pool, "intent-filter")
    body += _end_element(pool, "activity")
    # A service exported by an explicit android:exported="true", no filter.
    body += _start_element(pool, "service", [
        Attr(ANDROID_NS, "name", EXPORTED_SERVICE),
        Attr(ANDROID_NS, "exported", True, is_bool=True),
    ])
    body += _end_element(pool, "service")
    # A receiver an explicit "false" keeps private even though it carries an
    # intent-filter -- the case the reader must not mistake for exported.
    body += _start_element(pool, "receiver", [
        Attr(ANDROID_NS, "name", PRIVATE_RECEIVER),
        Attr(ANDROID_NS, "exported", False, is_bool=True),
    ])
    body += _start_element(pool, "intent-filter", [])
    body += _start_element(pool, "action", [Attr(ANDROID_NS, "name", CUSTOM_ACTION)])
    body += _end_element(pool, "action")
    body += _end_element(pool, "intent-filter")
    body += _end_element(pool, "receiver")
    # A content provider exported explicitly (authorities is required by aapt).
    body += _start_element(pool, "provider", [
        Attr(ANDROID_NS, "name", EXPORTED_PROVIDER),
        Attr(ANDROID_NS, "authorities", PROVIDER_AUTHORITY),
        Attr(ANDROID_NS, "exported", True, is_bool=True),
    ])
    body += _end_element(pool, "provider")
    body += _end_element(pool, "application")
    body += _end_element(pool, "manifest")
    body += _namespace(pool, RES_XML_END_NAMESPACE_TYPE)

    payload = pool.encode() + bytes(body)
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(payload)) + payload


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


def build_dex() -> bytes:
    """A minimal but structurally valid DEX (format 035).

    One class ``Lcom/example/headless/Sample;`` with a public static method
    ``getSecret()Ljava/lang/String;`` whose body is ``const-string v0,
    "flag{headless-re}"`` / ``return-object v0``. The id tables observe DEX's
    ordering rules (string_ids sorted by MUTF-8 bytes; type/method ids by their
    referenced indices) so androguard's AnalyzeAPK parses and analyses it.
    """
    # Strings, pre-sorted by MUTF-8 byte order as string_ids requires.
    strings = [
        "L",  # 0: shorty for ()L...
        "Lcom/example/headless/Sample;",  # 1
        "Ljava/lang/Object;",  # 2
        "Ljava/lang/String;",  # 3
        "Sample.java",  # 4
        "flag{headless-re}",  # 5
        "getSecret",  # 6
    ]
    type_string_idx = [1, 2, 3]  # Sample, Object, String
    type_sample, type_object, type_string = 0, 1, 2

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + len(type_string_idx) * 4
    method_ids_off = proto_ids_off + 12  # one proto
    class_defs_off = method_ids_off + 8  # one method
    data_off = class_defs_off + 32  # one class def

    data = bytearray()

    def align(width: int) -> None:
        while (data_off + len(data)) % width != 0:
            data.append(0)

    string_data_offs: list[int] = []
    for text in strings:
        string_data_offs.append(data_off + len(data))
        data += _uleb128(len(text))  # UTF-16 units; ASCII => char count
        data += text.encode("utf-8")
        data += b"\x00"

    align(4)
    code_off = data_off + len(data)
    insns = struct.pack("<HHH", 0x001A, 5, 0x0011)  # const-string v0, str@5; return-object v0
    data += struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(insns) // 2)
    data += insns

    class_data_off = data_off + len(data)
    data += _uleb128(0)  # static_fields_size
    data += _uleb128(0)  # instance_fields_size
    data += _uleb128(1)  # direct_methods_size
    data += _uleb128(0)  # virtual_methods_size
    data += _uleb128(0)  # method_idx_diff (first)
    data += _uleb128(0x9)  # ACC_PUBLIC | ACC_STATIC
    data += _uleb128(code_off)

    align(4)
    map_off = data_off + len(data)
    entries = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(type_string_idx), type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 1, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2000, 1, class_data_off),
        (0x2001, 1, code_off),
        (0x2002, len(strings), string_data_offs[0]),
        (0x1000, 1, map_off),
    ]
    data += struct.pack("<I", len(entries))
    for type_code, size, off in entries:
        data += struct.pack("<HHII", type_code, 0, size, off)

    data_size = len(data)

    string_ids = b"".join(struct.pack("<I", off) for off in string_data_offs)
    type_ids = b"".join(struct.pack("<I", idx) for idx in type_string_idx)
    proto_ids = struct.pack("<III", 0, type_string, 0)
    method_ids = struct.pack("<HHI", type_sample, 0, 6)
    class_defs = struct.pack(
        "<IIIIIIII", type_sample, 0x1, type_object, 0, 4, 0, class_data_off, 0
    )

    body = string_ids + type_ids + proto_ids + method_ids + class_defs + bytes(data)
    file_size = header_size + len(body)

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, len(type_string_idx))
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, 1)
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, 0)  # field_ids_size
    struct.pack_into("<I", header, 84, 0)  # field_ids_off
    struct.pack_into("<I", header, 88, 1)
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, 1)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, data_size)
    struct.pack_into("<I", header, 108, data_off)

    full = bytearray(bytes(header) + body)
    full[12:32] = hashlib.sha1(full[32:]).digest()
    struct.pack_into("<I", full, 8, zlib.adler32(bytes(full[12:])) & 0xFFFFFFFF)
    return bytes(full)


def assemble_apk(target: Path) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", build_manifest())
        archive.writestr("classes.dex", build_dex())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 32)
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELF" + b"\x00" * 32)
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 8)


def sign_apk(target: Path) -> None:
    password = "fixture123"
    with tempfile.TemporaryDirectory() as tmp:
        keystore = Path(tmp) / "fixture.jks"
        subprocess.run(
            [
                "keytool", "-genkeypair", "-keystore", str(keystore),
                "-storepass", password, "-keypass", password, "-alias", "fx",
                "-dname", "CN=Headless RE Fixture, O=headless-re-mcp, C=US",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "36500",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "jarsigner", "-keystore", str(keystore), "-storepass", password,
                "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256", str(target), "fx",
            ],
            check=True,
            capture_output=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsigned", action="store_true", help="skip JDK v1 signing")
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).with_name("minimal.apk")
    )
    args = parser.parse_args()
    assemble_apk(args.out)
    if not args.unsigned:
        sign_apk(args.out)
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
