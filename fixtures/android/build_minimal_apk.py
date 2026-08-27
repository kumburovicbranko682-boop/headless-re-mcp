"""Build the committed ``minimal.apk`` Android fixture from scratch.

There is no Android SDK on the machines that run this suite (no ``aapt2`` /
``d8`` / ``apksigner``), so the manifest is emitted here as compiled binary XML
(AXML) by a tiny purpose-built encoder -- just enough of the format for
androguard to read the package, versions, SDK levels, one permission, and one
launcher activity. The APK is then v1 (JAR) signed with the JDK's ``keytool``
and ``jarsigner`` so certificate parsing is exercised too.

The committed ``minimal.apk`` is the artifact the gate consumes; this script is
its provenance. Re-running it produces an equivalent APK (the embedded manifest
is byte-identical; the signature differs because a fresh throwaway key is
generated each time). ``classes.dex`` is an intentional placeholder: the gate
covers the manifest-level surface and asserts DEX analysis degrades cleanly, so
a full valid DEX is deliberately out of scope.

Usage::

    python fixtures/android/build_minimal_apk.py            # writes minimal.apk
    python fixtures/android/build_minimal_apk.py --unsigned  # skip JDK signing
"""

from __future__ import annotations

import argparse
import struct
import subprocess
import tempfile
import zipfile
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

ANDROID_NS = "http://schemas.android.com/apk/res/android"
PACKAGE = "com.example.headless"
MAIN_ACTIVITY = "com.example.headless.MainActivity"
PERMISSION = "android.permission.INTERNET"

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
        self, ns: str | None, name: str, value: str | int, *, is_int: bool = False
    ) -> None:
        self.ns = ns
        self.name = name
        self.value = value
        self.is_int = is_int


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
        if attr.is_int:
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
        "application",
        "activity",
        "intent-filter",
        "action",
        "category",
        PACKAGE,
        "1.0",
        MAIN_ACTIVITY,
        PERMISSION,
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
        "Headless",
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
    body += _start_element(pool, "application", [Attr(ANDROID_NS, "label", "Headless")])
    body += _start_element(pool, "activity", [Attr(ANDROID_NS, "name", MAIN_ACTIVITY)])
    body += _start_element(pool, "intent-filter", [])
    body += _start_element(pool, "action", [Attr(ANDROID_NS, "name", "android.intent.action.MAIN")])
    body += _end_element(pool, "action")
    body += _start_element(
        pool, "category", [Attr(ANDROID_NS, "name", "android.intent.category.LAUNCHER")]
    )
    body += _end_element(pool, "category")
    body += _end_element(pool, "intent-filter")
    body += _end_element(pool, "activity")
    body += _end_element(pool, "application")
    body += _end_element(pool, "manifest")
    body += _namespace(pool, RES_XML_END_NAMESPACE_TYPE)

    payload = pool.encode() + bytes(body)
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(payload)) + payload


def assemble_apk(target: Path) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", build_manifest())
        # Placeholder DEX: valid magic, but not analysable -- the gate asserts
        # DEX-level tools degrade to a structured envelope on it.
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
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
