"""Android backend boundaries: argument validation, no shell passthrough, auth.

These cover the properties that make the Android surface safe to expose, not the
happy paths (which need a real device and live in the integration gates).
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError, _check_package, _check_serial
from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import classify_target, describe_apk
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport


def _apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    return path


def _apk_with_signing_block(
    path: Path, scheme_ids: list[int], values: dict[int, bytes] | None = None
) -> Path:
    """Write an APK whose Signing Block advertises ``scheme_ids``.

    The block is spliced in just before the central directory -- exactly where
    a real signer puts it -- and the End Of Central Directory offset is fixed up
    so the archive still parses as a valid ZIP. ``values`` supplies a scheme's
    block value (e.g. a real signer sequence); absent ones get filler bytes.
    """
    base = path.with_suffix(".base.apk")
    with zipfile.ZipFile(base, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    raw = base.read_bytes()
    eocd = raw.rfind(b"PK\x05\x06")
    cd_size = int.from_bytes(raw[eocd + 12 : eocd + 16], "little")
    cd_offset = int.from_bytes(raw[eocd + 16 : eocd + 20], "little")
    pairs = b""
    for scheme_id in scheme_ids:
        value = (values or {}).get(scheme_id, b"\x00" * 8)
        pairs += struct.pack("<Q", 4 + len(value)) + struct.pack("<I", scheme_id) + value
    block_size = len(pairs) + 8 + 16
    block = (
        struct.pack("<Q", block_size)
        + pairs
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )
    local = raw[:cd_offset]
    central = raw[cd_offset : cd_offset + cd_size]
    trailer = bytearray(raw[cd_offset + cd_size :])
    inner = trailer.rfind(b"PK\x05\x06")
    trailer[inner + 16 : inner + 20] = struct.pack("<I", cd_offset + len(block))
    path.write_bytes(local + block + central + bytes(trailer))
    base.unlink()
    return path


def _v2_signer_value(cert_chains: list[list[bytes]]) -> bytes:
    """A well-formed v2/v3 ``signers`` value, one signer per certificate chain.

    Mirrors the real layout down to the certificates: signers sequence ->
    signer -> signed-data -> (digests, certificates, attributes), every length
    a uint32-LE. The digests sequence is left empty -- the reader must skip it
    by its declared length, not assume content.
    """
    entries = b""
    for chain in cert_chains:
        certs_seq = b"".join(struct.pack("<I", len(cert)) + cert for cert in chain)
        signed_data = (
            struct.pack("<I", 0)  # digests sequence (empty)
            + struct.pack("<I", len(certs_seq))
            + certs_seq
            + struct.pack("<I", 0)  # additional attributes
        )
        signer = (
            struct.pack("<I", len(signed_data))
            + signed_data
            + struct.pack("<I", 0)  # signatures
            + struct.pack("<I", 0)  # public key
        )
        entries += struct.pack("<I", len(signer)) + signer
    return struct.pack("<I", len(entries)) + entries


_APK_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"


def _axml_utf8_manifest() -> bytes:
    """A compiled manifest with a UTF-8 string pool, as aapt2 emits.

    The committed fixture uses a UTF-16 pool and keeps every attribute name, so
    this exercises the other two real-world shapes at once: an 8-bit pool, and an
    ``android:name`` whose name string aapt2 stripped, leaving only the framework
    resource id for the resource-map fallback to resolve.
    """
    strings = [
        "",  # 0: the stripped android:name, resolved via the resource map
        "manifest",  # 1
        "uses-permission",  # 2
        "package",  # 3: a plain (non-framework) attribute keeps its name
        "com.example.utf8",  # 4
        "android.permission.CAMERA",  # 5
    ]
    data = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        data += bytes([len(raw), len(raw)]) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + len(strings) * 4
    utf8_flag = 1 << 8
    pool = struct.pack(
        "<HHIIIIII", 0x0001, 28, strings_start + len(data), len(strings), 0, utf8_flag,
        strings_start, 0,
    )
    pool += b"".join(struct.pack("<I", off) for off in offsets) + bytes(data)
    res_ids = [0x01010003]  # android:name; index 0 lines up with the empty string
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(res_ids))
    resmap += b"".join(struct.pack("<I", rid) for rid in res_ids)

    def start(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
        body = bytearray()
        for ns, attr_name_idx, value_idx in attrs:
            body += struct.pack("<iiiHBBI", ns, attr_name_idx, value_idx, 8, 0, 0x03, value_idx)
        ext = struct.pack(
            "<IIiIHHHHHH", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx, 20, 20, len(attrs), 0, 0, 0
        )
        chunk = ext + bytes(body)
        return struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk

    def end(name_idx: int) -> bytes:
        body = struct.pack("<IIiI", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx)
        return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

    body = bytearray(resmap)
    body += start(1, [(-1, 3, 4)])  # <manifest package="com.example.utf8">
    body += start(2, [(-1, 0, 5)])  # <uses-permission android:name="...CAMERA">
    body += end(2)
    body += end(1)
    payload = pool + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _axml_flag_manifest(app_attrs: list[tuple[int, int, int]]) -> bytes:
    """A compiled manifest ``<manifest package><application ATTRS>``.

    ``app_attrs`` are ``(name_index, data_type, data)`` triples for the
    <application> element. A boolean flag (data_type 0x12) can be placed by name
    -- index 5 is ``debuggable``, 6 ``testOnly``, 7 ``allowBackup``, 8
    ``usesCleartextTraffic`` -- or, with name index 0 (the empty string) whose
    resource-map slot carries the debuggable id, by resource id, exactly how
    aapt2 leaves a stripped android:* attribute.
    """
    strings = [
        "",  # 0: stripped-name slot; its resource-map entry names debuggable
        "manifest",  # 1
        "application",  # 2
        "package",  # 3
        "com.example.flags",  # 4
        "debuggable",  # 5
        "testOnly",  # 6
        "allowBackup",  # 7
        "usesCleartextTraffic",  # 8
    ]
    data = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        data += bytes([len(raw), len(raw)]) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + len(strings) * 4
    pool = struct.pack(
        "<HHIIIIII", 0x0001, 28, strings_start + len(data), len(strings), 0, 1 << 8,
        strings_start, 0,
    )
    pool += b"".join(struct.pack("<I", off) for off in offsets) + bytes(data)
    res_ids = [0x0101000F, 0, 0, 0, 0, 0, 0, 0, 0]  # index 0 resolves to android:debuggable
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(res_ids))
    resmap += b"".join(struct.pack("<I", rid) for rid in res_ids)

    def start(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
        body = bytearray()
        for name_index, data_type, value in attrs:
            raw = value if data_type == 0x03 else -1
            body += struct.pack("<iiiHBBI", -1, name_index, raw, 8, 0, data_type, value)
        ext = struct.pack(
            "<IIiIHHHHHH", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx, 20, 20, len(attrs), 0, 0, 0
        )
        chunk = ext + bytes(body)
        return struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk

    def end(name_idx: int) -> bytes:
        body = struct.pack("<IIiI", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx)
        return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

    body = bytearray(resmap)
    body += start(1, [(3, 0x03, 4)])  # <manifest package="com.example.flags">
    body += start(2, app_attrs)  # <application ...flags...>
    body += end(2)
    body += end(1)
    payload = pool + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _axml_launcher_manifest(
    activities: list[tuple[str, str, list[tuple[list[str], list[str]]]]],
    *,
    package: str = "com.example.launch",
) -> bytes:
    """A compiled manifest with an <application> of the given activities.

    Each activity is ``(tag, name, filters)`` where ``tag`` is ``"activity"`` or
    ``"activity-alias"`` and each filter is ``(actions, categories)`` of
    ``android:name`` strings. Emits a UTF-8 AXML the stdlib reader walks exactly
    as it walks a real compiled manifest, so the launcher (entry-point)
    detection is exercised over genuine element nesting.
    """
    order: list[str] = []
    index: dict[str, int] = {}

    def intern(text: str) -> int:
        if text not in index:
            index[text] = len(order)
            order.append(text)
        return index[text]

    for fixed in ("name", "package", "manifest", "application", package):
        intern(fixed)
    for tag, name, filters in activities:
        intern(tag)
        intern(name)
        for actions, categories in filters:
            intern("intent-filter")
            for value in (*actions, *categories):
                intern("action")
                intern("category")
                intern(value)

    def start(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
        body = bytearray()
        for name_index, data_type, value in attrs:
            raw = value if data_type == 0x03 else -1
            body += struct.pack("<iiiHBBI", -1, name_index, raw, 8, 0, data_type, value)
        ext = struct.pack(
            "<IIiIHHHHHH", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx, 20, 20, len(attrs), 0, 0, 0
        )
        chunk = ext + bytes(body)
        return struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk

    def end(name_idx: int) -> bytes:
        body = struct.pack("<IIiI", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx)
        return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

    def named(value: str) -> list[tuple[int, int, int]]:
        return [(intern("name"), 0x03, intern(value))]

    body = bytearray()
    body += start(intern("manifest"), [(intern("package"), 0x03, intern(package))])
    body += start(intern("application"), [])
    for tag, name, filters in activities:
        body += start(intern(tag), named(name))
        for actions, categories in filters:
            body += start(intern("intent-filter"), [])
            for value in actions:
                body += start(intern("action"), named(value))
                body += end(intern("action"))
            for value in categories:
                body += start(intern("category"), named(value))
                body += end(intern("category"))
            body += end(intern("intent-filter"))
        body += end(intern(tag))
    body += end(intern("application"))
    body += end(intern("manifest"))

    data = bytearray()
    offsets: list[int] = []
    for text in order:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        data += bytes([len(raw), len(raw)]) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + len(order) * 4
    pool = struct.pack(
        "<HHIIIIII", 0x0001, 28, strings_start + len(data), len(order), 0, 1 << 8,
        strings_start, 0,
    )
    pool += b"".join(struct.pack("<I", off) for off in offsets) + bytes(data)
    payload = pool + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _axml_uses_library_manifest(
    libraries: list[tuple[str | None, bool | None]],
    *,
    package: str = "com.example.libs",
) -> bytes:
    """A compiled manifest whose <application> declares <uses-library> entries.

    Each entry is ``(name, required)``: ``name`` is the android:name value
    (None emits the element with no name at all, which the reader must skip)
    and ``required`` the android:required flag (None leaves the attribute out,
    which Android defaults to true).
    """
    order: list[str] = []
    index: dict[str, int] = {}

    def intern(text: str) -> int:
        if text not in index:
            index[text] = len(order)
            order.append(text)
        return index[text]

    for fixed in ("name", "required", "package", "manifest", "application", "uses-library"):
        intern(fixed)
    intern(package)
    for name, _required in libraries:
        if name is not None:
            intern(name)

    def start(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
        body = bytearray()
        for name_index, data_type, value in attrs:
            raw = value if data_type == 0x03 else -1
            body += struct.pack("<iiiHBBI", -1, name_index, raw, 8, 0, data_type, value)
        ext = struct.pack(
            "<IIiIHHHHHH", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx, 20, 20, len(attrs), 0, 0, 0
        )
        chunk = ext + bytes(body)
        return struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk

    def end(name_idx: int) -> bytes:
        body = struct.pack("<IIiI", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx)
        return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

    body = bytearray()
    body += start(intern("manifest"), [(intern("package"), 0x03, intern(package))])
    body += start(intern("application"), [])
    for name, required in libraries:
        attrs: list[tuple[int, int, int]] = []
        if name is not None:
            attrs.append((intern("name"), 0x03, intern(name)))
        if required is not None:
            attrs.append((intern("required"), 0x12, 0xFFFFFFFF if required else 0))
        body += start(intern("uses-library"), attrs)
        body += end(intern("uses-library"))
    body += end(intern("application"))
    body += end(intern("manifest"))

    data = bytearray()
    offsets: list[int] = []
    for text in order:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        data += bytes([len(raw), len(raw)]) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + len(order) * 4
    pool = struct.pack(
        "<HHIIIIII", 0x0001, 28, strings_start + len(data), len(order), 0, 1 << 8,
        strings_start, 0,
    )
    pool += b"".join(struct.pack("<I", off) for off in offsets) + bytes(data)
    payload = pool + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _axml_component_manifest(
    components: list[tuple[str, str | None, bool | None, bool]],
    *,
    package: str = "com.example.comp",
) -> bytes:
    """A compiled manifest with an <application> of the given components.

    Each component is ``(tag, name, exported, has_filter)`` where ``tag`` is
    one of activity/activity-alias/service/receiver/provider, ``name`` the
    android:name (None emits the component with no name at all), ``exported``
    the explicit android:exported flag (None leaves it out), and
    ``has_filter`` whether the component carries an <intent-filter>. Emits a
    UTF-8 AXML the stdlib reader walks exactly as a real compiled manifest.
    """
    order: list[str] = []
    index: dict[str, int] = {}

    def intern(text: str) -> int:
        if text not in index:
            index[text] = len(order)
            order.append(text)
        return index[text]

    for fixed in ("name", "exported", "package", "manifest", "application", "intent-filter"):
        intern(fixed)
    intern(package)
    for tag, name, _exported, _has_filter in components:
        intern(tag)
        if name is not None:
            intern(name)

    def start(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
        body = bytearray()
        for name_index, data_type, value in attrs:
            raw = value if data_type == 0x03 else -1
            body += struct.pack("<iiiHBBI", -1, name_index, raw, 8, 0, data_type, value)
        ext = struct.pack(
            "<IIiIHHHHHH", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx, 20, 20, len(attrs), 0, 0, 0
        )
        chunk = ext + bytes(body)
        return struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk

    def end(name_idx: int) -> bytes:
        body = struct.pack("<IIiI", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx)
        return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

    body = bytearray()
    body += start(intern("manifest"), [(intern("package"), 0x03, intern(package))])
    body += start(intern("application"), [])
    for tag, name, exported, has_filter in components:
        attrs: list[tuple[int, int, int]] = []
        if name is not None:
            attrs.append((intern("name"), 0x03, intern(name)))
        if exported is not None:
            attrs.append((intern("exported"), 0x12, 0xFFFFFFFF if exported else 0))
        body += start(intern(tag), attrs)
        if has_filter:
            body += start(intern("intent-filter"), [])
            body += end(intern("intent-filter"))
        body += end(intern(tag))
    body += end(intern("application"))
    body += end(intern("manifest"))

    data = bytearray()
    offsets: list[int] = []
    for text in order:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        data += bytes([len(raw), len(raw)]) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + len(order) * 4
    pool = struct.pack(
        "<HHIIIIII", 0x0001, 28, strings_start + len(data), len(order), 0, 1 << 8,
        strings_start, 0,
    )
    pool += b"".join(struct.pack("<I", off) for off in offsets) + bytes(data)
    payload = pool + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _axml_deep_link_manifest(
    components: list[tuple[str, str, list[tuple[list[str], list[dict[str, str]]]]]],
    *,
    package: str = "com.example.links",
) -> bytes:
    """A compiled manifest of components with intent-filters carrying <data>.

    Each component is ``(tag, name, filters)``; each filter is ``(actions,
    datas)`` where every data is a dict of android attribute names (scheme,
    host, pathPrefix, ...) to string values. Emits a UTF-8 AXML the stdlib
    reader walks exactly as a real compiled manifest, so deep-link extraction
    is exercised over genuine element nesting.
    """
    order: list[str] = []
    index: dict[str, int] = {}

    def intern(text: str) -> int:
        if text not in index:
            index[text] = len(order)
            order.append(text)
        return index[text]

    for fixed in (
        "name", "scheme", "host", "path", "pathPrefix", "pathPattern",
        "package", "manifest", "application", "intent-filter", "action", "data",
    ):
        intern(fixed)
    intern(package)
    for tag, name, filters in components:
        intern(tag)
        intern(name)
        for actions, datas in filters:
            for action in actions:
                intern(action)
            for data_attrs in datas:
                for attr, value in data_attrs.items():
                    intern(attr)
                    intern(value)

    def start(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
        body = bytearray()
        for name_index, data_type, value in attrs:
            raw = value if data_type == 0x03 else -1
            body += struct.pack("<iiiHBBI", -1, name_index, raw, 8, 0, data_type, value)
        ext = struct.pack(
            "<IIiIHHHHHH", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx, 20, 20, len(attrs), 0, 0, 0
        )
        chunk = ext + bytes(body)
        return struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk

    def end(name_idx: int) -> bytes:
        body = struct.pack("<IIiI", 0xFFFFFFFF, 0xFFFFFFFF, -1, name_idx)
        return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

    def named(value: str) -> list[tuple[int, int, int]]:
        return [(intern("name"), 0x03, intern(value))]

    body = bytearray()
    body += start(intern("manifest"), [(intern("package"), 0x03, intern(package))])
    body += start(intern("application"), [])
    for tag, name, filters in components:
        body += start(intern(tag), named(name))
        for actions, datas in filters:
            body += start(intern("intent-filter"), [])
            for action in actions:
                body += start(intern("action"), named(action))
                body += end(intern("action"))
            for data_attrs in datas:
                data_list = [
                    (intern(attr), 0x03, intern(value)) for attr, value in data_attrs.items()
                ]
                body += start(intern("data"), data_list)
                body += end(intern("data"))
            body += end(intern("intent-filter"))
        body += end(intern(tag))
    body += end(intern("application"))
    body += end(intern("manifest"))

    data = bytearray()
    offsets: list[int] = []
    for text in order:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        data += bytes([len(raw), len(raw)]) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + len(order) * 4
    pool = struct.pack(
        "<HHIIIIII", 0x0001, 28, strings_start + len(data), len(order), 0, 1 << 8,
        strings_start, 0,
    )
    pool += b"".join(struct.pack("<I", off) for off in offsets) + bytes(data)
    payload = pool + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


_MAIN = "android.intent.action.MAIN"
_LAUNCHER = "android.intent.category.LAUNCHER"
_VIEW = "android.intent.action.VIEW"


class TestManifestFactsWithoutAndroguard:
    """describe_apk reads the compiled AndroidManifest stdlib-only.

    The package, versions, SDK levels and permissions otherwise come only from
    androguard; parsing the AXML ourselves gives every APK session those facts on
    a machine without it -- the Android analogue of describe_wasm for WebAssembly.
    """

    def test_reads_the_committed_fixture_manifest(self) -> None:
        if not _APK_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_APK_FIXTURE}")
        manifest = describe_apk(_APK_FIXTURE)["apk"]["manifest"]
        assert manifest["package"] == "com.example.headless"
        assert manifest["version_code"] == 1
        assert manifest["version_name"] == "1.0"
        assert manifest["min_sdk"] == 21
        assert manifest["target_sdk"] == 33
        assert manifest["permissions"] == ["android.permission.INTERNET"]
        # The fixture's <application> declares android:debuggable="true"; the
        # apktool gate cross-checks this same fact against apktool's decode.
        assert manifest["debuggable"] is True
        # testOnly is not declared, so the fact is omitted rather than guessed.
        assert "test_only" not in manifest
        # The other declared posture flags -- one false, one true, so a wrong
        # constant cannot satisfy both; the apktool gate cross-checks them too.
        assert manifest["allow_backup"] is False
        assert manifest["uses_cleartext_traffic"] is True
        # The launchable activity (entry point) -- the <activity> whose
        # intent-filter carries MAIN + LAUNCHER; the apktool gate cross-checks
        # this same component against apktool's own decode.
        assert manifest["launcher_activity"] == "com.example.headless.MainActivity"
        # The device shared libraries the app depends on (<uses-library>), in
        # declaration order: one hard requirement (required left implicit,
        # defaulting true) and one declared optional -- the manifest-level
        # dependency list, cross-checked by the apktool and androguard gates.
        assert manifest["uses_libraries"] == [
            {"name": "org.apache.http.legacy", "required": True},
            {"name": "androidx.window.extensions", "required": False},
        ]
        # The exported attack surface, in declaration order: the launcher
        # activity (exported implicitly through its MAIN/LAUNCHER filter), a
        # service exported by an explicit true, and a provider exported
        # explicitly -- the private receiver (explicit false, despite its
        # intent-filter) is absent. The apktool/androguard gates cross-check
        # this same set against their own decode of the manifest.
        assert manifest["exported_components"] == [
            {
                "type": "activity",
                "name": "com.example.headless.MainActivity",
                "has_intent_filter": True,
            },
            {
                "type": "service",
                "name": "com.example.headless.ExportedService",
                "has_intent_filter": False,
            },
            {
                "type": "provider",
                "name": "com.example.headless.SharedProvider",
                "has_intent_filter": False,
            },
        ]
        # The deep links: the launcher's second intent-filter is ACTION_VIEW
        # with two <data> elements -- an https host/pathPrefix and a bare
        # custom scheme -- each one reported record, bound to its activity.
        # The apktool/androguard gates cross-check this same set.
        assert manifest["deep_links"] == [
            {
                "activity": "com.example.headless.MainActivity",
                "scheme": "https",
                "host": "deeplink.example.com",
                "path_prefix": "/open",
            },
            {
                "activity": "com.example.headless.MainActivity",
                "scheme": "headless",
            },
        ]

    def test_reads_a_utf8_pool_and_resolves_stripped_names_by_resource_id(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "utf8.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", _axml_utf8_manifest())
            archive.writestr("classes.dex", b"dex\n035\x00")
        manifest = describe_apk(path)["apk"]["manifest"]
        assert manifest["package"] == "com.example.utf8"
        # The android:name was resolved through the resource map, not a name string.
        assert manifest["permissions"] == ["android.permission.CAMERA"]

    def _apk_with_manifest(self, tmp_path: Path, name: str, manifest: bytes) -> Path:
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest)
            archive.writestr("classes.dex", b"dex\n035\x00")
        return path

    def test_reads_application_debuggable_and_test_only_by_name(self, tmp_path: Path) -> None:
        # Both flags are read as their real boolean, not merely detected: a false
        # value must come back False, a true value True -- and the second flag
        # proves it is not just the first attribute being reported twice.
        manifest_bytes = _axml_flag_manifest([(5, 0x12, 0), (6, 0x12, 0xFFFFFFFF)])
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "flags.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["debuggable"] is False
        assert manifest["test_only"] is True

    def test_resolves_debuggable_by_resource_id_when_name_is_stripped(
        self, tmp_path: Path
    ) -> None:
        # aapt2 can drop the android:debuggable name string, leaving only its
        # framework resource id; the reader must still resolve the flag via the
        # resource map, the same fallback it uses for versionCode and name.
        manifest_bytes = _axml_flag_manifest([(0, 0x12, 0xFFFFFFFF)])
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "stripped.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["debuggable"] is True
        assert "test_only" not in manifest

    def test_security_flags_absent_when_application_declares_none(self, tmp_path: Path) -> None:
        # An <application> that declares no flag leaves every fact out,
        # rather than inventing version-dependent defaults.
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "none.apk", _axml_flag_manifest([]))
        )["apk"]["manifest"]
        assert "debuggable" not in manifest
        assert "test_only" not in manifest
        assert "allow_backup" not in manifest
        assert "uses_cleartext_traffic" not in manifest

    def test_reads_allow_backup_and_cleartext_by_name(self, tmp_path: Path) -> None:
        # allowBackup=true, usesCleartextTraffic=false -- the opposite pairing
        # from the committed fixture, so both flags prove they carry their own
        # value rather than echoing a neighbour's.
        manifest_bytes = _axml_flag_manifest([(7, 0x12, 0xFFFFFFFF), (8, 0x12, 0)])
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "backup.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["allow_backup"] is True
        assert manifest["uses_cleartext_traffic"] is False
        assert "debuggable" not in manifest

    def test_uses_library_defaults_to_required(self, tmp_path: Path) -> None:
        # <uses-library> with no android:required attribute is a hard
        # dependency: Android's documented default is true, so a missing
        # library blocks install -- the reader must say required, not None.
        manifest_bytes = _axml_uses_library_manifest([("org.apache.http.legacy", None)])
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "deps.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["uses_libraries"] == [
            {"name": "org.apache.http.legacy", "required": True}
        ]

    def test_uses_library_required_carries_its_declared_value(self, tmp_path: Path) -> None:
        # One explicit true and one explicit false in the same manifest, in
        # declaration order -- so neither a stuck default nor an echo of a
        # neighbour's value can pass.
        manifest_bytes = _axml_uses_library_manifest(
            [("com.vendor.hard", True), ("androidx.window.extensions", False)]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "mixed.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["uses_libraries"] == [
            {"name": "com.vendor.hard", "required": True},
            {"name": "androidx.window.extensions", "required": False},
        ]

    def test_uses_library_without_a_name_is_skipped(self, tmp_path: Path) -> None:
        # A nameless <uses-library> declares nothing; the reader must skip it
        # rather than invent an empty-named dependency, while still reading
        # the well-formed sibling.
        manifest_bytes = _axml_uses_library_manifest([(None, True), ("com.real.lib", None)])
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "nameless.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["uses_libraries"] == [{"name": "com.real.lib", "required": True}]

    def test_no_uses_library_reads_as_an_empty_list(self, tmp_path: Path) -> None:
        # An app that needs no device shared library reports an empty
        # dependency list, not a missing fact -- "none" is a real answer here,
        # exactly like an ELF with no DT_NEEDED.
        manifest_bytes = _axml_uses_library_manifest([])
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "nodeps.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["uses_libraries"] == []

    def test_launcher_activity_from_a_main_launcher_intent_filter(self, tmp_path: Path) -> None:
        # The entry point: the <activity> whose intent-filter declares both
        # MAIN and LAUNCHER is reported by its android:name.
        manifest_bytes = _axml_launcher_manifest(
            [("activity", ".Main", [([_MAIN], [_LAUNCHER])])]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "launch.apk", manifest_bytes)
        )["apk"]["manifest"]
        # Reported exactly as declared (relative name not resolved), so it
        # matches apktool's text decode component-for-component.
        assert manifest["launcher_activity"] == ".Main"

    def test_main_and_launcher_in_separate_filters_is_not_a_launcher(self, tmp_path: Path) -> None:
        # MAIN in one intent-filter and LAUNCHER in another of the same activity
        # does not make it launchable -- Android requires both in one filter, so
        # the reader must reset its pair per filter and report no launcher.
        manifest_bytes = _axml_launcher_manifest(
            [("activity", ".Main", [([_MAIN], []), ([], [_LAUNCHER])])]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "split.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["launcher_activity"] is None

    def test_activity_alias_can_be_the_launcher(self, tmp_path: Path) -> None:
        # A common real pattern: the launcher is an <activity-alias>, not an
        # <activity>. Its own android:name is the launchable component.
        manifest_bytes = _axml_launcher_manifest(
            [
                ("activity", ".Impl", []),
                ("activity-alias", ".Alias", [([_MAIN], [_LAUNCHER])]),
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "alias.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["launcher_activity"] == ".Alias"

    def test_no_launcher_activity_reads_as_none(self, tmp_path: Path) -> None:
        # A service/library APK: an activity with a non-launcher filter (MAIN
        # only, e.g. a leanback or a plain VIEW handler) has no launcher.
        manifest_bytes = _axml_launcher_manifest(
            [("activity", ".Main", [([_MAIN], [])])]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "nolaunch.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["launcher_activity"] is None

    def test_first_launcher_wins_when_several_activities_qualify(self, tmp_path: Path) -> None:
        # A manifest can declare more than one LAUNCHER activity; the reader
        # reports the first in document order rather than the last or a set.
        manifest_bytes = _axml_launcher_manifest(
            [
                ("activity", ".First", [([_MAIN], [_LAUNCHER])]),
                ("activity", ".Second", [([_MAIN], [_LAUNCHER])]),
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "two.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["launcher_activity"] == ".First"

    def test_explicit_exported_true_is_reported_for_every_component_kind(
        self, tmp_path: Path
    ) -> None:
        # android:exported="true" exports a component regardless of filters,
        # and the reader carries each kind's own tag -- so a wrong tag or a
        # dropped kind cannot pass.
        manifest_bytes = _axml_component_manifest(
            [
                ("activity", ".A", True, False),
                ("service", ".S", True, False),
                ("receiver", ".R", True, False),
                ("provider", ".P", True, False),
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "exp.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["exported_components"] == [
            {"type": "activity", "name": ".A", "has_intent_filter": False},
            {"type": "service", "name": ".S", "has_intent_filter": False},
            {"type": "receiver", "name": ".R", "has_intent_filter": False},
            {"type": "provider", "name": ".P", "has_intent_filter": False},
        ]

    def test_explicit_exported_false_closes_a_component_with_a_filter(
        self, tmp_path: Path
    ) -> None:
        # The trap case: a component with an <intent-filter> but an explicit
        # android:exported="false" is NOT reachable -- the explicit flag wins
        # over the filter, so it must be absent from the surface.
        manifest_bytes = _axml_component_manifest(
            [("receiver", ".Guarded", False, True)]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "guarded.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["exported_components"] == []

    def test_an_intent_filter_exports_a_component_with_no_explicit_flag(
        self, tmp_path: Path
    ) -> None:
        # No android:exported, but an <intent-filter>: the pre-Android-12
        # implicit default makes it reachable, and the reader records that the
        # export came with a filter.
        manifest_bytes = _axml_component_manifest(
            [("service", ".Listening", None, True)]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "implicit.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["exported_components"] == [
            {"type": "service", "name": ".Listening", "has_intent_filter": True}
        ]

    def test_a_component_with_no_flag_and_no_filter_is_private(
        self, tmp_path: Path
    ) -> None:
        # The common default: neither android:exported nor an intent-filter
        # means the component is internal, so it is not part of the surface.
        manifest_bytes = _axml_component_manifest(
            [("activity", ".Internal", None, False)]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "internal.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["exported_components"] == []

    def test_exported_component_without_a_name_is_skipped(self, tmp_path: Path) -> None:
        # A nameless component names nothing to attack; the reader must skip it
        # rather than report an empty-named entry, while still reading the
        # well-formed sibling that follows.
        manifest_bytes = _axml_component_manifest(
            [
                ("activity", None, True, False),
                ("service", ".Real", True, False),
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "nameless-comp.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["exported_components"] == [
            {"type": "service", "name": ".Real", "has_intent_filter": False}
        ]

    def test_no_exported_components_reads_as_an_empty_list(self, tmp_path: Path) -> None:
        # An app that exposes nothing reports an empty surface, not a missing
        # fact -- "none exported" is a real, reassuring answer.
        manifest_bytes = _axml_component_manifest(
            [("activity", ".Private", False, False)]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "closed.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["exported_components"] == []

    def test_a_filter_binds_to_its_own_component_not_the_next(
        self, tmp_path: Path
    ) -> None:
        # Two adjacent implicit components: the first carries the intent-filter,
        # the second does not. The reader must attribute the filter to the
        # first only -- so the second (no flag, no filter) stays private.
        manifest_bytes = _axml_component_manifest(
            [
                ("activity", ".WithFilter", None, True),
                ("activity", ".WithoutFilter", None, False),
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "adjacent.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["exported_components"] == [
            {"type": "activity", "name": ".WithFilter", "has_intent_filter": True}
        ]

    def test_a_view_filter_with_scheme_data_is_a_deep_link(self, tmp_path: Path) -> None:
        # The canonical link handler: ACTION_VIEW plus a <data> naming a
        # scheme and host. One data element, one reported link, bound to its
        # activity with every declared URI part.
        manifest_bytes = _axml_deep_link_manifest(
            [
                (
                    "activity",
                    ".Links",
                    [([_VIEW], [{"scheme": "https", "host": "app.example", "path": "/x"}])],
                )
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "links.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["deep_links"] == [
            {"activity": ".Links", "scheme": "https", "host": "app.example", "path": "/x"}
        ]

    def test_data_without_a_scheme_is_not_a_link(self, tmp_path: Path) -> None:
        # A <data> with only a host (or mimeType) declares no URI scheme, so
        # there is no link to report even under ACTION_VIEW.
        manifest_bytes = _axml_deep_link_manifest(
            [("activity", ".NoScheme", [([_VIEW], [{"host": "app.example"}])])]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "noscheme.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["deep_links"] == []

    def test_a_filter_without_view_reports_no_links(self, tmp_path: Path) -> None:
        # A custom action's <data> is app-internal routing, not a deep link:
        # only ACTION_VIEW makes the URI reachable from a browser or another
        # app's plain view intent.
        manifest_bytes = _axml_deep_link_manifest(
            [("activity", ".Custom", [(["com.example.PING"], [{"scheme": "https"}])])]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "noview.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["deep_links"] == []

    def test_view_data_on_a_service_is_not_a_deep_link(self, tmp_path: Path) -> None:
        # Deep links start activities; a service with a VIEW filter is not a
        # link target and must not be reported as one.
        manifest_bytes = _axml_deep_link_manifest(
            [("service", ".Svc", [([_VIEW], [{"scheme": "https", "host": "app.example"}])])]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "svc.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["deep_links"] == []

    def test_data_before_the_view_action_still_counts(self, tmp_path: Path) -> None:
        # Element order inside a filter is free: aapt may emit <data> before
        # <action>. The filter is judged when it closes, so the link is
        # reported either way. The builder emits actions first, so this case
        # feeds the walker a manifest with the actions list empty and the VIEW
        # action arriving through a second filter -- which must NOT count for
        # the first filter's data; only the in-filter pairing does.
        manifest_bytes = _axml_deep_link_manifest(
            [
                (
                    "activity",
                    ".Ordered",
                    [
                        ([], [{"scheme": "https", "host": "first.example"}]),
                        ([_VIEW], [{"scheme": "app"}]),
                    ],
                )
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "ordered.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["deep_links"] == [{"activity": ".Ordered", "scheme": "app"}]

    def test_links_bind_to_their_own_activity(self, tmp_path: Path) -> None:
        # Two activities with one VIEW filter each: every link must carry the
        # activity whose filter declared it, and an alias counts like an
        # activity (it is what gets launched).
        manifest_bytes = _axml_deep_link_manifest(
            [
                ("activity", ".First", [([_VIEW], [{"scheme": "one"}])]),
                ("activity-alias", ".Second", [([_VIEW], [{"scheme": "two"}])]),
            ]
        )
        manifest = describe_apk(
            self._apk_with_manifest(tmp_path, "bound.apk", manifest_bytes)
        )["apk"]["manifest"]
        assert manifest["deep_links"] == [
            {"activity": ".First", "scheme": "one"},
            {"activity": ".Second", "scheme": "two"},
        ]

    def test_manifest_is_present_but_empty_on_a_garbage_axml(self, tmp_path: Path) -> None:
        # _apk() writes a RES_XML header with no real chunks behind it; the walk
        # must yield the empty-valued manifest rather than raising.
        manifest = describe_apk(_apk(tmp_path / "app.apk"))["apk"]["manifest"]
        assert manifest["package"] is None
        assert manifest["permissions"] == []

    def test_session_metadata_carries_the_manifest_facts(self) -> None:
        if not _APK_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_APK_FIXTURE}")
        from headless_re_mcp.core.session import SessionRegistry

        session = SessionRegistry().create(str(_APK_FIXTURE))
        assert session.target is TargetKind.APK
        assert session.metadata["apk"]["manifest"]["package"] == "com.example.headless"


def _dex_header(version: bytes, strings: int, methods: int, classes: int) -> bytes:
    """A minimal but well-formed 0x70-byte DEX header carrying the counts."""
    header = bytearray(0x70)
    header[0:8] = b"dex\n" + version + b"\x00"
    # A deterministic, per-input signature so multidex members are distinct.
    header[12:32] = hashlib.sha1(version + struct.pack("<III", strings, methods, classes)).digest()
    struct.pack_into("<I", header, 40, 0x12345678)  # endian tag
    struct.pack_into("<I", header, 56, strings)  # string_ids_size
    struct.pack_into("<I", header, 88, methods)  # method_ids_size
    struct.pack_into("<I", header, 96, classes)  # class_defs_size
    return bytes(header)


class TestDexFactsWithoutAndroguard:
    """describe_apk sums the DEX header counts stdlib-only.

    How many classes, methods and strings an APK carries -- the first read on how
    big and how obfuscated it is -- otherwise needs androguard's full parse. The
    counts sit at fixed offsets in each member's 0x70-byte header, so reading just
    those headers gives every session the totals for free.
    """

    def test_reads_the_committed_fixture_dex(self) -> None:
        if not _APK_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_APK_FIXTURE}")
        dex = describe_apk(_APK_FIXTURE)["apk"]["dex"]
        assert dex["versions"] == ["035"]
        assert dex["class_count"] == 1
        assert dex["method_count"] == 1
        assert dex["string_count"] == 7
        # The defined class name is resolved from the id tables, not just counted.
        assert dex["classes"] == ["com.example.headless.Sample"]
        # The DEX build fingerprint: the SHA-1 the builder stamps over the body,
        # per-member so a repackaged split is distinguishable. The fixture's dex
        # is byte-identical across rebuilds, so this value is stable.
        assert dex["signatures"] == [
            {"dex": "classes.dex", "sha1": "08b2b62009d67cfd8301354fbc30bfe0c84d5b64"}
        ]

    def test_committed_dex_fingerprint_is_the_real_spec_hash(self) -> None:
        """The reported signature must be the DEX's own content hash, per spec.

        The assertion above pins a constant, but a constant proves nothing about
        whether the fixture is a valid DEX or whether the reader reads the right
        20 bytes. Recompute both header integrity fields straight from the
        classes.dex bytes -- signature = SHA-1 over everything past byte 32,
        checksum = adler32 over everything past byte 12 -- and require that they
        match the bytes the fixture actually stores *and* the fact the reader
        surfaces. This is the DEX analogue of the monodis .NET cross-check: an
        independent computation, not a self-referential echo, and it needs no
        tool so it always runs.
        """
        if not _APK_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_APK_FIXTURE}")
        with zipfile.ZipFile(_APK_FIXTURE) as archive:
            raw = archive.read("classes.dex")
        # The fixture is a real, self-consistent DEX: its stored signature and
        # checksum equal a fresh recomputation of its own body.
        recomputed_sha1 = hashlib.sha1(raw[32:]).hexdigest()
        assert raw[12:32].hex() == recomputed_sha1
        assert struct.unpack_from("<I", raw, 8)[0] == zlib.adler32(raw[12:]) & 0xFFFFFFFF
        # And the reader's fingerprint fact is that same hash, not merely the
        # constant pinned above.
        dex = describe_apk(_APK_FIXTURE)["apk"]["dex"]
        assert dex["signatures"][0]["sha1"] == recomputed_sha1

    def test_class_names_are_empty_when_only_the_header_is_present(self, tmp_path: Path) -> None:
        # _dex_header carries no id tables, so the class-name walk finds nothing
        # and the facts still carry the counts. Bounds checks must not raise.
        path = tmp_path / "headeronly.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
            archive.writestr("classes.dex", _dex_header(b"035", 3, 2, 1))
        dex = describe_apk(path)["apk"]["dex"]
        assert dex["class_count"] == 1
        assert dex["classes"] == []

    def test_descriptor_conversion_and_string_reading(self) -> None:
        from headless_re_mcp.core.session import _dex_descriptor_to_name, _dex_read_mutf8

        assert _dex_descriptor_to_name("Lcom/example/headless/Sample;") == (
            "com.example.headless.Sample"
        )
        assert _dex_descriptor_to_name("Lorg/A;") == "org.A"
        # A primitive or array descriptor is not a class type and passes through.
        assert _dex_descriptor_to_name("[I") == "[I"
        assert _dex_descriptor_to_name("I") == "I"
        # A DEX string is a uleb128 length prefix then MUTF-8 bytes to a NUL.
        buffer = b"\x1dLcom/example/headless/Sample;\x00trailing"
        assert _dex_read_mutf8(buffer, 0) == "Lcom/example/headless/Sample;"
        # An out-of-range offset is refused, not indexed past the end.
        assert _dex_read_mutf8(buffer, 999) is None

    def test_sums_counts_and_collects_versions_across_multidex(self, tmp_path: Path) -> None:
        path = tmp_path / "multidex.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
            archive.writestr("classes.dex", _dex_header(b"035", 10, 20, 3))
            archive.writestr("classes2.dex", _dex_header(b"038", 5, 7, 2))
        dex = describe_apk(path)["apk"]["dex"]
        assert dex["versions"] == ["035", "038"]
        assert dex["string_count"] == 15
        assert dex["method_count"] == 27
        assert dex["class_count"] == 5
        # Each member reports its own fingerprint, in sorted dex-name order, so a
        # single repackaged split can be spotted without re-hashing the archive.
        sigs = dex["signatures"]
        assert [s["dex"] for s in sigs] == ["classes.dex", "classes2.dex"]
        assert sigs[0]["sha1"] == hashlib.sha1(b"035" + struct.pack("<III", 10, 20, 3)).hexdigest()
        assert sigs[1]["sha1"] == hashlib.sha1(b"038" + struct.pack("<III", 5, 7, 2)).hexdigest()
        assert sigs[0]["sha1"] != sigs[1]["sha1"]

    def test_dex_facts_are_empty_when_no_header_is_readable(self, tmp_path: Path) -> None:
        # A member named .dex whose magic is wrong is skipped; with no readable
        # header the facts are empty rather than raising.
        path = tmp_path / "bogus.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
            archive.writestr("classes.dex", b"not a dex file")
        assert describe_apk(path)["apk"]["dex"] == {}

    def test_a_corrupt_count_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "corrupt.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
            archive.writestr("classes.dex", _dex_header(b"035", 0xFFFFFFFF, 1, 1))
        # The absurd string count fails the sanity ceiling, so this DEX is
        # skipped entirely rather than reported with a nonsense total.
        assert describe_apk(path)["apk"]["dex"] == {}


class TestNoShellPassthrough:
    def test_catalog_exposes_no_generic_device_shell(self) -> None:
        """The debugger surface has no dynamic.command; devices get the same rule."""
        names = {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}
        assert "device.shell" not in names
        assert "device.exec" not in names
        assert not any(name.endswith((".shell", ".command", ".exec")) for name in names)

    def test_adb_backend_has_no_public_shell_method(self) -> None:
        public = {name for name in dir(AdbBackend) if not name.startswith("_")}
        assert "shell" not in public
        assert "exec" not in public


class TestAdbArgumentValidation:
    @pytest.mark.parametrize(
        "serial",
        ["", "a b", "127.0.0.1:5555; rm -rf /", "dev|cat", "$(whoami)", "x" * 200],
    )
    def test_hostile_serials_are_rejected(self, serial: str) -> None:
        with pytest.raises(AdbError) as info:
            _check_serial(serial)
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize("serial", ["127.0.0.1:5555", "emulator-5554", "ZY223KDTM7"])
    def test_valid_serials_pass(self, serial: str) -> None:
        assert _check_serial(serial) == serial

    @pytest.mark.parametrize(
        "package",
        ["", "notapackage", "com.x; id", "com.x/../y", "com .x", "-rf"],
    )
    def test_hostile_package_names_are_rejected(self, package: str) -> None:
        with pytest.raises(AdbError) as info:
            _check_package(package)
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize("package", ["com.example.app", "a.b", "com.foo_bar.baz2"])
    def test_valid_package_names_pass(self, package: str) -> None:
        assert _check_package(package) == package

    def test_missing_adbutils_degrades_instead_of_raising_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The degradation guard matters most where adbutils *is* installed (the
        # CI android lane), so skipping there left it untested exactly where it
        # would regress. Simulate the absent module instead, the way the frida
        # authorization tests do, so the contract runs unconditionally: a
        # missing adbutils yields capability_unavailable, never an ImportError.
        backend = AdbBackend()
        monkeypatch.setattr(backend, "_available", False)
        monkeypatch.setattr(backend, "_adbutils", None)
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "capability_unavailable"

    def test_adbutils_import_failure_degrades_at_construction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Prove the __init__ path itself: an adbutils whose import raises must
        # leave the backend unavailable rather than propagating, so readiness is
        # never blocked by a broken optional dependency.
        import builtins

        real_import = builtins.__import__

        def _boom(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "adbutils":
                raise ImportError("simulated missing adbutils")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _boom)
        backend = AdbBackend()
        assert backend.available is False
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "capability_unavailable"


class TestDevicePullSaysWhenNothingLanded:
    """adb sync can report a clean pull yet write no file for a missing remote."""

    def _backend(self, monkeypatch: pytest.MonkeyPatch, *, write: bool) -> AdbBackend:
        backend = AdbBackend()

        class _Sync:
            def stat(self, remote: str, **_: Any) -> Any:
                return SimpleNamespace(mode=0o100644, size=4)

            def pull(self, remote: str, local: str, **_: Any) -> None:
                if write:
                    Path(local).write_bytes(b"data")

        fake = SimpleNamespace(sync=_Sync())
        monkeypatch.setattr(backend, "_device", lambda serial: fake)
        return backend

    def test_a_pull_that_wrote_no_file_is_reported_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = self._backend(monkeypatch, write=False)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/missing.bin", tmp_path / "out.bin")
        assert info.value.code == "not_found"
        assert not (tmp_path / "out.bin").exists()

    def test_a_pull_that_wrote_a_file_returns_its_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = self._backend(monkeypatch, write=True)
        payload = backend.pull("emulator-5554", "/sdcard/report.bin", tmp_path / "out.bin")
        assert payload["size"] == 4
        assert payload["remote"] == "/sdcard/report.bin"
        assert Path(payload["local"]).is_file()


class TestFridaTargetAuthorization:
    # These assert the authorization boundary, which is decided before frida is
    # ever used, so they run whether or not the frida module is installed --
    # the CI unit lanes have no frida, and an authorization contract that only
    # skipped there would be untested exactly where it matters.
    def test_device_operations_refuse_unauthorized_pid(self) -> None:
        client = FridaClient()
        with pytest.raises(FridaError) as info:
            client.java_enumerate(
                "usb", 4242, allowed_pids=[1, 2, 3], mode="classes", limit=1
            )
        assert info.value.code == "permission_denied"
        assert info.value.details["pid"] == 4242

    def test_device_hook_refuses_unauthorized_pid(self) -> None:
        client = FridaClient()
        with pytest.raises(FridaError) as info:
            client.hook_template_device("usb", 99, "noop", allowed_pids=[7])
        assert info.value.code == "permission_denied"

    def test_local_single_pid_rule_is_unchanged(self) -> None:
        """The pre-existing PE contract must survive the device generalisation."""
        client = FridaClient()
        with pytest.raises(FridaError) as info:
            client.modules(4242, allowed_pid=4243, limit=1)
        assert info.value.code == "permission_denied"

    def test_unauthorized_pid_is_refused_even_with_no_frida_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whether a caller may touch a pid must not depend on frida's presence.

        With the module forced absent, an unauthorized device call must still
        report permission_denied -- never capability_unavailable, which would
        leak whether the tool is installed to a caller not allowed to ask.
        """
        client = FridaClient()
        monkeypatch.setattr(client, "_available", False)
        monkeypatch.setattr(client, "_frida", None)
        with pytest.raises(FridaError) as info:
            client.java_enumerate("usb", 4242, allowed_pids=[1], mode="classes", limit=1)
        assert info.value.code == "permission_denied"

    def test_unknown_hook_template_is_rejected_with_allowed_list(self) -> None:
        client = FridaClient()
        if not client.available:
            pytest.skip("frida not installed — template path not exercised (skip != pass)")
        with pytest.raises(FridaError) as info:
            client.hook_template_device("usb", 5, "arbitrary-script", allowed_pids=[5])
        assert info.value.code == "invalid_params"
        assert "android_ssl_unpin" in info.value.details["allowed"]


class _FakeScript:
    def __init__(self) -> None:
        self.loaded = False
        self.destroyed = False

    def load(self) -> None:
        self.loaded = True


class _FakeSession:
    def __init__(self) -> None:
        self.script = _FakeScript()
        self.detached = False

    def create_script(self, source: str) -> _FakeScript:
        assert source
        return self.script

    def detach(self) -> None:
        # What frida really does: detaching destroys every script in the
        # session. Measured on 16.5.9 via script.is_destroyed.
        self.detached = True
        self.script.destroyed = True


class _FakeFrida:
    def __init__(self) -> None:
        self.session = _FakeSession()

    def attach(self, pid: int) -> _FakeSession:
        assert pid > 0
        return self.session

    def get_usb_device(self, **_: object) -> _FakeFrida:
        return self

    def get_local_device(self) -> _FakeFrida:
        return self

    def get_device(self, device_id: str, **_: object) -> _FakeFrida:
        assert device_id
        return self


class TestHookTemplateSaysWhatItActuallyLeavesBehind:
    """The hook is gone before the caller reads the reply.

    Every operation detaches in a finally, which is what stops a failed call
    leaving an agent resident in someone else's process -- but for a hook that
    means the thing the caller asked for stops existing immediately. Reporting
    only ``loaded: True`` reads as "it is hooked now", and an unattended agent
    would then wait for output that can never arrive.
    """

    def _client(self) -> tuple[FridaClient, _FakeFrida]:
        client = FridaClient()
        fake = _FakeFrida()
        client._frida = fake
        client._available = True
        return client, fake

    def test_local_hook_reports_that_nothing_stays_hooked(self) -> None:
        client, fake = self._client()
        payload = client.hook_template(4242, "noop", allowed_pid=4242)

        assert payload["loaded"] is True
        assert payload["persisted"] is False
        assert "nothing stays hooked" in payload["note"]
        # The disclosure has to match the behaviour, not just soften it.
        assert fake.session.detached is True
        assert fake.session.script.destroyed is True

    def test_device_hook_reports_the_same(self) -> None:
        client, fake = self._client()
        payload = client.hook_template_device("usb", 4242, "noop", allowed_pids=[4242])

        assert payload["loaded"] is True
        assert payload["persisted"] is False
        assert fake.session.script.destroyed is True


class _FakeCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _FakeMethod:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callers)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class TestApkXrefsSayWhenTheyStopped:
    """A caller list that hit the cap looks exactly like one that ended."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, callers: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        client = ApkClient()
        monkeypatch.setattr(
            ApkClient,
            "_parsed",
            lambda self, path: _FakeParsed([_FakeMethod("decrypt", callers)]),
        )
        return client

    def test_hitting_the_cap_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=25)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)

        assert result["count"] == 10
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=3)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)

        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=10)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)

        assert result["count"] == 10
        assert result["has_more"] is False


class TestFridaEnumerationsSayWhenTheyStopped:
    """`count` alone cannot distinguish "that is all" from "that is your page"."""

    def test_a_full_page_reports_more(self) -> None:
        from headless_re_mcp.backends.frida.client import _page

        page, has_more = _page(list(range(25)), 10)
        assert page == list(range(10))
        assert has_more is True

    def test_a_short_answer_is_complete(self) -> None:
        from headless_re_mcp.backends.frida.client import _page

        page, has_more = _page(["a", "b"], 10)
        assert page == ["a", "b"]
        assert has_more is False

    def test_exactly_one_page_with_nothing_behind_it_is_complete(self) -> None:
        """The enumerations ask for limit+1, so this is what "exactly full" looks like."""
        from headless_re_mcp.backends.frida.client import _page

        page, has_more = _page(list(range(10)), 10)
        assert len(page) == 10
        assert has_more is False

    def test_nothing_at_all_is_not_partial(self) -> None:
        from headless_re_mcp.backends.frida.client import _page

        assert _page(None, 10) == ([], False)
        assert _page([], 10) == ([], False)


class TestApkClassification:
    def test_apk_is_detected_by_extension_and_by_content(self, tmp_path: Path) -> None:
        named = _apk(tmp_path / "app.apk")
        assert classify_target(named) is TargetKind.APK
        unnamed = _apk(tmp_path / "app.bin")
        assert classify_target(unnamed) is TargetKind.APK

    def test_plain_zip_is_not_an_apk(self, tmp_path: Path) -> None:
        plain = tmp_path / "archive.bin"
        with zipfile.ZipFile(plain, "w") as archive:
            archive.writestr("readme.txt", "hello")
        assert classify_target(plain) is TargetKind.PE

    def test_describe_apk_reads_abis_without_androguard(self, tmp_path: Path) -> None:
        info = describe_apk(_apk(tmp_path / "app.apk"))["apk"]
        assert info["native_abis"] == ["arm64-v8a"]
        assert info["dex_count"] == 1
        assert info["signed_v1"] is True
        # A v1-only archive with no signing block is not v2/v3 signed.
        assert info["signed_v2"] is False
        assert info["signed_v3"] is False

    def test_describe_apk_detects_v2_and_v3_signing_block(self, tmp_path: Path) -> None:
        """A modern signer is often v2/v3-only, which the META-INF check misses."""
        v2 = describe_apk(_apk_with_signing_block(tmp_path / "v2.apk", [0x7109871A]))["apk"]
        assert (v2["signed_v1"], v2["signed_v2"], v2["signed_v3"]) == (False, True, False)

        v3 = describe_apk(_apk_with_signing_block(tmp_path / "v3.apk", [0xF05368C0]))["apk"]
        assert (v3["signed_v2"], v3["signed_v3"]) == (False, True)

        both = describe_apk(
            _apk_with_signing_block(tmp_path / "both.apk", [0x7109871A, 0xF05368C0])
        )["apk"]
        assert (both["signed_v2"], both["signed_v3"]) == (True, True)

        # v3.1 (key rotation) is a v3 variant and counts as v3.
        v31 = describe_apk(_apk_with_signing_block(tmp_path / "v31.apk", [0x1B93AD61]))["apk"]
        assert (v31["signed_v2"], v31["signed_v3"]) == (False, True)

    def test_describe_apk_ignores_unknown_signing_block_ids(self, tmp_path: Path) -> None:
        """An unrelated block ID must not be read as a signature scheme."""
        info = describe_apk(_apk_with_signing_block(tmp_path / "u.apk", [0x11223344]))["apk"]
        assert info["signed_v2"] is False
        assert info["signed_v3"] is False
        assert info["signers"] == []


class TestApkSignerIdentity:
    """The signers fact answers *who* signed the APK, not just that someone did.

    The SHA-256 of the signing certificate's DER bytes is the identity Android
    pins for updates and the digest apksigner prints; the reader digests the
    certificate straight out of the v2/v3 block's signer sequence.
    """

    def test_signers_report_the_certificate_sha256(self, tmp_path: Path) -> None:
        cert = b"fake-der-signing-cert"
        value = _v2_signer_value([[cert]])
        path = _apk_with_signing_block(tmp_path / "s.apk", [0x7109871A], {0x7109871A: value})
        info = describe_apk(path)["apk"]
        assert info["signers"] == [
            {"scheme": "v2", "cert_sha256": hashlib.sha256(cert).hexdigest()}
        ]

    def test_only_the_signing_certificate_is_digested(self, tmp_path: Path) -> None:
        # The chain's later certificates (intermediates, the root) are not the
        # signer's identity; only the first one is, exactly as apksigner prints.
        value = _v2_signer_value([[b"leaf-cert", b"intermediate", b"root"]])
        path = _apk_with_signing_block(tmp_path / "c.apk", [0x7109871A], {0x7109871A: value})
        info = describe_apk(path)["apk"]
        assert info["signers"] == [
            {"scheme": "v2", "cert_sha256": hashlib.sha256(b"leaf-cert").hexdigest()}
        ]

    def test_each_signer_of_a_multi_signer_apk_is_reported(self, tmp_path: Path) -> None:
        value = _v2_signer_value([[b"first-signer"], [b"second-signer"]])
        path = _apk_with_signing_block(tmp_path / "m.apk", [0x7109871A], {0x7109871A: value})
        info = describe_apk(path)["apk"]
        assert [s["cert_sha256"] for s in info["signers"]] == [
            hashlib.sha256(b"first-signer").hexdigest(),
            hashlib.sha256(b"second-signer").hexdigest(),
        ]

    def test_v2_and_v3_blocks_each_carry_their_signer(self, tmp_path: Path) -> None:
        # A rotated key ships different certificates per scheme; each block's
        # signer is reported under its own scheme so the difference is visible.
        # (v3's extra SDK-bound fields sit after the certificates, so the same
        # walk reads both layouts.)
        old, new = _v2_signer_value([[b"old-key"]]), _v2_signer_value([[b"new-key"]])
        path = _apk_with_signing_block(
            tmp_path / "b.apk",
            [0x7109871A, 0xF05368C0],
            {0x7109871A: old, 0xF05368C0: new},
        )
        info = describe_apk(path)["apk"]
        assert info["signers"] == [
            {"scheme": "v2", "cert_sha256": hashlib.sha256(b"old-key").hexdigest()},
            {"scheme": "v3", "cert_sha256": hashlib.sha256(b"new-key").hexdigest()},
        ]

    def test_a_lying_certificate_length_yields_no_digest(self, tmp_path: Path) -> None:
        # The certificate claims more bytes than its sequence holds: nothing is
        # digested from out-of-bounds memory, and the scheme flag still stands.
        value = _v2_signer_value([[b"real-cert"]])
        certs_at = value.index(b"real-cert") - 4
        lying = value[:certs_at] + struct.pack("<I", 0x7FFFFFFF) + value[certs_at + 4 :]
        path = _apk_with_signing_block(tmp_path / "l.apk", [0x7109871A], {0x7109871A: lying})
        info = describe_apk(path)["apk"]
        assert info["signed_v2"] is True
        assert info["signers"] == []

    def test_a_dummy_block_value_names_no_signer(self, tmp_path: Path) -> None:
        # A block advertising the scheme with no parseable signer sequence
        # (the filler value) proves signed_v2 and signers are independent.
        path = _apk_with_signing_block(tmp_path / "d.apk", [0x7109871A])
        info = describe_apk(path)["apk"]
        assert info["signed_v2"] is True
        assert info["signers"] == []

    def test_describe_apk_rejects_archive_without_manifest(self, tmp_path: Path) -> None:
        plain = tmp_path / "archive.zip"
        with zipfile.ZipFile(plain, "w") as archive:
            archive.writestr("readme.txt", "hello")
        with pytest.raises(ValueError):
            describe_apk(plain)


class TestApkBundleAndSet:
    """.aab/.apks/.xapk carry .apk-family suffixes but have no root manifest.

    classify_target routes them to describe_apk on suffix alone, so opening a
    session over a legitimate bundle or set must return its structure -- and, for
    a set, its base APK's manifest -- instead of failing on the missing root
    AndroidManifest.xml.
    """

    def test_a_classic_apk_is_tagged_with_its_format(self, tmp_path: Path) -> None:
        info = describe_apk(_apk(tmp_path / "app.apk"))["apk"]
        assert info["format"] == "apk"

    def test_a_bundletool_set_reads_the_base_master_manifest(self, tmp_path: Path) -> None:
        if not _APK_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_APK_FIXTURE}")
        path = tmp_path / "app.apks"
        with zipfile.ZipFile(path, "w") as archive:
            # The base module's master split holds the manifest and dex; the
            # density split under the same splits/ dir must not be chosen as base.
            archive.writestr("splits/base-master.apk", _APK_FIXTURE.read_bytes())
            archive.writestr("splits/base-xxhdpi.apk", b"PK\x05\x06" + b"\x00" * 18)
            archive.writestr("toc.pb", b"")
        info = describe_apk(path)["apk"]
        assert info["format"] == "apk_set"
        assert info["apk_count"] == 2
        assert "splits/base-master.apk" in info["apks"]
        assert info["base_apk"] == "splits/base-master.apk"
        # The base APK's manifest is read by recursing into that member.
        assert info["manifest"]["package"] == "com.example.headless"

    def test_an_xapk_base_is_chosen_over_config_splits(self, tmp_path: Path) -> None:
        if not _APK_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_APK_FIXTURE}")
        path = tmp_path / "app.xapk"
        with zipfile.ZipFile(path, "w") as archive:
            # APKPure names the whole app after its package and the splits after
            # their ABI/density; the package APK is the one to read.
            archive.writestr("com.example.headless.apk", _APK_FIXTURE.read_bytes())
            archive.writestr("config.arm64_v8a.apk", b"PK\x05\x06" + b"\x00" * 18)
            archive.writestr("manifest.json", b'{"package_name": "com.example.headless"}')
            archive.writestr("icon.png", b"\x89PNG")
        info = describe_apk(path)["apk"]
        assert info["format"] == "apk_set"
        assert info["base_apk"] == "com.example.headless.apk"
        assert info["manifest"]["package"] == "com.example.headless"

    def test_a_set_without_a_readable_base_still_lists_its_apks(self, tmp_path: Path) -> None:
        # Both members are empty ZIP end-records: a set shape with no manifest to
        # recurse into must still report the listing rather than raise.
        path = tmp_path / "empty.apks"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("splits/base-master.apk", b"PK\x05\x06" + b"\x00" * 18)
            archive.writestr("splits/base-xhdpi.apk", b"PK\x05\x06" + b"\x00" * 18)
        info = describe_apk(path)["apk"]
        assert info["format"] == "apk_set"
        assert info["apk_count"] == 2
        assert "manifest" not in info

    def test_an_app_bundle_lists_its_modules(self, tmp_path: Path) -> None:
        path = tmp_path / "app.aab"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("BundleConfig.pb", b"")
            # An .aab manifest is protobuf under <module>/manifest/, not AXML.
            archive.writestr("base/manifest/AndroidManifest.xml", b"\x0a\x03pkg")
            archive.writestr("base/dex/classes.dex", b"dex\n035\x00")
            archive.writestr("feature1/manifest/AndroidManifest.xml", b"\x0a\x03pkg")
        info = describe_apk(path)["apk"]
        assert info["format"] == "aab"
        assert info["modules"] == ["base", "feature1"]

    def test_config_split_detection_spans_both_layouts(self) -> None:
        from headless_re_mcp.core.session import _apk_is_config_split

        assert _apk_is_config_split("base-xxhdpi.apk") is True
        assert _apk_is_config_split("config.arm64_v8a.apk") is True
        assert _apk_is_config_split("base-master.apk") is False
        assert _apk_is_config_split("com.example.app.apk") is False

    def test_session_over_a_set_opens_and_carries_the_format(self, tmp_path: Path) -> None:
        if not _APK_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_APK_FIXTURE}")
        from headless_re_mcp.core.session import SessionRegistry

        path = tmp_path / "app.apks"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("splits/base-master.apk", _APK_FIXTURE.read_bytes())
        session = SessionRegistry().create(str(path))
        assert session.target is TargetKind.APK
        assert session.metadata["apk"]["format"] == "apk_set"
        assert session.metadata["apk"]["manifest"]["package"] == "com.example.headless"


class TestApktoolBoundaries:
    def test_missing_apktool_degrades(self, tmp_path: Path) -> None:
        client = ApktoolClient(None, None)
        with pytest.raises(ApktoolError) as info:
            client.decode(_apk(tmp_path / "a.apk"), tmp_path / "out")
        assert info.value.code == "capability_unavailable"

    def test_build_rejects_a_directory_that_is_not_a_decode_tree(self, tmp_path: Path) -> None:
        fake_tool = tmp_path / "apktool.bat"
        fake_tool.write_text("@echo off\n", encoding="utf-8")
        source = tmp_path / "tree"
        source.mkdir()
        client = ApktoolClient(fake_tool, None)
        with pytest.raises(ApktoolError) as info:
            client.build(source, tmp_path / "out.apk")
        assert info.value.code == "invalid_params"

    def test_sign_without_apksigner_degrades(self, tmp_path: Path) -> None:
        client = ApktoolClient(None, None)
        with pytest.raises(ApktoolError) as info:
            client.sign(_apk(tmp_path / "a.apk"), tmp_path / "signed.apk")
        assert info.value.code == "capability_unavailable"

    def test_decode_does_not_call_a_nonzero_exit_a_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken decode that still wrote a manifest was returned as success.

        Measured: apktool exit 1 plus AndroidManifest.xml on disk produced a
        normal decoded_dir payload with no exit_code. The agent then edits
        smali in a tree apktool already said was wrong. Build already refuses
        a nonzero exit; decode did not.
        """
        fake_tool = tmp_path / "apktool.bat"
        fake_tool.write_text("@echo off\n", encoding="utf-8")
        apk = _apk(tmp_path / "a.apk")
        out = tmp_path / "decoded"
        out.mkdir()
        (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
            return "", "Could not decode resources", 1

        monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
        client = ApktoolClient(fake_tool, None)
        with pytest.raises(ApktoolError) as info:
            client.decode(apk, out)
        assert info.value.code == "backend_error"
        assert info.value.details.get("exit_code") == 1


class TestPeOnlyToolsRefuseApkSessions:
    def test_detect_dotnet_and_unpack_return_target_mismatch(self, tmp_path: Path) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        # Hosted quality has no UPX; the target check must still win.
        service = AnalysisService(
            replace(Settings.load(), artifact_root=tmp_path / "artifacts", upx=None)
        )
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            assert created.ok, created.error
            session_id = str(created.data["session"]["id"])
            detect = service.detect_scan(session_id, use_die=False)
            assert detect.ok is False
            assert detect.error is not None
            assert detect.error.code == "target_mismatch"
            dotnet = service.dotnet_inspect(session_id)
            assert dotnet.ok is False
            assert dotnet.error is not None
            assert dotnet.error.code == "target_mismatch"
            unpack = service.unpack_upx_test(session_id)
            assert unpack.ok is False
            assert unpack.error is not None
            assert unpack.error.code == "target_mismatch"
        finally:
            service.close_all()

    def test_static_and_dynamic_open_leave_an_apk_session_created(
        self, tmp_path: Path
    ) -> None:
        from headless_re_mcp.core.service import AnalysisService

        service = AnalysisService()
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            session_id = str(created.data["session"]["id"])
            static = service.open_static(session_id)
            assert static.ok is False
            assert static.error is not None
            assert static.error.code == "target_mismatch"
            assert service.get_session(session_id).data["session"]["state"] == "created"
            dynamic = service.open_dynamic(session_id)
            assert dynamic.ok is False
            assert dynamic.error is not None
            assert dynamic.error.code == "target_mismatch"
            assert service.get_session(session_id).data["session"]["state"] == "created"
        finally:
            service.close_all()

    def test_apk_repack_and_sign_refuse_host_paths(self, tmp_path: Path) -> None:
        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        service = AnalysisService(
            Settings(
                ida_home=None,
                x64dbg_source=None,
                x64dbg_headless_x64=None,
                x64dbg_headless_x86=None,
                artifact_root=tmp_path / "artifacts",
            )
        )
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            session_id = str(created.data["session"]["id"])
            outside = tmp_path / "host-decoded"
            outside.mkdir()
            (outside / "apktool.yml").write_text("x\n", encoding="utf-8")
            host_apk = tmp_path / "host.apk"
            host_apk.write_bytes(b"PK")
            host_ks = tmp_path / "host.keystore"
            host_ks.write_bytes(b"ks")
            repack = service.apk_repack(session_id, decoded_dir=str(outside))
            assert repack.ok is False
            assert repack.error is not None
            assert repack.error.code == "invalid_params"
            signed = service.apk_sign(
                session_id, apk_path=str(host_apk), keystore=str(host_ks)
            )
            assert signed.ok is False
            assert signed.error is not None
            assert signed.error.code == "invalid_params"
        finally:
            service.close_all()


def _adb_with_shell(output: str) -> AdbBackend:
    """An AdbBackend whose device shell always returns ``output``.

    adbutils' shell can hand back the adb host's own error text as stdout
    rather than raising, which is exactly the leak these tests pin.
    """

    class _Dev:
        def shell(self, cmd: object, timeout: float | None = None) -> str:
            del cmd, timeout
            return output

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = object()
    backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
    return backend


class TestPropertiesDoesNotInventAnEmptyDevice:
    """A host error line used to look like a device with no properties.

    Measured: a device whose getprop printed ``error: device offline`` still
    answered ``{'properties': {}, 'count': 0}``. An unattended agent then
    treats a dead device as having an empty property set.
    """

    def test_an_adb_error_line_is_not_an_empty_property_set(self) -> None:
        with pytest.raises(AdbError) as info:
            _adb_with_shell("error: device offline").properties("emulator-5554")
        assert info.value.code == "backend_error"
        assert "getprop failed" in info.value.message
        assert "offline" in str(info.value.details.get("output", ""))

    def test_no_prop_lines_is_empty(self) -> None:
        result = _adb_with_shell("").properties("emulator-5554")
        assert result["properties"] == {}
        assert result["count"] == 0

    def test_prop_lines_are_listed(self) -> None:
        result = _adb_with_shell("[ro.build.version.sdk]: [34]").properties("emulator-5554")
        assert result["properties"] == {"ro.build.version.sdk": "34"}
        assert result["count"] == 1


class TestPackagesDoesNotInventAnEmptyDevice:
    """A host error line used to look like a device with no apps.

    Measured: a device whose pm list printed ``error: device offline`` still
    answered ``{'packages': [], 'count': 0}``. An unattended agent then treats
    a dead device as having no apps.
    """

    def test_an_adb_error_line_is_not_an_empty_device(self) -> None:
        with pytest.raises(AdbError) as info:
            _adb_with_shell("adb: device 'emulator-5554' not found").packages("emulator-5554")
        assert info.value.code == "backend_error"
        assert "pm list failed" in info.value.message
        assert "not found" in str(info.value.details.get("output", ""))

    def test_no_package_lines_is_empty(self) -> None:
        result = _adb_with_shell("").packages("emulator-5554")
        assert result["packages"] == []
        assert result["count"] == 0

    def test_package_lines_are_listed_sorted(self) -> None:
        raw = "package:com.other.app\npackage:com.example.app\n"
        result = _adb_with_shell(raw).packages("emulator-5554")
        assert result["packages"] == ["com.example.app", "com.other.app"]
        assert result["count"] == 2


class TestLogcatDoesNotInventASnapshot:
    """A host error line used to look like a one-line log snapshot.

    Measured: a device whose logcat printed ``error: device offline`` still
    answered ``{'lines': ['error: device offline']}``. An unattended agent
    then treats a dead device as a one-line log.
    """

    def test_an_adb_error_line_is_not_a_snapshot(self) -> None:
        with pytest.raises(AdbError) as info:
            _adb_with_shell("error: device offline").logcat("emulator-5554")
        assert info.value.code == "backend_error"
        assert "logcat failed" in info.value.message
        assert "offline" in str(info.value.details.get("output", ""))

    def test_a_real_log_line_that_mentions_error_is_still_a_snapshot(self) -> None:
        raw = "10-10 10:00:00.000  W System: recovered from error: boom"
        result = _adb_with_shell(raw).logcat("emulator-5554")
        assert result["lines"] == [raw]

    def test_an_empty_log_is_a_snapshot_not_a_failure(self) -> None:
        result = _adb_with_shell("").logcat("emulator-5554")
        assert result["lines"] == []
