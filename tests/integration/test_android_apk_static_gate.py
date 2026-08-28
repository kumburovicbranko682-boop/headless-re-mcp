"""Android static gate: androguard's real parse path on a committed APK.

The sibling ``test_android_re_gate`` builds a synthetic archive whose manifest
is not valid AXML, so it can only prove the backend *degrades* cleanly. Nothing
exercised androguard's happy path -- the package, versions, permissions,
components, certificate, and native ABIs a real capture depends on, nor the
full DEX analysis behind classes/methods/strings/xrefs -- so a regression in
that extraction would pass CI unseen. This gate consumes a committed, v1-signed
minimal APK carrying a real one-class DEX (see
fixtures/android/build_minimal_apk.py) and asserts the extracted facts. skip !=
pass: it skips only when androguard is not installed, and says so.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"
_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _exported_from_manifest_xml(xml_text: str) -> set[tuple[str, str]]:
    """The exported (type, name) set, computed off androguard's decoded XML.

    androguard renders the binary AXML to text XML independently of the stdlib
    reader; applying the export rule here (explicit android:exported wins,
    otherwise an <intent-filter> exports) over that tree is a second, tool-based
    decode of the same components -- so agreement proves the stdlib reader
    walked the AXML the way androguard did, name for name and flag for flag.
    """
    root = ET.fromstring(xml_text)
    app = root.find("application")
    exported: set[tuple[str, str]] = set()
    if app is None:
        return exported
    for element in list(app):
        if element.tag not in _COMPONENT_TAGS:
            continue
        name = element.get(f"{{{_ANDROID_NS}}}name")
        if not name:
            continue
        flag = element.get(f"{{{_ANDROID_NS}}}exported")
        has_filter = element.find("intent-filter") is not None
        is_exported = (flag == "true") if flag is not None else has_filter
        if is_exported:
            exported.add((element.tag, name))
    return exported


def _deep_links_from_manifest_xml(xml_text: str) -> set[tuple[str, str, str | None, str | None]]:
    """The (activity, scheme, host, pathPrefix) links off androguard's XML.

    The same rule the stdlib reader applies -- an activity/alias intent-filter
    carrying ACTION_VIEW, one record per <data> element that names a scheme --
    evaluated over androguard's independent render of the manifest, so the two
    decoders can be compared link for link.
    """
    root = ET.fromstring(xml_text)
    app = root.find("application")
    links: set[tuple[str, str, str | None, str | None]] = set()
    if app is None:
        return links
    for element in list(app):
        if element.tag not in ("activity", "activity-alias"):
            continue
        name = element.get(f"{{{_ANDROID_NS}}}name")
        if not name:
            continue
        for intent_filter in element.findall("intent-filter"):
            actions = {
                action.get(f"{{{_ANDROID_NS}}}name")
                for action in intent_filter.findall("action")
            }
            if "android.intent.action.VIEW" not in actions:
                continue
            for data in intent_filter.findall("data"):
                scheme = data.get(f"{{{_ANDROID_NS}}}scheme")
                if scheme:
                    links.add(
                        (
                            name,
                            scheme,
                            data.get(f"{{{_ANDROID_NS}}}host"),
                            data.get(f"{{{_ANDROID_NS}}}pathPrefix"),
                        )
                    )
    return links


@pytest.mark.integration
def test_android_apk_static_happy_path() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    assert classify_target(_FIXTURE) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session = created.data["session"]
        session_id = session["id"]
        meta = session["metadata"]["apk"]
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True
        # Stdlib DEX header facts: the fixture's one class with three method
        # ids (its <init> and getSecret, plus the referenced Object.<init>).
        assert meta["dex"]["versions"] == ["035"]
        assert meta["dex"]["class_count"] == 1
        assert meta["dex"]["method_count"] == 3

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        info = opened.data
        assert info["package"] == "com.example.headless"
        assert info["version_name"] == "1.0"
        assert info["version_code"] == "1"
        assert info["min_sdk"] == "21"
        assert info["target_sdk"] == "33"
        assert info["main_activity"] == "com.example.headless.MainActivity"
        assert info["permission_count"] == 1
        assert set(info["native_abis"]) == {"arm64-v8a", "x86_64"}

        # The stdlib AXML facts attached at session creation must agree with
        # androguard's parse -- the same package, versions, SDK levels and
        # permission read two independent ways (androguard reports the numeric
        # ones as strings, so compare with a cast).
        tool_free = meta["manifest"]
        assert tool_free["package"] == info["package"]
        assert str(tool_free["version_code"]) == info["version_code"]
        assert tool_free["version_name"] == info["version_name"]
        assert str(tool_free["min_sdk"]) == info["min_sdk"]
        assert str(tool_free["target_sdk"]) == info["target_sdk"]
        assert tool_free["permissions"] == ["android.permission.INTERNET"]
        # The launchable activity (entry point) the stdlib reader found from the
        # MAIN + LAUNCHER intent-filter must be the one androguard's own
        # get_main_activity resolves -- a second independent cross-check of the
        # entry-point fact, alongside the apktool gate's.
        assert tool_free["launcher_activity"] == info["main_activity"]
        # The <uses-library> dependency names the stdlib reader collected must
        # be exactly the set androguard's get_libraries resolves -- the second
        # independent decode of the manifest-level dependency list (the apktool
        # gate checks names and required flags against its text rendering).
        assert sorted(lib["name"] for lib in tool_free["uses_libraries"]) == info[
            "uses_libraries"
        ]
        assert info["uses_libraries"] == [
            "androidx.window.extensions",
            "org.apache.http.legacy",
        ]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.headless"
        assert "android.permission.INTERNET" in manifest.data["manifest_xml"]
        # The exported attack surface the stdlib reader found must be exactly
        # the set derived from androguard's own decode of the manifest -- the
        # implicit-via-filter launcher, the explicit-true service and provider,
        # with the explicit-false receiver (despite its filter) excluded.
        reader_surface = {
            (comp["type"], comp["name"]) for comp in tool_free["exported_components"]
        }
        assert reader_surface == _exported_from_manifest_xml(manifest.data["manifest_xml"])
        assert reader_surface == {
            ("activity", "com.example.headless.MainActivity"),
            ("service", "com.example.headless.ExportedService"),
            ("provider", "com.example.headless.SharedProvider"),
        }

        # The deep links -- the remotely-triggerable subset of that surface --
        # must match androguard's decode link for link: the https host with
        # its pathPrefix and the bare custom scheme, both on the launcher.
        reader_links = {
            (
                link["activity"],
                link["scheme"],
                link.get("host"),
                link.get("path_prefix"),
            )
            for link in tool_free["deep_links"]
        }
        assert reader_links == _deep_links_from_manifest_xml(manifest.data["manifest_xml"])
        assert reader_links == {
            (
                "com.example.headless.MainActivity",
                "https",
                "deeplink.example.com",
                "/open",
            ),
            ("com.example.headless.MainActivity", "headless", None, None),
        }

        # The custom Application class (<application android:name>) -- the code
        # that runs before any component, where a packer's stub lives -- read
        # two independent ways: the stdlib reader off the binary AXML and
        # androguard's text render of the same manifest.
        app_element = ET.fromstring(manifest.data["manifest_xml"]).find("application")
        assert app_element is not None
        assert tool_free["application_name"] == app_element.get(f"{{{_ANDROID_NS}}}name")
        assert tool_free["application_name"] == "com.example.headless.HeadlessApp"

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert "android.permission.INTERNET" in perms.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == ["com.example.headless.MainActivity"]
        assert components.data["services"] == ["com.example.headless.ExportedService"]
        assert components.data["receivers"] == ["com.example.headless.PrivateReceiver"]
        assert components.data["providers"] == ["com.example.headless.SharedProvider"]
        assert components.data["main_activity"] == "com.example.headless.MainActivity"

        certs = service.apk_certificates(session_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is True
        assert len(certs.data["certificates"]) == 1
        assert certs.data["certificates"][0]["sha256"]

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert set(libs.data["abis"]) == {"arm64-v8a", "x86_64"}
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apk_dex_analysis_happy_path() -> None:
    """androguard's full AnalyzeAPK path: the fixture carries a real one-class
    DEX, so classes/methods/strings/xrefs must return the analysed facts rather
    than a degradation envelope."""
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert "Lcom/example/headless/Sample;" in classes.data["classes"]

        # The stdlib DEX reader resolves the same defined class androguard does,
        # in dotted form (the descriptor Lcom/.../Sample; without its L...; wrap).
        tool_free = created.data["session"]["metadata"]["apk"]["dex"]["classes"]
        assert "com.example.headless.Sample" in tool_free

        methods = service.apk_methods(session_id, "com.example.headless.Sample")
        assert methods.ok, methods.error
        assert "getSecret" in [m["name"] for m in methods.data["methods"]]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert any("flag{headless-re}" in s for s in strings.data["strings"])

        # getSecret has no callers in this DEX (the constructor only calls up
        # to Object.<init>): the enumeration must complete and say so, not
        # error and not claim a phantom caller.
        xrefs = service.apk_xrefs(session_id, "getSecret")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["count"] == 0
        assert xrefs.data["has_more"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_dex_external_api_surface_agrees_with_androguard() -> None:
    """The stdlib import-surface fact against androguard's cross-reference pass.

    The session's ``external_classes`` / ``external_method_count`` come from a
    raw walk of the DEX method_ids table -- rows whose class the DEX does not
    define. androguard derives the same surface a completely different way: its
    Analysis pass decodes every instruction and registers an external
    ClassAnalysis/MethodAnalysis for each invoked method it cannot resolve
    locally. On a dx-shaped DEX (every id row is referenced by code, which the
    fixture mirrors) the two views must coincide class for class and method for
    method -- the Android analogue of the ELF gate checking undefined dynamic
    symbols against readelf.
    """
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    from androguard.misc import AnalyzeAPK

    _apk, _dex, analysis = AnalyzeAPK(str(_FIXTURE))
    # androguard names classes by descriptor (Ljava/lang/Object;); normalise to
    # the reader's dotted form, keeping only real class types as the reader does.
    ag_classes = {
        cls.name[1:-1].replace("/", ".")
        for cls in analysis.get_external_classes()
        if cls.name.startswith("L") and cls.name.endswith(";")
    }
    ag_method_count = sum(1 for m in analysis.get_methods() if m.is_external())

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        dex_facts = created.data["session"]["metadata"]["apk"]["dex"]
    finally:
        service.close_all()

    assert set(dex_facts["external_classes"]) == ag_classes
    assert dex_facts["external_method_count"] == ag_method_count
    # And both agree on the concrete surface the fixture bakes in: the one
    # up-call every javac constructor makes.
    assert dex_facts["external_classes"] == ["java.lang.Object"]
    assert dex_facts["external_method_count"] == 1


@pytest.mark.integration
def test_dex_integrity_verdicts_agree_with_androguard(tmp_path: Path) -> None:
    """The DEX integrity verdicts, re-derived from androguard's header decode.

    The session verifies each DEX member's own claims -- file_size, adler32
    checksum, SHA-1 signature -- and reports bytes past the declared size as
    the member's overlay. The reader's field offsets and its unit fixtures are
    both ours, so androguard referees: its independent header decode supplies
    the declared values, and recomputing the sums over androguard's file_size
    must reproduce exactly the reader's True/False verdicts on a pristine, a
    hex-patched and a stowaway-carrying copy of the same DEX.
    """
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    import hashlib
    import zlib

    from androguard.core.dex import DEX

    with zipfile.ZipFile(_FIXTURE) as archive:
        raw = archive.read("classes.dex")
    header = DEX(raw).header

    def _verdicts(apk: Path) -> dict:
        service = AnalysisService()
        try:
            created = service.create_session(str(apk))
            assert created.ok, created.error
            (entry,) = created.data["session"]["metadata"]["apk"]["dex"]["signatures"]
            return entry
        finally:
            service.close_all()

    def _repack(name: str, dex: bytes) -> Path:
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
            archive.writestr("classes.dex", dex)
        return path

    # Pristine: the reader's fingerprint is byte for byte androguard's decoded
    # signature field, the sums recomputed over androguard's file_size match
    # the declared values, and the declared size covers the whole member.
    entry = _verdicts(_FIXTURE)
    assert entry["sha1"] == bytes(header.signature).hex()
    assert header.file_size == len(raw)
    assert entry["overlay"] is None
    assert entry["checksum_ok"] is (
        (zlib.adler32(raw[12 : header.file_size]) & 0xFFFFFFFF) == header.checksum
    )
    assert entry["signature_ok"] is (
        hashlib.sha1(raw[32 : header.file_size]).hexdigest() == bytes(header.signature).hex()
    )
    assert entry["checksum_ok"] is True
    assert entry["signature_ok"] is True

    # A raw hex patch: androguard's own strict constructor refuses the member
    # outright over the very same stale adler32 -- the independent verdict the
    # reader states as checksum_ok False (and the SHA-1 goes stale with it).
    patched = bytearray(raw)
    patched[-1] ^= 0xFF
    with pytest.raises(ValueError, match="[Aa]dler32"):
        DEX(bytes(patched))
    entry = _verdicts(_repack("tampered.apk", bytes(patched)))
    assert entry["checksum_ok"] is False
    assert entry["signature_ok"] is False
    assert entry["overlay"] is None

    # A stowaway appended past file_size: androguard, which sums to the end of
    # the buffer, refuses this shape too -- proof the residue sits outside the
    # DEX the sums vouch for. The reader instead verifies the file_size bytes
    # the header describes (still clean: a smuggle, not a corruption) and pins
    # the residue at exactly the boundary androguard decoded from the header.
    with pytest.raises(ValueError, match="[Aa]dler32"):
        DEX(raw + b"STOWAWAY")
    entry = _verdicts(_repack("stowaway.apk", raw + b"STOWAWAY"))
    assert entry["overlay"] == {"offset": header.file_size, "size": 8, "kind": None}
    assert entry["checksum_ok"] is True
    assert entry["signature_ok"] is True


@pytest.mark.integration
def test_apk_member_crc_verdict_agrees_with_unzip(tmp_path: Path) -> None:
    """The session's member-CRC replay against unzip's own -t verification.

    ``crc`` is the container's own integrity fact -- the APK pair to the DEX
    header checksum and the PE CheckSum: every ZIP member's stored CRC-32
    replayed against its actual bytes. Info-ZIP's ``unzip -t`` performs the
    same replay with its own extraction code, so its verdict referees the
    session's on the clean fixture, and on a copy with one STORED member
    edited in place (the naive-repack shape: bytes changed, CRC not
    recomputed) both sides must name the same member bad.
    """
    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("unzip not installed — APK CRC gate not run (skip != pass)")
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")

    # The clean leg: unzip -t exits 0 and reports no errors; the session
    # must call the same archive clean over the same member count.
    verify = subprocess.run(
        [unzip, "-t", str(_FIXTURE)], capture_output=True, text=True, timeout=60
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr
    assert "No errors detected" in verify.stdout

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        crc = created.data["session"]["metadata"]["apk"]["crc"]
        assert crc["ok"] is True
        assert crc["bad_members"] == []
    finally:
        service.close_all()

    # The tampered leg: repack the fixture with one member STORED, then edit
    # that member's bytes in place without recomputing its CRC -- the
    # naive-repack shape. unzip -t must flag exactly that member, and the
    # session must name the same one.
    victim_name = "resources.arsc"
    rebuilt = tmp_path / "rebuilt.apk"
    with zipfile.ZipFile(_FIXTURE) as src, zipfile.ZipFile(rebuilt, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == victim_name:
                dst.writestr(
                    zipfile.ZipInfo(info.filename), data, compress_type=zipfile.ZIP_STORED
                )
            else:
                dst.writestr(info, data, compress_type=info.compress_type)
    raw = rebuilt.read_bytes()
    with zipfile.ZipFile(rebuilt) as archive:
        victim = archive.getinfo(victim_name)
    assert victim.compress_type == zipfile.ZIP_STORED
    # The STORED payload starts after the 30-byte local header plus the local
    # name and extra fields -- read those lengths off the local record itself.
    name_len = int.from_bytes(raw[victim.header_offset + 26 : victim.header_offset + 28], "little")
    extra_len = int.from_bytes(raw[victim.header_offset + 28 : victim.header_offset + 30], "little")
    payload_at = victim.header_offset + 30 + name_len + extra_len
    patched = bytearray(raw)
    patched[payload_at] ^= 0xFF
    tampered = tmp_path / "tampered.apk"
    tampered.write_bytes(bytes(patched))

    verify = subprocess.run(
        [unzip, "-t", str(tampered)], capture_output=True, text=True, timeout=60
    )
    assert verify.returncode != 0, "unzip must reject the patched member"
    assert "bad CRC" in verify.stdout, verify.stdout

    service = AnalysisService()
    try:
        created = service.create_session(str(tampered))
        assert created.ok, created.error
        crc = created.data["session"]["metadata"]["apk"]["crc"]
        assert crc["ok"] is False
        # Name for name: the member unzip called bad is the one the session
        # lists (unzip prints it on the "Bad CRC" line's preceding entry).
        assert victim.filename in crc["bad_members"]
        assert victim.filename in verify.stdout
    finally:
        service.close_all()
