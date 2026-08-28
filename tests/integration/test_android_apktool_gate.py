"""Android repack gate: real apktool decode + rebuild of the committed APK.

apk_decode / apk_repack had only unit coverage (path safety, empty-rebuild
rejection, closed-session guards) -- nothing ran apktool end to end, so a break
in the decode/build adapters or in how the decoded tree is located and rebuilt
would pass CI unseen. This gate decodes the committed APK, checks apktool's own
baksmali really disassembled the fixture's class, re-derives the DEX import
surface (external classes and method refs) from the smali tree to cross-check
the tool-free method_ids reader, then rebuilds a valid APK.

Decode runs with no_resources: the fixture carries a placeholder resources.arsc
(a valid ARSC is a separate hand-built binary format, out of scope), and the
manifest uses only inline attribute values, so full-resource decoding is not
needed to exercise the smali + manifest + rebuild path. apktool is
auto-discovered from PATH by Settings.load(); skip != pass -- the gate skips
only when apktool is not installed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"

_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ACTION_MAIN = "android.intent.action.MAIN"
_CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER"
_COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}


def _apktool_manifest_text(apktool: Path, apk: Path, tmp_path: Path) -> str:
    """Decode only the manifest to text with apktool, independent of the backend.

    --only-manifest renders AndroidManifest.xml to text without decoding the
    resource table, so it works on the fixture's stub resources.arsc where a
    full decode fails and a --no-res decode leaves the manifest binary. This is
    the independent ground truth the reader is cross-checked against, obtained
    the way the monodis/pedump/r2 gates invoke their tool directly.
    """
    out = tmp_path / "manifest_decode"
    result = subprocess.run(
        [str(apktool), "d", "-f", "--only-manifest", "-o", str(out), str(apk)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    manifest = out / "AndroidManifest.xml"
    assert result.returncode == 0 and manifest.is_file(), result.stderr or result.stdout
    return manifest.read_text(encoding="utf-8", errors="replace")


def _apktool_uses_libraries(manifest_xml: str) -> list[dict[str, object]]:
    """The <uses-library> dependencies in apktool's text manifest.

    Parsed with a real XML parser in document order, applying Android's
    documented default (a missing android:required means true) -- the same
    shape the tool-free reader reports, decoded independently.
    """
    root = ET.fromstring(manifest_xml)
    name_attr = f"{{{_ANDROID_NS}}}name"
    required_attr = f"{{{_ANDROID_NS}}}required"
    libraries: list[dict[str, object]] = []
    for element in root.iter("uses-library"):
        name = element.get(name_attr)
        if name:
            libraries.append(
                {"name": name, "required": element.get(required_attr, "true") == "true"}
            )
    return libraries


def _apktool_exported_components(manifest_xml: str) -> set[tuple[str, str]]:
    """The exported (type, name) set in apktool's text manifest.

    Parsed with a real XML parser, applying the same export rule the tool-free
    reader does -- an explicit android:exported wins, otherwise an
    <intent-filter> exports -- so apktool's independent AXML decode is the
    ground truth for the reader's attack-surface fact.
    """
    root = ET.fromstring(manifest_xml)
    app = root.find("application")
    name_attr = f"{{{_ANDROID_NS}}}name"
    exported_attr = f"{{{_ANDROID_NS}}}exported"
    exported: set[tuple[str, str]] = set()
    if app is None:
        return exported
    for element in list(app):
        if element.tag not in _COMPONENT_TAGS:
            continue
        name = element.get(name_attr)
        if not name:
            continue
        flag = element.get(exported_attr)
        has_filter = element.find("intent-filter") is not None
        is_exported = (flag == "true") if flag is not None else has_filter
        if is_exported:
            exported.add((element.tag, name))
    return exported


def _apktool_deep_links(manifest_xml: str) -> set[tuple[str, str, str | None, str | None]]:
    """The (activity, scheme, host, pathPrefix) links in apktool's manifest.

    The same rule the tool-free reader applies -- an activity/alias
    intent-filter carrying ACTION_VIEW, one record per <data> element that
    names a scheme -- evaluated over apktool's independent text rendering, so
    the two decoders can be compared link for link.
    """
    root = ET.fromstring(manifest_xml)
    name_attr = f"{{{_ANDROID_NS}}}name"
    links: set[tuple[str, str, str | None, str | None]] = set()
    for activity in root.iter():
        if activity.tag not in ("activity", "activity-alias"):
            continue
        name = activity.get(name_attr)
        if not name:
            continue
        for filt in activity.findall("intent-filter"):
            actions = {a.get(name_attr) for a in filt.findall("action")}
            if "android.intent.action.VIEW" not in actions:
                continue
            for data in filt.findall("data"):
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


def _apktool_launcher_activity(manifest_xml: str) -> str | None:
    """The <activity>/<activity-alias> whose intent-filter has MAIN + LAUNCHER.

    Parsed from apktool's text manifest with a real XML parser (not a regex) so
    it is a genuinely independent decode of the same entry-point rule the
    tool-free reader applies.
    """
    root = ET.fromstring(manifest_xml)
    name_attr = f"{{{_ANDROID_NS}}}name"
    for activity in root.iter():
        if activity.tag not in ("activity", "activity-alias"):
            continue
        for filt in activity.findall("intent-filter"):
            actions = {a.get(name_attr) for a in filt.findall("action")}
            categories = {c.get(name_attr) for c in filt.findall("category")}
            if _ACTION_MAIN in actions and _CATEGORY_LAUNCHER in categories:
                return activity.get(name_attr)
    return None

# An invoke target in baksmali output: "invoke-direct {v0},
# Ljava/lang/Object;-><init>()V". The whole L...;->name(args)ret target is one
# distinct method reference, mirroring one method_ids row.
_SMALI_INVOKE_RE = re.compile(r"invoke-[a-z0-9/]+ \{[^}]*\}, (L[^;]+;)->(\S+)")
_SMALI_CLASS_RE = re.compile(r"^\.class.* (L[^;]+;)\s*$", re.MULTILINE)


def _smali_external_refs(decoded_dir: Path) -> tuple[set[str], int]:
    """The (external classes, distinct external method refs) per baksmali.

    Walk every .smali file apktool produced: the classes the tree defines come
    from its ``.class`` directives, the methods it calls from its ``invoke-*``
    lines. Whatever is invoked on a class the tree does not define is the
    import surface, re-derived at instruction level from an independent
    disassembler rather than from the method_ids table the reader walks.
    """
    defined: set[str] = set()
    targets: set[tuple[str, str]] = set()
    for smali_path in decoded_dir.rglob("*.smali"):
        text = smali_path.read_text(encoding="utf-8", errors="replace")
        for match in _SMALI_CLASS_RE.finditer(text):
            defined.add(match.group(1))
        for descriptor, method in _SMALI_INVOKE_RE.findall(text):
            targets.add((descriptor, method))
    external = {(d, m) for d, m in targets if d not in defined}
    classes = {d[1:-1].replace("/", ".") for d, _ in external}
    return classes, len(external)


# The standard Android debug keystore: exact alias/password/DN that Android
# tooling itself creates, so apk.sign's zero-config default is what gets
# exercised. Path.home() is read the same way the apktool backend reads it.
_DEBUG_KEYSTORE = Path.home() / ".android" / "debug.keystore"


def _ensure_debug_keystore() -> Path | None:
    """Return the debug keystore, creating it with keytool if absent.

    apk.sign's default path signs with ~/.android/debug.keystore. On a fresh
    runner that file does not exist yet; keytool (shipped with the JDK the lane
    already installs) builds the canonical one. Returns None only when neither
    the keystore nor keytool is available, so the gate can skip rather than
    fail -- skip != pass.
    """
    if _DEBUG_KEYSTORE.is_file():
        return _DEBUG_KEYSTORE
    keytool = shutil.which("keytool")
    if keytool is None:
        return None
    _DEBUG_KEYSTORE.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            keytool, "-genkeypair", "-alias", "androiddebugkey",
            "-keypass", "android", "-keystore", str(_DEBUG_KEYSTORE),
            "-storepass", "android", "-dname", "CN=Android Debug,O=Android,C=US",
            "-validity", "10000", "-keyalg", "RSA", "-keysize", "2048",
        ],
        capture_output=True, timeout=120,
    )
    return _DEBUG_KEYSTORE if result.returncode == 0 and _DEBUG_KEYSTORE.is_file() else None


@pytest.mark.integration
def test_android_apktool_decode_and_repack(tmp_path: Path) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    settings = Settings.load()
    if settings.apktool is None:
        pytest.skip("apktool not installed — repack gate not run (skip != pass)")

    service = AnalysisService(settings=settings)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=180.0, no_resources=True)
        assert decoded.ok, decoded.error
        assert decoded.data["smali_dirs"], "apktool produced no smali directory"
        decoded_dir = Path(decoded.data["decoded_dir"])
        assert (decoded_dir / "AndroidManifest.xml").is_file()

        # The tool-free AXML reader surfaced android:debuggable and the launcher
        # (entry-point) activity at session creation; apktool's own decode of
        # the same manifest must agree. This cross-checks the reader against an
        # independent AXML decoder -- the Android analogue of the native gate
        # cross-checking nx/relro against radare2 and the .NET gate against
        # monodis. The workflow decode above runs with --no-res (the fixture's
        # resources.arsc is a stub), which leaves AndroidManifest.xml binary, so
        # the ground truth comes from a separate --only-manifest decode that
        # renders it to text without touching the stub table.
        reader_flags = created.data["session"]["metadata"]["apk"]["manifest"]
        reader_dex = created.data["session"]["metadata"]["apk"]["dex"]
        assert reader_flags["debuggable"] is True
        assert reader_flags["launcher_activity"] == "com.example.headless.MainActivity"
        manifest_xml = _apktool_manifest_text(settings.apktool, _FIXTURE, tmp_path)
        # Every declared posture flag, checked value for value against
        # apktool's text rendering -- the fixture declares one of each
        # polarity, so a stuck-at-true reader cannot pass.
        for attr, fact in (
            ("debuggable", "debuggable"),
            ("allowBackup", "allow_backup"),
            ("usesCleartextTraffic", "uses_cleartext_traffic"),
        ):
            apktool_flag = re.search(rf'android:{attr}="(true|false)"', manifest_xml)
            assert apktool_flag, (attr, manifest_xml)
            assert (apktool_flag.group(1) == "true") is reader_flags[fact], attr
        # The launcher activity apktool reports -- the <activity> whose
        # intent-filter carries MAIN + LAUNCHER -- must be the same component
        # the tool-free reader named.
        assert _apktool_launcher_activity(manifest_xml) == reader_flags["launcher_activity"]
        # The <uses-library> dependency list, name for name and flag for flag
        # in declaration order: the fixture declares one implicitly-required
        # and one optional library, so both the default-true rule and the
        # explicit-false encoding are checked against apktool's decode.
        assert _apktool_uses_libraries(manifest_xml) == reader_flags["uses_libraries"]
        assert reader_flags["uses_libraries"] == [
            {"name": "org.apache.http.legacy", "required": True},
            {"name": "androidx.window.extensions", "required": False},
        ]
        # The exported attack surface, cross-checked component for component
        # against apktool's decode: the implicit-via-filter launcher activity,
        # the explicit-true service and provider, with the explicit-false
        # receiver (despite its intent-filter) held back -- the mobile analogue
        # of cross-checking exported symbols against an independent tool.
        reader_surface = {
            (comp["type"], comp["name"]) for comp in reader_flags["exported_components"]
        }
        assert reader_surface == _apktool_exported_components(manifest_xml)
        assert reader_surface == {
            ("activity", "com.example.headless.MainActivity"),
            ("service", "com.example.headless.ExportedService"),
            ("provider", "com.example.headless.SharedProvider"),
        }
        # The deep links -- the remotely-triggerable subset of that surface --
        # cross-checked link for link against apktool's rendering: the https
        # host with its pathPrefix and the bare custom scheme, both bound to
        # the launcher activity.
        reader_links = {
            (
                link["activity"],
                link["scheme"],
                link.get("host"),
                link.get("path_prefix"),
            )
            for link in reader_flags["deep_links"]
        }
        assert reader_links == _apktool_deep_links(manifest_xml)
        assert reader_links == {
            (
                "com.example.headless.MainActivity",
                "https",
                "deeplink.example.com",
                "/open",
            ),
            ("com.example.headless.MainActivity", "headless", None, None),
        }

        # The custom Application class (<application android:name>) -- the
        # code that runs before any component, Android's code-before-main --
        # must be the same class in apktool's text rendering as in the
        # tool-free reader's AXML walk.
        app_element = ET.fromstring(manifest_xml).find("application")
        assert app_element is not None
        assert reader_flags["application_name"] == app_element.get(f"{{{_ANDROID_NS}}}name")
        assert reader_flags["application_name"] == "com.example.headless.HeadlessApp"

        # apktool's own baksmali must have disassembled the fixture's class: the
        # method and the string it returns have to survive DEX -> smali, as must
        # the constructor's up-call into java.lang.Object.
        smali_files = list(decoded_dir.rglob("Sample.smali"))
        assert smali_files, "Sample.smali not found in the decoded tree"
        smali = smali_files[0].read_text(encoding="utf-8", errors="replace")
        assert "getSecret" in smali
        assert "flag{headless-re}" in smali
        assert "Ljava/lang/Object;-><init>()V" in smali

        # The DEX import surface, re-derived from baksmali's disassembly: the
        # classes invoked across the smali tree minus the classes the tree
        # defines. The tool-free reader gets the same answer from the raw
        # method_ids table; on a dx-shaped DEX (every id row is referenced by
        # code, as in the fixture) the instruction-level and table-level views
        # must coincide -- the Android analogue of the ELF gate re-deriving
        # undefined symbols from readelf.
        smali_external, smali_ref_count = _smali_external_refs(decoded_dir)
        assert set(reader_dex["external_classes"]) == smali_external
        assert reader_dex["external_method_count"] == smali_ref_count
        assert reader_dex["external_classes"] == ["java.lang.Object"]
        assert reader_dex["external_method_count"] == 1

        repacked = service.apk_repack(session_id, timeout=180.0)
        assert repacked.ok, repacked.error
        out_apk = Path(repacked.data["apk"])
        assert out_apk.is_file()
        assert repacked.data["size"] > 0
        assert repacked.data["signed"] is False
        # The rebuild must be a real archive, not an empty/truncated file that
        # happens to exist -- the same contract apk.sign/install depend on.
        assert zipfile.is_zipfile(out_apk)
        with zipfile.ZipFile(out_apk) as archive:
            names = set(archive.namelist())
        assert "AndroidManifest.xml" in names
        assert "classes.dex" in names
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apktool_repack_and_sign() -> None:
    """Complete the modify workflow: decode -> repack -> sign the rebuilt APK.

    apk.sign had only unit coverage (path safety, closed-session guards); no
    test ever ran apksigner, so a break in the sign/verify adapter or in the
    debug-keystore default would pass CI unseen. This gate rebuilds the fixture
    unsigned, then signs it with the zero-config debug keystore and confirms the
    result really verifies -- once via the backend's own apksigner verify (which
    gates signed=True) and again independently here -- and that the tool-free
    reader recovers the signer's certificate SHA-256 identical to the digest
    apksigner prints. It needs apktool (to rebuild), apksigner (to sign) and the
    debug keystore; it skips, naming which is missing, rather than pass silently.
    """
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    settings = Settings.load()
    if settings.apktool is None:
        pytest.skip("apktool not installed — sign gate not run (skip != pass)")
    if settings.apksigner is None:
        pytest.skip("apksigner not installed — sign gate not run (skip != pass)")
    keystore = _ensure_debug_keystore()
    if keystore is None:
        pytest.skip(
            "no debug keystore and no keytool to create one — sign gate not run (skip != pass)"
        )

    service = AnalysisService(settings=settings)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=180.0, no_resources=True)
        assert decoded.ok, decoded.error
        repacked = service.apk_repack(session_id, timeout=180.0)
        assert repacked.ok, repacked.error
        assert repacked.data["signed"] is False

        signed = service.apk_sign(session_id, timeout=180.0)
        assert signed.ok, signed.error
        # signed=True only after the backend's apksigner verify succeeded.
        assert signed.data["signed"] is True
        assert signed.data["debug_keystore"] is True
        assert Path(signed.data["keystore"]) == _DEBUG_KEYSTORE
        out_apk = Path(signed.data["apk"])
        assert out_apk.is_file()
        assert signed.data["size"] > 0
        assert zipfile.is_zipfile(out_apk)

        # Independent confirmation the signature is real, not just that the tool
        # exited 0: apksigner verify must accept the output as a signed APK.
        verify = subprocess.run(
            [str(settings.apksigner), "verify", "--verbose", str(out_apk)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert verify.returncode == 0, verify.stderr or verify.stdout
        # apktool rebuilds without a v1 (JAR) signature, so apksigner applies a
        # v2 APK Signature Scheme block; the verifier must report it as such.
        assert "v2 scheme" in verify.stdout.lower()

        # The pure-Python identity facts must agree with the real signer: a
        # fresh session over the signed APK sees the v2 Signing Block apksigner
        # just wrote, which the v1 META-INF check alone would have missed.
        resigned = service.create_session(str(out_apk))
        assert resigned.ok, resigned.error
        signed_meta = resigned.data["session"]["metadata"]["apk"]
        assert signed_meta["signed_v2"] is True
        # apktool rebuilds the manifest through aapt, so this also proves the
        # stdlib AXML reader handles real aapt output (an 8-bit string pool),
        # not just the committed fixture's hand-written UTF-16 one.
        assert signed_meta["manifest"]["package"] == "com.example.headless"

        # Who signed it, cross-validated: apksigner prints the SHA-256 of the
        # signing certificate it just used, and the tool-free reader digests
        # the DER certificate straight out of the v2 block's signer sequence.
        # Same bytes, same hash -- or one of the two parsers is wrong.
        certs = subprocess.run(
            [str(settings.apksigner), "verify", "--print-certs", str(out_apk)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert certs.returncode == 0, certs.stderr or certs.stdout
        printed = re.search(r"certificate SHA-256 digest: ([0-9a-f]{64})", certs.stdout)
        assert printed, certs.stdout
        reader_v2 = [s["cert_sha256"] for s in signed_meta["signers"] if s["scheme"] == "v2"]
        assert reader_v2 == [printed.group(1)]
    finally:
        service.close_all()
