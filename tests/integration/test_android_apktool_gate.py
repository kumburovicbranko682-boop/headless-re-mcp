"""Android repack gate: real apktool decode + rebuild of the committed APK.

apk_decode / apk_repack had only unit coverage (path safety, empty-rebuild
rejection, closed-session guards) -- nothing ran apktool end to end, so a break
in the decode/build adapters or in how the decoded tree is located and rebuilt
would pass CI unseen. This gate decodes the committed APK, checks apktool's own
baksmali really disassembled the fixture's class, then rebuilds a valid APK.

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

        # apktool's own baksmali must have disassembled the fixture's class: the
        # method and the string it returns have to survive DEX -> smali.
        smali_files = list(decoded_dir.rglob("Sample.smali"))
        assert smali_files, "Sample.smali not found in the decoded tree"
        smali = smali_files[0].read_text(encoding="utf-8", errors="replace")
        assert "getSecret" in smali
        assert "flag{headless-re}" in smali

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
