"""M11 Android APK live gate: androguard DEX analysis + apktool decode.

The androguard ``apk.*`` surface (open/classes/methods/strings/xrefs) and apktool
decode had no live coverage: every apk unit test mocks androguard (monkeypatching
``_parsed``) or asserts structured degradation, so an androguard whose 4.x API
drifted -- the 3->4 rewrite reshaped ``get_classes`` / ``is_external`` /
``get_xref_from`` / ``get_strings`` -- or an apktool whose decode output moved
would pass the whole suite while the real tools returned nothing usable. This
runs both against a tiny committed APK, ``fixtures/android/sample.apk``: a single
``com.example.gate.Sample`` class whose ``caller`` calls ``callee``, which
returns the marker string ``APK_GATE_MARKER_STRING``. The manifest declares the
``INTERNET`` permission, the APK ships a native ``lib/arm64-v8a/libgate.so``, and
the whole APK is v1 (JAR) signed with a self-signed ``CN=HeadlessRE Gate`` key,
so the manifest-side surface has something to find. androguard must list the
class, its methods, the marker string, resolve the caller->callee xref, decode
the binary manifest (package + main activity), read the declared permission,
enumerate the native ABI, and read the signing certificate back as a readable
DN; apktool must decode it back into a manifest plus a smali tree containing that
class. Each capability skips (skip != pass) when its backend is absent.

Fixture provenance: the smali is assembled into ``classes.dex`` by apktool 3.0.3
and the manifest is compiled to binary AXML by aapt2 linked against the android
framework; those, a minimal ``resources.arsc``, and a placeholder
``lib/arm64-v8a/libgate.so`` (a synthetic non-loadable stub, only ever listed by
name) are zipped into the APK, which is then jarsigner-signed with a throwaway
keytool RSA key (the committed ``.apk`` is the artifact; the keystore is not
kept). The readable sources are committed beside it as
``fixtures/android/sample.smali`` and ``fixtures/android/sample.AndroidManifest.xml``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK = _PROJECT_ROOT / "fixtures" / "android" / "sample.apk"
_CLASS = "com.example.gate.Sample"


@pytest.mark.integration
def test_m11_androguard_apk_surface() -> None:
    client = ApkClient()  # construction silences androguard's loguru flood
    if not client.available:
        pytest.skip("androguard not installed — APK Gate not run (skip != pass)")
    assert _APK.is_file(), f"fixture missing: {_APK}"

    opened = client.open(_APK)
    assert opened["opened"] is True
    assert opened["package"] == "com.example.gate"
    # open() summarises the manifest permission count and the native ABIs it walks
    # out of the lib/ entries; both are non-trivial on this fixture only because it
    # carries a permission and a native lib, so they pin those two reads at a glance.
    assert opened["permission_count"] == 1
    assert opened["native_abis"] == ["arm64-v8a"]

    # ApkClient silences androguard's DEBUG loguru flood on construction (~150
    # records per AnalyzeAPK, one per basic block). Prove a real analysis emits
    # no androguard records, so an unattended server's own logs are not buried.
    from loguru import logger

    origins: list[str] = []
    sink = logger.add(
        lambda message: origins.append(str(message.record["name"] or "")), level="TRACE"
    )
    try:
        classes = client.classes(_APK)
    finally:
        logger.remove(sink)
    assert not [name for name in origins if name.startswith("androguard")], origins

    assert any("Sample" in name for name in classes["classes"]), classes["classes"]

    methods = client.methods(_APK, _CLASS)
    names = {m["name"] for m in methods["methods"]}
    # caller/callee are the two methods the xref assertion below depends on.
    assert {"callee", "caller"} <= names, names

    strings = client.strings(_APK)
    assert any(
        "APK_GATE_MARKER_STRING" in value for value in strings["strings"]
    ), strings["strings"]

    # caller -> callee is a real invoke edge in the dex, so asking for callers of
    # callee must return caller. A wrong parse yields an empty caller list.
    xrefs = client.xrefs(_APK, "callee")
    assert xrefs["count"] >= 1
    assert any(
        caller["method"] == "caller" and "Sample" in caller["class"]
        for caller in xrefs["callers"]
    ), xrefs["callers"]

    # Manifest side: these use androguard's APK object (binary AXML decode plus
    # component queries), a different 4.x surface from the DEX analysis above.
    manifest = client.manifest(_APK)
    assert manifest["package"] == "com.example.gate"
    assert manifest["truncated"] is False
    assert "com.example.gate.MainActivity" in manifest["manifest_xml"]

    components = client.components(_APK)
    assert "com.example.gate.MainActivity" in components["activities"], components

    # permissions() and native_libs() are the remaining manifest-side reads: the
    # first parses <uses-permission> out of the AXML, the second walks the APK's
    # lib/<abi>/ entries. The fixture declares exactly INTERNET and ships one
    # arm64-v8a stub, so a drifted androguard that stopped reading either surface
    # (empty list) is caught here rather than in a mock that fabricates both.
    permissions = client.permissions(_APK)
    assert "android.permission.INTERNET" in permissions["permissions"], permissions
    assert "android.permission.INTERNET" in permissions["requested_permissions"], permissions

    native = client.native_libs(_APK)
    assert native["abis"] == ["arm64-v8a"], native
    assert any(
        name == "lib/arm64-v8a/libgate.so" for name in native["native_libs"]
    ), native["native_libs"]

    # certificates() reads the v1 (JAR) signature: get_signature_names for the
    # .RSA file and get_certificates for the asn1crypto x509 cert. The fixture is
    # jarsigner-signed with a self-signed CN=HeadlessRE Gate key, so a working
    # read must report v1_signed, name the .RSA, and -- the part a mock never
    # exercises -- render the subject as a readable DN rather than the
    # "<asn1crypto.x509.Name 0x..>" repr the old str(cert.subject) emitted.
    certs = client.certificates(_APK)
    assert certs["v1_signed"] is True, certs
    assert any(name.endswith(".RSA") for name in certs["signature_files"]), certs
    assert certs["certificates"], certs
    cert = certs["certificates"][0]
    assert "HeadlessRE Gate" in cert["subject"], cert
    assert "asn1crypto" not in cert["subject"], cert
    # serial and sha256 are the other two cert fields; pin them as readable JSON
    # scalars so an androguard that returns either as a non-string (bytes sha256,
    # an object serial) -- which would crash the MCP JSON serializer, not this
    # gate -- is caught here against the real cert.
    assert cert["serial"].isdigit(), cert
    assert isinstance(cert["sha256"], str) and cert["sha256"], cert


@pytest.mark.integration
def test_m11_apktool_decode(tmp_path: Path) -> None:
    client = ApktoolClient(getattr(Settings.load(), "apktool", None))
    if not client.available:
        pytest.skip("apktool not installed/configured — apktool Gate not run (skip != pass)")
    assert _APK.is_file(), f"fixture missing: {_APK}"

    decoded = client.decode(_APK, tmp_path / "decoded")
    assert decoded["manifest"] is not None
    assert decoded["smali_dirs"], decoded
    # The decoded smali tree must carry our class back out, proving baksmali ran
    # rather than only the manifest landing on disk.
    assert list((tmp_path / "decoded").rglob("Sample.smali")), "decoded tree has no Sample.smali"
