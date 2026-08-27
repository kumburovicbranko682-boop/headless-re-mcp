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
class, its methods, the marker string, resolve the caller->callee xref both
ways and the methods that reference the marker string, disassemble a method's
Dalvik bytecode, decode
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

import datetime
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

    # The class-name filter runs against the real DEX: a case-insensitive
    # substring keeps the Sample class and flags the narrowing, while a needle in
    # no class name yields an empty, honest list (filtered, not the whole DEX).
    sample_only = client.classes(_APK, contains="sample")
    assert sample_only["filtered"] is True
    assert sample_only["total"] >= 1
    assert all("sample" in name.casefold() for name in sample_only["classes"])
    miss_classes = client.classes(_APK, contains="no-such-class-marker")
    assert miss_classes["classes"] == []
    assert miss_classes["filtered"] is True

    methods = client.methods(_APK, _CLASS)
    names = {m["name"] for m in methods["methods"]}
    # caller/callee are the two methods the xref assertion below depends on.
    assert {"callee", "caller"} <= names, names

    strings = client.strings(_APK)
    assert any(
        "APK_GATE_MARKER_STRING" in value for value in strings["strings"]
    ), strings["strings"]

    # The string filter runs against the real DEX too: a substring of the marker
    # keeps it and flags filtered, so an agent can find a hardcoded URL/key
    # without paging every constant.
    marker_only = client.strings(_APK, contains="MARKER")
    assert marker_only["filtered"] is True
    assert any("MARKER" in value for value in marker_only["strings"]), marker_only["strings"]

    # caller -> callee is a real invoke edge in the dex, so asking for callers of
    # callee must return caller. A wrong parse yields an empty caller list.
    xrefs = client.xrefs(_APK, "callee")
    assert xrefs["direction"] == "callers"
    assert xrefs["count"] >= 1
    assert any(
        caller["method"] == "caller" and "Sample" in caller["class"]
        for caller in xrefs["callers"]
    ), xrefs["callers"]

    # The other direction of the same edge: asking for callees of caller must
    # return callee, read from androguard's get_xref_to (a different 4.x call than
    # get_xref_from above). This answers under callees, not callers, and echoes
    # the direction -- a drifted xref-to that returned nothing is caught here.
    callees = client.xrefs(_APK, "caller", direction="callees")
    assert callees["direction"] == "callees"
    assert "callers" not in callees
    assert callees["count"] >= 1
    assert any(
        callee["method"] == "callee" and "Sample" in callee["class"]
        for callee in callees["callees"]
    ), callees["callees"]

    # String xrefs close the loop that apk.strings only opens: the marker string
    # is returned in the const-string that callee() hands back, so asking who
    # references APK_GATE_MARKER_STRING must name callee. This reads a third 4.x
    # surface -- StringAnalysis.get_xref_from, distinct from the method xref-from
    # / xref-to above -- so a drift that stopped resolving string edges (empty
    # list) is caught here rather than in a unit mock.
    string_refs = client.string_xrefs(_APK, "APK_GATE_MARKER_STRING")
    assert string_refs["match"] == "exact"
    assert string_refs["strings_matched"] >= 1
    assert string_refs["count"] >= 1
    assert any(
        row["method"] == "callee" and "Sample" in row["class"]
        for row in string_refs["xrefs"]
    ), string_refs["xrefs"]
    assert all(
        row["string"] == "APK_GATE_MARKER_STRING" for row in string_refs["xrefs"]
    ), string_refs["xrefs"]
    # A substring query for the marker resolves the same edge, proving contains
    # mode matches the whole constant it is embedded in, not just an exact hit.
    contains_refs = client.string_xrefs(_APK, "MARKER", contains=True)
    assert contains_refs["match"] == "contains"
    assert any(
        row["method"] == "callee" and "MARKER" in row["string"]
        for row in contains_refs["xrefs"]
    ), contains_refs["xrefs"]

    # Disassembly reads the method's Dalvik bytecode straight from androguard --
    # no jadx (Java) or apktool (baksmali), which may be absent -- so it exercises
    # the EncodedMethod.get_instructions path the xref tools never touch. callee
    # loads the marker with a const-string and returns it; caller invokes callee.
    # A drifted disassembler that returned nothing (empty instructions) is caught
    # here against the real dex, not a mock.
    callee_body = client.disassemble(_APK, _CLASS, "callee")
    assert callee_body["descriptor"] == "()Ljava/lang/String;", callee_body
    assert callee_body["count"] >= 2, callee_body
    mnemonics = [ins["mnemonic"] for ins in callee_body["instructions"]]
    assert any("const-string" in m for m in mnemonics), callee_body["instructions"]
    assert any(
        "APK_GATE_MARKER_STRING" in ins["operands"]
        for ins in callee_body["instructions"]
    ), callee_body["instructions"]
    # addr is the code-unit offset, so the first instruction sits at 0.
    assert callee_body["instructions"][0]["addr"] == 0, callee_body
    assert callee_body["overloads"] == ["()Ljava/lang/String;"], callee_body

    caller_body = client.disassemble(_APK, _CLASS, "caller")
    assert any(
        "invoke" in ins["mnemonic"] and "callee" in ins["operands"]
        for ins in caller_body["instructions"]
    ), caller_body["instructions"]

    # Manifest side: these use androguard's APK object (binary AXML decode plus
    # component queries), a different 4.x surface from the DEX analysis above.
    manifest = client.manifest(_APK)
    assert manifest["package"] == "com.example.gate"
    assert manifest["truncated"] is False
    assert "com.example.gate.MainActivity" in manifest["manifest_xml"]
    # The fixture's <application> declares neither debuggable nor allowBackup,
    # so a working read reports both as None (not declared) -- exercising the
    # real get_attribute_value path that returns None for an absent attribute,
    # and pinning that None (never False) is what the field promises.
    assert manifest["debuggable"] is None, manifest
    assert manifest["allow_backup"] is None, manifest
    # Same for the network-posture fields: the fixture declares no
    # usesCleartextTraffic and ships no Network Security Config, so both read as
    # None off the real manifest -- proving the get_attribute_value path returns
    # None for an absent attribute rather than a fabricated False/empty string.
    assert manifest["uses_cleartext_traffic"] is None, manifest
    assert manifest["network_security_config"] is None, manifest

    components = client.components(_APK)
    assert "com.example.gate.MainActivity" in components["activities"], components
    # The exported subset is computed off the real decoded manifest, not a crafted
    # tree: the fixture's MainActivity declares no intent-filter and no
    # android:exported, so it is not reachable by other apps and every exported
    # group must be empty. A drifted read that fabricated an export (or crashed on
    # the real manifest and blanked the field) is caught here, not in unit mocks.
    exported = components["exported"]
    assert set(exported) == {"activities", "services", "receivers", "providers"}, exported
    assert "com.example.gate.MainActivity" not in exported["activities"], exported
    assert all(names == [] for names in exported.values()), exported

    # intent_filters walks the same decoded manifest for the IPC/deep-link
    # surface. This fixture's MainActivity declares no intent-filter, so a
    # working read returns an empty component list and total 0 off the real AXML
    # decode -- proving the walk runs and degrades honestly (empty, not crash) on
    # a manifest with nothing to find, the same tier as the exported check above.
    # The populated shape (actions/categories/data + the deep_link flag) is
    # covered against crafted manifests in test_apk_intent_filters.py.
    intents = client.intent_filters(_APK)
    assert intents["components"] == [], intents
    assert intents["total"] == 0, intents
    assert intents["scan_capped"] is False, intents

    # permissions() and native_libs() are the remaining manifest-side reads: the
    # first parses <uses-permission> out of the AXML, the second walks the APK's
    # lib/<abi>/ entries. The fixture declares exactly INTERNET and ships one
    # arm64-v8a stub, so a drifted androguard that stopped reading either surface
    # (empty list) is caught here rather than in a mock that fabricates both.
    permissions = client.permissions(_APK)
    assert "android.permission.INTERNET" in permissions["permissions"], permissions
    assert "android.permission.INTERNET" in permissions["requested_permissions"], permissions
    # Protection levels are read from androguard's real AOSP permission DB, not a
    # mock: INTERNET is a "normal" permission, so it resolves to that level and is
    # not in the dangerous subset. The fixture declares no <permission> of its own.
    assert permissions["protection_levels"].get("android.permission.INTERNET") == "normal", (
        permissions
    )
    assert permissions["dangerous"] == [], permissions
    assert permissions["custom_permissions"] == [], permissions

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
    # The fixture is jarsigner (v1/JAR) signed only, so the scheme flags read
    # against the real signing block must be v1-only: signed True (some scheme
    # covers it), but v2 and v3 both explicitly False -- not null, which would
    # mean androguard could not parse the signing block on this host.
    assert certs["signed"] is True, certs
    assert certs["v2_signed"] is False, certs
    assert certs["v3_signed"] is False, certs
    # not_before/not_after come off the real asn1crypto cert as tz-aware
    # datetimes the JSON layer cannot encode; a working read renders both to
    # parseable ISO-8601 strings with not_after strictly after not_before.
    # Assert the ordering rather than the exact stamps so regenerating the
    # fixture's throwaway key does not break the gate.
    not_before = datetime.datetime.fromisoformat(cert["not_before"])
    not_after = datetime.datetime.fromisoformat(cert["not_after"])
    assert not_after > not_before, cert


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
