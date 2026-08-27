"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building APKs in a temp dir. A
deliberately invalid archive proves classification, stdlib metadata, and safe
degradation on a bare machine; a second, genuinely androguard-parseable APK
(real binary manifest plus a real compiled ``classes.dex``, built by
``_apk_fixture``) exercises the androguard success path -- package, version,
permissions, every component type, and the DEX code surface (classes, methods,
strings, xrefs) -- skipping only where the ``android`` extra is absent. When
jadx or apktool are configured, further gates decompile that same DEX back to
Java, disassemble it to smali, and run the decode -> repack -> sign loop to
rebuild a re-openable, apksigner-signed APK -- asserting the class, its methods,
and an embedded constant come back out, and that the rebuilt/signed archive
re-opens under androguard. Parts that need a real device / adbutils are asserted
only for a structured envelope, never a crash (skip != pass for the live-device
parts).
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from _apk_fixture import EXPECTED, build_valid_apk

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _build_synthetic_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        # Minimal (not AXML-valid) manifest is enough for stdlib classification.
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return path


@pytest.mark.integration
def test_android_session_classification_and_metadata(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")

    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        meta = session["metadata"]["apk"]
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True

        session_id = session["id"]

        # androguard opens a real APK; on the synthetic archive it must still
        # answer with a structured envelope rather than raising.
        opened = service.apk_open(session_id)
        assert isinstance(opened.ok, bool)
        assert opened.ok or opened.error is not None

        # Device enumeration degrades cleanly when adbutils / adb is absent.
        listed = service.device_list()
        assert isinstance(listed.ok, bool)
        assert listed.ok or listed.error is not None

        # Frida device enumeration returns an envelope (frida may be present).
        devices = service.frida_devices()
        assert isinstance(devices.ok, bool)
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_static_reads_a_real_manifest(tmp_path: Path) -> None:
    """Exercise the androguard success path against a real binary manifest.

    The synthetic-APK test above only proves the adapter degrades on garbage.
    This one hands androguard a valid AXML manifest and asserts it reads the
    package, version, permissions, and every component type back out -- the path
    that silently breaks when androguard renames an accessor between releases.
    Skips (skip != pass) where the ``android`` extra is not installed.
    """
    pytest.importorskip("androguard")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == EXPECTED["package"]
        assert str(opened.data["version_name"]) == EXPECTED["version_name"]
        assert str(opened.data["version_code"]) == EXPECTED["version_code"]
        assert opened.data["main_activity"] == EXPECTED["main_activity"]
        assert opened.data["permission_count"] == len(EXPECTED["permissions"])
        assert set(opened.data["native_abis"]) == EXPECTED["native_abis"]

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert set(permissions.data["permissions"]) == EXPECTED["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert set(components.data["activities"]) == EXPECTED["activities"]
        assert set(components.data["services"]) == EXPECTED["services"]
        assert set(components.data["receivers"]) == EXPECTED["receivers"]
        assert set(components.data["providers"]) == EXPECTED["providers"]
        assert components.data["main_activity"] == EXPECTED["main_activity"]

        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert set(native.data["abis"]) == EXPECTED["native_abis"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert EXPECTED["package"] in manifest.data["manifest_xml"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_static_reads_dex_code(tmp_path: Path) -> None:
    """Exercise androguard's DEX analysis against a real compiled classes.dex.

    The manifest test above proves the resource surface; this one proves the
    code surface -- the path that needs a genuine DEX and that mocked unit tests
    (which stub androguard's analysis) cannot reach. It asserts the class, its
    methods, an embedded string, and an intra-DEX xref (run -> greet) all read
    back out. Skips (skip != pass) where the ``android`` extra is not installed.
    """
    pytest.importorskip("androguard")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert EXPECTED["dex_class"] in classes.data["classes"]

        methods = service.apk_methods(session_id, EXPECTED["dex_class"])
        assert methods.ok, methods.error
        assert {m["name"] for m in methods.data["methods"]} == EXPECTED["dex_methods"]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert any(EXPECTED["dex_string"] in s for s in strings.data["strings"]), (
            strings.data["strings"]
        )

        # run() calls greet(); androguard must see that intra-DEX cross-reference.
        xrefs = service.apk_xrefs(session_id, EXPECTED["dex_xref_target"])
        assert xrefs.ok, xrefs.error
        callers = {(c["class"], c["method"]) for c in xrefs.data["callers"]}
        assert (EXPECTED["dex_class"], EXPECTED["dex_xref_caller"]) in callers, xrefs.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_jadx_decompiles_dex_to_java(tmp_path: Path) -> None:
    """Exercise the jadx decompiler end to end against the real classes.dex.

    androguard reads the DEX at the bytecode level; jadx is the separate
    subprocess adapter that turns it back into Java, and nothing else in the
    suite runs a real jadx (unit tests stub the CLI). With a genuine DEX in the
    fixture we can prove ``apk.decompile`` shells out, jadx produces sources,
    and the named class reads back with its methods and constant -- catching a
    broken jadx invocation or output-layout change that mocks cannot. Skips
    (skip != pass) where jadx is not configured on the host.
    """
    pytest.importorskip("androguard")
    if Settings.load().jadx is None:
        pytest.skip("jadx not configured — Android decompile Gate not run (skip != pass)")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        result = service.apk_decompile(session_id, EXPECTED["dex_class_dotted"])
        assert result.ok, result.error
        assert result.data["class_name"] == EXPECTED["dex_class_dotted"]
        source = result.data["source"]
        # A real decompile reproduces the class, its declared methods, and the
        # embedded constant -- not just an empty stub.
        assert "class Hello" in source, source
        assert EXPECTED["dex_string"] in source, source
        for method in EXPECTED["dex_source_methods"]:
            assert f"{method}(" in source, (method, source)
        # run()'s body calls the other two methods; seeing those calls proves
        # jadx reconstructed method bodies, not merely signatures.
        assert "greet(" in source and "add(" in source, source
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apktool_baksmalis_dex(tmp_path: Path) -> None:
    """Exercise apktool's baksmali path end to end against the real classes.dex.

    apktool is the third Android adapter (androguard reads bytecode, jadx emits
    Java, apktool disassembles to smali and unpacks resources), and unit tests
    stub its CLI. ``no_resources=True`` runs ``apktool d -r`` so the decode needs
    only the real DEX, not a full resources.arsc: it must shell out, land a smali
    tree, and disassemble the class with its field, methods, and the intra-class
    call that a signatures-only stub could not show. Skips (skip != pass) where
    apktool is not configured on the host.
    """
    if Settings.load().apktool is None:
        pytest.skip("apktool not configured — Android baksmali Gate not run (skip != pass)")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, no_resources=True)
        assert decoded.ok, decoded.error
        assert "smali" in decoded.data["smali_dirs"], decoded.data
        decoded_dir = Path(decoded.data["decoded_dir"])
        matches = list(decoded_dir.rglob("Hello.smali"))
        assert matches, sorted(str(p) for p in decoded_dir.rglob("*.smali"))
        smali = matches[0].read_text(encoding="utf-8", errors="replace")

        assert f".class public {EXPECTED['dex_class']}" in smali, smali
        assert EXPECTED["dex_string"] in smali, smali
        for method in EXPECTED["dex_source_methods"]:
            assert f".method public {method}(" in smali, (method, smali)
        # run() invokes greet(); the smali call site proves method bodies were
        # disassembled, not just their signatures.
        assert f"{EXPECTED['dex_class']}->{EXPECTED['dex_xref_target']}(" in smali, smali
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apktool_repack_roundtrip(tmp_path: Path) -> None:
    """Prove the decode -> repack loop rebuilds a real, re-openable APK.

    The gates above only read APKs; this exercises the write side -- apktool's
    ``b`` (build) path, which recompiles the smali back into a DEX and repackages
    it. Unit tests stub the build CLI, so nothing else proves apktool actually
    produces a valid archive. The rebuilt APK is fed back to androguard from a
    fresh session: reading its package out again is end-to-end proof that the
    repackage produced a genuine APK, not just some bytes on disk. Skips (skip
    != pass) where apktool or the ``android`` extra is absent.
    """
    pytest.importorskip("androguard")
    if Settings.load().apktool is None:
        pytest.skip("apktool not configured — Android repack Gate not run (skip != pass)")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        decoded = service.apk_decode(session_id, no_resources=True)
        assert decoded.ok, decoded.error

        repacked = service.apk_repack(session_id)
        assert repacked.ok, repacked.error
        # repack must not silently sign; that is apk.sign's job, and the contract
        # is that the rebuilt APK is unsigned so a caller cannot mistake it for
        # installable output.
        assert repacked.data["signed"] is False, repacked.data
        rebuilt = Path(repacked.data["apk"])
        assert zipfile.is_zipfile(rebuilt), rebuilt
        with zipfile.ZipFile(rebuilt) as archive:
            names = set(archive.namelist())
        assert "classes.dex" in names, names
        assert "AndroidManifest.xml" in names, names

        # The real test: androguard opens the rebuilt APK as a fresh target and
        # reads the same package back. A corrupt repackage fails here.
        reopened_id = service.create_session(str(rebuilt)).data["session"]["id"]
        reopened = service.apk_open(reopened_id)
        assert reopened.ok, reopened.error
        assert reopened.data["package"] == EXPECTED["package"]
    finally:
        service.close_all()


def _ensure_debug_keystore() -> bool:
    """Create the standard Android debug keystore if absent; report usability.

    ``apk.sign`` defaults to ``~/.android/debug.keystore`` (alias
    ``androiddebugkey``, password ``android``) -- the well-known keystore every
    Android build tool auto-creates. Making it here when missing keeps the gate
    self-contained on a fresh runner without depending on a prior SDK install.
    """
    keystore = Path.home() / ".android" / "debug.keystore"
    if keystore.is_file():
        return True
    keytool = shutil.which("keytool")
    if keytool is None:
        return False
    keystore.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            keytool, "-genkeypair", "-v", "-keystore", str(keystore),
            "-storepass", "android", "-keypass", "android",
            "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000", "-dname", "CN=Android Debug,O=Android,C=US",
        ],
        capture_output=True,
    )
    return completed.returncode == 0 and keystore.is_file()


@pytest.mark.integration
def test_android_apktool_sign_produces_a_signed_apk(tmp_path: Path) -> None:
    """Close the modify loop: decode -> repack -> sign yields a signed APK.

    ``apk.repack`` deliberately leaves the rebuilt APK unsigned, so on its own it
    is not installable. ``apk.sign`` is the final step, and it is the only one
    that shells out to apksigner -- unit tests stub that CLI, so nothing else
    proves a real signature comes out. The service verifies with ``apksigner
    verify`` before returning ``signed=True``, and here androguard re-opens the
    signed APK as a fresh target: a v1 (JAR) signature really lands in META-INF
    and the package still reads. Skips (skip != pass) where apktool, apksigner,
    the ``android`` extra, or a usable debug keystore is absent.
    """
    pytest.importorskip("androguard")
    settings = Settings.load()
    if settings.apktool is None:
        pytest.skip("apktool not configured — Android sign Gate not run (skip != pass)")
    if settings.apksigner is None:
        pytest.skip("apksigner not configured — Android sign Gate not run (skip != pass)")
    if not _ensure_debug_keystore():
        pytest.skip("no debug keystore and no keytool — Android sign Gate not run (skip != pass)")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]
        assert service.apk_decode(session_id, no_resources=True).ok
        assert service.apk_repack(session_id).ok

        signed = service.apk_sign(session_id)
        assert signed.ok, signed.error
        # signed=True is only returned after the service's own apksigner-verify
        # step passes, so this already means the signature validates.
        assert signed.data["signed"] is True, signed.data
        assert signed.data["debug_keystore"] is True, signed.data
        out = Path(signed.data["apk"])
        assert zipfile.is_zipfile(out), out
        with zipfile.ZipFile(out) as archive:
            names = archive.namelist()
        # The v1 signature is a .RSA/.SF pair under META-INF; a cosmetic "sign"
        # that copied bytes without signing would not produce it.
        assert any(n.startswith("META-INF/") and n.endswith(".RSA") for n in names), names
        assert any(n.startswith("META-INF/") and n.endswith(".SF") for n in names), names

        # androguard re-opens the signed APK and still reads the package: the
        # signature did not corrupt the archive.
        reopened_id = service.create_session(str(out)).data["session"]["id"]
        reopened = service.apk_open(reopened_id)
        assert reopened.ok, reopened.error
        assert reopened.data["package"] == EXPECTED["package"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_pe_tool_rejects_apk_session(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        session_id = created.data["session"]["id"]
        # A PE-only tool must refuse an APK session with target_mismatch, not crash.
        opened = service.open_static(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code in {"target_mismatch", "invalid_request", "backend_unavailable"}
    finally:
        service.close_all()
