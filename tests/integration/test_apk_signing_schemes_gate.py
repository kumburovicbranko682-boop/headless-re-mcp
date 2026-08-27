"""Live gate: describe_apk's v2/v3 detection against real apksigner output.

``describe_apk`` reads the APK Signing Block with a stdlib-only parser so
session creation reports whether a package is signed with APK Signature Scheme
v2/v3, not just the legacy v1 (``META-INF/*.RSA``) marker. Every unit test for
that parser hand-assembles the block; nothing here proves the ids and layout
match what a real signer writes. This gate signs the same base APK four ways
with the genuine ``apksigner`` (v1-only, v2-only, v3-only, v2+v3) and asserts
``describe_apk`` classifies each one exactly -- the case that matters most being
the v2-only package, which has no ``META-INF`` signature at all and was read as
unsigned before the parser existed.

skip != pass: with ``apksigner`` (from the Android build-tools) and ``keytool``
on PATH -- or ``HEADLESS_RE_APKSIGNER`` pointing at one -- the gate signs and
verifies for real; it only skips when those JRE/SDK tools are absent. No device,
emulator, pyaxml, or androguard is needed: apksigner signs a plain zip once it
is told the min-sdk version, and the parser is pure stdlib.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.session import describe_apk


def _find_apksigner() -> str | None:
    explicit = os.environ.get("HEADLESS_RE_APKSIGNER")
    if explicit and Path(explicit).exists():
        return explicit
    return shutil.which("apksigner")


def _find_keytool() -> str | None:
    return shutil.which("keytool")


_APKSIGNER = _find_apksigner()
_KEYTOOL = _find_keytool()
_SKIP = pytest.mark.skipif(
    not _APKSIGNER or not _KEYTOOL,
    reason="apksigner and keytool are required for the signing-scheme gate",
)

_STORE_PASS = "android"
_ALIAS = "gatekey"


def _make_keystore(path: Path) -> None:
    assert _KEYTOOL is not None
    subprocess.run(
        [
            _KEYTOOL,
            "-genkeypair",
            "-keystore",
            str(path),
            "-storepass",
            _STORE_PASS,
            "-keypass",
            _STORE_PASS,
            "-alias",
            _ALIAS,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "3650",
            "-dname",
            "CN=Gate, O=Test, C=US",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )


def _base_apk(path: Path) -> Path:
    # apksigner signs a zip; it needs no real AXML manifest once --min-sdk-version
    # is supplied, so a placeholder keeps the fixture stdlib-only.
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00placeholder")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
    return path


def _sign(src: Path, dst: Path, keystore: Path, *, v1: bool, v2: bool, v3: bool) -> None:
    assert _APKSIGNER is not None
    dst.write_bytes(src.read_bytes())
    result = subprocess.run(
        [
            _APKSIGNER,
            "sign",
            "--ks",
            str(keystore),
            "--ks-pass",
            f"pass:{_STORE_PASS}",
            "--key-pass",
            f"pass:{_STORE_PASS}",
            "--min-sdk-version",
            "21",
            "--max-sdk-version",
            "33",
            f"--v1-signing-enabled={'true' if v1 else 'false'}",
            f"--v2-signing-enabled={'true' if v2 else 'false'}",
            f"--v3-signing-enabled={'true' if v3 else 'false'}",
            "--v4-signing-enabled=false",
            str(dst),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"apksigner sign failed: {result.stderr or result.stdout}"


@_SKIP
def test_describe_apk_matches_real_apksigner_schemes(tmp_path: Path) -> None:
    keystore = tmp_path / "gate.jks"
    _make_keystore(keystore)
    base = _base_apk(tmp_path / "base.apk")

    # (v1, v2, v3) enabled at signing -> expected describe_apk classification.
    cases = {
        "v1only": ((True, False, False), (True, False, False)),
        "v2only": ((False, True, False), (False, True, False)),
        "v3only": ((False, False, True), (False, False, True)),
        "v2v3": ((False, True, True), (False, True, True)),
    }
    for label, (enabled, expected) in cases.items():
        signed = tmp_path / f"{label}.apk"
        v1, v2, v3 = enabled
        _sign(base, signed, keystore, v1=v1, v2=v2, v3=v3)
        info = describe_apk(signed)["apk"]
        got = (info["signed_v1"], info["signed_v2"], info["signed_v3"])
        assert got == expected, f"{label}: describe_apk said {got}, expected {expected}"

    # The unsigned base must read as signed by nothing -- no false positives.
    info = describe_apk(base)["apk"]
    assert (info["signed_v1"], info["signed_v2"], info["signed_v3"]) == (False, False, False)


@_SKIP
def test_v2_only_package_is_not_read_as_unsigned(tmp_path: Path) -> None:
    """The regression this parser exists for: a modern v2-only APK.

    Such a package carries no ``META-INF/*.RSA``, so the v1-only check reported
    it unsigned. The signing block must flip signed_v2 True while signed_v1
    stays False.
    """
    keystore = tmp_path / "gate.jks"
    _make_keystore(keystore)
    base = _base_apk(tmp_path / "base.apk")
    signed = tmp_path / "modern.apk"
    _sign(base, signed, keystore, v1=False, v2=True, v3=False)

    info = describe_apk(signed)["apk"]
    assert info["signed_v1"] is False, "fixture should have no v1 JAR signature"
    assert info["signed_v2"] is True, "v2-only package must not read as unsigned"


@_SKIP
def test_apk_certificates_scheme_flags_match_real_signer(tmp_path: Path) -> None:
    """The androguard-backed certificates() surface agrees on the real APK.

    describe_apk parses the signing block with stdlib; ApkClient.certificates()
    reports the same schemes through androguard. This proves both honesty
    surfaces against genuine apksigner output. Skips (without failing the gate)
    if androguard is not installed, since it is an optional dependency.
    """
    androguard = pytest.importorskip("androguard")
    assert androguard is not None
    from headless_re_mcp.backends.apk.client import ApkClient

    keystore = tmp_path / "gate.jks"
    _make_keystore(keystore)
    base = _base_apk(tmp_path / "base.apk")

    v2 = tmp_path / "v2.apk"
    _sign(base, v2, keystore, v1=False, v2=True, v3=False)
    v3 = tmp_path / "v3.apk"
    _sign(base, v3, keystore, v1=False, v2=False, v3=True)

    client = ApkClient()
    if not client.available:
        pytest.skip("androguard import present but ApkClient reports unavailable")

    v2_report = client.certificates(v2)
    assert v2_report["v1_signed"] is False
    assert v2_report["v2_signed"] is True
    assert v2_report["v3_signed"] is False

    v3_report = client.certificates(v3)
    assert v3_report["v3_signed"] is True
    assert v3_report["v2_signed"] is False
