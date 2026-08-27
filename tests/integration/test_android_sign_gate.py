"""Android signing gate: apktool build -> apksigner sign -> verify, end to end.

The android tools gate builds an APK and, where apksigner is absent, asserts the
signer degrades to capability_unavailable -- the negative half. Nothing proves
the positive: that ApktoolClient.sign actually produces a signed APK a verifier
accepts. This gate builds a framework-free APK, signs it with a keytool-made
keystore through ApktoolClient.sign, and then independently runs `apksigner
verify` on the output to confirm it really is signed (the client verifies too,
but an outside check keeps the assertion self-standing). It also pins the
keystore-not-found and missing-credentials contracts.

skip != pass: it skips honestly when apktool, apksigner or keytool is missing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.config import Settings

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.headlessre.gate">\n</manifest>\n'
)
# A framework-free manifest keeps apktool's bundled aapt2 from needing an
# installed android.jar; the MetaInfo header is what build reads back.
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"


def _make_keystore(dest: Path) -> Path | None:
    """Create a throwaway RSA keystore with keytool, or None when it is absent."""
    keytool = shutil.which("keytool")
    if keytool is None:
        return None
    keystore = dest / "gate.keystore"
    try:
        subprocess.run(
            [
                keytool, "-genkeypair", "-keystore", str(keystore),
                "-storepass", "gatepass", "-keypass", "gatepass",
                "-alias", "gatekey", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "365", "-dname", "CN=gate,O=test,C=US",
            ],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return keystore if keystore.is_file() else None


@pytest.mark.integration
def test_android_apksigner_signs_a_built_apk_and_verify_passes(tmp_path: Path) -> None:
    settings = Settings.load()
    client = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not client.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    if not client.signer_available or settings.apksigner is None:
        pytest.skip("apksigner not configured (HEADLESS_RE_APKSIGNER / PATH) — skip != pass")

    skeleton = tmp_path / "skeleton"
    skeleton.mkdir()
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")

    built = client.build(skeleton, tmp_path / "built.apk")
    built_apk = Path(built["apk"])
    assert built_apk.is_file()
    assert built["signed"] is False

    keystore = _make_keystore(tmp_path)
    if keystore is None:
        pytest.skip("no keytool (JDK) to make a keystore — sign Gate not run (skip != pass)")

    signed_apk = tmp_path / "signed.apk"
    result = client.sign(
        built_apk,
        signed_apk,
        keystore=keystore,
        keystore_password="gatepass",
        key_alias="gatekey",
    )
    # The client signs and then verifies internally; a returned signed=True means
    # apksigner accepted its own output.
    assert result["signed"] is True, result
    assert result["debug_keystore"] is False, result
    assert result["keystore"] == str(keystore), result
    assert signed_apk.is_file()
    # Signing wraps the archive with signature blocks, so it is larger than the
    # unsigned build.
    assert signed_apk.stat().st_size > built_apk.stat().st_size, result

    # Independent proof: run apksigner verify directly on the artifact.
    verify = subprocess.run(
        [str(settings.apksigner), "verify", "--verbose", str(signed_apk)],
        capture_output=True,
        timeout=60.0,
    )
    stdout = verify.stdout.decode("utf-8", errors="replace")
    assert verify.returncode == 0, verify.stderr.decode("utf-8", errors="replace")[:400]
    assert "Number of signers: 1" in stdout, stdout

    # Contract: a keystore path that does not exist fails closed with not_found,
    # not a raw launcher error.
    with pytest.raises(ApktoolError) as missing_ks:
        client.sign(
            built_apk,
            tmp_path / "nope.apk",
            keystore=tmp_path / "does-not-exist.keystore",
            keystore_password="x",
            key_alias="y",
        )
    assert missing_ks.value.code == "not_found"

    # Contract: a custom keystore with no password/alias is invalid_params,
    # refused before spawning apksigner.
    with pytest.raises(ApktoolError) as missing_creds:
        client.sign(built_apk, tmp_path / "nope2.apk", keystore=keystore)
    assert missing_creds.value.code == "invalid_params"
