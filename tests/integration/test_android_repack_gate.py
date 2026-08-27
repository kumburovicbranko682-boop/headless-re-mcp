"""Android repackaging gate: decode -> rebuild -> sign -> it still parses.

The static gate proves we can read an APK; this proves the write side of the
Android track -- that apktool can take the committed fixture apart into smali,
put it back together, apksigner can sign the rebuild, and androguard can still
open the result. apktool and apksigner are user-provided JVM tools discovered on
PATH (``shutil.which``, same as the config does), so this skips honestly when
either is absent -- skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK = _PROJECT_ROOT / "fixtures" / "android" / "sample.apk"
_PKG = "com.headlessre.sample"


def _client() -> ApktoolClient:
    apktool = shutil.which("apktool")
    apksigner = shutil.which("apksigner")
    return ApktoolClient(
        Path(apktool) if apktool else None,
        Path(apksigner) if apksigner else None,
    )


def _make_keystore(path: Path) -> tuple[str, str]:
    keytool = shutil.which("keytool")
    if keytool is None:
        pytest.skip("keytool (JDK) not installed — repack Gate not run (skip != pass)")
    password, alias = "gatepass", "gatekey"
    result = subprocess.run(
        [
            keytool, "-genkeypair", "-keystore", str(path),
            "-storepass", password, "-keypass", password, "-alias", alias,
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
            "-dname", "CN=Headless RE Repack Gate",
        ],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("keytool could not create a keystore — repack Gate not run (skip != pass)")
    return password, alias


@pytest.mark.integration
def test_decode_rebuild_sign_roundtrip_stays_parseable(tmp_path: Path) -> None:
    client = _client()
    if not client.available:
        pytest.skip("apktool not installed — repack Gate not run (skip != pass)")
    if not client.signer_available:
        pytest.skip("apksigner not installed — repack Gate not run (skip != pass)")
    assert _APK.is_file(), f"fixture missing: {_APK}"

    decoded = tmp_path / "decoded"
    result = client.decode(_APK, decoded, timeout=300.0)
    # apktool must produce a manifest and at least one smali tree to edit.
    assert result["manifest"] is not None
    assert result["smali_dirs"], "no smali output to repack"
    assert (decoded / "AndroidManifest.xml").is_file()

    rebuilt = tmp_path / "rebuilt.apk"
    built = client.build(decoded, rebuilt, timeout=300.0)
    assert built["signed"] is False
    assert rebuilt.is_file() and built["size"] > 0

    keystore = tmp_path / "gate.keystore"
    password, alias = _make_keystore(keystore)
    signed = tmp_path / "signed.apk"
    result = client.sign(
        rebuilt, signed,
        keystore=keystore, keystore_password=password, key_alias=alias, timeout=300.0,
    )
    assert result["signed"] is True
    assert result["debug_keystore"] is False
    assert signed.is_file()

    # The whole point: a rebuilt, re-signed APK is still a real APK. androguard
    # (the android extra) re-opens it and the package identity survives.
    reopened = ApkClient().open(signed)
    assert reopened["package"] == _PKG


@pytest.mark.integration
def test_build_refuses_a_directory_that_is_not_a_decode_tree(tmp_path: Path) -> None:
    client = _client()
    if not client.available:
        pytest.skip("apktool not installed — repack Gate not run (skip != pass)")
    from headless_re_mcp.backends.apktool.client import ApktoolError

    bare = tmp_path / "not-a-decode"
    bare.mkdir()
    with pytest.raises(ApktoolError) as info:
        client.build(bare, tmp_path / "out.apk", timeout=60.0)
    assert info.value.code == "invalid_params"
