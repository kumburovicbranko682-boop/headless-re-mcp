"""androguard manifest live gate: real binary-AXML facts through ApkClient.

The DEX-analysis gate covers ``apk.classes`` / ``methods`` / ``strings`` /
``xrefs`` from a bare classes.dex, but the manifest-level tools -- ``apk.open``,
``apk.manifest``, ``apk.permissions``, ``apk.components`` -- read the binary
AndroidManifest.xml (AXML), which a hand-zipped archive does not have. So those
four never parsed a real manifest; their output only came from mocks and the
synthetic-APK test that asserts merely "ok or an error".

Producing binary AXML needs the Android build tools, so the fixture
``fixtures/android/gate_sample.apk`` is built once and committed (like the PE
fixture under artifacts/). It was produced with::

    aapt2 link --manifest AndroidManifest.xml -I android.jar \
        --min-sdk-version 21 --target-sdk-version 34 -o base.apk
    # then javac + D8 (--release --min-api 21) a MainActivity into classes.dex
    # and add it to the archive

from a manifest declaring package ``com.example.gate`` (version 1.4 / code 7),
the ``INTERNET`` permission, and a launcher activity ``com.example.MainActivity``.
The gate asserts androguard decoded exactly those facts from the real AXML, so
it depends only on androguard -- no Android SDK, no emulator.

Skip != pass: the gate skips with a reason when androguard is absent and runs
for real when present. CI installs it, so a skip there is a genuine regression
rather than a bare machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "gate_sample.apk"


def _quiet_androguard() -> None:
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - logging quiet is best-effort
        pass


@pytest.mark.integration
def test_androguard_decodes_real_binary_manifest(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — manifest Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"
    _quiet_androguard()

    # open: identity fields decoded from the binary manifest.
    opened = client.open(_FIXTURE)
    assert opened["package"] == "com.example.gate"
    assert opened["version_name"] == "1.4"
    assert str(opened["version_code"]) == "7"
    assert opened["main_activity"] == "com.example.MainActivity"
    assert opened["permission_count"] == 1

    # permissions: the one declared uses-permission, by full name.
    permissions = client.permissions(_FIXTURE)
    assert "android.permission.INTERNET" in permissions["permissions"]

    # components: the launcher activity, and it is resolved as the main one.
    components = client.components(_FIXTURE)
    assert "com.example.MainActivity" in components["activities"]
    assert components["main_activity"] == "com.example.MainActivity"

    # manifest: AXML decoded back to text naming the same package and activity.
    manifest = client.manifest(_FIXTURE)
    xml = manifest["manifest_xml"]
    assert manifest["package"] == "com.example.gate"
    assert "com.example.gate" in xml
    assert "MainActivity" in xml
    assert "android.permission.INTERNET" in xml
