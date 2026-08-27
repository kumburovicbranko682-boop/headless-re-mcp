"""apktool live gate: real APK repack (build), the write half of the round-trip.

``test_apk_apktool_decode_gate`` covers ``apktool d`` against a real APK, but the
rebuild path (``apktool b`` behind ``ApktoolClient.build`` / ``apk.repack``) has
no live coverage -- and it is just as version-sensitive: the ``b`` invocation, the
"looks like a decode output" guard, or the produced APK layout could drift across
apktool releases (aapt2 is bundled), and every fake-based unit test would still
pass. A rebuild that silently stops producing a loadable APK is the runtime-only
class of break this fixture set exists to catch.

This gate discovers apktool exactly as ``config.py`` does (``HEADLESS_RE_APKTOOL``
or ``apktool`` on PATH), decodes the committed real APK, rebuilds it with
``ApktoolClient.build``, and then re-parses the *rebuilt* APK with androguard to
prove the round-trip preserved a loadable app -- same package, class, and methods.
Skipped when apktool or the ``android`` extra is absent; skip is not pass.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient

_FIXTURE_APK = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "fixture.apk"
_CLASS_SMALI = "Lcom/example/fixture/MainActivity;"
_CLASS_DOTTED = "com.example.fixture.MainActivity"


def _discover_apktool() -> Path | None:
    # The same resolution order config.py uses to populate settings.apktool.
    candidate = (
        os.environ.get("HEADLESS_RE_APKTOOL")
        or shutil.which("apktool")
        or shutil.which("apktool.bat")
    )
    return Path(candidate) if candidate else None


@pytest.mark.integration
def test_apktool_repacks_a_real_apk(tmp_path: Path) -> None:
    apktool = _discover_apktool()
    if apktool is None or not apktool.is_file():
        pytest.skip("apktool not installed — apktool repack Gate not run (skip != pass)")
    if not ApkClient().available:
        pytest.skip("androguard not installed — cannot verify the rebuild (skip != pass)")
    if not _FIXTURE_APK.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_APK}")

    client = ApktoolClient(apktool=apktool)
    assert client.available

    decoded = tmp_path / "decoded"
    client.decode(_FIXTURE_APK, decoded, timeout=180.0)
    assert (decoded / "AndroidManifest.xml").is_file()

    rebuilt = tmp_path / "rebuilt.apk"
    built = client.build(decoded, rebuilt, timeout=180.0)

    # build returns an unsigned APK on disk and says so -- installing it needs a
    # separate sign step, which the envelope must not silently claim to have done.
    assert built["signed"] is False
    assert "sign" in built["note"].lower()
    assert Path(built["apk"]) == rebuilt
    assert rebuilt.is_file()
    assert built["size"] == rebuilt.stat().st_size > 0

    # The rebuilt APK must still be a loadable app: androguard re-parses the
    # manifest and DEX round-tripped through decode+build with the app intact.
    apk = ApkClient()
    opened = apk.open(rebuilt)
    assert opened["package"] == "com.example.fixture"
    assert opened["version_name"] == "1.0"

    classes = apk.classes(rebuilt)
    assert classes["classes"] == [_CLASS_SMALI]

    methods = apk.methods(rebuilt, _CLASS_DOTTED)
    names = {entry["name"] for entry in methods["methods"]}
    assert {"<init>", "decryptSecret", "main"} <= names

    strings = apk.strings(rebuilt)
    assert "s3cr3t-flag-value" in strings["strings"]
