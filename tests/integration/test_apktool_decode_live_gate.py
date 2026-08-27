"""apktool decode/build live gate: real APK to smali and back.

The apktool line (``apk.decode`` / ``apk.repack``) had no live coverage at all:
its decode/build/sign methods only ran against mocks, so nothing ever proved
apktool turns a real APK into a smali tree and a decoded manifest, or that a
decoded tree rebuilds into a valid APK. apktool needs a real APK with binary
resources to do either, which a hand-zipped archive cannot provide.

The fixture ``fixtures/android/gate_sample.apk`` (built once with aapt2 + D8 and
committed) carries real binary AXML, a resources table and a ``classes.dex`` for
``com.example.MainActivity``. The gate decodes it -- asserting the smali for that
class carries its distinctive string and method -- then rebuilds the decoded
tree, asserting a valid APK comes back out. It covers decode and build; ``sign``
needs apksigner (a separate Android build tool) and is left out, stated here so
a green is not read as "the whole repack+sign flow is covered".

Skip != pass: the gate skips with a reason when apktool or a JRE is absent, and
runs for real when both are present. CI installs both, so a skip there is a
genuine regression rather than a bare machine.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "gate_sample.apk"


def _apktool_path() -> Path | None:
    found = os.environ.get("HEADLESS_RE_APKTOOL") or shutil.which("apktool")
    if not found:
        return None
    path = Path(found)
    return path if path.is_file() else None


@pytest.mark.integration
def test_apktool_decodes_and_rebuilds_a_real_apk(tmp_path: Path) -> None:
    apktool = _apktool_path()
    if apktool is None:
        pytest.skip("apktool not installed/configured — decode Gate not run (skip != pass)")
    if shutil.which("java") is None:
        pytest.skip("no JRE for apktool — decode Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"

    client = ApktoolClient(apktool=apktool)
    assert client.available

    decoded = tmp_path / "decoded"
    result = client.decode(_FIXTURE, decoded, timeout=300.0)
    # A real decode yields a smali tree, decoded resources and the manifest.
    assert result["smali_dirs"], "apktool produced no smali directories"
    assert result["has_resources"] is True
    manifest = Path(result["manifest"]).read_text(encoding="utf-8")
    assert "com.example.gate" in manifest
    assert "com.example.MainActivity" in manifest

    # The class's smali must be real disassembly: its string and method survive.
    smali_files = list(decoded.rglob("MainActivity.smali"))
    assert smali_files, "MainActivity was not disassembled to smali"
    smali = smali_files[0].read_text(encoding="utf-8")
    assert "ANDROGUARD_APK_MARKER" in smali
    assert "addNumbers" in smali

    # build: the decoded tree must rebuild into a valid (zip) APK.
    rebuilt = tmp_path / "rebuilt.apk"
    built = client.build(decoded, rebuilt, timeout=300.0)
    assert built["size"] > 0
    assert rebuilt.is_file()
    assert zipfile.is_zipfile(rebuilt), "apktool build did not produce a valid APK"
