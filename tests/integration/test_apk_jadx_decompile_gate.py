"""jadx live gate: real APK decompilation, not just structured degradation.

The Android RE gate only asserts that jadx-backed tools return an envelope
without crashing when jadx is absent; nothing drives jadx against a real APK.
jadx is a CLI whose flags and on-disk layout drift across releases (the class of
break that only shows up at runtime): ``--output-dir`` / ``--no-imports`` could
be renamed, or sources could stop landing under ``<out>/sources/``, and every
fake-based unit test would still pass.

This gate discovers jadx exactly as ``config.py`` does (``HEADLESS_RE_JADX`` or
``jadx`` on PATH), packs the committed real DEX into an APK, and drives the
JadxClient end to end -- mirroring ``test_m11_r2_live_gate`` which exercises its
client directly. Skipped when jadx is not installed; skip is not pass.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient

_FIXTURE_DEX = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "classes.dex"


def _discover_jadx() -> Path | None:
    # The same resolution order config.py uses to populate settings.jadx.
    candidate = (
        os.environ.get("HEADLESS_RE_JADX") or shutil.which("jadx") or shutil.which("jadx.bat")
    )
    return Path(candidate) if candidate else None


def _build_apk_with_real_dex(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.write(_FIXTURE_DEX, "classes.dex")
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return path


@pytest.mark.integration
def test_jadx_decompiles_a_real_apk(tmp_path: Path) -> None:
    jadx = _discover_jadx()
    if jadx is None or not jadx.is_file():
        pytest.skip("jadx not installed — jadx decompile Gate not run (skip != pass)")
    if not _FIXTURE_DEX.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_DEX}")

    client = JadxClient(executable=jadx)
    assert client.available
    apk = _build_apk_with_real_dex(tmp_path / "sample.apk")

    # export_sources: jadx must emit a Java tree under <out>/sources/. The one
    # class in the DEX lands as exactly one .java file; a layout drift (no
    # sources/ dir, or --output-dir renamed) would break this.
    exported = client.export_sources(apk, tmp_path / "out", timeout=180.0)
    assert exported["java_file_count"] == 1
    assert exported["sources_dir"] is not None
    assert exported["java_files"][0].endswith("Hello.java")

    # --no-imports is a distinct flag on the export path; keep it exercised so a
    # rename is caught, not just silently ignored.
    exported_ni = client.export_sources(apk, tmp_path / "out_ni", timeout=180.0, no_imports=True)
    assert exported_ni["java_file_count"] == 1

    # decompile: the recovered source must be the class the caller named and must
    # carry the real method and string constant, proving jadx actually decompiled
    # bytecode rather than the tool merely returning an empty envelope.
    result = client.decompile(apk, tmp_path / "out_one", "Hello", timeout=180.0)
    assert result["path"].endswith("Hello.java")
    assert result["truncated"] is False
    assert "decryptSecret" in result["source"]
    assert "s3cr3t-flag-value" in result["source"]
