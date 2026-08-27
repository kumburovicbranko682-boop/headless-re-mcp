"""Android decompilation gate: jadx turns the fixture back into readable Java.

The static gate reads the DEX; this proves the decompilation path -- that jadx
exports the whole APK to Java and that a named class comes back with its real
source (the marker string and the call we compiled in). jadx is a user-provided
JVM tool discovered on PATH (``shutil.which``, same as the config does), so this
skips honestly when it is absent -- skip != pass.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK = _PROJECT_ROOT / "fixtures" / "android" / "sample.apk"
_PKG = "com.headlessre.sample"


def _client() -> JadxClient:
    jadx = shutil.which("jadx")
    return JadxClient(Path(jadx) if jadx else None)


@pytest.mark.integration
def test_export_sources_recovers_every_class(tmp_path: Path) -> None:
    client = _client()
    if not client.available:
        pytest.skip("jadx not installed — decompile Gate not run (skip != pass)")
    assert _APK.is_file(), f"fixture missing: {_APK}"

    result = client.export_sources(_APK, tmp_path / "src", timeout=300.0)
    assert result["java_file_count"] >= 4
    names = {Path(rel).name for rel in result["java_files"]}
    for expected in ("MainActivity.java", "Crypto.java", "SyncService.java", "BootReceiver.java"):
        assert expected in names, expected


@pytest.mark.integration
def test_decompile_one_class_returns_its_real_source(tmp_path: Path) -> None:
    client = _client()
    if not client.available:
        pytest.skip("jadx not installed — decompile Gate not run (skip != pass)")

    result = client.decompile(_APK, tmp_path / "one", f"{_PKG}.MainActivity", timeout=300.0)
    assert Path(result["path"]).name == "MainActivity.java"
    source = result["source"]
    # The marker string and the call we compiled in must survive decompilation.
    assert "HEADLESS_RE_SECRET_TOKEN" in source
    assert "secret" in source


@pytest.mark.integration
def test_decompile_rejects_an_unknown_class(tmp_path: Path) -> None:
    client = _client()
    if not client.available:
        pytest.skip("jadx not installed — decompile Gate not run (skip != pass)")
    from headless_re_mcp.backends.jadx.client import JadxError

    with pytest.raises(JadxError) as info:
        client.decompile(_APK, tmp_path / "miss", f"{_PKG}.NoSuchClass", timeout=300.0)
    assert info.value.code == "not_found"
