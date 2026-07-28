"""M4.5: predictable-imports fixture contract (static PE parse)."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.detection.pe import scan_pe

_PROJECT = Path(__file__).resolve().parents[2]
_EXPECTED_SUSPICIOUS = {
    "virtualalloc",
    "virtualprotect",
    "loadlibrarya",
    "getprocaddress",
}


@pytest.mark.parametrize(
    "relative",
    [
        Path("artifacts/fixtures-x64/predictable_imports_fixture.exe"),
        Path("artifacts/fixtures-x86/predictable_imports_fixture.exe"),
    ],
)
def test_predictable_imports_fixture_has_documented_apis(relative: Path) -> None:
    path = _PROJECT / relative
    if not path.is_file():
        pytest.skip(f"fixture not built: {path}")
    report = scan_pe(path)
    libs = {name.casefold() for name in report.pe.imports.libraries}
    assert any(name.startswith("kernel32") for name in libs)
    assert report.pe.imports.function_count >= 5
    seen = {name.casefold() for name in report.pe.imports.suspicious_apis}
    missing = sorted(_EXPECTED_SUSPICIOUS - seen)
    assert not missing, f"missing expected APIs: {missing}; have={sorted(seen)}"
