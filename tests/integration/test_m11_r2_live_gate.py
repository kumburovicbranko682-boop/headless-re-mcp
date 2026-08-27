"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _r2_fixture() -> Path | None:
    """A PE for r2 to map, preferring the Windows-built gate fixture.

    r2 is a portable static backend, so it analyses a PE the same way on
    Linux as on Windows. The primary fixture is generated on the Windows CI
    and is absent from a plain checkout; falling back to a committed PE keeps
    this gate a real pass on Linux instead of an always-skip that only ever
    exercised the backend on one platform.
    """
    primary = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if primary.is_file():
        return primary
    committed = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
    return committed if committed.is_file() else None


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _r2_fixture()
    if fixture is None:
        pytest.skip("no PE fixture available for r2 — live Gate not run (skip≠pass)")

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        assert item["address"].get("module") == fixture.name
