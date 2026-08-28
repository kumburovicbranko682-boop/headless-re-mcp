"""M11 r2 live gate: the r2.imports item fields the docs promise must exist.

The unit fakes for iij used to say ``lib``, and the tool description promised
a ``lib`` field -- but radare2 prints ``libname`` (measured on 5.5.0; rizin
matches). No test with a fake can catch a field the fake itself invents, so
this gate reads the real backend's output. skip≠pass when r2 is missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_m11_r2_live_imports_carry_libname_not_lib() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")

    payload = client.run(fixture, ["iij"], timeout=60.0)
    assert payload.get("parsed") is True
    items = payload.get("items", [])
    # The fixture imports the CRT and kernel32, so an empty list means the
    # command or the parse regressed, not that the binary has no imports.
    assert len(items) >= 1
    named = [item for item in items if item.get("name")]
    assert named, "no import carried a name"
    for item in named:
        assert "lib" not in item, "backend grew a lib field; update the r2.imports docs"
    assert any(
        isinstance(item.get("libname"), str) and item["libname"] for item in named
    ), "no import carried libname -- the documented field is missing from real output"
