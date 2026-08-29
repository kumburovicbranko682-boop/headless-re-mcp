"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_TWO_CALLERS_C = """
int helper(int x) { return x * 3 + 1; }
int main(void) { return helper(10) + helper(20); }
"""


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")

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


@pytest.mark.integration
def test_m11_r2_live_xrefs_are_scoped_to_the_requested_address(tmp_path: Path) -> None:
    """Every xref item touches the address asked about; callers are found.

    The regression this pins: ``axj @ addr`` (the command xrefs() used to
    build) lists the binary's entire xref database -- the seek does not
    filter it -- so a two-caller fixture answered every address with entry0,
    printf and section relocs, and zero of it was about the address asked.
    Only a live radare2 can catch a recurrence, because the bug lives in
    what the r2 command *means*, not in any code path a stub exercises.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler — live xref Gate not run (skip≠pass)")

    source = tmp_path / "two_callers.c"
    source.write_text(_TWO_CALLERS_C, encoding="utf-8")
    binary = tmp_path / "two_callers"
    built = subprocess.run(
        [compiler, "-O0", "-o", str(binary), str(source)],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if built.returncode != 0 or not binary.is_file():
        pytest.skip(f"fixture did not compile: {built.stderr.decode(errors='replace')[:200]}")

    funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    helper_va = next(
        (
            item["address"]["va"]
            for item in funcs.get("items", [])
            if str(item.get("name", "")).endswith("helper")
            and isinstance(item.get("address"), dict)
        ),
        None,
    )
    if helper_va is None:
        pytest.skip("this radare2 build did not name sym.helper — live xref Gate not run")

    xrefs = client.xrefs(binary, helper_va, timeout=60.0)
    assert xrefs.get("parsed") is True, xrefs.get("raw", "")[:500]
    items = xrefs.get("items", [])
    # Both call sites in main arrive as direction="to" entries...
    incoming = [item for item in items if item.get("direction") == "to"]
    assert len(incoming) >= 2, items
    # ...and nothing in the answer is about some other address. The old
    # whole-database dump fails here on its first entry.
    for item in items:
        assert item.get("from") == helper_va or item.get("to") == helper_va, item
