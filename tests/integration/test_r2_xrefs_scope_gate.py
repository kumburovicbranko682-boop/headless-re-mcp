"""r2.xrefs scope gate: prove xrefs are scoped to the address, not the binary.

Regression proof for the axj -> axtj fix. ``axj`` ignored the ``@`` seek and
returned r2's entire cross-reference table (capped at 4096) for *any* address;
``axtj`` returns the references *to* the queried address. With a PE we authored
-- ``gate_add`` is called only by ``gate_compute``, which is called only by
``main`` -- the correct answer for ``gate_add`` is exactly one CALL, and the
global table has far more rows, so a scoped result is unmistakable.

Needs radare2 plus a mingw-w64 cross-compiler to build the fixture; skips loudly
("skip != pass") when either is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

pytestmark = pytest.mark.integration

_FIXTURE_C = r"""
#include <stdio.h>
__attribute__((noinline)) int gate_add(int a, int b) { return a + b; }
__attribute__((noinline)) int gate_compute(int x) { return gate_add(x, 7); }
int main(void) {
    printf("%d\n", gate_compute(35));
    return 0;
}
"""


@pytest.fixture(scope="module")
def _pe() -> Iterator[Path]:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — r2.xrefs scope gate not run (skip != pass)")
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if cc is None:
        pytest.skip("no mingw-w64 cross-compiler to build the PE — skip != pass")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "fixture.c"
        src.write_text(_FIXTURE_C)
        exe = Path(tmp) / "scope_fixture.exe"
        proc = subprocess.run([cc, "-O0", "-o", str(exe), str(src)], capture_output=True)
        if proc.returncode != 0 or not exe.is_file():
            pytest.skip(f"mingw-w64 could not build the PE — skip != pass: {proc.stderr[:200]!r}")
        yield exe


def _va_of(service: AnalysisService, session_id: str, name: str) -> tuple[int, int]:
    """Return (va of the named function, total analysed function count)."""
    funcs = service.r2_functions(session_id, timeout=90.0)
    assert funcs.ok, funcs.error
    for item in funcs.data["items"]:
        if name in str(item.get("name", "")):
            return item["address"]["va"], funcs.data["count"]
    raise AssertionError(f"{name} not among analysed functions: {funcs.data['count']}")


def test_r2_xrefs_returns_only_the_callers_of_the_address(_pe: Path) -> None:
    service = AnalysisService()
    created = service.create_session(str(_pe))
    assert created.ok, created.error
    session_id = created.data["session"]["id"]
    try:
        add_va, function_count = _va_of(service, session_id, "gate_add")

        xrefs = service.r2_xrefs(session_id, add_va, timeout=90.0)
        assert xrefs.ok, xrefs.error
        assert xrefs.data["parsed"] is True
        rows = xrefs.data["items"]

        # Scoped, not the global table: gate_add has a single caller. The old
        # axj answered with the whole binary's refs (many more than there are
        # functions), so bounding well below the function count is decisive.
        assert 1 <= xrefs.data["count"] <= 4, xrefs.data
        assert xrefs.data["count"] < function_count, (xrefs.data["count"], function_count)

        # ...and that caller is gate_compute calling gate_add.
        calls = [r for r in rows if str(r.get("type")) == "CALL"]
        assert calls, rows
        assert any("gate_add" in str(r.get("refname", "")) for r in calls), rows
        assert any("gate_compute" in str(r.get("fcn_name", "")) for r in calls), rows
        assert any("from_address" in r or "address" in r for r in calls), rows

        # The queried target rides on the top-level address, not the rows.
        assert xrefs.data["address_va"] == add_va
        assert xrefs.data["address"]["va"] == add_va
    finally:
        service.close_all()


def test_r2_xrefs_walks_one_edge_up_the_call_chain(_pe: Path) -> None:
    service = AnalysisService()
    created = service.create_session(str(_pe))
    assert created.ok, created.error
    session_id = created.data["session"]["id"]
    try:
        compute_va, _ = _va_of(service, session_id, "gate_compute")
        xrefs = service.r2_xrefs(session_id, compute_va, timeout=90.0)
        assert xrefs.ok, xrefs.error
        # gate_compute is called only by main -- again scoped to this address.
        assert 1 <= xrefs.data["count"] <= 4, xrefs.data
        assert any(
            "main" in str(r.get("fcn_name", "")) and str(r.get("type")) == "CALL"
            for r in xrefs.data["items"]
        ), xrefs.data["items"]
    finally:
        service.close_all()
