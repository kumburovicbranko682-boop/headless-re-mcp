"""PE r2 service gate: prove the whole radare2 tool surface on a real PE.

The existing M11 r2 gate opens one PE fixture and checks that ``r2.functions``
returns address-mapped entries -- one tool, through the low-level ``R2Client``.
This gate drives the *service* layer end to end (``r2.open`` / ``info`` /
``functions`` / ``strings`` / ``imports`` / ``exports`` / ``disasm`` / ``xrefs``)
the way an MCP client would, against a genuine 64-bit PE.

Fixture resolution keeps the gate runnable in two very different places:

* If the committed reference fixture (``artifacts/fixtures-x64/...``) is present
  -- the case on the equipped Windows reference machine -- it is used directly,
  and only format-level assertions that hold for any non-trivial x64 PE run.
* Otherwise, if a POSIX mingw-w64 cross-compiler is available (Linux/CI), a tiny
  PE is compiled at test time. Because this gate then *knows* the binary, it
  additionally asserts on named functions, a planted string, and a real import.

Both radare2 and a fixture source are checked up front; the gate skips loudly
("skip != pass") when neither is available, rather than passing vacuously.
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

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_REFERENCE_FIXTURE = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"

# Planted so the built-fixture assertions bind to bytes this gate authored, not
# to whatever the toolchain happened to emit. -O0 + noinline keep the two helper
# functions from being folded away, so a real call edge survives to analyse.
_STRING_MARKER = "GATE_R2_STRING_MARKER"
_FIXTURE_C = r"""
#include <stdio.h>
__attribute__((noinline)) int gate_add(int a, int b) { return a + b; }
__attribute__((noinline)) int gate_compute(int x) { return gate_add(x, 7); }
int main(void) {
    const char *m = "GATE_R2_STRING_MARKER";
    printf("%s %d\n", m, gate_compute(35));
    return 0;
}
"""


def _r2_or_skip() -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — PE r2 service gate not run (skip != pass)")


@pytest.fixture(scope="module")
def _pe_fixture() -> Iterator[tuple[Path, bool]]:
    """Yield ``(path, built_here)`` for a real 64-bit PE, or skip loudly."""
    if _REFERENCE_FIXTURE.is_file():
        yield _REFERENCE_FIXTURE, False
        return
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if cc is None:
        pytest.skip(
            "no reference PE fixture and no mingw-w64 cross-compiler to build one "
            "— PE r2 service gate not run (skip != pass)"
        )
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "fixture.c"
        src.write_text(_FIXTURE_C)
        exe = Path(tmp) / "headless_fixture.exe"
        proc = subprocess.run(
            [cc, "-O0", "-o", str(exe), str(src)],
            capture_output=True,
        )
        if proc.returncode != 0 or not exe.is_file():
            pytest.skip(
                f"mingw-w64 could not build the PE fixture — skip != pass: {proc.stderr[:200]!r}"
            )
        yield exe, True


def _open_pe(fixture: Path) -> tuple[AnalysisService, str]:
    service = AnalysisService()
    created = service.create_session(str(fixture))
    assert created.ok, created.error
    assert created.data["session"]["target"] == "pe", created.data["session"]
    return service, created.data["session"]["id"]


def _function_va(service: AnalysisService, session_id: str, prefer: str | None) -> tuple[int, dict]:
    funcs = service.r2_functions(session_id, timeout=90.0)
    assert funcs.ok, funcs.error
    assert funcs.data["parsed"] is True
    assert funcs.data["count"] >= 1, funcs.data
    items = funcs.data["items"]
    chosen = items[0]
    if prefer is not None:
        for item in items:
            if prefer in str(item.get("name", "")):
                chosen = item
                break
    va = chosen["address"]["va"]
    assert isinstance(va, int) and va > 0, chosen
    return va, funcs.data


def test_pe_r2_open_info_and_functions(_pe_fixture: tuple[Path, bool]) -> None:
    _r2_or_skip()
    fixture, built = _pe_fixture
    service, session_id = _open_pe(fixture)
    try:
        opened = service.r2_open(session_id, timeout=90.0)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True
        assert opened.data["binary"].endswith(fixture.name)

        info = service.r2_info(session_id, timeout=90.0)
        assert info.ok, info.error
        # Identity comes from the PE header read (not from r2 parsing the `i`
        # text): a 64-bit PE with a real preferred base and the module name.
        assert info.data["architecture"] == "x64", info.data
        assert isinstance(info.data.get("image_base"), int) and info.data["image_base"] > 0
        assert info.data["module"] == fixture.name

        va, funcs = _function_va(service, session_id, prefer=None)
        first = funcs["items"][0]["address"]
        assert "va" in first
        # image_base known -> the mapping also carries an rva against this module.
        assert first.get("rva") is not None and first.get("module") == fixture.name

        if built:
            names = {str(i.get("name", "")) for i in funcs["items"]}
            joined = " ".join(names)
            assert "gate_add" in joined, sorted(names)[:20]
            assert "gate_compute" in joined, sorted(names)[:20]
            assert "main" in joined, sorted(names)[:20]
    finally:
        service.close_all()


def test_pe_r2_strings_imports_and_exports(_pe_fixture: tuple[Path, bool]) -> None:
    _r2_or_skip()
    fixture, built = _pe_fixture
    service, session_id = _open_pe(fixture)
    try:
        strings = service.r2_strings(session_id, timeout=90.0)
        assert strings.ok, strings.error
        assert strings.data["parsed"] is True
        assert strings.data["count"] >= 1, strings.data
        assert any("address" in s for s in strings.data["items"]), "no string carried an address"

        imports = service.r2_imports(session_id, timeout=90.0)
        assert imports.ok, imports.error
        assert imports.data["parsed"] is True
        # Any non-trivial PE links against system DLLs.
        assert imports.data["count"] >= 1, imports.data
        assert all(isinstance(i, dict) for i in imports.data["items"])
        assert any(str(i.get("name", "")) for i in imports.data["items"]), "imports had no names"

        # An exe may legitimately export nothing; the tool must still return a
        # well-formed, parsed (possibly empty) listing rather than erroring.
        exports = service.r2_exports(session_id, timeout=90.0)
        assert exports.ok, exports.error
        assert exports.data["parsed"] is True
        assert isinstance(exports.data["items"], list)

        if built:
            planted = [
                s for s in strings.data["items"] if _STRING_MARKER in str(s.get("string", ""))
            ]
            assert planted, "planted string marker not recovered by r2.strings"
            assert "address" in planted[0], planted[0]
    finally:
        service.close_all()


def test_pe_r2_disasm_and_xrefs(_pe_fixture: tuple[Path, bool]) -> None:
    _r2_or_skip()
    fixture, built = _pe_fixture
    service, session_id = _open_pe(fixture)
    try:
        # Disassemble at a real function entry: prefer our helper when we built
        # the fixture, otherwise the first analysed function.
        va, _ = _function_va(service, session_id, prefer="gate_add" if built else None)

        disasm = service.r2_disasm(session_id, va, count=8, timeout=90.0)
        assert disasm.ok, disasm.error
        assert disasm.data["parsed"] is True
        assert disasm.data["count"] >= 1, disasm.data
        first = disasm.data["items"][0]
        assert first.get("offset") == va, first
        assert isinstance(first.get("opcode"), str) and first["opcode"], first
        assert first["address"]["va"] == va

        xrefs = service.r2_xrefs(session_id, va, timeout=90.0)
        assert xrefs.ok, xrefs.error
        assert xrefs.data["parsed"] is True
        assert isinstance(xrefs.data["items"], list)
        # The enriched xref rows carry unified Address fields for their endpoints.
        assert any("address" in row or "from_address" in row for row in xrefs.data["items"]), (
            "no xref row carried a mapped address"
        )

        # Guard: a negative address is rejected before touching r2.
        bad = service.r2_disasm(session_id, -1, timeout=90.0)
        assert not bad.ok
        assert bad.error is not None and bad.error.code == "invalid_params", bad.error
    finally:
        service.close_all()
