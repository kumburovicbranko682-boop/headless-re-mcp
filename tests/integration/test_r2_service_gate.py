"""radare2 service gate: drive r2.* through a BINARY session on a real ELF.

The existing M11 gate calls ``R2Client`` directly for address mapping. This one
goes through the product surface a caller actually uses -- ``session.create`` ->
``r2.open`` / ``r2.info`` / ``r2.functions`` / ``r2.strings`` / ``r2.imports`` /
``r2.exports`` / ``r2.disasm`` / ``r2.xrefs`` -- which only became reachable for
an ELF once sessions learned the ``binary`` target kind (ELF/Mach-O were funneled
into PE before and rejected with "not a PE file"). It asserts on recovered
*content* (our own function, a marker string, a libc import, the call edge), not
just envelope shapes, so a regression in the r2 backend, the JSON parse, or the
address enrichment is caught rather than skipped past.

skip != pass: skips honestly when radare2/rizin or a C compiler is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

# Unstripped, non-PIE C so r2 recovers named symbols and absolute addresses:
# our own headless_compute (called by main), a marker string, and a libc import.
_SOURCE = """
#include <stdio.h>
int headless_compute(int a, int b) { return a * b + 7; }
int main(void) {
    puts("HEADLESS-R2-SVC-GATE");
    return headless_compute(3, 4);
}
"""
_MARKER = "HEADLESS-R2-SVC-GATE"
_FUNC = "headless_compute"


def _compile_elf(tmp_path: Path) -> Path | None:
    """Compile the source to a small ELF, or None when no compiler exists.

    Prefer a non-PIE build for absolute addresses, but fall back to a plain
    build so a toolchain that defaults to PIE and rejects -no-pie still yields a
    target. Returns None (never raises) on Windows or a bare machine.
    """
    if os.name == "nt":
        return None
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "r2svc.c"
    source.write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / "r2svc"
    for extra in (["-no-pie"], []):
        try:
            subprocess.run(
                [compiler, "-O0", *extra, "-o", str(out), str(source)],
                check=True,
                capture_output=True,
                timeout=90,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if out.is_file():
            return out
    return None


def _names(result_data: dict) -> list[str]:
    return [str(item.get("name") or "") for item in result_data.get("items", [])]


def _va_of(result_data: dict, name: str) -> int | None:
    for item in result_data.get("items", []):
        if item.get("name") == name:
            address = item.get("address")
            if isinstance(address, dict) and isinstance(address.get("va"), int):
                return int(address["va"])
    return None


@pytest.mark.integration
def test_r2_service_recovers_elf_content(tmp_path: Path) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — r2 service gate not run (skip != pass)")
    target = _compile_elf(tmp_path)
    if target is None:
        pytest.skip("no C compiler to build an ELF target (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(target))
        assert created.ok, created.error
        # The whole point: an ELF is now a first-class binary session, not a
        # rejected "not a PE file".
        assert created.data["session"]["target"] == "binary"
        session_id = created.data["session"]["id"]

        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error
        assert opened.data["opened"] is True

        info = service.r2_info(session_id, timeout=60.0)
        assert info.ok, info.error
        # `i` is plain text, not JSON, so it lands in raw with parsed False.
        assert "elf" in info.data["raw"].lower(), info.data["raw"][:200]

        functions = service.r2_functions(session_id, timeout=60.0)
        assert functions.ok, functions.error
        assert functions.data["parsed"] is True
        assert functions.data["count"] >= 1
        names = _names(functions.data)
        assert "main" in names, names
        assert f"sym.{_FUNC}" in names, names
        # Every function carries a unified Address the caller can navigate by.
        first = functions.data["items"][0]
        assert isinstance(first.get("address"), dict) and "va" in first["address"]

        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok, strings.error
        assert any(
            _MARKER in str(item.get("string") or "") for item in strings.data["items"]
        ), strings.data.get("items")

        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok, imports.error
        assert "puts" in _names(imports.data), _names(imports.data)

        exports = service.r2_exports(session_id, timeout=60.0)
        assert exports.ok, exports.error
        export_names = _names(exports.data)
        assert {"main", f"{_FUNC}"} & set(export_names) or _FUNC in export_names, export_names

        main_va = _va_of(functions.data, "main")
        func_va = _va_of(functions.data, f"sym.{_FUNC}")
        assert main_va is not None and func_va is not None, functions.data["items"]

        disasm = service.r2_disasm(session_id, main_va, count=64, timeout=60.0)
        assert disasm.ok, disasm.error
        assert disasm.data["count"] >= 1
        opcodes = [str(item.get("disasm") or "") for item in disasm.data["items"]]
        # main must contain the call to our function -- proof disasm decoded real
        # instructions at the mapped address, not an empty listing.
        assert any(_FUNC in op for op in opcodes), opcodes

        xrefs = service.r2_xrefs(session_id, func_va, timeout=60.0)
        assert xrefs.ok, xrefs.error
        call_edges = [
            item
            for item in xrefs.data["items"]
            if item.get("type") == "CALL"
            and func_va in (item.get("addr"), item.get("to"))
        ]
        assert call_edges, xrefs.data["items"]
        edge = call_edges[0]
        # The call site is inside main and maps back through the module.
        assert isinstance(edge.get("from_address"), dict), edge
        assert "va" in edge["from_address"], edge
    finally:
        service.close_all()
