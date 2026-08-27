"""M11 ELF session end-to-end: a local ELF drives the Ghidra tools via a session.

The r2 ELF-session gate proved radare2 reaches an ELF through the session API
now that ELF is a first-class target; this pins the same for the Ghidra tool
surface, which shares the ``require_binary`` path. Every ``ghidra.*`` service
method used to be exercised only against a PE fixture or the client directly, so
"can a non-Windows binary be analyzed through a session" went untested for the
higher-level engine.

The gate compiles a -no-pie ELF, creates an AnalysisService session (asserting
it is classified ELF with the x86-64 machine named), then drives functions,
decompile, xrefs and symbols entirely through the service. It checks real
recovered semantics rather than non-emptiness: functions names crackme_check and
mangle, the decompiled crackme_check calls mangle and prints the marker string,
decompiling mangle instead surfaces its arithmetic constants and not the marker
(per-address scoping), and xrefs on mangle reports a call edge originating inside
crackme_check's body. skip != pass when a Jython-capable Ghidra
(HEADLESS_RE_GHIDRA_HOME) or a C compiler is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MARKER = "ghidra-elf-sess-marker"
_SRC = """
#include <stdio.h>

__attribute__((noinline))
static int mangle(int x) { return (x ^ 0x5a) + 0x1337; }

__attribute__((noinline))
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    if (acc == 0x2b67) puts("ghidra-elf-sess-marker");
    return acc;
}

int main(int argc, char **argv) { return argc > 1 ? crackme_check(argv[1]) : 0; }
"""
_TIMEOUT_S = 300.0


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


def _build_no_pie_elf(dest: Path) -> Path | None:
    compiler = _compiler()
    if compiler is None:
        return None
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "f.bin"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local compiler
            [compiler, "-O0", "-fno-pic", "-no-pie", "-o", str(binary), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return binary if binary.is_file() else None


def _ghidra_available() -> bool:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return False
    return GhidraClient(home=Path(home)).available


def _within(source: str, entry: str, body_size: int) -> bool:
    start = int(str(entry), 16)
    return start <= int(str(source), 16) < start + body_size


@pytest.mark.integration
def test_m11_elf_session_drives_ghidra_tools_end_to_end(tmp_path: Path) -> None:
    if not _ghidra_available():
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    binary = _build_no_pie_elf(tmp_path)
    if binary is None:
        pytest.skip("no C compiler (cc/gcc/clang) — ELF Ghidra Gate not run (skip != pass)")

    service = AnalysisService(Settings.load())

    # The session-layer regression this depends on: an ELF creates a session,
    # classified ELF with the x86-64 machine, and every ghidra tool below
    # reaches it through require_binary -- no PE-only guard in the way.
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session["target"] == "elf", session
    assert session["architecture"] == "x64", session
    sid = str(session["id"])

    # functions: the analysis runs and names both functions, with an entry and
    # a body size the xref check below attributes call sites to.
    funcs = service.ghidra_functions(sid, limit=256, timeout=_TIMEOUT_S)
    assert funcs.ok and funcs.data is not None, funcs.error
    items = funcs.data.get("items", [])
    entry_for = {str(i.get("name")): str(i.get("entry")) for i in items}
    body_for = {str(i.get("name")): int(i.get("body_size") or 0) for i in items}
    for name in ("crackme_check", "mangle"):
        assert name in entry_for, list(entry_for)
    check_entry = entry_for["crackme_check"]
    mangle_entry = entry_for["mangle"]

    # Address enrichment (parity with the r2 backend): the ELF load base is
    # named once at the top level, and each function entry gains the structured
    # companion with module and an rva relative to that base.
    assert funcs.data.get("module"), funcs.data
    image_base = funcs.data.get("image_base")
    assert isinstance(image_base, int), funcs.data
    assert funcs.data.get("architecture") == "x64", funcs.data
    check_item = next(i for i in items if str(i.get("name")) == "crackme_check")
    entry_obj = check_item.get("entry_address")
    assert isinstance(entry_obj, dict), check_item
    assert entry_obj.get("va") == int(check_entry, 16), (entry_obj, check_entry)
    assert entry_obj.get("module") == funcs.data["module"], entry_obj
    assert entry_obj.get("rva") == int(check_entry, 16) - image_base, (entry_obj, image_base)

    # decompile(crackme_check): recovered C carries the function's behaviour --
    # it names itself, calls the helper, and prints the marker literal inline.
    outer = service.ghidra_decompile(sid, check_entry, timeout=_TIMEOUT_S)
    assert outer.ok and outer.data is not None, outer.error
    assert outer.data.get("function") == "crackme_check", outer.data
    assert outer.data.get("truncated") is False
    outer_c = str(outer.data.get("decompiled"))
    assert outer_c.strip(), "empty decompilation"
    assert "mangle(" in outer_c, outer_c
    assert _MARKER in outer_c, outer_c

    # decompile(mangle): a different address decompiles a different function --
    # its arithmetic constants surface and the outer marker does not, proving
    # decompilation is scoped to the requested address, through the session.
    inner = service.ghidra_decompile(sid, mangle_entry, timeout=_TIMEOUT_S)
    assert inner.ok and inner.data is not None, inner.error
    assert inner.data.get("function") == "mangle", inner.data
    inner_c = str(inner.data.get("decompiled"))
    assert "0x5a" in inner_c, inner_c
    assert "0x1337" in inner_c, inner_c
    assert _MARKER not in inner_c, inner_c

    # xrefs(mangle): the reference set is non-empty and contains a call edge
    # into mangle that originates inside crackme_check's recovered body -- the
    # crackme_check -> mangle call, read through the service on an ELF.
    xrefs = service.ghidra_xrefs(sid, mangle_entry, limit=256, timeout=_TIMEOUT_S)
    assert xrefs.ok and xrefs.data is not None, xrefs.error
    assert xrefs.data.get("mode") == "xrefs"
    xitems = xrefs.data.get("items", [])
    assert xitems, xrefs.data
    assert all(str(x.get("to")) == mangle_entry for x in xitems), xitems
    call_edges = [x for x in xitems if "CALL" in str(x.get("type"))]
    assert call_edges, [str(x.get("type")) for x in xitems]
    # Both endpoints of a call edge carry the same from_address/to_address
    # objects r2 emits, so the two engines' ELF xrefs join on rva coordinates.
    edge = call_edges[0]
    for string_field, object_field in (("from", "from_address"), ("to", "to_address")):
        endpoint = edge.get(object_field)
        assert isinstance(endpoint, dict), edge
        assert endpoint.get("va") == int(str(edge.get(string_field)), 16), edge
        assert isinstance(endpoint.get("rva"), int), edge
    check_size = body_for["crackme_check"]
    assert check_size > 0, body_for
    assert any(
        _within(str(x.get("from")), check_entry, check_size) for x in call_edges
    ), [(x.get("type"), x.get("from")) for x in call_edges]

    # symbols: the export is reachable through the session and non-empty.
    symbols = service.ghidra_symbols(sid, limit=1024, timeout=_TIMEOUT_S)
    assert symbols.ok and symbols.data is not None, symbols.error
    assert symbols.data.get("count", 0) > 0, symbols.data
