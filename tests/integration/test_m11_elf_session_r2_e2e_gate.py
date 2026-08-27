"""M11 ELF session end-to-end: a local ELF drives the r2 tools through a session.

Before ELF was a session target, create_session ran the PE machine probe on
every local file, so an ELF failed with "not a PE file" and never reached the
radare2 or Ghidra tools that read it perfectly well -- the whole cross-platform
static surface was unreachable through the session API for non-Windows binaries.

This gate stands up a real AnalysisService session on a compiled ELF and drives
the r2 tools the way an MCP caller would: it asserts the session is classified
ELF with the x86-64 machine named, then opens, lists functions, and follows
outbound references -- all through the service, not the client. On a *stripped*
copy it exercises the analysis-depth knob end to end: the shallow default finds
no function to walk (parsed is not true), while analysis="aaa" recovers the body
and its call to mangle plus the marker-string load, and xrefs_to reads the same
edge back inbound. skip != pass when radare2/rizin, a C compiler, or binutils
(strip/nm) is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_SRC = """
#include <stdio.h>

__attribute__((noinline))
static int mangle(int x) { return (x ^ 0x5a) + 0x1337; }

__attribute__((noinline))
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    if (acc == 0x2b67) puts("elf-e2e-marker");
    return acc;
}

int main(int argc, char **argv) { return argc > 1 ? crackme_check(argv[1]) : 0; }
"""


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


def _build_unstripped(dest: Path) -> Path | None:
    compiler = _compiler()
    if compiler is None:
        return None
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "u.bin"
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


def _strip_copy(binary: Path, dest: Path) -> Path | None:
    strip = shutil.which("strip")
    if strip is None:
        return None
    stripped = dest / "s.bin"
    shutil.copy(binary, stripped)
    try:
        subprocess.run(  # noqa: S603 - fixed args, local binutils
            [strip, "-s", str(stripped)], check=True, capture_output=True, timeout=60.0
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return stripped


def _nm_addr(binary: Path, name: str) -> int | None:
    nm = shutil.which("nm")
    if nm is None:
        return None
    out = subprocess.run(  # noqa: S603 - fixed args, local binutils
        [nm, str(binary)], capture_output=True, text=True, timeout=60.0
    )
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == name:
            return int(parts[0], 16)
    return None


@pytest.mark.integration
def test_m11_elf_session_drives_r2_tools_end_to_end() -> None:
    if shutil.which("r2") is None and shutil.which("rizin") is None:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the ELF (skip != pass)")
    if shutil.which("strip") is None or shutil.which("nm") is None:
        pytest.skip("binutils strip/nm missing — cannot build ground truth (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp)
        unstripped = _build_unstripped(dest)
        assert unstripped is not None
        check_addr = _nm_addr(unstripped, "crackme_check")
        mangle_addr = _nm_addr(unstripped, "mangle")
        assert check_addr is not None and mangle_addr is not None

        service = AnalysisService(Settings.load())

        # The regression this branch fixes: an ELF now creates a session, is
        # classified ELF, and carries the x86-64 machine the header declares --
        # where create_session used to raise "not a PE file".
        created = service.create_session(str(unstripped))
        assert created.ok and created.data is not None, created.error
        session = created.data["session"]
        assert session["target"] == "elf", session
        assert session["architecture"] == "x64", session
        sid = str(session["id"])

        opened = service.r2_open(sid)
        assert opened.ok, opened.error

        funcs = service.r2_functions(sid, timeout=60.0)
        assert funcs.ok and funcs.data is not None, funcs.error
        assert funcs.data.get("parsed") is True
        by_name = {str(f.get("name")): f for f in funcs.data["items"]}
        assert any("crackme_check" in n for n in by_name), list(by_name)

        # Disassembly reaches the ELF's code through the session, and the tool
        # threads the deeper pass verbatim into the spawned command.
        disasm = service.r2_disasm(sid, check_addr, count=4, analysis="aaa", timeout=60.0)
        assert disasm.ok and disasm.data is not None, disasm.error
        assert disasm.data.get("parsed") is True
        assert disasm.data["commands"][0] == "aaa"

        # Outbound refs on the named ELF: the internal call to mangle is found.
        frm = service.r2_xrefs_from(sid, check_addr, analysis="aaa", timeout=120.0)
        assert frm.ok and frm.data is not None, frm.error
        refs = frm.data.get("items", [])
        assert any(
            str(i.get("type")) == "CALL" and i.get("ref") == mangle_addr for i in refs
        ), [(str(i.get("type")), i.get("ref")) for i in refs]

        # Now the stripped copy, in its own ELF session: the analysis knob is
        # what makes the outbound walk work, proven through the service.
        stripped = _strip_copy(unstripped, dest)
        assert stripped is not None
        created_s = service.create_session(str(stripped))
        assert created_s.ok and created_s.data is not None
        assert created_s.data["session"]["target"] == "elf"
        sid_s = str(created_s.data["session"]["id"])
        assert service.r2_open(sid_s).ok

        # Shallow default: no function reachable only by call is analyzed, so
        # axffj has nothing to walk -- an unparsed, item-less answer.
        shallow = service.r2_xrefs_from(sid_s, check_addr, timeout=60.0)
        assert shallow.ok, shallow.error
        assert shallow.data is not None
        assert shallow.data.get("parsed") is not True, shallow.data
        assert not shallow.data.get("items"), shallow.data.get("items")

        # Deeper pass: the body is recovered and its edges appear, named purely
        # from addresses since the symbol table is gone.
        deep = service.r2_xrefs_from(sid_s, check_addr, analysis="aaa", timeout=120.0)
        assert deep.ok and deep.data is not None, deep.error
        assert deep.data.get("parsed") is True
        deep_refs = deep.data.get("items", [])
        call_sites = [
            i.get("at")
            for i in deep_refs
            if str(i.get("type")) == "CALL" and i.get("ref") == mangle_addr
        ]
        assert len(call_sites) == 1, [
            (str(i.get("type")), i.get("ref")) for i in deep_refs
        ]
        assert any(
            "elf_e2e_marker" in str(i.get("name")) and str(i.get("type")) == "DATA"
            for i in deep_refs
        ), deep_refs

        # The same edge, read back inbound through the service on the stripped
        # session: who-calls-mangle names the exact site the outbound walk gave.
        inbound = service.r2_xrefs_to(sid_s, mangle_addr, analysis="aaa", timeout=120.0)
        assert inbound.ok and inbound.data is not None, inbound.error
        inbound_calls = [
            i for i in inbound.data.get("items", []) if i.get("type") == "CALL"
        ]
        assert len(inbound_calls) == 1, inbound.data.get("items")
        assert inbound_calls[0].get("from") == call_sites[0], (
            inbound_calls[0],
            call_sites,
        )
