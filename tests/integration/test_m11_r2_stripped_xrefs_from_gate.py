"""M11 r2 stripped outbound-xref gate: the analysis knob unlocks axffj.

``xrefs_to`` already threads an ``analysis`` depth parameter; this gate proves
the same knob matters on the *outbound* path. On a stripped binary the shallow
default ``aa`` never analyzes a function that is only reachable through a call,
so ``axffj`` at its entry has no function to walk and returns nothing -- the
honest baseline this gate pins down first. With ``analysis="aaa"`` r2 recovers
the body and ``xrefs_from`` yields the function's real outbound graph: the
internal CALL to ``mangle`` at its exact site, the DATA load of the marker
string, and the PLT call for ``puts`` -- all without a symbol table, with the
call target verified against ``nm`` ground truth from an unstripped twin.

The recovered edge is then read back from the other direction:
``xrefs_to(mangle, analysis="aaa")`` reports the same single call site inside
``crackme_check``'s recovered ``fcn.<addr>`` body, so the outbound and inbound
views describe one identical call edge on a symbol-free image. skip != pass
when radare2/rizin, a C compiler, or binutils (nm/strip) is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_SRC = """
#include <stdio.h>

__attribute__((noinline))
static int mangle(int x) { return (x ^ 0x5a) + 0x1337; }

__attribute__((noinline))
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    if (acc == 0x2b67) puts("outbound-xref-marker");
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


def _nm(binary: Path) -> str | None:
    nm = shutil.which("nm")
    if nm is None:
        return None
    out = subprocess.run(  # noqa: S603 - fixed args, local binutils
        [nm, str(binary)], capture_output=True, text=True, timeout=60.0
    )
    return out.stdout


def _nm_addr(nm_output: str, name: str) -> int | None:
    for line in nm_output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == name:
            return int(parts[0], 16)
    return None


@pytest.mark.integration
def test_m11_r2_stripped_xrefs_from_needs_and_uses_the_deeper_pass() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the fixture (skip != pass)")
    if shutil.which("strip") is None or shutil.which("nm") is None:
        pytest.skip("binutils strip/nm missing — cannot build ground truth (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp)
        unstripped = _build_unstripped(dest)
        assert unstripped is not None

        # Ground truth from the unstripped twin; -no-pie keeps addresses equal.
        symbols = _nm(unstripped)
        assert symbols is not None
        check_addr = _nm_addr(symbols, "crackme_check")
        mangle_addr = _nm_addr(symbols, "mangle")
        assert check_addr is not None and mangle_addr is not None, symbols

        stripped = _strip_copy(unstripped, dest)
        assert stripped is not None
        stripped_syms = _nm(stripped) or ""
        assert "crackme_check" not in stripped_syms, stripped_syms
        assert "mangle" not in stripped_syms, stripped_syms

        # Baseline: the shallow default pass does not analyze a function that
        # is only reachable through a call, so axffj has nothing to walk. r2
        # prints no JSON at all, which the client reports as an unparsed,
        # item-less payload -- not a silent empty success.
        shallow = client.xrefs_from(stripped, check_addr, timeout=60.0)
        assert shallow.get("parsed") is not True, shallow
        assert not shallow.get("items"), shallow.get("items")

        # Deeper pass: aaa recovers crackme_check's body, and the outbound
        # walk returns its real edges.
        deep = client.xrefs_from(stripped, check_addr, analysis="aaa", timeout=120.0)
        assert deep.get("parsed") is True, deep
        assert deep.get("address_va") == check_addr
        assert deep["commands"][-1] == f"axffj @ {check_addr}"
        items = deep.get("items", [])
        assert isinstance(items, list) and len(items) >= 3, items
        for item in items:
            assert isinstance(item.get("at_address"), dict), item
            assert isinstance(item.get("ref_address"), dict), item

        # The internal call: exactly one CALL edge targets mangle's true
        # address, named purely from that address (no symbol to borrow), and
        # its site lies past crackme_check's entry inside the walked body.
        calls_to_mangle = [
            i for i in items if str(i.get("type")) == "CALL" and i.get("ref") == mangle_addr
        ]
        assert len(calls_to_mangle) == 1, [
            (str(i.get("type")), hex(int(i.get("ref", 0)))) for i in items
        ]
        mangle_edge = calls_to_mangle[0]
        assert f"{mangle_addr:08x}" in str(mangle_edge.get("name")), mangle_edge
        call_site = mangle_edge.get("at")
        assert isinstance(call_site, int) and call_site > check_addr, mangle_edge

        # The data load: the marker literal is referenced as DATA and r2 names
        # the recovered string flag after its content (hyphens fold to _).
        data_names = [str(i.get("name")) for i in items if str(i.get("type")) == "DATA"]
        assert any("outbound_xref_marker" in n for n in data_names), items

        # The import call: puts is reached through the PLT, so a second CALL
        # edge leaves the function beside the internal one.
        call_edges = [i for i in items if str(i.get("type")) == "CALL"]
        assert len(call_edges) >= 2, [
            (str(i.get("name")), hex(int(i.get("ref", 0)))) for i in call_edges
        ]

        # Read the same edge back inbound: who-calls-mangle names the exact
        # site axffj reported, enclosed in crackme_check's recovered function.
        inbound = client.xrefs_to(stripped, mangle_addr, analysis="aaa", timeout=120.0)
        assert inbound.get("parsed") is True, inbound
        inbound_calls = [i for i in inbound.get("items", []) if i.get("type") == "CALL"]
        assert len(inbound_calls) == 1, inbound.get("items")
        assert inbound_calls[0].get("from") == call_site, (inbound_calls[0], hex(call_site))
        assert inbound_calls[0].get("fcn_addr") == check_addr, inbound_calls[0]
        assert f"{check_addr:08x}" in str(inbound_calls[0].get("fcn_name")), inbound_calls[0]
