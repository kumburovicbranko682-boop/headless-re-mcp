"""M11 r2 exports gate: enumerate a shared library's exported API surface.

The r2 static gate proves strings/imports/functions/disasm/xrefs on an
executable, but never the dynamic *export* table -- the first question asked of
an unknown ``.so``/native library: "what does it expose?". That is a distinct
analysis (``iEj`` over the dynamic symbol table, not ``iij`` imports or ``aflj``
recovered functions), and getting it wrong would misreport a library's public
interface even when disassembly is fine.

This gate compiles a shared object with two exported functions and one
static/hidden helper, then asserts r2 lists exactly the two exports as GLOBAL
FUNC symbols with mapped addresses, that the hidden helper is absent from the
export surface, that each export address really lands on a function r2's analysis
recovered, and that the library's own import (``strlen``) still resolves. The
fixture is confirmed to be an ET_DYN shared object from its ELF header before r2
is trusted. skip != pass when radare2/rizin or a C compiler is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

# Two exported functions form the public surface; secret_helper is static, so it
# must stay out of the dynamic export table while still being called internally.
_SRC = r"""
#include <string.h>

static int secret_helper(int x) { return x * 3 + 1; }

int re_export_alpha(int x) { return secret_helper(x) ^ 0x41; }

int re_export_beta(const char *s) { return (int)strlen(s) + secret_helper(2); }
"""
_EXPORTS = {"re_export_alpha", "re_export_beta"}
_HIDDEN = "secret_helper"
_ET_DYN = 3  # ELF e_type for a shared object / PIE.


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc")


def _build_shared_object(dest: Path) -> Path:
    compiler = _compiler()
    assert compiler is not None
    src = dest / "lib.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "libre_gate.so"
    subprocess.run(  # noqa: S603 - fixed args, local compiler
        [compiler, "-O0", "-fno-inline", "-shared", "-fPIC", "-o", str(binary), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


def _elf_type(binary: Path) -> int:
    header = binary.read_bytes()[:18]
    assert header[:4] == b"\x7fELF", header[:4]
    return int.from_bytes(header[16:18], "little")


@pytest.mark.integration
def test_m11_r2_enumerates_shared_object_exports() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — exports Gate not run (skip != pass)")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) — cannot build the .so fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build_shared_object(Path(tmp))

        # Independent of r2: the fixture really is an ET_DYN shared object.
        assert _elf_type(binary) == _ET_DYN, _elf_type(binary)
        assert client.open(binary, timeout=60.0).get("opened") is True

        # Exports: the dynamic symbol table lists exactly the public API.
        exports = client.run(binary, ["iEj"], timeout=60.0)
        assert exports.get("parsed") is True
        by_name = {str(e.get("name")): e for e in exports["items"]}
        assert set(by_name) >= _EXPORTS, sorted(by_name)

        export_va: dict[str, int] = {}
        for name in _EXPORTS:
            entry = by_name[name]
            assert entry.get("type") == "FUNC", entry
            assert entry.get("bind") == "GLOBAL", entry
            assert entry.get("is_imported") is False, entry
            addr = entry.get("address")
            assert isinstance(addr, dict) and isinstance(addr.get("va"), int), entry
            assert addr["va"] == entry.get("vaddr"), entry
            assert addr["va"] > 0, entry
            export_va[name] = int(addr["va"])
        assert export_va["re_export_alpha"] != export_va["re_export_beta"], export_va

        # The hidden static helper is internal, never part of the export surface.
        assert _HIDDEN not in by_name, sorted(by_name)
        assert all(
            _HIDDEN not in str(e.get("name")) or e.get("is_imported") for e in exports["items"]
        ), exports["items"]

        # Each export address really lands on a function r2's analysis recovered
        # -- the exported symbol points at analysable code, not a bare address.
        funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
        assert funcs.get("parsed") is True
        func_offsets = {
            int(f["offset"]) for f in funcs["items"] if isinstance(f.get("offset"), int)
        }
        for name, va in export_va.items():
            assert va in func_offsets, (name, hex(va), sorted(map(hex, func_offsets))[:12])

        # The library's own import still resolves as a FUNC -- exports and
        # imports are read from the same object without confusing the two.
        imports = client.run(binary, ["iij"], timeout=60.0)
        assert imports.get("parsed") is True
        strlen = [i for i in imports["items"] if str(i.get("name")) == "strlen"]
        assert strlen, [i.get("name") for i in imports["items"]]
        assert strlen[0].get("type") == "FUNC", strlen[0]
