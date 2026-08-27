"""M11 r2 static gate: strings, imports, functions, disassembly and xrefs.

The live r2 gate proves address mapping on a PE fixture but exercises only
function listing. r2 is the cross-platform static backend, so its other
whitelisted analyses -- string extraction, import enumeration, disassembly and
the cross-reference graph -- deserve the same real-binary proof. This gate
compiles a tiny ELF with a known string, real libc imports and a named function
that calls them, then asserts each analysis returns that content. skip != pass
when radare2/rizin or a C compiler is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_SRC = r"""
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int check_password(const char *s) {
    if (strcmp(s, "r2-gate-secret-marker-7a3f") == 0) {
        puts("access granted");
        return 1;
    }
    puts("access denied");
    return 0;
}

int main(int argc, char **argv) {
    const char *pw = argc > 1 ? argv[1] : "nope";
    return check_password(pw) ? 0 : 2;
}
"""
_MARKER = "r2-gate-secret-marker-7a3f"


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc")


def _build_elf(dest: Path) -> Path:
    compiler = _compiler()
    assert compiler is not None
    src = dest / "fixture.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "fixture"
    subprocess.run(  # noqa: S603 - fixed args, local compiler
        [compiler, "-O0", "-fno-inline", "-o", str(binary), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


@pytest.mark.integration
def test_m11_r2_static_strings_imports_functions_disasm_xrefs() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) — cannot build the ELF fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build_elf(Path(tmp))

        assert client.open(binary, timeout=60.0).get("opened") is True

        # Strings: the marker literal is recovered with a mapped address.
        strings = client.run(binary, ["izj"], timeout=60.0)
        assert strings.get("parsed") is True
        found = [s for s in strings["items"] if s.get("string") == _MARKER]
        assert found, [s.get("string") for s in strings["items"]]
        assert isinstance(found[0].get("address"), dict)
        assert any(s.get("string") == "access granted" for s in strings["items"])

        # Imports: the libc calls the code makes are enumerated as functions.
        imports = client.run(binary, ["iij"], timeout=60.0)
        assert imports.get("parsed") is True
        import_names = {str(i.get("name")) for i in imports["items"]}
        assert {"puts", "strcmp"} <= import_names, import_names
        assert all(
            i.get("type") == "FUNC"
            for i in imports["items"]
            if i.get("name") in {"puts", "strcmp"}
        )

        # Functions: analysis discovers the named function (and main).
        funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
        assert funcs.get("parsed") is True
        assert funcs.get("count", 0) >= 5
        func_names = [str(f.get("name")) for f in funcs["items"]]
        check = next(
            (f for f in funcs["items"] if "check_password" in str(f.get("name"))), None
        )
        assert check is not None, func_names
        assert any("main" in n for n in func_names), func_names
        check_va = check.get("offset")
        assert isinstance(check_va, int)
        assert isinstance(check.get("address"), dict)

        # Disassembly of that function shows the strcmp call and marker, and its
        # entry carries an inbound CALL xref -- it really is called from main.
        disasm = client.disasm(binary, check_va, count=32, timeout=60.0)
        assert disasm.get("parsed") is True
        assert disasm.get("count", 0) >= 1
        text = disasm.get("raw", "")
        assert "strcmp" in text, text[:400]
        assert "r2_gate_secret_marker" in text, text[:400]
        inbound_call = any(
            x.get("type") == "CALL"
            for item in disasm["items"]
            for x in (item.get("xrefs") or [])
        )
        assert inbound_call, "expected an inbound CALL xref on the function entry"

        # Cross-reference graph is populated and names the imported targets.
        xrefs = client.xrefs(binary, check_va, timeout=60.0)
        assert xrefs.get("parsed") is True
        assert xrefs.get("count", 0) >= 1
        assert any(
            "strcmp" in str(x.get("refname")) or "puts" in str(x.get("refname"))
            for x in xrefs["items"]
        ), [x.get("refname") for x in xrefs["items"]][:12]
        assert any(isinstance(x.get("from_address"), dict) for x in xrefs["items"])
