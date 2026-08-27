"""M11 Ghidra live gate: analyzeHeadless + ExportJson.py against a real ELF.

The unit tests drive the Ghidra adapter with a fake analyzeHeadless, so the one
thing they cannot check is the part that runs *inside* Ghidra: the bundled
``ExportJson.py`` post-script, which is Jython and only executes under a real
install. This gate compiles a tiny ELF and runs the functions/symbols/decompile
exports against it end to end, so the Ghidra line is actually exercised on Linux
instead of resting on mocks.

It runs wherever a Ghidra with ``support/analyzeHeadless`` and a JDK are present
(``HEADLESS_RE_GHIDRA_HOME``; the integration conftest exports it from
config.json too) and skips honestly otherwise. skip != pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

# Same shape as the r2 ELF gate: a couple of named functions with a call edge so
# Ghidra has real code to recover and decompile. Harmless arithmetic.
_ELF_SOURCE = """
#include <stdio.h>
static int mangle(int x) { return (x ^ 0x41) + 7; }
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    return acc;
}
int main(int argc, char **argv) {
    if (argc > 1) return crackme_check(argv[1]);
    printf("gate\\n");
    return 0;
}
"""


def _build_native_fixture(tmp_path: Path) -> Path | None:
    """Compile a tiny native binary, or None when no compiler is available."""
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "ghidra_fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    binary = tmp_path / "ghidra_fixture.bin"
    # Symbols kept (no -s) so Ghidra recovers the named functions; -no-pie keeps
    # the entry addresses stable. Fall back if the toolchain rejects the flags.
    for extra in (["-O0", "-fno-pic", "-no-pie"], ["-O0"], []):
        try:
            subprocess.run(
                [compiler, *extra, str(source), "-o", str(binary)],
                check=True,
                capture_output=True,
                timeout=60.0,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue
        if binary.is_file():
            return binary
    return None


def _client() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


# analyzeHeadless imports and analyses the binary from scratch on every call
# (each export is independent), and the first invocation also warms Ghidra's
# per-user caches, so give each a generous JVM-sized deadline.
_ANALYZE_TIMEOUT_S = 300.0


@pytest.mark.integration
def test_m11_ghidra_live_functions_symbols_and_decompile(tmp_path: Path) -> None:
    client = _client()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    fixture = _build_native_fixture(tmp_path)
    if fixture is None:
        pytest.skip("no C compiler (cc/gcc/clang) — Ghidra ELF Gate not run (skip != pass)")
    project = tmp_path / "ghidra_project"

    # Functions: the ExportJson.py "functions" branch, parsed back through the
    # client's JSON reader. Ghidra prefixes nothing, so names are exact.
    funcs = client.functions(fixture, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert funcs.get("mode") == "functions"
    assert funcs.get("count", 0) >= 2
    entry_for: dict[str, str] = {}
    for item in funcs["items"]:
        name = str(item.get("name") or "")
        assert isinstance(item.get("entry"), str) and item["entry"], item
        assert isinstance(item.get("body_size"), int), item
        entry_for[name] = str(item["entry"])
    assert "crackme_check" in entry_for, list(entry_for)
    assert any(name == "main" for name in entry_for), list(entry_for)

    # Symbols: a different ExportJson.py branch and a different Ghidra API.
    symbols = client.symbols(fixture, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert symbols.get("mode") == "symbols"
    assert symbols.get("count", 0) >= 1
    assert any(str(item.get("name")) for item in symbols["items"])

    # Decompile the function we located: proves DecompInterface ran and returned
    # real C, not just that the script did not throw.
    decomp = client.decompile(
        fixture, project, entry_for["crackme_check"], timeout=_ANALYZE_TIMEOUT_S
    )
    assert decomp.get("mode") == "decompile"
    assert "crackme_check" in str(decomp.get("function") or "")
    body = str(decomp.get("decompiled") or "")
    assert body.strip(), decomp
    # The decompiler emits a C function; the recovered name appears in its text.
    assert "crackme_check" in body, body
