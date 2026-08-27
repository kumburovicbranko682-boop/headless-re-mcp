"""M11 Ghidra live gate: analyzeHeadless + ExportJson.py against a real ELF.

The unit tests drive the Ghidra adapter with a fake analyzeHeadless, so the one
thing they cannot check is the part that runs *inside* Ghidra: the bundled
``ExportJson.py`` post-script, which is Jython and only executes under a real
install. This gate compiles a tiny ELF and runs the functions/symbols/xrefs and
decompile exports against it end to end, so the Ghidra line is actually
exercised on Linux instead of resting on mocks.

The fixture is a two-edge call graph (main -> crackme_check -> mangle) so the
gate can prove Ghidra recovered real analysis, not just that the script ran:
the xrefs branch must surface the inbound CALL from each caller's body, and the
decompiler must emit C that reflects the actual code -- the surviving call to
the helper, the loop bound, and mangle's exact ``(x ^ 0x41) + 7`` arithmetic.

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


def _within_body(from_addr: str, entry_hex: str, body_size: int) -> bool:
    """True when a Ghidra ``from`` address falls inside ``[entry, entry+body)``.

    Reference sources are hex strings like ``004011d8``, except synthetic ones
    such as ``Entry Point`` which are not addresses and are simply not inside
    any body.
    """
    try:
        source = int(from_addr, 16)
    except ValueError:
        return False
    start = int(entry_hex, 16)
    return start <= source < start + body_size


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
def test_m11_ghidra_live_functions_symbols_xrefs_and_decompile(tmp_path: Path) -> None:
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
    body_for: dict[str, int] = {}
    for item in funcs["items"]:
        name = str(item.get("name") or "")
        assert isinstance(item.get("entry"), str) and item["entry"], item
        assert isinstance(item.get("body_size"), int), item
        entry_for[name] = str(item["entry"])
        body_for[name] = int(item["body_size"])
    # The whole call graph was recovered as named functions.
    assert "crackme_check" in entry_for, list(entry_for)
    assert "main" in entry_for, list(entry_for)
    assert "mangle" in entry_for, list(entry_for)

    # Symbols: a different ExportJson.py branch and a different Ghidra API.
    symbols = client.symbols(fixture, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert symbols.get("mode") == "symbols"
    assert symbols.get("count", 0) >= 1
    assert any(str(item.get("name")) for item in symbols["items"])

    # Xrefs: the ExportJson.py "xrefs" branch (Ghidra's ReferenceManager), which
    # no other gate exercises. Ghidra recovered the call graph, so the sole
    # caller of crackme_check -- main -- shows up as a CALL reference whose
    # source address lies inside main's body. Every reference points at the
    # address that was asked for.
    xrefs = client.xrefs(
        fixture, project, entry_for["crackme_check"], limit=256, timeout=_ANALYZE_TIMEOUT_S
    )
    assert xrefs.get("mode") == "xrefs"
    assert xrefs.get("count", 0) >= 1
    assert all(str(x.get("to")) == entry_for["crackme_check"] for x in xrefs["items"]), xrefs[
        "items"
    ]
    call_from_main = [
        x
        for x in xrefs["items"]
        if "CALL" in str(x.get("type"))
        and _within_body(str(x.get("from")), entry_for["main"], body_for["main"])
    ]
    assert call_from_main, xrefs["items"]

    # The inner edge is recovered too: crackme_check calls mangle, so mangle
    # carries an inbound CALL originating inside crackme_check's body.
    xrefs_mangle = client.xrefs(
        fixture, project, entry_for["mangle"], limit=256, timeout=_ANALYZE_TIMEOUT_S
    )
    call_from_check = [
        x
        for x in xrefs_mangle["items"]
        if "CALL" in str(x.get("type"))
        and _within_body(str(x.get("from")), entry_for["crackme_check"], body_for["crackme_check"])
    ]
    assert call_from_check, xrefs_mangle["items"]

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
    # The recovered C reflects the real body, not a stub: the call to the helper
    # survived and the loop bound is present.
    assert "mangle(" in body, body
    assert "< 8" in body, body

    # mangle decompiles to its exact arithmetic. Asserting the operators and
    # constants -- not just that some text came back -- proves the decompiler
    # recovered the logic ((x ^ 0x41) + 7), the strongest content check here.
    decomp_mangle = client.decompile(
        fixture, project, entry_for["mangle"], timeout=_ANALYZE_TIMEOUT_S
    )
    assert "mangle" in str(decomp_mangle.get("function") or "")
    mangle_body = str(decomp_mangle.get("decompiled") or "")
    assert "0x41" in mangle_body, mangle_body
    assert "^" in mangle_body, mangle_body
    assert "+ 7" in mangle_body, mangle_body
