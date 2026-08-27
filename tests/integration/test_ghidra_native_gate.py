"""Ghidra headless gate on a native ELF. skip != pass when Ghidra is absent.

The Ghidra line had *no* live coverage: every ghidra.* test drove mocked
subprocesses, so two real breakages hid behind green runs. First, Ghidra
removed its bundled Jython in 11.4, so the former ``@runtime Jython``
post-script silently stopped running -- analyzeHeadless reported success, wrote
no JSON, and every ghidra tool degraded to "export JSON missing after
postScript" on every current Ghidra. Second, the native target kind made ELF
sessions reachable at all (before it, an ELF was classified PE and rejected).

This drives the real ``analyzeHeadless`` against a tiny ELF compiled by the
system C compiler: ``ghidra.functions`` must list the fixture's own functions
and ``ghidra.decompile`` must recover a named call from one of them, proving the
Java post-script both loads and reads the program. A PE-only tool on the same
session must still be refused, so the native kind does not loosen the debugger
guard. Skips honestly when Ghidra (``HEADLESS_RE_GHIDRA_HOME``) or a C compiler
is not present; a real headless import/analyze takes a few seconds, no network.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# Distinct, non-inlined functions with a clear call graph: gate_root calls
# gate_leaf directly, so a correct decompilation of gate_root must name it.
# Not stripped, so Ghidra recovers the symbol names rather than FUN_xxxx.
_ELF_FIXTURE_C = """
#include <stdio.h>

__attribute__((noinline)) int gate_leaf(int x) { return (x ^ 0x5a) + 3; }

__attribute__((noinline)) int gate_mid(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += gate_leaf(i);
    return total;
}

__attribute__((noinline)) int gate_root(int n) {
    return gate_mid(n) + gate_leaf(n);
}

int main(void) {
    volatile int result = gate_root(11);
    printf("ghidra-gate %d\\n", result);
    return 0;
}
"""


def _build_elf_fixture(tmp_path: Path) -> Path:
    compiler = next(
        (shutil.which(name) for name in ("cc", "gcc", "clang") if shutil.which(name)),
        None,
    )
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) to build a Ghidra ELF fixture (skip != pass)")
    source = tmp_path / "ghidra_gate_fixture.c"
    source.write_text(_ELF_FIXTURE_C, encoding="utf-8")
    out = tmp_path / "ghidra_gate_fixture"
    # -no-pie fixes the load base so addresses are stable; -O0 keeps the helpers
    # as separate functions. Neither is required for the export under test.
    for extra in (["-no-pie"], []):
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [compiler, "-O0", *extra, "-o", str(out), str(source)],
            capture_output=True,
            text=True,
            timeout=120.0,
        )
        if completed.returncode == 0 and out.is_file():
            return out
    pytest.skip(
        f"C compiler present but could not build the Ghidra ELF fixture (skip != pass): "
        f"{completed.stderr.strip()[:400]}"
    )


@pytest.mark.integration
def test_ghidra_functions_and_decompile_on_a_native_elf(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    client = GhidraClient(home=getattr(settings, "ghidra_home", None))
    if not client.available:
        pytest.skip(
            "Ghidra analyzeHeadless not configured (set HEADLESS_RE_GHIDRA_HOME) — skip != pass"
        )
    fixture = _build_elf_fixture(tmp_path)

    service = AnalysisService(settings)
    try:
        created = service.create_session(str(fixture))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        # The native target kind is what makes this reachable: an ELF used to be
        # classified PE and rejected as "not a PE file" before a session existed.
        assert created.data["session"]["target"] == "native"

        funcs = service.ghidra_functions(session_id, limit=256, timeout=300.0)
        assert funcs.ok, funcs.error
        assert funcs.data["count"] >= 1
        by_name = {str(item.get("name", "")): item for item in funcs.data["items"]}
        assert "main" in by_name, sorted(by_name)
        assert "gate_root" in by_name, sorted(by_name)
        # Ghidra items carry entry + body_size, not address/size.
        assert by_name["gate_root"]["entry"]
        assert int(by_name["gate_root"]["body_size"]) > 0

        # Decompile gate_root: it calls gate_leaf directly, and the binary is not
        # stripped, so the recovered C must name that call -- proof the Java
        # post-script both loaded and actually read the analysed program, not
        # merely that analyzeHeadless ran.
        entry = str(by_name["gate_root"]["entry"])
        decompiled = service.ghidra_decompile(session_id, entry, timeout=300.0)
        assert decompiled.ok, decompiled.error
        assert decompiled.data["found"] is True
        assert decompiled.data["function"] == "gate_root"
        body = str(decompiled.data["decompiled"])
        assert body.strip(), "decompilation came back empty"
        assert "gate_leaf" in body, body

        # A PE-only tool must reject the native session with target_mismatch,
        # not analyse it -- the native kind does not loosen the debugger guard.
        launched = service.dynamic_launch(session_id)
        assert not launched.ok
        assert launched.error.code == "target_mismatch"
    finally:
        service.close_all()
