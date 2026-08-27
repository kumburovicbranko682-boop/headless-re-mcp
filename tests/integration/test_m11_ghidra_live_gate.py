"""M11 Ghidra live gate: headless import/analyze. skip≠pass when Ghidra missing.

Portable across the platforms Ghidra runs on. Windows analyses the committed PE
sample; elsewhere a tiny ELF is compiled on the fly so the gate exercises the
headless pipeline on this platform's own object format. This guards the
launcher-selection fix: Ghidra ships analyzeHeadless (Unix script) and
analyzeHeadless.bat (Windows batch) side by side, and picking the .bat first
made every Ghidra tool fail on Linux/macOS with a PermissionError before
launch. Configure via HEADLESS_RE_GHIDRA_HOME; the gate skips, never fails,
when Ghidra, Java, or a C compiler is absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _ghidra_client() -> GhidraClient:
    home = Settings.load().ghidra_home
    if home is None:
        pytest.skip(
            "HEADLESS_RE_GHIDRA_HOME not configured — Ghidra Gate not run (skip != pass)"
        )
    client = GhidraClient(home=home)
    if not client.available:
        pytest.skip(
            "Ghidra home has no analyzeHeadless or no Java — Gate not run (skip != pass)"
        )
    return client


def _ghidra_fixture(tmp_path: Path) -> Path:
    """A binary Ghidra can import on this platform.

    Windows uses the committed x64 PE sample; elsewhere any C toolchain builds a
    small ELF with a couple of real functions to analyse. Skips when the sample
    or a compiler is unavailable rather than failing.
    """
    if os.name == "nt":
        fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
        if not fixture.is_file():
            pytest.skip(f"fixture missing: {fixture}")
        return fixture

    compiler = next((name for name in ("cc", "gcc", "clang") if shutil.which(name)), None)
    if compiler is None:
        pytest.skip("no C compiler to build an ELF fixture — Ghidra Gate not run (skip != pass)")
    source = tmp_path / "ghidrafix.c"
    source.write_text(
        "#include <stdio.h>\n"
        "static int secret(int x){ return x * 3 + 1; }\n"
        "int helper(int a){ return secret(a) + a; }\n"
        'int main(void){ printf("%d\\n", helper(7)); return 0; }\n',
        encoding="utf-8",
    )
    binary = tmp_path / "ghidrafix.elf"
    try:
        built = subprocess.run(  # noqa: S603 - fixed local toolchain, fixed args
            [compiler, "-O0", "-o", str(binary), str(source)],
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"C compiler could not build an ELF fixture ({exc}) — skip != pass")
    if built.returncode != 0 or not binary.is_file():
        pytest.skip("C compiler produced no ELF fixture — Ghidra Gate not run (skip != pass)")
    return binary


@pytest.mark.integration
def test_m11_ghidra_live_headless_analyze(tmp_path: Path) -> None:
    """ghidra.analyze must run a real headless import/analyze on this OS.

    Before the launcher fix this failed on POSIX at spawn time -- the client
    exec'd the Windows analyzeHeadless.bat -- so a passing run proves the Unix
    launcher was selected, the JVM came up, Ghidra imported and analysed the
    binary, and -deleteProject removed the project afterwards.
    """
    client = _ghidra_client()
    if os.name != "nt":
        assert client.analyze is not None
        assert client.analyze.name == "analyzeHeadless", (
            f"POSIX must pick the Unix launcher, got {client.analyze.name}"
        )
    fixture = _ghidra_fixture(tmp_path)
    project = tmp_path / "ghidra-project"

    result = client.analyze_binary(fixture, project, timeout=600.0)

    assert result["project_dir"] == str(project)
    assert "deleted" in str(result["note"])
    excerpt = str(result.get("stdout_excerpt", ""))
    assert "succeeded" in excerpt.lower(), f"no success report in output: {excerpt[-500:]}"
    leftovers = list(project.glob("*.gpr")) + list(project.glob("*.rep"))
    assert not leftovers, f"-deleteProject left project files behind: {leftovers}"


@pytest.mark.integration
def test_m11_ghidra_live_export_tools_run_the_java_script(tmp_path: Path) -> None:
    """functions/symbols/xrefs/decompile must return via the Java post-script.

    Guards the Jython->Java rewrite: Ghidra 11.3 dropped Jython, so the old
    @runtime Jython post-script errored with "Ghidra was not started with
    PyGhidra" and every export came back empty on current Ghidra. The Java
    GhidraScript compiles headlessly with no extra runtime. Against the compiled
    ELF this checks the whole contract the client parses: named functions with
    entry/body_size, symbols with type, the real main->helper CALL edge from
    xrefs, and decompiled C naming the callee. POSIX only -- it needs the
    compiled ELF's own symbols, which the committed PE sample does not share.
    """
    if os.name == "nt":
        pytest.skip("export assertions target the compiled ELF fixture (skip != pass)")
    client = _ghidra_client()
    fixture = _ghidra_fixture(tmp_path)
    project = tmp_path / "ghidra-export"

    funcs = client.functions(fixture, project, limit=256, timeout=600.0)
    by_name = {str(item.get("name")): item for item in funcs.get("items", [])}
    assert "helper" in by_name, f"no helper among {sorted(by_name)}"
    helper = by_name["helper"]
    assert isinstance(helper.get("entry"), str) and helper["entry"]
    assert isinstance(helper.get("body_size"), int) and helper["body_size"] > 0

    symbols = client.symbols(fixture, project, limit=512, timeout=600.0)
    assert symbols.get("count", 0) >= 1
    assert all("type" in item for item in symbols.get("items", []))

    xrefs = client.xrefs(fixture, project, helper["entry"], timeout=600.0)
    call_edges = [
        item
        for item in xrefs.get("items", [])
        if str(item.get("type", "")).endswith("CALL") and item.get("to") == helper["entry"]
    ]
    assert call_edges, f"no CALL edge into helper@{helper['entry']}: {xrefs.get('items')}"

    decompiled = client.decompile(fixture, project, helper["entry"], timeout=600.0)
    assert decompiled.get("function") == "helper"
    assert decompiled.get("truncated") is False
    body = str(decompiled.get("decompiled", ""))
    assert "secret" in body, f"decompiled helper did not name its callee: {body!r}"
