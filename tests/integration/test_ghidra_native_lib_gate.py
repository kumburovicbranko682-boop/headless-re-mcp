"""Ghidra native-library decompile gate: JNI .so triaged to C, not just ELF exe.

The r2 native-lib gate (``test_android_native_lib_gate.py``) triages an Android
JNI shared object -- exports, imports, disassembly. The next step a reverser
takes is *decompilation*, and that is Ghidra's job. The existing Ghidra gate
only ever ran on an ELF executable, so Ghidra on a real ``ET_DYN`` shared object
with a ``Java_...`` JNI entrypoint was never exercised here.

This compiles the same JNI-shaped ``.so`` (a ``Java_...stringFromJNI`` export, a
``native_add`` / ``native_compute`` pair, a libc ``strlen`` import, an embedded
string) and drives ``functions`` / ``symbols`` / ``xrefs`` / ``decompile``
against real Ghidra. The decompile assertions are the point: the recovered C for
``native_compute`` must show the calls it makes into ``native_add`` and
``strlen``, and the JNI export must decompile to a body that returns the string
symbol -- proof the decompiler resolved the call graph and data references in a
shared object, not merely that analysis ran. Built x86-64 for portability; the
decompiler path is identical for an arm64 device library.

Skips honestly when Ghidra (``HEADLESS_RE_GHIDRA_HOME``), a JRE, or a C compiler
is absent -- skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

_MARKER = "HEADLESS_RE_SO_MARKER"
_JNI_EXPORT = "Java_com_headlessre_sample_MainActivity_stringFromJNI"
_C_SOURCE = textwrap.dedent(
    f"""
    #include <string.h>
    static const char *SECRET = "{_MARKER}";
    int native_add(int a, int b) {{ return a + b; }}
    int native_compute(int x) {{ return native_add(x, 42) + (int) strlen(SECRET); }}
    const char *{_JNI_EXPORT}(void *env, void *thiz) {{
        (void) env;
        (void) thiz;
        return SECRET;
    }}
    """
)


def _ghidra_home() -> Path | None:
    return Settings.load().ghidra_home


def _compile_so(dest_dir: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = dest_dir / "native.c"
    src.write_text(_C_SOURCE, encoding="utf-8")
    out = dest_dir / "libnative.so"
    result = subprocess.run(
        [compiler, "-shared", "-fPIC", "-O0", "-o", str(out), str(src)],
        capture_output=True,
    )
    return out if result.returncode == 0 and out.is_file() else None


@dataclass
class _Harness:
    client: GhidraClient
    so: Path
    projects: Path
    entries: dict[str, str]
    functions: dict

    def project(self, name: str) -> Path:
        path = self.projects / name
        path.mkdir(parents=True, exist_ok=True)
        return path


@pytest.fixture(scope="module")
def _harness(tmp_path_factory: pytest.TempPathFactory) -> _Harness:
    home = _ghidra_home()
    if home is None:
        pytest.skip(
            "HEADLESS_RE_GHIDRA_HOME not set — Ghidra native-lib Gate not run (skip != pass)"
        )
    client = GhidraClient(home=home)
    if not client.available:
        pytest.skip("Ghidra analyzeHeadless / JRE not available — Gate not run (skip != pass)")
    root = tmp_path_factory.mktemp("ghidra-so")
    so = _compile_so(root)
    if so is None:
        pytest.skip("no C compiler to build the .so fixture — Gate not run (skip != pass)")
    functions = client.functions(so, root / "proj-fn", limit=256, timeout=300.0)
    entries = {item["name"]: item["entry"] for item in functions["items"]}
    return _Harness(client=client, so=so, projects=root, entries=entries, functions=functions)


@pytest.mark.integration
def test_functions_list_the_jni_export_and_native_helpers(_harness: _Harness) -> None:
    assert _harness.functions["count"] >= 3
    names = set(_harness.entries)
    assert {"native_add", "native_compute", _JNI_EXPORT} <= names, sorted(names)


@pytest.mark.integration
def test_symbols_include_the_jni_export(_harness: _Harness) -> None:
    symbols = _harness.client.symbols(_harness.so, _harness.project("proj-sym"), timeout=300.0)
    names = {item["name"] for item in symbols["items"]}
    assert {"native_add", "native_compute", _JNI_EXPORT} <= names, sorted(names)


@pytest.mark.integration
def test_xrefs_find_the_call_into_native_add(_harness: _Harness) -> None:
    entry = _harness.entries.get("native_add")
    assert entry, "functions export did not surface native_add"
    xrefs = _harness.client.xrefs(_harness.so, _harness.project("proj-xref"), entry, timeout=300.0)
    # native_compute calls native_add, so at least one reference must land on it.
    assert xrefs["count"] >= 1
    assert all("from" in item and "to" in item for item in xrefs["items"])


@pytest.mark.integration
def test_decompile_native_compute_shows_its_calls(_harness: _Harness) -> None:
    entry = _harness.entries.get("native_compute")
    assert entry, "functions export did not surface native_compute"
    result = _harness.client.decompile(
        _harness.so, _harness.project("proj-dec-compute"), entry, timeout=300.0
    )
    assert result.get("function") == "native_compute"
    decompiled = result.get("decompiled", "")
    # The recovered C must show both calls native_compute makes -- a decompiler
    # that only listed the function without resolving its body would not.
    assert "native_add" in decompiled, decompiled
    assert "strlen" in decompiled, decompiled
    assert result.get("truncated") is False


@pytest.mark.integration
def test_decompile_the_jni_export_returns_the_string(_harness: _Harness) -> None:
    entry = _harness.entries.get(_JNI_EXPORT)
    assert entry, "functions export did not surface the JNI entrypoint"
    result = _harness.client.decompile(
        _harness.so, _harness.project("proj-dec-jni"), entry, timeout=300.0
    )
    assert result.get("function") == _JNI_EXPORT
    decompiled = result.get("decompiled", "")
    # The JNI stub returns the embedded string; Ghidra recovers the data symbol
    # and renders the return, so both tokens appear in the decompiled body.
    assert "return" in decompiled, decompiled
    assert "SECRET" in decompiled, decompiled
