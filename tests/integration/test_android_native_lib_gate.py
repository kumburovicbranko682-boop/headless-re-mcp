"""Android native-library static gate: r2 on a real JNI-shaped shared object.

Android reverse engineering does not stop at the DEX. Every non-trivial app
ships native code as ``lib/<abi>/*.so`` (an ELF shared object), and the first
move is to enumerate the ``Java_...`` JNI entry points it exports, then read
their disassembly, imports and strings. The committed ``sample.apk`` only
carries placeholder ``.so`` bytes (the androguard gate reads zip paths, never
loads them), and the existing r2 gate analyses an *executable*, so r2's
**exports** path (``iEj``) on a real ``ET_DYN`` library had no live coverage.

This compiles a real shared object on the fly -- a JNI-named export plus two
native helpers, a libc import and an embedded string, the exact shape of an
Android native library -- and drives the r2 backend across open / exports /
functions / imports / strings / disasm. It is x86-64 for buildability, but r2's
read surface is identical for an arm64 device library.

Skips honestly when r2/rizin or a C compiler is absent -- skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "HEADLESS_RE_SO_MARKER"
_JNI_EXPORT = "Java_com_headlessre_sample_MainActivity_stringFromJNI"
_C_SOURCE = textwrap.dedent(
    f"""
    #include <string.h>

    static const char *SECRET = "{_MARKER}";

    int native_add(int a, int b) {{ return a + b; }}

    int native_compute(int x) {{ return native_add(x, 42) + (int)strlen(SECRET); }}

    const char *{_JNI_EXPORT}(void *env, void *thiz) {{
        (void)env;
        (void)thiz;
        return SECRET;
    }}
    """
)


def _compile_so(dest_dir: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = dest_dir / "libsample.c"
    src.write_text(_C_SOURCE, encoding="utf-8")
    out = dest_dir / "libsample.so"
    args = [compiler, "-shared", "-fPIC", "-O0", "-o", str(out), str(src)]
    if subprocess.run(args, capture_output=True).returncode == 0 and out.is_file():
        return out
    return None


def _basenames(names: list[str]) -> set[str]:
    """r2 labels functions sym.native_add; compare on the last dotted component."""
    return {str(name).split(".")[-1] for name in names if name}


def _va(item: dict) -> int | None:
    address = item.get("address")
    if isinstance(address, dict) and isinstance(address.get("va"), int):
        return int(address["va"])
    va = item.get("vaddr")
    return int(va) if isinstance(va, int) else None


@dataclass
class _Harness:
    client: R2Client
    so: Path
    exports: list[dict]
    export_va: dict[str, int] = field(default_factory=dict)


@pytest.fixture(scope="module")
def _harness(tmp_path_factory: pytest.TempPathFactory) -> _Harness:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — Android Native Gate not run (skip != pass)")
    root = tmp_path_factory.mktemp("android-native")
    so = _compile_so(root)
    if so is None:
        pytest.skip(
            "no C compiler to build the .so fixture — Android Native Gate not run (skip != pass)"
        )
    exports = client.run(so, ["iEj"], timeout=60.0).get("items", [])
    export_va = {
        str(item.get("realname") or item.get("name")): va
        for item in exports
        if (va := _va(item)) is not None
    }
    return _Harness(client=client, so=so, exports=exports, export_va=export_va)


@pytest.mark.integration
def test_open_reads_the_shared_object_header(_harness: _Harness) -> None:
    opened = _harness.client.open(_harness.so, timeout=60.0)
    assert opened["opened"] is True
    assert opened["info"]
    info = _harness.client.run(_harness.so, ["iI"], timeout=60.0)["raw"].lower()
    # r2 parsed the ELF container, not just stat()'d the file.
    assert "elf" in info
    assert "elf64" in info


@pytest.mark.integration
def test_exports_list_the_jni_entrypoint(_harness: _Harness) -> None:
    names = {str(item.get("realname") or item.get("name")) for item in _harness.exports}
    # The JNI entry point and both native helpers are exported from .dynsym.
    assert _JNI_EXPORT in names, names
    assert {"native_add", "native_compute"} <= names, names
    jni = next(
        item
        for item in _harness.exports
        if str(item.get("realname") or item.get("name")) == _JNI_EXPORT
    )
    # An export, not an import, and it carries a resolvable virtual address.
    assert jni.get("is_imported") is False
    assert _va(jni) is not None and _va(jni) > 0


@pytest.mark.integration
def test_functions_include_the_native_helpers(_harness: _Harness) -> None:
    functions = _harness.client.run(_harness.so, ["aa", "aflj"], timeout=60.0)
    assert functions["parsed"] is True
    assert functions["count"] >= 1
    names = [item.get("name") for item in functions["items"]]
    assert {"native_add", "native_compute"} <= _basenames(names), names


@pytest.mark.integration
def test_imports_list_libc_symbols(_harness: _Harness) -> None:
    result = _harness.client.run(_harness.so, ["iij"], timeout=60.0)
    assert result["parsed"] is True
    names = _basenames([str(item.get("name") or "") for item in result.get("items", [])])
    # native_compute calls strlen, so the dynamic import must be listed.
    assert "strlen" in names, names


@pytest.mark.integration
def test_strings_find_the_embedded_marker(_harness: _Harness) -> None:
    result = _harness.client.run(_harness.so, ["izj"], timeout=60.0)
    assert result["parsed"] is True
    strings = [str(item.get("string", "")) for item in result.get("items", [])]
    assert any(_MARKER in value for value in strings), strings


@pytest.mark.integration
def test_disasm_decodes_the_jni_export(_harness: _Harness) -> None:
    va = _harness.export_va.get(_JNI_EXPORT)
    assert va is not None, f"no VA for {_JNI_EXPORT} among {sorted(_harness.export_va)}"
    result = _harness.client.disasm(_harness.so, va, count=8, timeout=60.0)
    assert result["parsed"] is True
    assert result["count"] >= 1
    opcodes = [str(item.get("opcode") or item.get("disasm") or "") for item in result["items"]]
    assert any(opcodes), opcodes
    assert result.get("address_va") == va
