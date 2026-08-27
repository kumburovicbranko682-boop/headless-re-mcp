"""M11 dynamic<->static gate: Frida's runtime bytes agree with r2's disassembly.

The WASM gate chains one dynamic capability into a static one; this does the
same across the native RE lines. r2 reads a function's machine code statically,
Frida reads the very same function out of a live process, and this gate asserts
the two agree byte for byte. Because it compares two backends' views of the
*same* compiled binary rather than hard-coded opcodes, the check is
compiler- and version-independent: whatever the toolchain emitted, static and
dynamic must see identical bytes at the entry (the compared region is the
relocation-free prologue/arithmetic, so the load address does not matter).

It builds a shared object with a known function, locates it with r2 (proving
function recovery), reconstructs its leading bytes from the disassembly, then
attaches Frida to a process holding the library and reads the same bytes back.
skip != pass when frida, radare2/rizin or a C compiler is missing.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida.client import FridaClient
from headless_re_mcp.backends.r2.client import R2Client

_SRC = r"""
unsigned char gate_magic[16] = {
    0xDE,0xAD,0xBE,0xEF,0x13,0x37,0xC0,0xDE,
    0xCA,0xFE,0xBA,0xBE,0x0B,0xAD,0xF0,0x0D
};
int gate_reveal(int x) { return (x ^ 0x41) + 7; }
"""
_COMPARE_BYTES = 12  # inside the ~18-byte body; relocation-free region.


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


def _build_shared_object(dest: Path) -> Path | None:
    compiler = _compiler()
    if compiler is None:
        return None
    src = dest / "gate.c"
    src.write_text(_SRC, encoding="utf-8")
    so = dest / "libgate.so"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local compiler
            [compiler, "-O0", "-shared", "-fPIC", "-o", str(so), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return so if so.is_file() else None


@pytest.mark.integration
def test_m11_frida_runtime_bytes_match_r2_disassembly(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("Linux-native dynamic<->static gate: POSIX only (skip != pass)")
    r2 = R2Client()
    if not r2.available:
        pytest.skip("radare2/rizin not installed — cross-check Gate not run (skip != pass)")
    frida = FridaClient()
    if not frida.available:
        pytest.skip("frida Python module not installed — cross-check Gate not run (skip != pass)")
    so = _build_shared_object(tmp_path)
    if so is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the .so fixture (skip != pass)")

    # Static side: r2 recovers gate_reveal and hands back its instruction bytes.
    funcs = r2.run(so, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    reveal = next(
        (f for f in funcs["items"] if "gate_reveal" in str(f.get("name"))), None
    )
    assert reveal is not None, [f.get("name") for f in funcs["items"]]
    offset = reveal.get("offset")
    assert isinstance(offset, int)

    disasm = r2.disasm(so, offset, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    static_hex = "".join(str(item.get("bytes") or "") for item in disasm["items"])
    assert len(static_hex) >= _COMPARE_BYTES * 2, disasm["items"]
    static_head = static_hex[: _COMPARE_BYTES * 2].lower()

    # The recovered instructions really are gate_reveal's arithmetic on x86-64;
    # elsewhere the byte-level agreement below still stands on its own.
    if platform.machine().lower() in {"x86_64", "amd64"}:
        ops = " \n".join(str(item.get("disasm", "")) for item in disasm["items"])
        assert "0x41" in ops, ops
        assert "xor" in ops, ops

    # Dynamic side: Frida reads the same function out of a live process.
    host = subprocess.Popen(
        [sys.executable, "-c", f"import ctypes,time; ctypes.CDLL({str(so)!r}); time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.6)
        assert host.poll() is None, "host exited early"
        assert frida.attach(host.pid, allowed_pid=host.pid).get("attached") is True

        module_name: str | None = None
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            mods = frida.modules(host.pid, allowed_pid=host.pid, limit=256)
            module_name = next(
                (str(m["name"]) for m in mods["modules"] if "libgate" in str(m.get("name", ""))),
                None,
            )
            if module_name is not None:
                break
            time.sleep(0.2)
        assert module_name is not None, "libgate.so never appeared among frida modules"

        exports = frida.exports(host.pid, module_name, allowed_pid=host.pid, limit=64)
        by_name = {str(e.get("name")): e for e in exports["exports"]}
        assert "gate_reveal" in by_name, list(by_name)
        fn_addr = int(by_name["gate_reveal"]["address"], 16)
        read = frida.memory_read(host.pid, fn_addr, _COMPARE_BYTES, allowed_pid=host.pid)
        dynamic_head = str(read.get("data") or "").lower()

        # The core claim: the static disassembler and the live process see the
        # exact same machine code for the exact same function.
        assert len(dynamic_head) == _COMPARE_BYTES * 2, read
        assert dynamic_head == static_head, {
            "static": static_head,
            "dynamic": dynamic_head,
        }
    finally:
        host.terminate()
        try:
            host.wait(timeout=5)
        except subprocess.TimeoutExpired:
            host.kill()
