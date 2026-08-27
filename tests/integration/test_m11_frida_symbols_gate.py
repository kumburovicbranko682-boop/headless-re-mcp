"""M11 Frida symbols gate: resolve a caller-defined symbol and read its bytes.

The existing Frida live gate proves attach/modules/exports/memory_read, but
every read targets libc: it shows the machinery works, not that Frida resolves
the *analyst's own* symbols to the *right* bytes. That round trip -- name to
runtime address to memory content -- is the whole point of dynamic analysis and
is exactly what an agent draws conclusions from.

This gate builds a tiny shared object with known ground truth: a data symbol
initialised to a fixed 16-byte magic and an exported function. It loads the
library into a process we own, attaches with Frida, resolves both exports and
reads them back, asserting the data symbol returns the exact magic (arch
independent) and the function's memory starts with a real prologue. It is the
dynamic counterpart of the r2/Ghidra static gates: same idea, proven at runtime.
skip != pass when frida or a C compiler is missing.
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

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# A data symbol with a fixed value and an exported function. Default ELF
# visibility publishes both in the .so's dynamic symbol table.
_SRC = r"""
unsigned char gate_magic[16] = {
    0xDE,0xAD,0xBE,0xEF,0x13,0x37,0xC0,0xDE,
    0xCA,0xFE,0xBA,0xBE,0x0B,0xAD,0xF0,0x0D
};
int gate_reveal(int x) { return (x ^ 0x41) + 7; }
"""
_MAGIC_HEX = "deadbeef1337c0decafebabe0badf00d"


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
def test_m11_frida_resolves_and_reads_a_caller_defined_symbol(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("Linux-native frida symbols gate: POSIX only (skip != pass)")
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — symbols Gate not run (skip != pass)")
    so = _build_shared_object(tmp_path)
    if so is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the .so fixture (skip != pass)")

    # Host process we own keeps the library resident; attaching to a descendant
    # is allowed even under yama ptrace_scope=1.
    host = subprocess.Popen(
        [sys.executable, "-c", f"import ctypes,time; ctypes.CDLL({str(so)!r}); time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # The per-session pid allow-list is enforced before anything runs.
        denied = None
        try:
            client.modules(host.pid, allowed_pid=host.pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        assert client.attach(host.pid, allowed_pid=host.pid).get("attached") is True

        # Wait for the loader to map our library, then find its frida name.
        module_name: str | None = None
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            mods = client.modules(host.pid, allowed_pid=host.pid, limit=256)
            module_name = next(
                (str(m["name"]) for m in mods["modules"] if "libgate" in str(m.get("name", ""))),
                None,
            )
            if module_name is not None:
                break
            time.sleep(0.2)
        assert module_name is not None, "libgate.so never appeared among frida modules"

        # Both caller-defined symbols resolve as exports of that module.
        exports = client.exports(host.pid, module_name, allowed_pid=host.pid, limit=64)
        assert exports.get("found") is True
        assert exports.get("count", 0) >= 2
        by_name = {str(e.get("name")): e for e in exports["exports"]}
        assert "gate_magic" in by_name, list(by_name)
        assert "gate_reveal" in by_name, list(by_name)
        assert all(
            str(by_name[n]["address"]).startswith("0x") for n in ("gate_magic", "gate_reveal")
        )
        assert str(by_name["gate_reveal"].get("type")) == "function"

        # The data symbol reads back as the exact magic we compiled in -- a
        # name-to-address-to-bytes round trip on our own binary, arch independent.
        magic_addr = int(by_name["gate_magic"]["address"], 16)
        magic = client.memory_read(host.pid, magic_addr, 16, allowed_pid=host.pid)
        assert magic.get("encoding") == "hex"
        assert magic.get("data") == _MAGIC_HEX, magic

        # The function symbol's memory is real code of the length requested. On
        # x86-64 the -O0 prologue is the canonical frame setup (push rbp; mov
        # rbp, rsp); elsewhere we still prove the bytes are mapped and readable.
        fn_addr = int(by_name["gate_reveal"]["address"], 16)
        code = client.memory_read(host.pid, fn_addr, 8, allowed_pid=host.pid)
        data = str(code.get("data") or "")
        assert len(data) == 16, code  # 8 bytes as hex
        assert all(c in "0123456789abcdef" for c in data), code
        if platform.machine().lower() in {"x86_64", "amd64"}:
            assert data.startswith("554889e5"), data  # push rbp; mov rbp, rsp
    finally:
        host.terminate()
        try:
            host.wait(timeout=5)
        except subprocess.TimeoutExpired:
            host.kill()
