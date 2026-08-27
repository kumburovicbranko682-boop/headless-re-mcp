"""M11 ELF session ARM labelling: a cross-arch ELF is named, not just opened.

Adding ELF as a session target first landed with only x86/x64 labelled; an ARM
or AArch64 ELF opened but carried architecture=None. The Architecture enum now
has ARM and ARM64 members, so a foreign-arch ELF session states its machine.

This gate builds real AArch64 and ARM32 ELFs with a cross compiler and asserts
two things at once, per architecture: create_session classifies the target ELF
and labels it with the matching machine (arm64 / arm), and the session is not a
dead label -- radare2 reads the foreign-arch image through the service and
recovers the named functions. So the label is both accurate and backed by a
working analysis session. skip != pass when radare2/rizin or the ARM cross
compilers are missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_SRC = """
#include <stdio.h>

__attribute__((noinline))
static int mangle(int x) { return (x ^ 0x5a) + 0x1337; }

__attribute__((noinline))
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    if (acc == 0x2b67) puts("arm-elf-label-marker");
    return acc;
}

int main(int argc, char **argv) { return argc > 1 ? crackme_check(argv[1]) : 0; }
"""

# (cross compiler, expected architecture label) for each ARM ELF variant.
_VARIANTS = [
    ("aarch64-linux-gnu-gcc", "arm64"),
    ("arm-linux-gnueabihf-gcc", "arm"),
]


def _build(compiler: str, dest: Path) -> Path | None:
    src = dest / "f.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "f.bin"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local cross compiler
            [compiler, "-O0", "-fno-inline", "-o", str(binary), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return binary if binary.is_file() else None


@pytest.mark.integration
@pytest.mark.parametrize(("compiler", "expected_arch"), _VARIANTS)
def test_m11_elf_session_labels_and_analyzes_arm(compiler: str, expected_arch: str) -> None:
    if shutil.which("r2") is None and shutil.which("rizin") is None:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} missing — cannot build the ARM ELF (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build(compiler, Path(tmp))
        assert binary is not None

        service = AnalysisService(Settings.load())
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session = created.data["session"]

        # The new capability: the ELF is classified and carries its real ARM
        # machine label, where it used to open with architecture=None.
        assert session["target"] == "elf", session
        assert session["architecture"] == expected_arch, session
        sid = str(session["id"])

        # The label is not a dead field: radare2 opens and analyzes the
        # foreign-arch image through the same session and finds the functions,
        # so the session is genuinely usable, not merely classified.
        assert service.r2_open(sid).ok
        funcs = service.r2_functions(sid, timeout=90.0)
        assert funcs.ok and funcs.data is not None, funcs.error
        assert funcs.data.get("parsed") is True
        names = {str(f.get("name")) for f in funcs.data["items"]}
        assert any("crackme_check" in n for n in names), sorted(names)
        assert any("mangle" in n for n in names), sorted(names)
