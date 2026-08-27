"""Native search paths (ELF DT_RPATH/DT_RUNPATH, Mach-O LC_RPATH) vs binutils/llvm.

The baked-in library search path is a first-order hijack/supply-chain triage
fact: a writable or relative entry lets an attacker plant a library the loader
picks up. The other native gates cross-check the stdlib reader against radare2
on system binaries, but system binaries almost never carry a search path, so
the positive case needs binaries that do. For ELF this gate builds them with
the real toolchain: gcc links a probe with a known rpath (old tags) and another
with a known runpath (new tags), the session's tool-free facts must name those
exact paths, and readelf -d -- binutils' independent decoder of the same
dynamic table -- must agree entry for entry. For Mach-O the committed fixture
carries an LC_RPATH, and llvm-objdump --macho (LLVM's independent Mach-O
decoder, strict enough to have rejected the fixture's earlier 4-byte-aligned
load commands) must report the same path. skip != pass when a tool is missing;
gcc/readelf ship with the CI runner and llvm is installed on the Linux lane.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"

# readelf -d prints e.g. " 0x...f (RPATH)  Library rpath: [/opt/lib:$ORIGIN]".
_READELF_RPATH_RE = re.compile(r"\(RPATH\)\s+Library rpath: \[([^\]]*)\]")
_READELF_RUNPATH_RE = re.compile(r"\(RUNPATH\)\s+Library runpath: \[([^\]]*)\]")

# llvm-objdump --macho --all-headers prints the LC_BUILD_VERSION block as
# "cmd LC_BUILD_VERSION" followed by platform/sdk/minos lines.
_LLVM_BUILD_VERSION_RE = re.compile(
    r"cmd LC_BUILD_VERSION\n"
    r"\s*cmdsize \d+\n"
    r"\s*platform (\S+)\n"
    r"\s*sdk (\S+)\n"
    r"\s*minos (\S+)"
)

_PROBE_C = "int main(void) { return 0; }\n"
# $ORIGIN exercises the loader token passthrough; the reader must not expand it.
_SEARCH_PATH = "/opt/probe/lib:$ORIGIN/../lib"
_SEARCH_LIST = ["/opt/probe/lib", "$ORIGIN/../lib"]


def _compile_probe(gcc: str, tmp_path: Path, name: str, *link_args: str) -> Path:
    source = tmp_path / "probe.c"
    source.write_text(_PROBE_C)
    out = tmp_path / name
    result = subprocess.run(
        [gcc, str(source), "-o", str(out), *link_args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return out


def _readelf_paths(readelf: str, binary: Path) -> tuple[list[str] | None, list[str] | None]:
    """``(rpath, runpath)`` as readelf -d decodes them, None when a tag is absent."""
    result = subprocess.run(
        [readelf, "-d", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr

    def parse(pattern: re.Pattern[str]) -> list[str] | None:
        match = pattern.search(result.stdout)
        if match is None:
            return None
        return [part for part in match.group(1).split(":") if part]

    return parse(_READELF_RPATH_RE), parse(_READELF_RUNPATH_RE)


def _session_native(service: AnalysisService, binary: Path) -> tuple[str, dict[str, Any]]:
    created = service.create_session(str(binary))
    assert created.ok, created.error
    session = created.data["session"]
    assert session["target"] == "native"
    return str(session["id"]), cast(dict[str, Any], session["metadata"]["native"])


@pytest.mark.integration
def test_elf_search_paths_agree_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — toolchain gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — toolchain gate not run (skip != pass)")

    # --disable-new-dtags asks the linker for the old tag, --enable-new-dtags
    # for the new one; together they cover both loader-precedence variants.
    rpath_bin = _compile_probe(
        gcc, tmp_path, "probe_rpath", f"-Wl,--disable-new-dtags,-rpath,{_SEARCH_PATH}"
    )
    runpath_bin = _compile_probe(
        gcc, tmp_path, "probe_runpath", f"-Wl,--enable-new-dtags,-rpath,{_SEARCH_PATH}"
    )

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, rpath_facts = _session_native(service, rpath_bin)
        sessions.append(session_id)
        session_id, runpath_facts = _session_native(service, runpath_bin)
        sessions.append(session_id)

        # The tool-free reader names the exact paths the link line requested.
        assert rpath_facts["rpath"] == _SEARCH_LIST
        assert "runpath" not in rpath_facts
        assert runpath_facts["runpath"] == _SEARCH_LIST
        assert "rpath" not in runpath_facts

        # readelf decodes the same dynamic table independently; both views of
        # both binaries must agree, including which tag is absent.
        assert _readelf_paths(readelf, rpath_bin) == (_SEARCH_LIST, None)
        assert _readelf_paths(readelf, runpath_bin) == (None, _SEARCH_LIST)

        # The freshly linked probes also exercise the rest of the dynamic-table
        # reading on real toolchain output rather than hand-built fixtures.
        for facts in (rpath_facts, runpath_facts):
            assert facts["linking"] == "dynamic"
            assert any(name.startswith("libc.so") for name in facts["needed"])
            assert facts["entry"] > 0
    finally:
        for session_id in sessions:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_rpath_agrees_with_llvm_objdump() -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O rpath gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    # llvm-objdump validates every load command before it prints anything (it
    # is what caught the fixture's earlier 4-byte-aligned commands), so a zero
    # exit is itself a well-formedness check on the committed image.
    result = subprocess.run(
        [objdump, "--macho", "--rpaths", str(_MACHO_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    # Output is the file name line, then one search path per line.
    llvm_rpaths = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.strip().endswith(":")
    ]
    assert llvm_rpaths, result.stdout

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, _MACHO_FIXTURE)
        # The tool-free LC_RPATH walk and LLVM's decoder name the same paths,
        # verbatim (no @loader_path expansion) and in the same order.
        assert native["rpath"] == llvm_rpaths == ["@loader_path/../Frameworks"]
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_build_version_agrees_with_llvm_objdump() -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O platform gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    result = subprocess.run(
        [objdump, "--macho", "--all-headers", str(_MACHO_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    match = _LLVM_BUILD_VERSION_RE.search(result.stdout)
    assert match, result.stdout
    llvm_platform, llvm_sdk, llvm_minos = match.groups()

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, _MACHO_FIXTURE)
        # The tool-free LC_BUILD_VERSION walk and LLVM's decoder answer the
        # Apple-binary identity questions with the same strings.
        assert native["platform"] == llvm_platform == "macos"
        assert native["min_os"] == llvm_minos == "13.0"
        assert native["sdk"] == llvm_sdk == "14.2"
    finally:
        if session_id is not None:
            service.close_session(session_id)
