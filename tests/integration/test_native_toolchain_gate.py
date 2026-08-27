"""ELF search paths (DT_RPATH/DT_RUNPATH), cross-validated against readelf.

The baked-in library search path is a first-order hijack/supply-chain triage
fact: a writable or relative entry lets an attacker plant a library the loader
picks up. The other native gates cross-check the stdlib reader against radare2
on system binaries, but system binaries almost never carry a search path, so
the positive case needs a binary that does. This gate builds one with the real
toolchain: gcc links a probe with a known rpath (old tags) and another with a
known runpath (new tags), the session's tool-free facts must name those exact
paths, and readelf -d -- binutils' independent decoder of the same dynamic
table -- must agree entry for entry. skip != pass when gcc or readelf is
missing; both are present on the Linux CI lane, so it runs there.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.core.service import AnalysisService

# readelf -d prints e.g. " 0x...f (RPATH)  Library rpath: [/opt/lib:$ORIGIN]".
_READELF_RPATH_RE = re.compile(r"\(RPATH\)\s+Library rpath: \[([^\]]*)\]")
_READELF_RUNPATH_RE = re.compile(r"\(RUNPATH\)\s+Library runpath: \[([^\]]*)\]")

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
