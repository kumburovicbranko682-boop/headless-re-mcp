"""Cross-validate the tool-free Go build-info reader against ``go version -m``.

A session over a Go-compiled binary now carries its ``.go.buildinfo`` stamp --
the toolchain version, the main package/module path and the build settings
(GOOS/GOARCH, -buildmode, CGO_ENABLED) -- a first-order triage fact as a
growing share of malware ships as Go. The magic scan, the inline varint
decode and the sentinel-stripped module parse are all ours, so the Go tool
itself referees them: ``go version -m`` reads the same blob through the
standard library's ``debug/buildinfo`` and prints every field this compares
against, field for field.

The reader is cross-format by construction -- the inline blob is identical in
an ELF, a Mach-O and a PE -- so the gate compiles the same program for linux,
darwin and windows and checks all three, the ELF/Mach-O landing on the native
metadata and the PE on the pe metadata. ``go version -m`` is pure parsing, so
one Linux host reads the cross-compiled darwin and windows binaries too.

The Go toolchain is preinstalled on the CI runner; skip != pass -- the gate
skips, naming the missing tool, only when ``go`` is unavailable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_MAIN_GO = 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hi") }\n'
_GO_MOD = "module example.com/tool\n\ngo 1.20\n"


def _go() -> str | None:
    return shutil.which("go")


def _build(go: str, workdir: Path, out: Path, *, goos: str, goarch: str) -> None:
    (workdir / "main.go").write_text(_MAIN_GO)
    (workdir / "go.mod").write_text(_GO_MOD)
    env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "GOFLAGS": "-mod=mod", "CGO_ENABLED": "0"}
    # A fresh module cache-free build in a temp dir; -mod=mod so the toolchain
    # does not insist on a checked-in go.sum for the stdlib-only program.
    result = subprocess.run(
        [go, "build", "-o", str(out), "."],
        cwd=str(workdir),
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    assert result.returncode == 0, result.stderr


def _go_version_m(go: str, binary: Path) -> dict[str, Any]:
    """The referee's view: ``go version -m`` decoded to the reader's fact shape."""
    result = subprocess.run(
        [go, "version", "-m", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    version_match = re.search(r":\s+(go\S+)", lines[0])
    assert version_match, lines[0]
    facts: dict[str, Any] = {"version": version_match.group(1)}
    settings: dict[str, str] = {}
    for line in lines[1:]:
        parts = line.strip("\t").split("\t")
        if len(parts) >= 2 and parts[0] == "path":
            facts["path"] = parts[1]
        elif len(parts) >= 3 and parts[0] == "mod":
            facts["main_module"] = parts[1]
            facts["main_module_version"] = parts[2]
        elif len(parts) >= 2 and parts[0] == "build":
            key, sep, value = parts[1].partition("=")
            if sep:
                settings[key] = value
    if settings:
        facts["settings"] = settings
    return facts


def _session_go(binary: Path) -> dict[str, Any]:
    """The Go block off the session, whether the binary classified native or PE."""
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        metadata = created.data["session"]["metadata"]
        block = metadata.get("native") or metadata.get("pe") or {}
        go = block.get("go")
        assert isinstance(go, dict), f"session carried no go block: {metadata.keys()}"
        return go
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize(
    ("goos", "goarch", "suffix"),
    [
        ("linux", "amd64", "elf"),
        ("darwin", "arm64", "macho"),
        ("windows", "amd64", "exe"),
    ],
)
def test_go_buildinfo_agrees_with_go_version_m(
    tmp_path: Path, goos: str, goarch: str, suffix: str
) -> None:
    go = _go()
    if go is None:
        pytest.skip("go toolchain not installed — Go build-info gate not run (skip != pass)")

    binary = tmp_path / f"tool.{suffix}"
    _build(go, tmp_path, binary, goos=goos, goarch=goarch)

    # Independent ground truth: the Go tool's own decode of the same stamp.
    referee = _go_version_m(go, binary)
    # Referee sanity: the fields that make the fact worth having really landed.
    assert referee["version"].startswith("go1.")
    assert referee["path"] == "example.com/tool"
    assert referee["settings"]["GOOS"] == goos
    assert referee["settings"]["GOARCH"] == goarch

    # Field for field, the tool-free reader matches the Go tool -- including
    # the full build-settings map, on all three container formats.
    assert _session_go(binary) == referee
