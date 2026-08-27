"""Cross-validate the tool-free .NET corflags against Mono's pedump.

describe_pe_clr reads the COR20 header Flags field itself to report il_only and
the build-posture bits (requires_32bit, prefers_32bit, strong_name_signed) --
the corflags surface -- with no external tool. But that reader and the fixture
it reads are both ours, so nothing proved its view of the CLI header matches an
independent decoder. Mono's ``pedump`` decodes the same header into human
tokens (``Flags: ilonly, 32/64, no-trackdebug, notsigned``) plus a ``Strong
name:`` line and an ``Entry Point Token:``; this requires they agree, the
corflags analogue of the metadata gate cross-checking the reader against monodis
and the native gate cross-checking nx/relro against radare2.

pedump ships in the same ``mono-utils`` package as monodis; skip != pass -- the
gate skips, naming the missing tool, only when pedump is not installed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"

_ENTRY_TOKEN_RE = re.compile(r"^\s*Entry Point Token:\s*0x([0-9A-Fa-f]+)\s*$", re.MULTILINE)
_STRONG_NAME_RE = re.compile(r"^Strong name:\s*(.+?)\s*$", re.MULTILINE)


def _pedump(path: Path) -> str:
    result = subprocess.run(
        ["pedump", str(path)], capture_output=True, text=True, timeout=60
    )
    # pedump writes the dump to stdout and exits 0; stderr, if any, is noise this
    # gate does not read.
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


def _cli_flag_tokens(dump: str) -> set[str]:
    """The comma-separated tokens on the CLI header's own ``Flags:`` line.

    pedump prints two ``Flags:`` lines -- one for a section's characteristics
    (``code, exec, read``) and one for the CLI header (``ilonly, ...``). The CLI
    one immediately follows ``CLI header size:``, so anchor on that rather than
    guess by content.
    """
    lines = dump.splitlines()
    for i, line in enumerate(lines):
        if "CLI header size:" in line:
            for nxt in lines[i + 1 : i + 4]:
                if "Flags:" in nxt:
                    body = nxt.split("Flags:", 1)[1]
                    return {tok.strip() for tok in body.split(",") if tok.strip()}
    raise AssertionError(f"no CLI header Flags line in pedump output:\n{dump}")


@pytest.mark.integration
def test_pure_python_corflags_agree_with_pedump() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("pedump") is None:
        pytest.skip(
            "pedump (mono-utils) not installed — corflags cross-check not run (skip != pass)"
        )

    # Independent ground truth: Mono decodes the CLI header straight from the
    # file, with no code of ours involved.
    dump = _pedump(_FIXTURE)
    tokens = _cli_flag_tokens(dump)
    entry_match = _ENTRY_TOKEN_RE.search(dump)
    strong_match = _STRONG_NAME_RE.search(dump)
    assert entry_match, dump
    assert strong_match, dump
    pedump_entry_token = int(entry_match.group(1), 16)
    pedump_strong_name = strong_match.group(1).lower()

    # The tool-free reader, reached exactly as a client would: the facts ride on
    # the session metadata the moment the .NET PE is opened.
    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        dotnet = created.data["session"]["metadata"]["dotnet"]
    finally:
        service.close_all()

    # Every corflags bit the reader surfaces must match pedump's own decode of
    # the same COR20 Flags field, token for token.
    assert dotnet["il_only"] is ("ilonly" in tokens), tokens
    # pedump prints "32bitrequired" when the bit is set and "32/64" when it is not.
    assert dotnet["requires_32bit"] is ("32bitrequired" in tokens), tokens
    # "signed" is a distinct token from "notsigned"; membership, not substring.
    assert dotnet["strong_name_signed"] is ("signed" in tokens), tokens
    # And pedump's separate "Strong name:" line must tell the same story.
    assert dotnet["strong_name_signed"] is (pedump_strong_name != "none"), pedump_strong_name
    # The entry-point token the reader read from the header is the one pedump read.
    assert dotnet["entry_point_token"] == pedump_entry_token
