"""webcrack deobfuscate/beautify live gate: real obfuscated JS to readable code.

The jsre line advertises JavaScript deobfuscation, but only its bundle-unpack path
(``js.n`` / ``unpack_bundle``, the ``webcrack -o <dir>`` invocation) had live
coverage. The headline single-file path -- ``js.deobfuscate`` and its
formatting-named alias ``js.beautify``, which run ``webcrack <file>`` and capture
the rewritten source from stdout -- only ever ran against a fake webcrack in unit
tests. So the actual deobfuscation, the stdout capture, and the byte-bounded
wrapping around it were never exercised against the real tool.

This gate feeds webcrack a small but genuinely obfuscated snippet -- a hex-escaped
string array indexed by a hex literal, reached through bracket member access -- and
asserts webcrack recovered readable code: the escaped string decoded to text and
was inlined at its use site, ``obj['prop']`` became ``obj.prop``, and the result
came back formatted rather than as the original one-liner. The fixture is inline
JS, so the gate needs only webcrack (and its Node runtime), no network.

Skip != pass: the gate skips with a reason when webcrack is absent, and runs for
real when present. CI installs it, so a skip there is a genuine regression rather
than a bare machine.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsClient

# Obfuscated on purpose: the greeting lives in a hex-escaped string array
# (['\x68\x65\x6c\x6c\x6f'] == ['hello']), is read as _0x1[0x0] through a hex
# index, and console.log is reached via bracket access. A real deobfuscation
# decodes the escapes, inlines the constant, and normalises the member access.
_OBFUSCATED = (
    r"var _0x1=['\x68\x65\x6c\x6c\x6f'];"
    r"function greet(_0x2){console['log'](_0x1[0x0]+' '+_0x2);}"
    r"greet('world');"
)


def _webcrack_path() -> Path | None:
    found = os.environ.get("HEADLESS_RE_WEBCRACK") or shutil.which("webcrack")
    if not found:
        return None
    path = Path(found)
    return path if path.exists() else None


@pytest.mark.integration
def test_webcrack_deobfuscates_a_real_snippet(tmp_path: Path) -> None:
    webcrack = _webcrack_path()
    if webcrack is None:
        pytest.skip("webcrack not installed — deobfuscate Gate not run (skip != pass)")

    source = tmp_path / "obfuscated.js"
    source.write_text(_OBFUSCATED, encoding="utf-8")

    client = JsClient(webcrack)
    assert client.available

    result = client.deobfuscate(source, timeout=180.0)
    code = str(result.get("code", ""))

    assert not result.get("tool_failed"), result.get("stderr")
    assert result.get("bytes", 0) > 0

    # The hex-escaped string was decoded to text and inlined at its use site...
    assert "hello " in code
    assert "\\x68" not in code, code
    # ...bracket member access was normalised to dot access...
    assert "console.log(" in code
    assert "console['log']" not in code
    # ...the call survived with its decoded argument...
    assert 'greet("world")' in code
    # ...and the result is formatted code, not the original one-liner.
    assert "\n" in code


@pytest.mark.integration
def test_webcrack_beautify_alias_runs_the_real_tool(tmp_path: Path) -> None:
    """beautify is a formatting-named alias of deobfuscate; prove it also runs."""
    webcrack = _webcrack_path()
    if webcrack is None:
        pytest.skip("webcrack not installed — beautify Gate not run (skip != pass)")

    source = tmp_path / "obfuscated.js"
    source.write_text(_OBFUSCATED, encoding="utf-8")

    client = JsClient(webcrack)
    beautified = str(client.beautify(source, timeout=180.0).get("code", ""))

    # Same real transformation the deobfuscate path performs.
    assert "console.log(" in beautified
    assert "hello " in beautified
    assert "\n" in beautified
