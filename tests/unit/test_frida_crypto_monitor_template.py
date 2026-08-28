"""android_crypto_monitor must watch every Cipher.doFinal overload.

The template used to hook only ``doFinal(byte[])``. An app that encrypts by
streaming ``update()`` then calling ``doFinal()``, or that uses the
``doFinal(input, offset, len)`` / output-buffer forms, produced no events at
all -- the monitor read as "no crypto happening", a false negative for the one
thing it exists to surface.

The behavioural part of the fix is which byte count each overload reports, and
that lives in a named ``headlessReCipherInputLen`` helper so it can be run in
isolation. This extracts that helper from the template string and executes it
with Node against argument shapes standing in for each real overload, exactly
as the app's bytecode would call them. Without Node the behavioural checks skip
(skip != pass); the pure-Python structural guards always run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida.client import _HOOK_TEMPLATES

_TEMPLATE = _HOOK_TEMPLATES["android_crypto_monitor"]


def _extract_function(source: str, name: str) -> str:
    """Return the ``function name(...) { ... }`` block, brace-matched."""
    marker = f"function {name}("
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
    raise AssertionError(f"unbalanced braces extracting {name}")


def test_the_single_overload_hook_is_gone() -> None:
    """The old form hooked exactly one overload; guard against a regression."""
    assert "doFinal.overload('[B')" not in _TEMPLATE
    assert "doFinal.overloads" in _TEMPLATE
    assert "function headlessReCipherInputLen" in _TEMPLATE


def test_length_helper_reports_input_bytes_per_overload(tmp_path: Path) -> None:
    """Run the extracted length helper against every doFinal overload shape."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed; cannot exercise the template JavaScript")
    helper = _extract_function(_TEMPLATE, "headlessReCipherInputLen")
    # Each case: [label, argument-array, expected len]. A byte[] argument is a
    # plain object with a numeric .length, which is all the helper inspects.
    cases = [
        ["doFinal()", [], -1],
        ["doFinal(output, outOffset)", [{"length": 16}, 0], -1],
        ["doFinal(input)", [{"length": 32}], 32],
        ["doFinal(input, off, len)", [{"length": 64}, 0, 40], 40],
        ["doFinal(input, off, len, out)", [{"length": 64}, 0, 40, {"length": 64}], 40],
        ["doFinal(input, off, len, out, outOff)", [{"length": 64}, 0, 40, {"length": 64}, 0], 40],
    ]
    driver = "\n".join(
        [
            helper,
            f"const cases = {json.dumps(cases)};",
            "let failures = [];",
            "for (const [label, args, want] of cases) {",
            "  const got = headlessReCipherInputLen(args);",
            "  if (got !== want) { failures.push(label + ': got ' + got + ' want ' + want); }",
            "}",
            "if (failures.length) { console.error(failures.join('\\n')); process.exit(1); }",
            "console.log('ok');",
        ]
    )
    harness = tmp_path / "len_check.js"
    harness.write_text(driver, encoding="utf-8")
    result = subprocess.run([node, str(harness)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_template_is_syntactically_valid_javascript(tmp_path: Path) -> None:
    """A template that fails to parse loads as nothing and hooks nothing."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed; cannot parse the template JavaScript")
    driver = "\n".join(
        [
            "const vm = require('vm');",
            f"const src = {json.dumps(_TEMPLATE)};",
            "try { new vm.Script(src); }",
            "catch (e) { console.error(String(e)); process.exit(1); }",
            "console.log('ok');",
        ]
    )
    harness = tmp_path / "parse_check.js"
    harness.write_text(driver, encoding="utf-8")
    result = subprocess.run([node, str(harness)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
