"""android_root_bypass must hide the su *binary*, not any path containing "su".

The canned hook rewrites ``java.io.File.exists()`` to conceal root artifacts.
It used to test the path with ``p.indexOf('su') !== -1``, which fires on any
absolute path that merely contains the letters "su" -- a legitimate
``/data/app/com.example.measure/base.apk``, ``.../resume/...``, ``issue.txt``,
``com.sudoku.game``, every ``/usr`` path. Reporting those files as absent
breaks the very app the analyst is bypassing root detection *in*, the opposite
of what the hook is for.

Rather than reimplement the JavaScript in Python, these tests extract the real
``headlessReIsRootPath`` function out of the template string and execute it with
Node.js against representative paths, so the assertion binds to the code frida
will actually run. When Node is unavailable the execution test skips (skip is
not pass); a Node-free guard still pins that the naive substring check is gone.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida.client import _HOOK_TEMPLATES

_TEMPLATE = _HOOK_TEMPLATES["android_root_bypass"]

# Legitimate paths whose text contains "su" somewhere; the hook must NOT hide
# them. Root artifacts the hook MUST hide: the su binary as a path component,
# and any magisk path.
_NOT_ROOT = [
    "/data/app/com.example.measure/base.apk",
    "/data/data/com.foo.resume/files/x",
    "/storage/emulated/0/issue.txt",
    "/data/user/0/com.sudoku.game/databases/d",
    "/system/usr/share/zoneinfo",
    "/system/framework/framework.jar",
]
_ROOT = [
    "/system/bin/su",
    "/sbin/su",
    "/system/xbin/su",
    "/su/bin/su",
    "/data/adb/magisk/util_functions.sh",
]


def _extract_predicate(template: str) -> str:
    """Pull the ``headlessReIsRootPath`` function source out of the template.

    Brace-matched from its declaration so the returned string is a complete,
    self-contained function definition that Node can evaluate on its own.
    """
    marker = "function headlessReIsRootPath"
    start = template.index(marker)
    brace = template.index("{", start)
    depth = 0
    for index in range(brace, len(template)):
        char = template[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return template[start : index + 1]
    raise AssertionError("headlessReIsRootPath function not found / unbalanced braces")


def test_the_naive_su_substring_check_is_gone() -> None:
    # Guards against a regression to indexOf('su'); runs without Node.
    assert "indexOf('su')" not in _TEMPLATE
    assert 'indexOf("su")' not in _TEMPLATE
    assert "function headlessReIsRootPath" in _TEMPLATE


def test_predicate_hides_su_binary_and_magisk_but_not_lookalike_paths(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed — root-bypass predicate not executed (skip != pass)")
    predicate = _extract_predicate(_TEMPLATE)
    driver = "\n".join(
        [
            predicate,
            f"const notRoot = {json.dumps(_NOT_ROOT)};",
            f"const root = {json.dumps(_ROOT)};",
            "let ok = true;",
            "for (const p of notRoot) {",
            "  if (headlessReIsRootPath(p)) { console.error('WRONGLY HID', p); ok = false; }",
            "}",
            "for (const p of root) {",
            "  if (!headlessReIsRootPath(p)) { console.error('FAILED TO HIDE', p); ok = false; }",
            "}",
            "process.exit(ok ? 0 : 1);",
        ]
    )
    harness = tmp_path / "check.js"
    harness.write_text(driver, encoding="utf-8")
    result = subprocess.run([node, str(harness)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
