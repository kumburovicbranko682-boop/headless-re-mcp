"""Every Frida agent script the client ships must be valid JavaScript.

The Frida backend embeds JavaScript that only ever runs inside a target
process: the canned ``frida.hook.template`` scripts, and the RPC agents behind
``frida.modules`` / ``frida.exports`` / ``frida.memory.read`` / ``frida.java.*``.
None of it is exercised by the Python tests -- those stub ``create_script`` and
never compile the source -- and the live gates need a device, so a syntax slip
in any of these strings would sail through CI and only surface as a
``backend_error`` the first time an analyst pointed the tool at a real process.

Node's ``--check`` parses a file and reports syntax errors without executing it,
so undefined Frida runtime globals (``Java``, ``Process``, ``ptr``, ``send``,
``rpc``) do not matter here -- only whether the source parses. That is exactly
the failure this guards: a script that will not compile in the target.

The scripts are discovered from the module, so a template added later is checked
for free. Node ships on the GitHub-hosted runners the unit jobs use; when it is
genuinely absent the check skips with an explicit message rather than passing on
nothing (skip != pass).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida import client as frida_client


def _embedded_scripts() -> dict[str, str]:
    """Name -> source for every JavaScript string the Frida client ships."""
    scripts = dict(frida_client._HOOK_TEMPLATES)
    scripts["__enum_rpc__"] = frida_client._ENUM_SCRIPT
    scripts["__java_rpc__"] = frida_client._JAVA_SCRIPT
    return scripts


_SCRIPTS = _embedded_scripts()


def _node() -> str | None:
    return shutil.which("node")


def test_the_script_inventory_is_not_empty() -> None:
    """A rename that emptied the discovery would make every case below vacuous.

    Pin the shape the rest of the file depends on: the four documented hook
    templates plus the two RPC agents, all non-empty strings.
    """
    assert {
        "noop",
        "android_ssl_unpin",
        "android_crypto_monitor",
        "android_root_bypass",
        "__enum_rpc__",
        "__java_rpc__",
    } <= set(_SCRIPTS)
    for name, source in _SCRIPTS.items():
        assert isinstance(source, str) and source.strip(), name


@pytest.mark.parametrize("name", sorted(_SCRIPTS))
def test_embedded_frida_script_parses_as_javascript(name: str, tmp_path: Path) -> None:
    node = _node()
    if node is None:
        pytest.skip("node not found — Frida script syntax check not run (skip != pass)")
    source = _SCRIPTS[name]
    script = tmp_path / f"{name.strip('_') or 'script'}.js"
    script.write_text(source, encoding="utf-8")
    completed = subprocess.run(
        [node, "--check", str(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, (
        f"Frida agent script {name!r} is not valid JavaScript and would fail to "
        f"compile in the target process:\n{completed.stderr.strip()}"
    )
