"""The web package must import without the optional ``web`` extra (fastapi).

``web/__init__.py`` used to eagerly ``from headless_re_mcp.web.app import
create_app, run_web`` at package load, and ``web.app`` imports fastapi. That
made importing *any* web utility submodule -- ``web.setup``, which installer
IDA configuration imports on a base install -- drag fastapi in and crash with a
bare ``ModuleNotFoundError: No module named 'fastapi'`` far from anything
web-served.

The six web-utility unit tests only guard this on a bare machine: with fastapi
installed (as CI always has it) they collect fine even if the eager import came
back, so they cannot catch a regression. This test runs in a subprocess with
fastapi blocked at the importer, so it fails in normal CI too -- exactly where
the other tests are blind.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

# fastapi-free utility submodules the installer / CLI reach on a base install.
_UTILITIES = (
    "headless_re_mcp.web",
    "headless_re_mcp.web.setup",
    "headless_re_mcp.web.deps",
    "headless_re_mcp.web.monitor",
    "headless_re_mcp.web.launch_util",
    "headless_re_mcp.web.commands",
)


def test_web_utilities_import_and_create_app_stays_lazy_without_fastapi() -> None:
    program = textwrap.dedent(
        f"""
        import builtins
        import importlib

        _real_import = builtins.__import__

        def _blocked_import(name, *args, **kwargs):
            if name == "fastapi" or name.startswith("fastapi."):
                raise ModuleNotFoundError(f"No module named {{name!r}}")
            return _real_import(name, *args, **kwargs)

        builtins.__import__ = _blocked_import

        # Guard against the test lying to itself: fastapi must really be blocked.
        try:
            importlib.import_module("fastapi")
        except ModuleNotFoundError:
            pass
        else:
            raise SystemExit("setup error: fastapi was not blocked")

        for mod in {_UTILITIES!r}:
            importlib.import_module(mod)

        # create_app/run_web stay on the package's public surface but resolve
        # lazily -- reaching them is the only thing that needs fastapi.
        import headless_re_mcp.web as web
        for name in ("create_app", "run_web"):
            try:
                getattr(web, name)
            except ModuleNotFoundError:
                pass
            else:
                raise SystemExit(name + " resolved without fastapi -- __init__ is eager again")

        print("OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    assert result.stdout.strip().splitlines()[-1] == "OK", result.stdout
