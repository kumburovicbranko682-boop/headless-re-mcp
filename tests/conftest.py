"""Isolate the suite from the developer's real config, data and artifacts.

``Settings.load()`` reads the user config file (``platformdirs``), the
``HEADLESS_RE_IDA_HOME`` / ``HEADLESS_RE_X64DBG_SOURCE`` /
``HEADLESS_RE_ARTIFACT_ROOT`` environment variables, and defaults
``artifact_root`` into the user's data directory. CI is a clean environment,
so it can never catch what happens on a developer machine: with a saved
``config.json`` (the setup wizard writes one) 59 tests fail outright, and
with a real ``artifact_root`` configured the suite silently writes test
sessions and artifacts into the developer's actual artifact store even while
every test passes.

Logging leaks the same way through a different root: ``resolve_log_dir()``
prefers ``HEADLESS_RE_LOG_DIR`` and falls back to ``user_log_path`` -- the
*state* directory (``XDG_STATE_HOME``), not the data directory. Measured on a
clean checkout, one full unit run appends ~7 KB of fabricated test incidents
to the developer's real ``~/.local/state/headless-re-mcp/log/incidents.log``
plus telemetry rows next to it, corrupting the operational incident history
the error boundary exists to keep.

This must run at import time -- some test modules call ``Settings.load()``
at module level, before any fixture. Setting the ``platformdirs`` roots
covers Linux (XDG) and Windows (APPDATA/LOCALAPPDATA); macOS resolves config
under ``~/Library`` and is not covered by these variables, so a saved config
there would still leak -- no supported CI leg runs macOS.

Per-test overrides via ``monkeypatch.setenv`` / ``setattr`` are unaffected:
they apply after this module is imported.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_isolation_root = Path(tempfile.mkdtemp(prefix="headless-re-mcp-tests-"))
(_isolation_root / "config").mkdir()
(_isolation_root / "data").mkdir()
(_isolation_root / "state").mkdir()

os.environ["XDG_CONFIG_HOME"] = str(_isolation_root / "config")
os.environ["XDG_DATA_HOME"] = str(_isolation_root / "data")
# user_log_path resolves under the state dir on Linux; on Windows it lives
# under LOCALAPPDATA, which is redirected two lines down.
os.environ["XDG_STATE_HOME"] = str(_isolation_root / "state")
os.environ["APPDATA"] = str(_isolation_root / "config")
os.environ["LOCALAPPDATA"] = str(_isolation_root / "data")

# Exactly the variables Settings.load() and resolve_log_dir() consume for
# paths. Tool opt-ins (HEADLESS_RE_UPX and friends) deliberately stay: they
# gate integration fixtures that are meant to be enabled from the environment.
for _var in (
    "HEADLESS_RE_IDA_HOME",
    "HEADLESS_RE_X64DBG_SOURCE",
    "HEADLESS_RE_ARTIFACT_ROOT",
    "HEADLESS_RE_LOG_DIR",
):
    os.environ.pop(_var, None)
