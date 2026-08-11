"""Bridge config.json into the environment variables the gates read.

Most gates decide whether to run by looking only at ``HEADLESS_RE_*`` environment
variables, so a machine configured through ``config.json`` skipped them even with
every backend installed. Exporting the resolved settings keeps "skip != pass"
meaningful: a skip should mean the backend is genuinely missing, not that the
configuration lives in a file instead of the environment.

Existing environment variables always win, so a caller can still force a gate to
skip or point it somewhere else.
"""

from __future__ import annotations

import os
from pathlib import Path

from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_PATH_SETTINGS = {
    "HEADLESS_RE_X64DBG_HEADLESS_X64": "x64dbg_headless_x64",
    "HEADLESS_RE_X64DBG_HEADLESS_X86": "x64dbg_headless_x86",
    "HEADLESS_RE_X64DBG_SOURCE": "x64dbg_source",
    "HEADLESS_RE_IDA_HOME": "ida_home",
    "HEADLESS_RE_DIEC": "diec",
    "HEADLESS_RE_EXEINFOPE": "exeinfope",
    "HEADLESS_RE_UPX": "upx",
    "HEADLESS_RE_DE4DOT": "de4dot",
    "HEADLESS_RE_NET_REACTOR_SLAYER": "net_reactor_slayer",
    "HEADLESS_RE_XVLKC": "xvlkc",
    "HEADLESS_RE_VMP_DUMPER": "vmp_dumper",
    "HEADLESS_RE_SCYLLA": "scylla",
    "HEADLESS_RE_R2": "r2",
    "HEADLESS_RE_GHIDRA_HOME": "ghidra_home",
    "HEADLESS_RE_CDB": "cdb",
}


def _default_ida_gate_binary() -> None:
    """Give the idalib gates a target instead of skipping for want of a path."""
    if os.environ.get("HEADLESS_RE_IDA_GATE_BINARY"):
        return
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if fixture.is_file():
        os.environ["HEADLESS_RE_IDA_GATE_BINARY"] = str(fixture)


def pytest_configure() -> None:
    try:
        settings = Settings.load()
    except Exception:  # noqa: BLE001 - never block collection on config problems
        return
    for variable, attribute in _PATH_SETTINGS.items():
        if os.environ.get(variable):
            continue
        value = getattr(settings, attribute, None)
        if value:
            os.environ[variable] = str(value)
    _default_ida_gate_binary()
