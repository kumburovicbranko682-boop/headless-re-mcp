"""The launcher's console URL must be clickable on an IPv6-loopback host."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _load_start_web() -> ModuleType:
    """Load the root-level launcher script without running it."""
    spec = importlib.util.spec_from_file_location("start_web_under_test", ROOT / "start_web.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ipv4_and_hostname_authorities_are_unchanged() -> None:
    start_web = _load_start_web()
    assert start_web._bracketed_authority("127.0.0.1", 8765) == "127.0.0.1:8765"
    assert start_web._bracketed_authority("localhost", 9000) == "localhost:9000"


def test_ipv6_literal_host_is_bracketed() -> None:
    start_web = _load_start_web()
    # run_web admits any loopback address, including ``::1``. Unbracketed,
    # ``http://::1:8765/`` is not a URL a browser can parse, so the printed link
    # and the one handed to webbrowser.open both pointed nowhere.
    assert start_web._bracketed_authority("::1", 8765) == "[::1]:8765"
    assert f"http://{start_web._bracketed_authority('::1', 8765)}/" == "http://[::1]:8765/"
