"""Loopback bind helpers for the web console launcher."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any

JsonObject = dict[str, Any]


def port_is_free(host: str, port: int) -> bool:
    """Return True if we can bind ``host:port`` right now."""
    family = socket.AF_INET6 if ":" in host and not host.startswith("127.") else socket.AF_INET
    # Normalize common loopback forms.
    bind_host = host
    if host in {"localhost"}:
        bind_host = "127.0.0.1"
        family = socket.AF_INET
    # Do not set SO_REUSEADDR: on Windows it can falsely report a busy port as free.
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((bind_host, int(port)))
        return True
    except OSError:
        return False


def choose_bind_port(
    host: str,
    preferred: int,
    *,
    span: int = 40,
    auto: bool = True,
) -> tuple[int, str]:
    """Pick a free loopback port.

    Returns ``(port, reason)`` where reason is ``preferred`` / ``fallback`` / ``exhausted``.
    """
    preferred = int(preferred)
    if port_is_free(host, preferred):
        return preferred, "preferred"
    if not auto:
        return preferred, "busy"
    for port in range(preferred + 1, preferred + max(1, span) + 1):
        if port_is_free(host, port):
            return port, "fallback"
    return preferred, "exhausted"


def probe_our_healthz(host: str, port: int, *, timeout: float = 0.6) -> JsonObject | None:
    """If an existing Headless RE web console answers /healthz, return its JSON."""
    url = f"http://{host}:{int(port)}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - loopback only
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    if isinstance(data, dict) and data.get("service") == "headless-re-mcp-web":
        return data
    return None
