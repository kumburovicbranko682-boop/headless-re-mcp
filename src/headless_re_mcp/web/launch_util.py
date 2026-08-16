"""Loopback bind helpers for the web console launcher."""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any

JsonObject = dict[str, Any]

# /healthz is a tiny JSON object (ok, service, build). Anything larger is not
# this console, and reading it used to be how a leftover listener hung startup.
_MAX_HEALTHZ_BYTES = 4096


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


def _close_raw_socket(resp: Any) -> None:
    """Drop the TCP connection so a give-up cannot drain the rest of the body.

    Leaving ``urlopen`` after a bounded read still tries to consume whatever
    remains so the socket can be reused. A trickle that reset the read timeout
    also reset that drain, and the launcher stayed parked until the listener
    finished.
    """
    fp = getattr(resp, "fp", None)
    raw = getattr(fp, "raw", None)
    sock = getattr(raw, "_sock", None)
    if sock is None:
        return
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(OSError):
        sock.close()


def _read_healthz_body(resp: Any, *, cap: int, deadline: float) -> bytes | None:
    """Read at most ``cap`` bytes, or give up when ``deadline`` is reached.

    ``urlopen(..., timeout=)`` is the socket timeout. A body that delivers one
    byte inside that window resets it, so ``read()`` of an unending trickle
    never returns. The join is the overall bound; closing the raw socket is
    what stops the leftover drain from waiting out the rest of the body.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _close_raw_socket(resp)
        return None
    box: list[bytes | BaseException] = []

    def work() -> None:
        try:
            box.append(resp.read(cap + 1))
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            box.append(exc)

    thread = threading.Thread(target=work, name="healthz-read", daemon=True)
    thread.start()
    thread.join(remaining)
    if thread.is_alive():
        _close_raw_socket(resp)
        return None
    if not box:
        _close_raw_socket(resp)
        return None
    result = box[0]
    if isinstance(result, BaseException):
        _close_raw_socket(resp)
        raise result
    if len(result) > cap:
        _close_raw_socket(resp)
        return None
    return result


def probe_our_healthz(host: str, port: int, *, timeout: float = 0.6) -> JsonObject | None:
    """If an existing Headless RE web console answers /healthz, return its JSON."""
    url = f"http://{host}:{int(port)}/healthz"
    deadline = time.monotonic() + max(0.05, float(timeout))
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - loopback only
            length = resp.headers.get("Content-Length")
            if length is not None:
                try:
                    if int(length) > _MAX_HEALTHZ_BYTES:
                        _close_raw_socket(resp)
                        return None
                except ValueError:
                    pass
            raw = _read_healthz_body(resp, cap=_MAX_HEALTHZ_BYTES, deadline=deadline)
            if raw is None:
                return None
            data = json.loads(raw.decode("utf-8", errors="replace"))
    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        OSError,
        http.client.HTTPException,
    ):
        return None
    if isinstance(data, dict) and data.get("service") == "headless-re-mcp-web":
        return data
    return None
