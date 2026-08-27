"""Loopback bind helpers for the web console launcher."""

from __future__ import annotations

import contextlib
import json
import socket
import time
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


def _recv_until(sock: socket.socket, *, cap: int, deadline: float) -> bytes:
    """Read at most ``cap`` bytes, giving up when ``deadline`` is reached.

    ``urlopen(..., timeout=)`` is per-recv. A body that delivers one byte
    inside that window resets it, and leaving the response still drains
    whatever remains so the socket can be reused. A leftover listener that
    dribbles then parks the launcher — and the supervisor that started it —
    until the trickle finishes. Slice the deadline onto every recv instead.
    """
    buf = bytearray()
    while len(buf) < cap:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(max(0.01, min(0.05, remaining)))
        try:
            chunk = sock.recv(min(512, cap - len(buf)))
        except TimeoutError:
            continue
        except OSError:
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _parse_healthz_http(raw: bytes) -> JsonObject | None:
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        return None
    header_blob = raw[:header_end]
    body = raw[header_end + 4 :]
    header_lines = header_blob.split(b"\r\n")
    status = header_lines[0].split(b" ", 2)
    if len(status) < 2 or status[0] not in {b"HTTP/1.0", b"HTTP/1.1"} or status[1] != b"200":
        return None
    content_length: int | None = None
    for line in header_lines[1:]:
        if not line.lower().startswith(b"content-length:"):
            continue
        try:
            length = int(line.split(b":", 1)[1].strip())
        except ValueError:
            return None
        if length < 0 or length > _MAX_HEALTHZ_BYTES:
            return None
        if content_length is not None and length != content_length:
            return None
        content_length = length
    if content_length is None or len(body) < content_length:
        return None
    body = body[:content_length]
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if isinstance(data, dict) and data.get("service") == "headless-re-mcp-web":
        return data
    return None


def probe_our_healthz(host: str, port: int, *, timeout: float = 0.6) -> JsonObject | None:
    """If an existing Headless RE web console answers /healthz, return its JSON."""
    deadline = time.monotonic() + max(0.05, float(timeout))
    sock: socket.socket | None = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock = socket.create_connection((host, int(port)), timeout=remaining)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        request = (
            f"GET /healthz HTTP/1.0\r\nHost: {host}:{int(port)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        raw = _recv_until(sock, cap=_MAX_HEALTHZ_BYTES + 1024, deadline=deadline)
    except OSError:
        return None
    finally:
        # no branch: sock is None only when a return is already pending, so the
        # false case never falls through to the parse below.
        if sock is not None:  # pragma: no branch
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()
    return _parse_healthz_http(raw)
