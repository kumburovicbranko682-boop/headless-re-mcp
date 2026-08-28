"""URL path normalisation shared by the traffic-aggregating tools.

proxy.endpoints and web.network.endpoints both fold a capture into a
route-grouped API surface, and both need the same answer to "does this path
segment look like an id?" so that ``/users/1`` and ``/users/2`` collapse into a
single ``/users/{id}`` route. Keeping the heuristic here means the two backends
cannot drift apart on what counts as a variable segment.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX_RE = re.compile(r"(?i)^[0-9a-f]+$")
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9._~-]+$")


def is_variable_segment(seg: str) -> bool:
    """True when a path segment looks like an id/hash/token, not a route name.

    Collapsing these to a placeholder is what turns ``/users/123`` and
    ``/users/456`` into one endpoint. Conservative on purpose: a plain numeric
    segment, a UUID, a hex string of 12+ chars (an object id / md5 / sha) or a
    long (24+) mixed alnum token qualifies, but an ordinary word never does.
    """
    if seg.isdigit():
        return True
    if _UUID_RE.match(seg):
        return True
    if len(seg) >= 12 and _HEX_RE.match(seg):
        return True
    return bool(
        len(seg) >= 24 and _TOKENISH_RE.match(seg) and any(c.isdigit() for c in seg)
    )


def normalize_endpoint_path(path: str) -> str:
    """Replace id-like path segments with ``{id}`` so routes group together."""
    if not path:
        return "/"
    return "/".join("{id}" if is_variable_segment(seg) else seg for seg in path.split("/"))


def endpoint_parts(url: str) -> tuple[str, str, bool]:
    """Split a URL into (host, path, has_query).

    host is the netloc with any ``user:pass@`` credentials stripped so a route
    is keyed by the server, not by who called it; path defaults to ``/``.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", "/", False
    host = parts.netloc.rsplit("@", 1)[-1]
    return host, (parts.path or "/"), bool(parts.query)
