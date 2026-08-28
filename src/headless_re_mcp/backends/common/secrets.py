"""Credential / secret detection shared by the traffic-scanning tools.

proxy.secrets and web.network.secrets both enumerate the authentication material
flowing through a capture -- Authorization headers (with JWT decoding), API-key
and token headers, secret-ish URL query parameters and cookies (request Cookie
and response Set-Cookie) -- and both need the exact same heuristics for "what
looks like a secret", the same redaction, JWT decode and cross-flow aggregation.
Keeping that here means the browser-side and proxy-side scanners cannot drift on
what counts as a credential or how a value is masked.

A finding is a plain dict {kind, name, location, value, ...}; a backend turns its
own capture (mitmproxy flows, or CDP request entries) into (name, value) header
pairs and a URL, feeds them to the scanners, folds the results into an aggregate
with :func:`record_secret`, then renders the page with :func:`finalize_secrets`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import OrderedDict
from typing import Any
from urllib.parse import parse_qsl, urlsplit

JsonObject = dict[str, Any]

# Bounds. Distinct findings kept, the page returned, distinct hosts kept per
# finding, and the per-request scan ceilings, so a capture full of unique tokens
# or one request with thousands of headers/cookies cannot build an unbounded
# reply. Values are clipped before storage so a huge header cannot bloat memory.
MAX_SECRETS_COLLECT = 5000
MAX_SECRETS_PAGE = 500
MAX_SECRET_HOSTS = 20
MAX_HEADERS_PER_REQUEST = 200
MAX_COOKIES_PER_REQUEST = 100
MAX_QUERY_PARAMS_PER_REQUEST = 100
MAX_SECRET_VALUE = 4096
SECRET_VALUE_KEEP = 4

SECRET_KINDS = frozenset(
    {"authorization", "api_key_header", "query_param", "cookie", "set_cookie"}
)
# Request headers that carry credentials directly (scheme + token).
AUTH_HEADER_NAMES = frozenset({"authorization", "proxy-authorization"})
# Request headers commonly used to carry an API key / bearer token / CSRF token.
APIKEY_HEADER_NAMES = frozenset(
    {
        "x-api-key", "api-key", "apikey", "x-apikey",
        "x-auth-token", "x-access-token", "x-session-token", "x-app-token",
        "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
        "x-goog-api-key", "x-functions-key", "private-token", "access-token",
        "auth-token", "authentication", "x-secret", "x-auth", "token",
    }
)
# Query-string parameter names that typically hold a secret.
SECRET_QUERY_NAMES = frozenset(
    {
        "token", "access_token", "refresh_token", "id_token",
        "api_key", "apikey", "key", "auth", "authorization",
        "sig", "signature", "password", "passwd", "pwd",
        "secret", "client_secret", "session", "sessionid", "sid", "code",
    }
)
# Cookie-name fragments that mark a session/auth cookie (vs. an analytics one).
SESSION_COOKIE_SUBSTR = (
    "session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf",
    "access", "refresh", "login", "identity",
)
JWT_RE = re.compile(r"^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")


def is_apikey_header(lname: str) -> bool:
    """True when a request header name looks like an API-key/token carrier."""
    if lname in APIKEY_HEADER_NAMES:
        return True
    if any(frag in lname for frag in ("api-key", "apikey", "api_key")):
        return True
    return lname.startswith("x-") and (
        lname.endswith("-token") or lname.endswith("-key") or "auth" in lname
    )


def is_secret_query(lname: str) -> bool:
    if lname in SECRET_QUERY_NAMES:
        return True
    return any(
        frag in lname
        for frag in ("token", "secret", "password", "apikey", "api_key", "signature")
    )


def is_session_cookie(lname: str) -> bool:
    return any(frag in lname for frag in SESSION_COOKIE_SUBSTR)


def clip_secret(value: str) -> tuple[str, bool]:
    """Clip an over-long value before storage; returns (clipped, was_clipped)."""
    if len(value) > MAX_SECRET_VALUE:
        return value[:MAX_SECRET_VALUE], True
    return value, False


def redact_value(value: str) -> str:
    """A safe-to-display preview: first/last few chars with the middle masked."""
    n = len(value)
    if n <= 4:
        return "\u2026"
    if n <= 2 * SECRET_VALUE_KEEP + 3:
        return value[:2] + "\u2026" + value[-1:]
    return f"{value[:SECRET_VALUE_KEEP]}\u2026{value[-SECRET_VALUE_KEEP:]}"


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> JsonObject | None:
    """Decode a JWT's header and registered claims (never its signature).

    Returns the algorithm/type from the header and the standard registered
    claims (issuer, subject, audience, expiry, ...) plus the names of every
    payload claim, so a caller can see who issued a token and when it expires
    without the tool interpreting arbitrary custom claim values. Any structural
    fault yields None -- the value is simply reported as an opaque token.
    """
    if not JWT_RE.match(token):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:  # noqa: BLE001 - malformed base64/JSON is just "not a JWT"
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    hdr = {k: header[k] for k in ("alg", "typ", "kid") if k in header}
    claims = {
        k: payload[k]
        for k in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "azp", "scope")
        if k in payload
    }
    return {
        "header": hdr,
        "claims": claims,
        "claim_names": sorted(str(k) for k in payload)[:64],
    }


def split_cookie_header(value: str) -> list[tuple[str, str]]:
    """Parse a request Cookie header into (name, value) pairs."""
    pairs: list[tuple[str, str]] = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, val = chunk.partition("=")
        name = name.strip()
        if sep and name:
            pairs.append((name, val.strip()))
    return pairs


def parse_set_cookie(value: str) -> tuple[str, str, JsonObject]:
    """Parse a Set-Cookie value into (name, value, attribute-flags)."""
    first, _, rest = value.partition(";")
    name, sep, val = first.partition("=")
    name = name.strip()
    val = val.strip() if sep else ""
    attrs: JsonObject = {}
    for chunk in rest.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        akey, asep, aval = chunk.partition("=")
        akey = akey.strip().lower()
        if not akey:
            continue
        if asep:
            attrs[akey] = aval.strip()
        else:
            attrs[akey] = True
    return name, val, attrs


def scan_url_query(url: str, *, kind: str = "") -> list[JsonObject]:
    """Findings for secret-ish query parameters in a request URL."""
    if kind and kind != "query_param":
        return []
    try:
        query = urlsplit(url).query
    except ValueError:
        return []
    if not query:
        return []
    out: list[JsonObject] = []
    for i, (qname, qval) in enumerate(parse_qsl(query, keep_blank_values=False)):
        if i >= MAX_QUERY_PARAMS_PER_REQUEST:
            break
        if qval and is_secret_query(qname.lower()):
            out.append(
                {
                    "kind": "query_param",
                    "name": qname,
                    "location": "request",
                    "value": qval,
                }
            )
    return out


def scan_request_headers(
    pairs: list[tuple[str, str]], *, kind: str = ""
) -> list[JsonObject]:
    """Findings for Authorization / API-key / Cookie request headers."""
    out: list[JsonObject] = []
    for hi, (hname, hval) in enumerate(pairs):
        if hi >= MAX_HEADERS_PER_REQUEST:
            break
        lname = hname.lower()
        if not hval:
            continue
        if lname in AUTH_HEADER_NAMES:
            if kind and kind != "authorization":
                continue
            scheme, sep, cred = hval.partition(" ")
            token = cred.strip() if sep else hval
            out.append(
                {
                    "kind": "authorization",
                    "name": hname,
                    "location": "request",
                    "value": token,
                    "scheme": scheme if sep else "",
                }
            )
        elif lname == "cookie":
            if kind and kind != "cookie":
                continue
            for ci, (cname, cval) in enumerate(split_cookie_header(hval)):
                if ci >= MAX_COOKIES_PER_REQUEST:
                    break
                if not cval:
                    continue
                out.append(
                    {
                        "kind": "cookie",
                        "name": cname,
                        "location": "request",
                        "value": cval,
                        "session": is_session_cookie(cname.lower()),
                    }
                )
        elif is_apikey_header(lname):
            if kind and kind != "api_key_header":
                continue
            out.append(
                {
                    "kind": "api_key_header",
                    "name": hname,
                    "location": "request",
                    "value": hval,
                }
            )
    return out


def scan_response_headers(
    pairs: list[tuple[str, str]], *, kind: str = ""
) -> list[JsonObject]:
    """Findings for Set-Cookie response headers (session flag + attributes)."""
    if kind and kind != "set_cookie":
        return []
    out: list[JsonObject] = []
    for hi, (hname, hval) in enumerate(pairs):
        if hi >= MAX_HEADERS_PER_REQUEST:
            break
        if hname.lower() != "set-cookie" or not hval:
            continue
        cname, cval, cattrs = parse_set_cookie(hval)
        if not cname or not cval:
            continue
        session = is_session_cookie(cname.lower()) or ("httponly" in cattrs)
        out.append(
            {
                "kind": "set_cookie",
                "name": cname,
                "location": "response",
                "value": cval,
                "session": session,
                "cookie_attributes": cattrs,
            }
        )
    return out


def record_secret(
    aggregated: OrderedDict[tuple[str, str, str, str], JsonObject],
    seen: set[tuple[str, str, str, str]],
    finding: JsonObject,
) -> bool:
    """Fold one finding into the aggregate; return True if the collect cap blocked it.

    ``seen`` is reset per request/flow so a secret repeated within one exchange
    is counted once, making ``count`` the number of distinct exchanges a secret
    appeared in. Identical (kind, name, location, value) findings collapse into
    one row whose count and host set grow. A JWT value is decoded once, on first
    sight, into its header/claims (never its signature).
    """
    value = str(finding["value"])
    clipped, was_clipped = clip_secret(value)
    key = (
        str(finding["kind"]),
        str(finding["name"]),
        str(finding["location"]),
        clipped,
    )
    if key in seen:
        return False
    seen.add(key)
    agg = aggregated.get(key)
    if agg is None:
        if len(aggregated) >= MAX_SECRETS_COLLECT:
            return True
        agg = {
            "kind": finding["kind"],
            "name": finding["name"],
            "location": finding["location"],
            "_value": clipped,
            "value_length": len(value),
            "value_sha256": hashlib.sha256(
                value.encode("utf-8", "replace")
            ).hexdigest()[:16],
            "count": 0,
            "_hosts": set(),
            "example_id": finding.get("flow_id", ""),
        }
        if was_clipped:
            agg["value_clipped"] = True
        if finding.get("scheme"):
            agg["scheme"] = finding["scheme"]
        if "session" in finding:
            agg["session"] = bool(finding["session"])
        if finding.get("cookie_attributes"):
            agg["cookie_attributes"] = finding["cookie_attributes"]
        jwt = decode_jwt(value)
        if jwt is not None:
            agg["jwt"] = jwt
        aggregated[key] = agg
    agg["count"] = int(agg["count"]) + 1
    hostname = str(finding.get("host") or "")
    hosts: set[str] = agg["_hosts"]
    if hostname and len(hosts) < MAX_SECRET_HOSTS:
        hosts.add(hostname)
    return False


def finalize_secrets(
    aggregated: OrderedDict[tuple[str, str, str, str], JsonObject],
    *,
    reveal: bool,
    offset: int,
    limit: int,
) -> JsonObject:
    """Rank, page and render the aggregate into the common reply fields.

    Returns secrets (the page), count/total/offset/has_more and kind_counts; a
    caller merges in its own capture-scope fields (captured, dropped, scanned).
    Redacts each value to a preview unless ``reveal`` is set.
    """
    collected = list(aggregated.values())
    collected.sort(
        key=lambda s: (-int(s["count"]), s["kind"], s["name"], s["value_sha256"])
    )
    kind_counts: dict[str, int] = {}
    for entry in collected:
        kind_counts[entry["kind"]] = kind_counts.get(entry["kind"], 0) + 1
    total = len(collected)
    start = max(0, int(offset))
    cap = max(1, min(int(limit), MAX_SECRETS_PAGE))
    window = collected[start : start + cap]
    secrets: list[JsonObject] = []
    for entry in window:
        item = {k: v for k, v in entry.items() if not k.startswith("_")}
        item["hosts"] = sorted(entry["_hosts"])
        item["value"] = entry["_value"] if reveal else redact_value(entry["_value"])
        secrets.append(item)
    return {
        "secrets": secrets,
        "count": len(window),
        "total": total,
        "offset": start,
        "has_more": start + len(window) < total,
        "kind_counts": kind_counts,
    }
