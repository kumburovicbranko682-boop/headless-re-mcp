"""Workspace profiles: the startup work direction that shapes the tool surface.

A profile trims the MCP tool surface to one workflow so a client is not flooded
with unrelated tools. The trimming is by dotted-name prefix, applied after the
full catalog is registered, so the full catalog remains the single authority and
"full" is always a superset of every profile.
"""

from __future__ import annotations

PROFILES: tuple[str, ...] = ("full", "pe", "android", "web")

# Tool-name prefixes that belong to each optional work direction. Anything not
# listed here (session/static/dynamic/frida/workspace/...) is core and stays in
# every non-full profile.
_ANDROID_PREFIXES = ("apk.", "dex.", "device.")
_WEB_PREFIXES = ("web.", "js.", "wasm.")
# The interception proxy (mitmproxy) is shared by the android and web directions
# -- it captures browser traffic in a web session and, via
# proxy.ca.install_android, a device's TLS in an android session -- so it is
# hidden only in the pe direction, never in android or web. Grouping proxy under
# _WEB_PREFIXES had hidden the whole proxy.* surface, including the android-only
# proxy.ca.install_android, from the android work direction, contradicting the
# "shared by Web and Android" scope stated in the README and the proxy service.
_SHARED_ANDROID_WEB_PREFIXES = ("proxy.",)

PROFILE_LABELS: dict[str, str] = {
    "full": "All tools",
    "pe": "Local PE reversing",
    "android": "Android app reversing",
    "web": "Web reversing",
}


def excluded_prefixes(profile: str) -> tuple[str, ...]:
    """Dotted-name prefixes to hide for a profile (empty means hide nothing)."""
    normalized = profile if profile in PROFILES else "full"
    if normalized == "full":
        return ()
    if normalized == "pe":
        return _ANDROID_PREFIXES + _WEB_PREFIXES + _SHARED_ANDROID_WEB_PREFIXES
    if normalized == "android":
        return _WEB_PREFIXES
    if normalized == "web":
        return _ANDROID_PREFIXES
    return ()


def is_tool_visible(name: str, profile: str) -> bool:
    return not name.startswith(excluded_prefixes(profile))


def profile_summary(profile: str) -> dict[str, object]:
    normalized = profile if profile in PROFILES else "full"
    return {
        "profile": normalized,
        "label": PROFILE_LABELS.get(normalized, normalized),
        "available": [
            {"id": item, "label": PROFILE_LABELS.get(item, item)} for item in PROFILES
        ],
        "hidden_prefixes": list(excluded_prefixes(normalized)),
    }
