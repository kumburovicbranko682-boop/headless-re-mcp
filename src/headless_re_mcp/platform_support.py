"""Runtime platform support policy shared by doctor and readiness.

Linux support deliberately covers the Python service and portable backends.  It
does not attempt to emulate Win32 debuggers, UI automation, or installer
technology.  Keeping that distinction in one place prevents a missing Windows
backend from making the portable service look unusable.
"""

from __future__ import annotations

import os
import platform
from typing import Any

JsonObject = dict[str, Any]

WINDOWS_ONLY_FEATURES: tuple[str, ...] = (
    "x64dbg headless RPC",
    "WinDbg/cdb",
    "Win32 UI, UIA, SendInput, and Windows OCR",
    "hidden Win32 desktop",
    "WiX/MSI packaging",
)

_X86_64_NAMES = frozenset({"amd64", "x86_64"})


def is_windows_host() -> bool:
    return os.name == "nt"


def platform_key(*, os_name: str | None = None, system: str | None = None) -> str:
    """Return the support-policy key, independent of display-name spelling."""
    current_os = os.name if os_name is None else os_name
    current_system = platform.system() if system is None else system
    if current_os == "nt" or current_system.casefold() == "windows":
        return "windows"
    if current_system.casefold() == "linux":
        return "linux"
    return current_system.casefold() or current_os.casefold() or "unknown"


def runtime_platform_report(
    *,
    os_name: str | None = None,
    system: str | None = None,
    machine: str | None = None,
) -> JsonObject:
    """Describe supported core scope without probing optional backends."""
    current_system = platform.system() if system is None else system
    current_machine = platform.machine() if machine is None else machine
    key = platform_key(os_name=os_name, system=current_system)
    normalized_machine = current_machine.casefold()
    x86_64 = normalized_machine in _X86_64_NAMES
    supported = key in {"windows", "linux"} and x86_64

    if key == "windows" and supported:
        support_level = "full"
        package_format = "wheel_sdist_or_msi"
    elif key == "linux" and supported:
        support_level = "core"
        package_format = "wheel_or_sdist"
    else:
        support_level = "unsupported"
        package_format = "wheel_or_sdist"

    windows_status = "ready" if key == "windows" and supported else "unsupported_on_platform"
    return {
        "name": key,
        "system": current_system or "unknown",
        "machine": current_machine or "unknown",
        "architecture": "x86_64" if x86_64 else normalized_machine or "unknown",
        "core_supported": supported,
        "support_level": support_level,
        "package_format": package_format,
        "windows_only_status": windows_status,
        "windows_only_features": list(WINDOWS_ONLY_FEATURES),
    }


def unsupported_on_platform_details(capability: str) -> JsonObject:
    """Build the stable error/probe details for a Windows-only capability."""
    current = runtime_platform_report()
    return {
        "capability": capability,
        "current_platform": current["name"],
        "current_system": current["system"],
        "current_machine": current["machine"],
        "supported_platforms": ["windows"],
    }
