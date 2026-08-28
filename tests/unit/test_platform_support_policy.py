"""Platform-key and support-level policy coverage.

``test_linux_platform_support.py`` pins the Linux core scope. This file
covers the remaining policy arms via injected ``os_name``/``system``/
``machine`` (so Windows and non-win/linux keys are exercised off-platform):
the Windows key resolution, the non-win/linux fallback, and the Windows
``full`` support level.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.platform_support import (
    WINDOWS_ONLY_FEATURES,
    platform_key,
    runtime_platform_report,
)


@pytest.mark.parametrize(
    ("os_name", "system"),
    [
        ("nt", "Linux"),
        ("posix", "Windows"),
        ("posix", "WINDOWS"),
    ],
)
def test_platform_key_resolves_windows(os_name: str, system: str) -> None:
    assert platform_key(os_name=os_name, system=system) == "windows"


def test_platform_key_resolves_linux() -> None:
    assert platform_key(os_name="posix", system="Linux") == "linux"


@pytest.mark.parametrize(
    ("os_name", "system", "expected"),
    [
        ("posix", "Darwin", "darwin"),
        ("java", "", "java"),
        ("", "", "unknown"),
    ],
)
def test_platform_key_falls_back_for_other_platforms(
    os_name: str, system: str, expected: str
) -> None:
    assert platform_key(os_name=os_name, system=system) == expected


def test_windows_x86_64_report_names_full_scope() -> None:
    report = runtime_platform_report(
        os_name="nt",
        system="Windows",
        machine="AMD64",
    )

    assert report["name"] == "windows"
    assert report["core_supported"] is True
    assert report["support_level"] == "full"
    assert report["package_format"] == "wheel_sdist_or_msi"
    assert report["windows_only_status"] == "ready"
    assert report["architecture"] == "x86_64"
    assert report["windows_only_features"] == list(WINDOWS_ONLY_FEATURES)


def test_non_supported_platform_report_is_unsupported() -> None:
    report = runtime_platform_report(
        os_name="posix",
        system="Darwin",
        machine="arm64",
    )

    assert report["name"] == "darwin"
    assert report["core_supported"] is False
    assert report["support_level"] == "unsupported"
    assert report["windows_only_status"] == "unsupported_on_platform"
