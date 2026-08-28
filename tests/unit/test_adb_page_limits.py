"""Page-limit bounds for adb properties/packages/logcat.

Each took ``max(1, min(int(value), max))``. A negative or huge value clamps
cleanly, but the tool schemas type these as integers while the agent and
OpenAI-bridge transports call the handler with no pydantic coercion, so a float
(inf from a JSON 1e400), nan, null, or non-numeric string reached ``int(value)``
and raised OverflowError/ValueError/TypeError -- none an AdbError, so the service
filed an internal_error incident for a bad page size. The clamp now runs before
_device, so these exercise on Linux whether or not adbutils is installed.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

_BAD = [float("inf"), float("nan"), None, "abc", {}, [], True]
_BAD_IDS = ["inf", "nan", "none", "non-numeric", "dict", "list", "bool"]


@pytest.mark.parametrize("bad", _BAD, ids=_BAD_IDS)
def test_properties_rejects_a_bad_limit_before_touching_the_device(bad: Any) -> None:
    with pytest.raises(AdbError) as caught:
        AdbBackend().properties("emulator-5554", limit=bad)
    assert caught.value.code == "invalid_params"
    assert "limit" in caught.value.message


@pytest.mark.parametrize("bad", _BAD, ids=_BAD_IDS)
def test_packages_rejects_a_bad_limit_before_touching_the_device(bad: Any) -> None:
    with pytest.raises(AdbError) as caught:
        AdbBackend().packages("emulator-5554", limit=bad)
    assert caught.value.code == "invalid_params"
    assert "limit" in caught.value.message


@pytest.mark.parametrize("bad", _BAD, ids=_BAD_IDS)
def test_logcat_rejects_a_bad_lines_before_touching_the_device(bad: Any) -> None:
    with pytest.raises(AdbError) as caught:
        AdbBackend().logcat("emulator-5554", lines=bad)
    assert caught.value.code == "invalid_params"
    assert "lines" in caught.value.message


@pytest.mark.parametrize(
    "good", [500, "500", 2.9, -5, 10**9], ids=["int", "str", "float", "neg", "huge"]
)
def test_properties_clamps_a_valid_or_clampable_limit_and_proceeds(good: Any) -> None:
    # A clampable value clears the guard and reaches _device; without adbutils
    # installed that is capability_unavailable -- never the invalid_params a
    # rejected argument gives.
    with pytest.raises(AdbError) as caught:
        AdbBackend().properties("emulator-5554", limit=good)
    assert caught.value.code != "invalid_params"
