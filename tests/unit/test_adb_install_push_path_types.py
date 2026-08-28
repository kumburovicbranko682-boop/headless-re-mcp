"""AdbBackend.install/push must refuse a non-string path arg as invalid_params.

apk_path (install) and local_path (push) are schema-typed as strings, but the
agent and OpenAI-bridge transports bind handler kwargs straight from model
output with no pydantic coercion. Each method calls Path(arg).expanduser() before
it reaches the adb server, so a non-string value raised a raw TypeError. The
device.* service wrapper's except BaseException filed that as a logged
internal_error incident instead of the invalid_params a bad path deserves.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

_NON_STRING_PATHS = [123, ["/x"], {"p": "/x"}, 1.5, b"/x", True, None]


@pytest.mark.parametrize("apk_path", _NON_STRING_PATHS)
def test_install_refuses_a_non_string_apk_path(monkeypatch: Any, apk_path: object) -> None:
    backend = AdbBackend()
    # A rejected path must fail before any device handle is resolved; make the
    # resolver explode so the test proves the guard fires first.
    monkeypatch.setattr(
        backend, "_device", lambda serial: pytest.fail("adb server must not be touched")
    )
    with pytest.raises(AdbError) as caught:
        backend.install("emulator-5554", cast(Any, apk_path))
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("local_path", _NON_STRING_PATHS)
def test_push_refuses_a_non_string_local_path(monkeypatch: Any, local_path: object) -> None:
    backend = AdbBackend()
    monkeypatch.setattr(
        backend, "_device", lambda serial: pytest.fail("adb server must not be touched")
    )
    with pytest.raises(AdbError) as caught:
        backend.push("emulator-5554", cast(Any, local_path), "/data/local/tmp/x")
    assert caught.value.code == "invalid_params"
