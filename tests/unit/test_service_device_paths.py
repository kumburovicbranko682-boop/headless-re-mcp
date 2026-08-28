"""Coverage for service_device helper OSError arms and the oversized-capture path.

The existing device suite covers the happy capture path (small files kept) and
the byte-cap refusal helper; these reach the ``OSError`` fall-throughs in the
directory/size helpers, the fallback ``AdbBackend`` construction, the generic
exception arm of ``_adb_wrap``, and the oversized screenshot/pull branches that
delete the capture and return the refusal.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_device as service_device
from headless_re_mcp.backends.adb import AdbBackend
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    prune_device_artifacts,
    refuse_oversized_device_file,
)

JsonObject = dict[str, Any]


# ---------------------------------------------------------------------------
# module-level helper arms
# ---------------------------------------------------------------------------


def test_prune_device_artifacts_ignores_an_unlistable_directory(tmp_path: Path) -> None:
    prune_device_artifacts(tmp_path / "does-not-exist")  # iterdir raises OSError


def test_prune_device_artifacts_is_a_noop_below_the_keep_count(tmp_path: Path) -> None:
    directory = tmp_path / "device"
    directory.mkdir()
    (directory / "only.png").write_bytes(b"x")
    prune_device_artifacts(directory, keep=32)
    assert (directory / "only.png").exists()


def test_prune_device_artifacts_treats_unstattable_files_as_oldest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "device"
    directory.mkdir()
    for index in range(3):
        (directory / f"e{index}.png").write_bytes(b"x")

    def _raise_stat(self: Path) -> object:
        raise OSError("stat refused")

    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(Path, "stat", _raise_stat)  # every _mtime() falls back to 0
    prune_device_artifacts(directory, keep=1)
    assert len(list(directory.iterdir())) == 1


def test_refuse_oversized_device_file_ignores_a_missing_file(tmp_path: Path) -> None:
    assert refuse_oversized_device_file(tmp_path / "gone.bin") is None


# ---------------------------------------------------------------------------
# mixin backend selection and wrap arms
# ---------------------------------------------------------------------------


class _PlainHarness(DeviceAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, adb=None)  # type: ignore[assignment]


def test_backend_falls_back_to_a_fresh_adb_backend(tmp_path: Path) -> None:
    assert isinstance(_PlainHarness(tmp_path)._backend(), AdbBackend)


class _RaisingHarness(DeviceAnalysisMixin):
    def __init__(self) -> None:
        self.settings = SimpleNamespace(artifact_root=Path("/tmp"))  # type: ignore[assignment]

    def _backend(self) -> Any:
        def _boom(**_kwargs: object) -> object:
            raise RuntimeError("backend down")

        return SimpleNamespace(list_devices=_boom)


def test_adb_wrap_wraps_an_unexpected_exception() -> None:
    result = _RaisingHarness().device_list()
    assert result.ok is False
    assert result.error is not None


# ---------------------------------------------------------------------------
# oversized screenshot / pull branches
# ---------------------------------------------------------------------------


class _WritingHarness(DeviceAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root)  # type: ignore[assignment]

    def _adb_wrap(self, op: str, /, **kwargs: object) -> Result[JsonObject]:
        path = Path(str(kwargs.get("out_path") or kwargs.get("local_path")))
        path.write_bytes(b"x" * 10)
        return _success({"path": str(path)}, backend="adb")


def _oversized_result() -> Result[JsonObject]:
    return Result[JsonObject](
        ok=False,
        error=RpcError(code="output_too_large", message="too big", details={}),
    )


@pytest.mark.parametrize("method", ["device_screenshot", "device_pull"])
def test_oversized_capture_is_pruned_and_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    monkeypatch.setattr(
        service_device, "refuse_oversized_device_file", lambda _path: _oversized_result()
    )
    harness = _WritingHarness(tmp_path)
    if method == "device_screenshot":
        result = harness.device_screenshot("emulator-5554")
    else:
        result = harness.device_pull("emulator-5554", "/sdcard/big.bin")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "output_too_large"
