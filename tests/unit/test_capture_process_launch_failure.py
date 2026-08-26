"""A _capture_process spawn failure must be a structured tool error, not a leak.

The four adapters that run a fixed argv through their own capture loop
(die, exeinfope, upx, de4dot -- the last shared by scylla/xvlkc/vmp_dumper and
NETReactorSlayer) each guard subprocess.Popen: FileNotFoundError becomes
``executable_not_found`` and any other OSError becomes ``process_failed``.

subprocess.Popen raises OSError when a configured tool is present but cannot be
launched (a file that is not marked +x raises PermissionError; a path that
vanished between an is_file() check and the spawn raises FileNotFoundError).
This pins that the launch mapping stays -- a raw OSError escaping here would
reach the service envelope as an internal_error with a logged incident, casting
a backend misconfiguration as a server defect, the same miscasting the
run_bounded adapters (r2/ghidra/tesseract) grew a guard for.

Cross-platform: Popen is monkeypatched to raise the OSError a real
non-executable produces, so the mapping is exercised identically on POSIX and
Windows with no real tool on the box.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.detection.die as die_mod
import headless_re_mcp.detection.exeinfope as exeinfope_mod
import headless_re_mcp.dotnet.de4dot as de4dot_mod
import headless_re_mcp.unpack.upx as upx_mod

# (module, base-error-type). Every module's _capture_process raises a subclass
# of this base for both the not-found and the process-failed case.
_ADAPTERS = [
    pytest.param(die_mod, die_mod.DieScanError, id="die"),
    pytest.param(exeinfope_mod, exeinfope_mod.ExeinfopeScanError, id="exeinfope"),
    pytest.param(upx_mod, upx_mod.UpxScanError, id="upx"),
    pytest.param(de4dot_mod, de4dot_mod.De4dotError, id="de4dot"),
]


@pytest.mark.parametrize(("module", "error_type"), _ADAPTERS)
def test_capture_process_maps_launch_permissionerror_to_process_failed(
    module: Any, error_type: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(module.subprocess, "Popen", boom)

    with pytest.raises(error_type) as caught:
        module._capture_process(["/configured/but/not/executable"], timeout=1.0, max_output_size=64)
    # StrEnum compares equal to its value; a launch failure is process_failed,
    # never a raw OSError that the envelope would file as internal_error.
    assert caught.value.code == "process_failed"


@pytest.mark.parametrize(("module", "error_type"), _ADAPTERS)
def test_capture_process_maps_missing_executable_to_executable_not_found(
    module: Any, error_type: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    def gone(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(module.subprocess, "Popen", gone)

    with pytest.raises(error_type) as caught:
        module._capture_process(["/vanished/tool"], timeout=1.0, max_output_size=64)
    assert caught.value.code == "executable_not_found"
