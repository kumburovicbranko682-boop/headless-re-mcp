"""The four bounded-subprocess capture paths must not drift apart.

DIE, Exeinfo PE, UPX and the de4dot / NETReactorSlayer adapter each carry a
near-identical ``_capture_process`` plus ``_creation_options``. They were copied,
not shared, so a fix or an invariant added to one does not reach the others.
Two of those invariants are load-bearing for the whole project and are pinned
here across every copy at once, rather than trusting each hand-written per-adapter
test to have remembered them:

* Headless launch. The project's core promise is that no analyzer/CLI console
  window appears; a capture path that forgets ``CREATE_NO_WINDOW`` (or that
  inherits the parent's stdin) breaks that quietly and only on Windows.
* A missing executable is a structured ``executable_not_found`` envelope code,
  never a bare ``FileNotFoundError`` crossing the tool boundary.

The de4dot module owns the shared capture that NETReactorSlayer imports, so the
four modules below cover all five CLI adapters.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from headless_re_mcp.detection import die, exeinfope
from headless_re_mcp.dotnet import de4dot
from headless_re_mcp.unpack import upx

# Every adapter spells the missing-binary code the same way; a copy that renamed
# it would break the shared MCP error contract callers key on.
NOT_FOUND_CODE = "executable_not_found"

CAPTURE_MODULES: list[tuple[str, ModuleType]] = [
    ("die", die),
    ("exeinfope", exeinfope),
    ("upx", upx),
    ("de4dot", de4dot),
]

_IDS = [name for name, _ in CAPTURE_MODULES]
_MODULES = [module for _, module in CAPTURE_MODULES]


@pytest.mark.parametrize("module", _MODULES, ids=_IDS)
def test_creation_options_are_headless_and_do_not_inherit_stdin(module: ModuleType) -> None:
    options = module._creation_options()

    # stdin is closed off so a probe can never block waiting on a console, and
    # both streams are captured rather than shared with ours.
    assert options["stdin"] is subprocess.DEVNULL
    assert options["stdout"] is subprocess.PIPE
    assert options["stderr"] is subprocess.PIPE

    # The headless promise is a Windows concern (a hidden console window); on
    # POSIX there is nothing to hide, and de4dot deliberately omits the key.
    if os.name == "nt":
        no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        assert options.get("creationflags", 0) & no_window, (
            f"{module.__name__} would let a CLI console window appear"
        )


@pytest.mark.parametrize("module", _MODULES, ids=_IDS)
def test_a_missing_executable_is_a_structured_not_found(
    module: ModuleType, tmp_path: Path
) -> None:
    # An absolute path that does not exist makes Popen raise FileNotFoundError
    # immediately -- no process is spawned, so this cannot hang.
    missing = tmp_path / "definitely-missing-binary"
    assert not missing.exists()

    with pytest.raises(Exception) as caught:  # noqa: PT011 - each adapter has its own type
        module._capture_process([str(missing)], timeout=1.0, max_output_size=64)

    # It must be the adapter's own structured error, not a bare OS exception.
    assert not isinstance(caught.value, (FileNotFoundError, OSError))
    assert getattr(caught.value, "code", None) == NOT_FOUND_CODE
