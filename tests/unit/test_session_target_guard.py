"""The Session.require_* guards are what turn a wrong-target call into a clean
``target_mismatch`` envelope instead of a failure deep inside a backend.

test_service.py exercises the guard end to end for two tools; these pin the
guard itself -- which target each accessor demands, and that the raised
TargetMismatch carries the code and the expected/actual detail the error
envelope is built from -- so a change to the model is caught without standing up
a session and a backend for every PE-only tool.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import (
    Architecture,
    Session,
    TargetKind,
    TargetMismatch,
)


def _session(target: TargetKind, **overrides: object) -> Session:
    return Session(target=target, **overrides)  # type: ignore[arg-type]


def test_require_pe_accepts_a_pe_session_and_returns_its_binary(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    session = _session(TargetKind.PE, binary=binary)

    assert session.require_pe() == binary
    assert session.require_target(TargetKind.PE) == binary


@pytest.mark.parametrize("wrong", [TargetKind.APK, TargetKind.WEB, TargetKind.ELF])
def test_require_pe_refuses_non_pe_sessions_with_a_structured_mismatch(
    wrong: TargetKind, tmp_path: Path
) -> None:
    session = _session(wrong, binary=tmp_path / "thing")

    with pytest.raises(TargetMismatch) as caught:
        session.require_pe()

    error = caught.value
    assert error.code == "target_mismatch"
    assert error.details["actual_target"] == wrong.value
    assert error.details["expected_targets"] == [TargetKind.PE.value]


def test_require_binary_explains_a_locator_only_session() -> None:
    """A web session has no local file; asking for one is a mismatch, not None."""
    session = _session(TargetKind.WEB, locator="https://example.com/app")

    with pytest.raises(TargetMismatch) as caught:
        session.require_binary()

    assert caught.value.code == "target_mismatch"
    assert caught.value.details["actual_target"] == TargetKind.WEB.value
    # A PE, an APK or an ELF is the thing that would have a local file.
    assert set(caught.value.details["expected_targets"]) == {
        TargetKind.PE.value,
        TargetKind.APK.value,
        TargetKind.ELF.value,
    }


def test_require_binary_returns_the_file_for_an_elf_session(tmp_path: Path) -> None:
    """An ELF session has a local file: the portable backends must reach it.

    require_pe refuses ELF (asserted above), but r2.*/ghidra.*/frida.* gate on
    require_binary, not require_pe -- so an ELF session must hand its binary back
    from require_binary, which is what makes those backends reachable on a native
    Linux target rather than the session being unusable.
    """
    binary = tmp_path / "a.out"
    session = _session(TargetKind.ELF, binary=binary)
    assert session.require_binary() == binary
    with pytest.raises(TargetMismatch):
        session.require_pe()


def test_require_architecture_needs_a_known_machine_type() -> None:
    with_arch = _session(TargetKind.PE, binary=Path("s.exe"), architecture=Architecture.X64)
    assert with_arch.require_architecture() is Architecture.X64

    without = _session(TargetKind.WEB, locator="https://example.com")
    with pytest.raises(TargetMismatch) as caught:
        without.require_architecture()
    assert caught.value.details["expected_targets"] == [TargetKind.PE.value]


def test_require_locator_needs_a_web_style_target() -> None:
    web = _session(TargetKind.WEB, locator="https://example.com/app")
    assert web.require_locator() == "https://example.com/app"

    pe = _session(TargetKind.PE, binary=Path("s.exe"))
    with pytest.raises(TargetMismatch) as caught:
        pe.require_locator()
    assert caught.value.details["expected_targets"] == [TargetKind.WEB.value]
