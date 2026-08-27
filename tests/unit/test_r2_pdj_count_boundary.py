"""The r2 ``pdj`` allowlist accepts exactly 1..512 instructions, and ``disasm`` agrees.

``_require_allowed_command`` is the r2 command gate -- r2 can write memory, seek,
open files, or shell out (``!``), so only a fixed allowlist reaches the process.
For paged disassembly it accepts ``pdj N @ addr`` only when N is a positive
integer with no leading zero *and* no larger than 512::

    _PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\\Z")
    ...
    pdj = _PDJ_COMMAND.fullmatch(command)
    if pdj is not None and int(pdj.group(1)) <= 512:
        return

512 is not an arbitrary number: ``disasm`` clamps its own ``count`` to the same
ceiling (``not 1 <= count <= 512`` -> invalid_params) and then builds
``pdj {count} @ {address}``. The two limits must be the *same* 512 or a legal
``disasm(count=512)`` would construct a command its own gate rejects.

The existing whitelist test pins the reject side of both edges -- ``pdj 513 @ 0``
is refused, and composed/injected forms never launch -- and one interior accept
(``pdj 32``). What it never pins is the *accept* boundary or the count shape, and
those are the pieces a plausible edit slips past:

* **512 is allowed; 513 is not.** With only 513 tested as rejected and 32 as
  accepted, tightening ``<= 512`` to ``< 512`` stays green -- yet it silently
  drops the maximum page, and worse, makes ``disasm(count=512)`` build a command
  the gate now refuses. This pins 511 and 512 as accepted against that off-by-one.

* **The count is a positive integer, not zero and not zero-padded.** The
  ``[1-9][0-9]*`` class rejects ``pdj 0 @ 0`` (matching ``disasm``'s ``1 <=``
  floor) and ``pdj 01 @ 0``. Loosen it to ``[0-9]+`` and both start slipping
  through; these pin the shape.

* **``disasm``'s ceiling and the gate's ceiling are one number.** A max-count
  disasm must survive its own allowlist and reach launch. Move either 512 and
  this breaks, catching a divergence the reject-only edge test cannot see.

These call ``_require_allowed_command`` directly for the pure boundary and drive
``disasm`` with a fake ``run_bounded`` for the consistency -- no r2 binary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _require_allowed_command


def _is_allowed(command: str) -> bool:
    try:
        _require_allowed_command(command)
    except R2Error:
        return False
    return True


@pytest.mark.parametrize("count", [1, 2, 511, 512])
def test_a_pdj_page_up_to_512_is_allowed(count: int) -> None:
    """1..512 instructions are the legal page sizes, 512 included.

    512 is the accept boundary the reject-only existing test leaves open: it is
    the largest page ``disasm`` can ask for, so it must pass the gate.
    """
    assert _is_allowed(f"pdj {count} @ 0x401000") is True
    assert _is_allowed(f"pdj {count} @ 4198400") is True


@pytest.mark.parametrize("count", [513, 1000, 99999])
def test_a_pdj_page_over_512_is_rejected(count: int) -> None:
    """513 and up exceed the ceiling and are refused, however the address is written."""
    assert _is_allowed(f"pdj {count} @ 0x401000") is False
    assert _is_allowed(f"pdj {count} @ 4198400") is False


@pytest.mark.parametrize("bad", ["pdj 0 @ 0", "pdj 01 @ 0", "pdj 00 @ 0x10", "pdj 0512 @ 0"])
def test_a_pdj_count_must_be_a_bare_positive_integer(bad: str) -> None:
    """Zero and zero-padded counts are not legal page sizes.

    ``[1-9][0-9]*`` mirrors ``disasm``'s ``1 <= count`` floor: a page of zero is
    refused, and a zero-padded count (which could smuggle a different numeric
    reading) never matches.
    """
    assert _is_allowed(bad) is False


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    return R2Client(executable), binary


def test_disasm_at_the_max_count_builds_a_command_its_own_gate_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``disasm(count=512)`` must survive the allowlist and reach launch.

    ``disasm`` clamps count to 1..512 and then builds ``pdj 512 @ addr``. If that
    ceiling and the gate's ceiling ever diverge, the maximum-count disassembly
    would be refused by its own whitelist before r2 is ever run. This proves the
    two 512s are the same number: the command is built and launched.
    """
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = client.disasm(binary, 0x401000, count=512)

    assert "pdj 512 @ 4198400" in result["commands"]
    assert len(launched) == 1
    # The built r2 script carries the max-count page verbatim.
    script = launched[0][launched[0].index("-c") + 1]
    assert "pdj 512 @ 4198400" in script


def test_disasm_refuses_a_count_over_the_ceiling_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``disasm`` rejects count 513 at its own boundary, never reaching r2.

    The clamp and the gate agree from the other side too: one past the ceiling is
    invalid_params, and no process is spawned.
    """
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    with pytest.raises(R2Error) as caught:
        client.disasm(binary, 0x401000, count=513)
    assert caught.value.code == "invalid_params"
    assert launched == []
