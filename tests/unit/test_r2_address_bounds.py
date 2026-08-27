"""r2.disasm / r2.xrefs must bound address and count before the subprocess.

The MCP schema bounds these arguments, but the direct (non-MCP) service path
does not go through that pydantic validation -- the client's own check is the
backstop, exactly as apk's _clamp_page is for the apk pages. test_r2_xrefs_fields
asserts only that the message string appears in the source, which would still
pass if the raise became unreachable (moved after self.run, or the bound
loosened). These exercise the behaviour instead: a bad address/count raises
invalid_params, and -- the property the source check cannot make -- the
rejection happens before self.run, so it holds whether or not radare2 is on the
host. No r2 needed: validation precedes the availability check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error

_BINARY = Path("/tmp/does-not-matter.bin")


@pytest.mark.parametrize("address", [-1, -(10**9), True])
def test_disasm_rejects_a_non_negative_int_address(address: object) -> None:
    # True is included on purpose: `type(x) is int` is False for bool, so the
    # check refuses it rather than silently disassembling at address 1.
    with pytest.raises(R2Error) as info:
        R2Client().disasm(_BINARY, address)  # type: ignore[arg-type]
    assert info.value.code == "invalid_params"
    assert "address" in info.value.message


@pytest.mark.parametrize("count", [0, -1, 513, 10**9, True])
def test_disasm_rejects_an_out_of_range_count(count: object) -> None:
    with pytest.raises(R2Error) as info:
        R2Client().disasm(_BINARY, 0x1000, count=count)  # type: ignore[arg-type]
    assert info.value.code == "invalid_params"
    assert "count" in info.value.message


@pytest.mark.parametrize("address", [-1, -(10**9), True])
def test_xrefs_rejects_a_non_negative_int_address(address: object) -> None:
    with pytest.raises(R2Error) as info:
        R2Client().xrefs(_BINARY, address)  # type: ignore[arg-type]
    assert info.value.code == "invalid_params"
    assert "address" in info.value.message


def test_bad_params_are_rejected_before_self_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bound is a pre-check, not a post-hoc filter on r2's output.

    Stub run() so reaching it is observable: a bad argument must raise
    invalid_params without run() being called, and a well-formed one must reach
    run(). This is what makes the bound meaningful when radare2 is installed --
    otherwise a reordered check would only surface once the subprocess ran.
    """
    client = R2Client()
    reached = []

    def fake_run(*args: object, **kwargs: object) -> dict[str, object]:
        reached.append(True)
        raise RuntimeError("self.run was reached")

    monkeypatch.setattr(client, "run", fake_run)

    with pytest.raises(R2Error) as info:
        client.disasm(_BINARY, -1)
    assert info.value.code == "invalid_params"
    assert not reached, "validation must reject before self.run"

    with pytest.raises(RuntimeError, match="self.run was reached"):
        client.disasm(_BINARY, 0x1000, count=16)
    assert reached, "a valid call must reach self.run"
