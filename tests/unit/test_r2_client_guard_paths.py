"""Guard-path coverage for the r2 client (no live radare2 required).

Complements ``test_r2_address_mapping.py`` (payload shaping) and
``test_r2_command_whitelist.py`` (the command allow-list) with the client
branches nothing exercised:

* ``open`` and ``run`` on a missing target binary (``not_found``), and ``run``
  without a usable executable (``capability_unavailable``).
* ``disasm`` / ``xrefs`` input validation -- a bool or string address, a
  negative address, a count outside 1..512 -- and, on the happy path, the
  exact ``pdj``/``axtj``+``axfj`` script handed to the process plus the
  echoed address/count fields.
* ``_discover`` returning the first radare2 binary name found on PATH.

The disasm/xrefs commands matter because they are built from caller input and
must stay inside the allow-list the client enforces: a change to the format
string that stops matching ``_PDJ_COMMAND``/``_AXREF_COMMAND`` would reject
every disasm call at runtime, which these tests would catch immediately.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_client
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover


def _stub_executable(tmp_path: Path) -> Path:
    """A file that exists, so the client considers r2 available without one."""
    path = tmp_path / "r2"
    path.write_bytes(b"")
    return path


def _target(tmp_path: Path) -> Path:
    """Any existing file: enrichment reads it and finds no PE, which is fine."""
    path = tmp_path / "target.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return path


def _capture(recorded: list[list[str]], stdout: bytes = b"[]") -> Any:
    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        recorded.append(list(cmd))
        return Completed(returncode=0, stdout=stdout, stderr=b"")

    return fake


def _script_lines(argv: list[str]) -> list[str]:
    return argv[argv.index("-c") + 1].splitlines()


# --- open / run error contracts ----------------------------------------------


def test_open_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    client = R2Client(_stub_executable(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.open(tmp_path / "nope.bin")
    assert caught.value.code == "not_found"


def test_run_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    client = R2Client(_stub_executable(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "nope.bin", ["i"])
    assert caught.value.code == "not_found"


def test_run_without_a_usable_executable_is_capability_unavailable(
    tmp_path: Path,
) -> None:
    """A configured path that no longer exists must not read as installed."""
    client = R2Client(tmp_path / "gone-r2")
    assert client.available is False
    with pytest.raises(R2Error) as caught:
        client.run(_target(tmp_path), ["i"])
    assert caught.value.code == "capability_unavailable"


# --- disasm ------------------------------------------------------------------


def test_disasm_rejects_a_non_int_address(tmp_path: Path) -> None:
    """A string address -- and a bool, which JSON true would arrive as -- are
    invalid_params, not coerced."""
    client = R2Client(_stub_executable(tmp_path))
    for bad in ("0x10", True, 1.0, None):
        with pytest.raises(R2Error) as caught:
            client.disasm(_target(tmp_path), bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_disasm_rejects_a_negative_address(tmp_path: Path) -> None:
    client = R2Client(_stub_executable(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.disasm(_target(tmp_path), -1)
    assert caught.value.code == "invalid_params"


def test_disasm_rejects_a_count_outside_1_to_512(tmp_path: Path) -> None:
    client = R2Client(_stub_executable(tmp_path))
    for bad in (0, 513, -3, True):
        with pytest.raises(R2Error) as caught:
            client.disasm(_target(tmp_path), 0x10, count=bad)
        assert caught.value.code == "invalid_params"


def test_disasm_builds_the_whitelisted_pdj_script_and_echoes_the_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The script is ``aa`` then ``pdj <count> @ <addr>`` then ``q``.

    Both commands must clear the allow-list ``run`` enforces (a drifted format
    string would raise ``invalid_params`` for every call). The payload echoes
    the requested address as ``address_va``; ``count`` is the number of parsed
    instructions, not the request -- enrichment overwrites the requested value
    whenever the output parses to a list, so pinning 2 here keeps that
    behaviour honest.
    """
    recorded: list[list[str]] = []
    listing = b'[{"offset": 16, "opcode": "nop"}, {"offset": 17, "opcode": "ret"}]'
    monkeypatch.setattr(r2_client, "run_bounded", _capture(recorded, stdout=listing))
    client = R2Client(_stub_executable(tmp_path))

    payload = client.disasm(_target(tmp_path), 0x10, count=4)

    assert len(recorded) == 1
    assert _script_lines(recorded[0]) == ["aa", "pdj 4 @ 16", "q"]
    assert payload["address_va"] == 0x10
    assert payload["count"] == 2
    assert payload["items"][0]["address"]["va"] == 0x10
    assert payload["parsed"] is True


# --- xrefs -------------------------------------------------------------------


def test_xrefs_rejects_a_non_int_or_negative_address(tmp_path: Path) -> None:
    client = R2Client(_stub_executable(tmp_path))
    for bad in ("0x10", True, -1):
        with pytest.raises(R2Error) as caught:
            client.xrefs(_target(tmp_path), bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_xrefs_builds_the_scoped_axtj_axfj_script_and_tags_directions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One process, both scoped queries, and per-item direction tags.

    The script must be ``aa`` then ``axtj @ addr`` then ``axfj @ addr`` --
    never ``axj``, which ignores the seek and dumps the whole xref database
    (the address parameter was inert until this was fixed). The two root
    arrays are attributed by print order: axtj rows become direction "to"
    with the seek address filled in as their implicit ``to`` endpoint, axfj
    rows become direction "from".
    """
    recorded: list[list[str]] = []
    stdout = (
        b'[{"from": 64, "type": "CALL", "opcode": "call 0x20"}]\n'
        b'[{"from": 32, "to": 96, "type": "CALL"}]\n'
    )
    monkeypatch.setattr(r2_client, "run_bounded", _capture(recorded, stdout=stdout))
    client = R2Client(_stub_executable(tmp_path))

    payload = client.xrefs(_target(tmp_path), 0x20)

    assert len(recorded) == 1
    assert _script_lines(recorded[0]) == ["aa", "axtj @ 32", "axfj @ 32", "q"]
    assert payload["address_va"] == 0x20
    assert payload["parsed"] is True
    assert [(item["direction"], item["from"], item["to"]) for item in payload["items"]] == [
        ("to", 64, 32),
        ("from", 32, 96),
    ]
    # Both endpoints of every row map through the unified Address shape.
    assert payload["items"][0]["from_address"]["va"] == 64
    assert payload["items"][0]["to_address"]["va"] == 32
    assert payload["items"][1]["to_address"]["va"] == 96


def test_xrefs_reports_unparsed_when_a_direction_array_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single root array cannot be attributed to a direction safely.

    Truncated output or a backend that rejected one command leaves one array
    behind; guessing which query produced it would silently mislabel every
    row, so the payload degrades to ``parsed: False`` with the raw text kept.
    """
    recorded: list[list[str]] = []
    monkeypatch.setattr(r2_client, "run_bounded", _capture(recorded, stdout=b'[{"from": 64}]'))
    client = R2Client(_stub_executable(tmp_path))

    payload = client.xrefs(_target(tmp_path), 0x20)

    assert payload["parsed"] is False
    assert "items" not in payload
    assert payload["raw"] == '[{"from": 64}]'


# --- _discover ---------------------------------------------------------------


def test_discover_returns_the_first_name_found_on_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only ``rizin`` is installed here: the scan steps past ``r2`` and finds
    it, and a bare ``R2Client()`` picks the same executable up."""
    found = tmp_path / "rizin"
    found.write_bytes(b"")

    def fake_which(name: str) -> str | None:
        return str(found) if name == "rizin" else None

    monkeypatch.setattr(shutil, "which", fake_which)
    assert _discover() == found
    assert R2Client().executable == found


def test_discover_returns_none_when_no_name_is_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert _discover() is None
