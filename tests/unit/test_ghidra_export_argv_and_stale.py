"""ghidra _export_unlocked: stale-artifact removal and the argv it hands ExportJson.

The export tests all drive a run whose fake writes fresh JSON and pass a string
address with the default limit, so three things _export_unlocked does before and
around the run go unchecked:

  * ``if out_path.exists(): out_path.unlink()`` -- a prior run's export_<mode>.json
    is deleted first, so a run that writes nothing raises instead of handing back
    a previous binary's results as if they were this one's.
  * ``addr = "" if address is None else (hex(address) if isinstance(address, int)
    else str(address))`` -- an int address must reach the script as hex, a string
    passes through, and functions/symbols (no address) send an empty argument.
  * ``capped = max(1, min(int(limit), 1024))`` -- the page size handed to the
    script is floored at one and capped at 1024.

A stale read would report the wrong binary; a decimal address or an out-of-range
limit would make the postScript look somewhere or return more/less than asked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    return home


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 40)
    return path


def _client(tmp_path: Path) -> ghidra_client.GhidraClient:
    client = ghidra_client.GhidraClient(home=_fake_home(tmp_path))
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _post_script_args(cmd: list[str]) -> list[str]:
    """Return [script, mode, out_path, capped, addr] following -postScript."""
    index = cmd.index("-postScript")
    return cmd[index + 1 : index + 6]


def _capture_writing(monkeypatch: pytest.MonkeyPatch, payload: str) -> dict[str, list[str]]:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        argv = [str(part) for part in cmd]
        captured["cmd"] = argv
        for arg in argv:
            if arg.endswith(".json"):
                Path(arg).write_text(payload, encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return captured


def test_a_stale_export_from_a_prior_run_is_removed_not_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A previous run left export_functions.json in the project dir. This run's
    script writes nothing (exit 0). Without the unlink, the client would read the
    stale file and report another binary's functions; with it, the missing output
    is a backend_error.
    """
    project = tmp_path / "project"
    project.mkdir()
    stale = project / "export_functions.json"
    stale.write_text(
        '{"mode": "functions", "items": [{"entry": "0xdead"}], "count": 1}',
        encoding="utf-8",
    )

    def fake_run_nowrite(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run_nowrite)
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), project)

    assert caught.value.code == "backend_error"
    assert "missing" in caught.value.message


def test_an_integer_address_reaches_the_script_as_hex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ghidra wants a hex address string. An int must be formatted with hex(),
    not str() -- 0x401000 as the decimal 4198400 would point the script at the
    wrong place.
    """
    captured = _capture_writing(
        monkeypatch, '{"mode": "xrefs", "items": [], "count": 0}'
    )
    client = _client(tmp_path)

    client.xrefs(_binary(tmp_path), tmp_path / "project", 0x401000)

    addr = _post_script_args(captured["cmd"])[4]
    assert addr == "0x401000"
    assert addr != "4198400"


def test_a_string_address_passes_through_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A string address is forwarded verbatim (the else branch). If the code
    always called hex(), a string would raise TypeError instead.
    """
    captured = _capture_writing(
        monkeypatch, '{"mode": "xrefs", "items": [], "count": 0}'
    )
    client = _client(tmp_path)

    client.xrefs(_binary(tmp_path), tmp_path / "project", "0x401000")

    assert _post_script_args(captured["cmd"])[4] == "0x401000"


def test_a_listing_without_an_address_sends_an_empty_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """functions/symbols carry no address, so the addr slot must be the empty
    string -- the None branch. A None leaking through as the literal "None"
    would be a bogus address argument.
    """
    captured = _capture_writing(
        monkeypatch, '{"mode": "functions", "items": [], "count": 0}'
    )
    client = _client(tmp_path)

    client.functions(_binary(tmp_path), tmp_path / "project")

    assert _post_script_args(captured["cmd"])[4] == ""


@pytest.mark.parametrize(
    ("limit", "expected"),
    [(0, "1"), (-5, "1"), (1, "1"), (5000, "1024"), (1024, "1024")],
)
def test_the_page_size_is_floored_at_one_and_capped_at_1024(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: int, expected: str
) -> None:
    """max(1, min(int(limit), 1024)): a non-positive limit must not send 0 (an
    empty page) to the script, and a huge one must not ask for an unbounded
    export.
    """
    captured = _capture_writing(
        monkeypatch, '{"mode": "functions", "items": [], "count": 0}'
    )
    client = _client(tmp_path)

    client.functions(_binary(tmp_path), tmp_path / "project", limit=limit)

    assert _post_script_args(captured["cmd"])[3] == expected
