"""``_export_has_content`` judges a non-zero-exit export by the *mode's* field.

analyzeHeadless routinely exits non-zero after a postScript that actually wrote
its JSON, so ``_export`` keeps a non-zero exit whose payload still carries
content and only fails the ones that came back empty::

    if code != 0 and not _export_has_content(payload, mode):
        raise GhidraError("backend_error", "analyzeHeadless export failed", ...)

Which field counts as "content" depends on the mode -- that is the whole reason
``_export_has_content`` takes ``mode``::

    def _export_has_content(payload, mode):
        if mode == "decompile":
            text = payload.get("decompiled")
            return isinstance(text, str) and bool(text.strip())
        items = payload.get("items")
        return isinstance(items, list) and bool(items)

The existing client tests only ever pair each mode with its own field: the
decompile cases carry ``decompiled`` and the list cases carry ``items``, and the
two non-zero-exit tests both use an *empty* payload, so both just re-confirm the
raise. Nothing pins the field *selection*:

* No test keeps a non-zero-exit **decompile** whose ``decompiled`` body is
  non-empty (the current one that decompiles a body runs at exit 0, so it never
  reaches the ``code != 0`` guard). Collapse the function to always inspect
  ``items`` and a decompile payload -- which never has an ``items`` key -- reads
  as empty, so every analyzeHeadless run that exits non-zero after decompiling a
  real function is thrown away as a backend error.

* No test proves a **list** export is judged by ``items`` *alone*: a functions
  run that came back with empty ``items`` must still fail even if some stray
  ``decompiled`` string rode along. Loosen the check to accept either field and
  that empty-but-non-zero export starts reading as success with zero functions.

These pin both directions with cross-field payloads the existing fixtures never
produce -- no real analyzeHeadless required.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed


def _client(tmp_path: Path) -> ghidra_client.GhidraClient:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    client = ghidra_client.GhidraClient(home=home)
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


def _run_writing(payload: str, *, exit_code: int) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(str(arg)).write_text(payload, encoding="utf-8")
        return Completed(exit_code, b"analyze log", b"script noise")

    return fake_run


def test_a_nonzero_exit_decompile_with_a_body_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """decompile content is the ``decompiled`` string, never an ``items`` list.

    Exit 1 with a real function body must survive: the payload has no ``items``
    key, so a check that inspected ``items`` here would discard a successful
    decompile as a backend error.
    """
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        _run_writing(
            '{"mode": "decompile", "function": "main", "entry": "0x401000",'
            ' "decompiled": "int main(){ return 0; }", "truncated": false}',
            exit_code=1,
        ),
    )
    client = _client(tmp_path)

    payload = client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")

    assert payload["found"] is True
    assert payload["decompiled"] == "int main(){ return 0; }"
    assert "items" not in payload


def test_a_nonzero_exit_list_export_with_empty_items_still_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A list mode is judged by ``items`` alone; a stray ``decompiled`` is noise.

    Empty ``items`` on a non-zero exit is a failed run even when some unrelated
    ``decompiled`` string tagged along. Accepting either field would let this
    read as a binary with zero functions instead of the backend error it is.
    """
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        _run_writing(
            '{"mode": "functions", "items": [], "count": 0,'
            ' "decompiled": "stray body that must not count"}',
            exit_code=1,
        ),
    )
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
