"""The shared jsre/wasm input guard, pinned tool-free.

``_require_existing_file`` is the one gate every ``js.*`` and ``wasm.*``
endpoint runs before it hands a path to webcrack or wabt. It refuses a
missing file (``not_found``), a file past the 16 MiB cap (``too_large`` --
so an unattended pass cannot bind node/wat2wasm to an arbitrarily large
file on disk for the whole timeout), and a file whose size cannot be read
(``backend_error``, never an uncaught ``OSError`` reaching the envelope as
an internal_error).

Every other test of this guard needs the real CLI: the service-level
web_jsre gate skips without webcrack/wabt, and the one unit test that
reaches these methods (test_unattended_resource_bounds) monkeypatches
``_require_input`` away to get at the file-listing cap behind it. So on any
checkout without both tools -- the common case, including this VM -- the
guard itself had no coverage.

These tests are pure: they never launch a subprocess (a spy fails the test
if one is attempted), so they run everywhere and pin the "refused before
the child is launched" contract that the integration gate can only assert
when the tools happen to be installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as jsre
from headless_re_mcp.backends.jsre.client import (
    _MAX_INPUT_BYTES,
    JsClient,
    JsReError,
    WasmClient,
    _require_existing_file,
)


def _sized(path: Path, size: int) -> Path:
    """A sparse file of exactly ``size`` bytes (truncate, so 16 MiB is cheap)."""
    with path.open("wb") as sink:
        sink.truncate(size)
    return path


def _forbid_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any subprocess launch fail the test loudly.

    The guard must reject before ``_run`` is reached; if it does not, this
    turns the silent bypass into an AssertionError rather than a confusing
    downstream failure on a fake executable.
    """

    def boom(*args: object, **kwargs: object) -> tuple[str, str, int]:
        raise AssertionError("subprocess launched despite the input guard")

    monkeypatch.setattr(jsre, "_run", boom)


# --- the guard as a pure function -------------------------------------------


def test_missing_input_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        _require_existing_file(tmp_path / "nope.js", missing="input file not found")
    assert caught.value.code == "not_found"
    # The caller-supplied message is the one that reaches the envelope.
    assert caught.value.message == "input file not found"
    assert str(caught.value.details["path"]).endswith("nope.js")


def test_input_at_the_cap_is_accepted(tmp_path: Path) -> None:
    # The bound is strict (``size > cap``): a file exactly at the cap is still
    # analysable, so the boundary is not off by one against a real max module.
    exact = _sized(tmp_path / "exact.js", _MAX_INPUT_BYTES)
    assert _require_existing_file(exact, missing="input file not found") == exact


def test_input_one_byte_over_the_cap_is_too_large(tmp_path: Path) -> None:
    over = _sized(tmp_path / "over.js", _MAX_INPUT_BYTES + 1)
    with pytest.raises(JsReError) as caught:
        _require_existing_file(over, missing="input file not found")
    assert caught.value.code == "too_large"
    assert caught.value.details["max_file_size"] == _MAX_INPUT_BYTES
    assert caught.value.details["size"] == _MAX_INPUT_BYTES + 1
    assert str(caught.value.details["path"]).endswith("over.js")


def test_unreadable_input_is_backend_error_not_raw_oserror() -> None:
    # is_file() True but stat() raising is the TOCTOU race: a file that loses
    # permission or vanishes between the existence check and the size read must
    # degrade to backend_error, never let the OSError escape the parser.
    class _StatRaises:
        def expanduser(self) -> _StatRaises:
            return self

        def is_file(self) -> bool:
            return True

        def stat(self) -> object:
            raise OSError("gone")

        def __str__(self) -> str:
            return "/vanished/input.js"

    with pytest.raises(JsReError) as caught:
        _require_existing_file(_StatRaises(), missing="input file not found")  # type: ignore[arg-type]
    assert caught.value.code == "backend_error"
    assert "unreadable" in caught.value.message


# --- the guard wired into the real client methods ---------------------------


@pytest.mark.parametrize("method", ["deobfuscate", "beautify"])
def test_jsclient_rejects_missing_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    _forbid_launch(monkeypatch)
    # The executable need not exist: the input guard fires before it is used.
    client = JsClient(executable=tmp_path / "webcrack")
    with pytest.raises(JsReError) as caught:
        getattr(client, method)(tmp_path / "nope.js")
    assert caught.value.code == "not_found"


@pytest.mark.parametrize("method", ["deobfuscate", "beautify"])
def test_jsclient_rejects_oversized_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    _forbid_launch(monkeypatch)
    client = JsClient(executable=tmp_path / "webcrack")
    big = _sized(tmp_path / "big.js", _MAX_INPUT_BYTES + 1)
    with pytest.raises(JsReError) as caught:
        getattr(client, method)(big)
    assert caught.value.code == "too_large"


def test_unpack_bundle_rejects_oversized_before_mkdir_or_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_launch(monkeypatch)
    client = JsClient(executable=tmp_path / "webcrack")
    big = _sized(tmp_path / "big.js", _MAX_INPUT_BYTES + 1)
    out_dir = tmp_path / "unpack-out"
    with pytest.raises(JsReError) as caught:
        client.unpack_bundle(big, out_dir)
    assert caught.value.code == "too_large"
    # The guard runs before out_dir.mkdir, so a rejected unpack leaves no tree.
    assert out_dir.exists() is False


def test_unpack_bundle_rejects_missing_before_mkdir_or_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_launch(monkeypatch)
    client = JsClient(executable=tmp_path / "webcrack")
    out_dir = tmp_path / "unpack-out"
    with pytest.raises(JsReError) as caught:
        client.unpack_bundle(tmp_path / "nope.js", out_dir)
    assert caught.value.code == "not_found"
    assert out_dir.exists() is False


def _wasm_client(tmp_path: Path) -> WasmClient:
    """A WasmClient with both tools present (fake paths) but never launched."""
    client = WasmClient()
    client._wasm2wat = tmp_path / "wasm2wat"
    client._objdump = tmp_path / "wasm-objdump"
    return client


@pytest.mark.parametrize("method", ["wat", "info"])
def test_wasmclient_rejects_missing_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    _forbid_launch(monkeypatch)
    client = _wasm_client(tmp_path)
    with pytest.raises(JsReError) as caught:
        getattr(client, method)(tmp_path / "nope.wasm")
    assert caught.value.code == "not_found"
    # The wasm path carries its own message, distinct from the JS one.
    assert caught.value.message == "wasm file not found"


@pytest.mark.parametrize("method", ["wat", "info"])
def test_wasmclient_rejects_oversized_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    _forbid_launch(monkeypatch)
    client = _wasm_client(tmp_path)
    big = _sized(tmp_path / "big.wasm", _MAX_INPUT_BYTES + 1)
    with pytest.raises(JsReError) as caught:
        getattr(client, method)(big)
    assert caught.value.code == "too_large"
