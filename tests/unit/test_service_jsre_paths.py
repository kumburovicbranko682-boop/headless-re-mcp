"""JS/WASM service methods: success envelopes, error mapping, unpack pruning.

The backend tests bound JsClient and WasmClient themselves; these pin the
mixin the tool surface calls -- each success answer carries the backend name,
a JsReError keeps its code through the envelope, an unexpected exception
still becomes a failure envelope, and the unpack tree pruning survives a
directory that vanishes between listing and stat.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service_jsre import JsReAnalysisMixin, prune_jsre_unpack_dirs

JsonObject = dict[str, Any]


class _Service(JsReAnalysisMixin):
    def __init__(self, tmp_path: Path) -> None:
        self.settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")


class _FakeClient:
    """Stands in for JsClient / WasmClient; every op answers the same way."""

    def __init__(self, answer: JsonObject | BaseException) -> None:
        self._answer = answer

    def _reply(self) -> JsonObject:
        if isinstance(self._answer, BaseException):
            raise self._answer
        return dict(self._answer)

    def deobfuscate(self, path: Path, *, timeout: float) -> JsonObject:
        return self._reply()

    def beautify(self, path: Path, *, timeout: float) -> JsonObject:
        return self._reply()

    def unpack_bundle(
        self, path: Path, out_dir: Path, *, timeout: float, offset: int, limit: int
    ) -> JsonObject:
        return self._reply()

    def wat(
        self, path: Path, *, timeout: float, spill_path: Path | None = None
    ) -> JsonObject:
        return self._reply()

    def info(
        self, path: Path, *, timeout: float, spill_path: Path | None = None
    ) -> JsonObject:
        return self._reply()


def _patch_clients(monkeypatch: pytest.MonkeyPatch, answer: JsonObject | BaseException) -> None:
    for name in ("JsClient", "WasmClient"):
        monkeypatch.setattr(
            f"headless_re_mcp.core.service_jsre.{name}",
            lambda _settings, _answer=answer: _FakeClient(_answer),
        )


def test_success_envelopes_name_the_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    _patch_clients(monkeypatch, {"changed": True})
    js_ops = [service.js_deobfuscate, service.js_beautify]
    for op in js_ops:
        result = op("bundle.js")
        assert result.ok is True
        assert result.data == {"changed": True}
        assert result.meta["backend"] == "webcrack"
    wasm_ops = [service.wasm_wat, service.wasm_info]
    for op in wasm_ops:
        result = op("module.wasm")
        assert result.ok is True
        assert result.meta["backend"] == "wabt"


def test_jsre_errors_keep_their_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _Service(tmp_path)
    _patch_clients(monkeypatch, JsReError("not_found", "no such file", path="bundle.js"))
    for op in (
        service.js_deobfuscate,
        service.js_beautify,
        service.wasm_wat,
        service.wasm_info,
    ):
        result = op("bundle.js")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
        assert result.error.details["path"] == "bundle.js"


def test_unexpected_exceptions_become_failure_envelopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash in the client must answer as an envelope, not a traceback."""
    service = _Service(tmp_path)
    _patch_clients(monkeypatch, RuntimeError("node exploded"))
    for op in (
        service.js_deobfuscate,
        service.js_beautify,
        service.wasm_wat,
        service.wasm_info,
    ):
        result = op("bundle.js")
        assert result.ok is False
        assert result.error is not None

    result = service.js_unpack_bundle("bundle.js")
    assert result.ok is False
    assert result.error is not None
    # The out dir minted for the failed unpack does not accumulate: pruning
    # ran in finally, so at most the retained window of trees remains.
    jsre_root = service.settings.artifact_root.expanduser().resolve() / "jsre"
    assert len(list(jsre_root.glob("unpack-*"))) <= 8


def test_prune_survives_a_missing_root(tmp_path: Path) -> None:
    prune_jsre_unpack_dirs(tmp_path / "never-created")
    assert not (tmp_path / "never-created").exists()


def test_prune_treats_an_unstatable_dir_as_oldest(tmp_path: Path) -> None:
    """A tree that vanishes between iterdir and stat must not abort pruning:
    it sorts as mtime 0 -- oldest -- and is removed first."""
    root = tmp_path / "jsre"
    root.mkdir()
    keep_me = root / "unpack-keep"
    keep_me.mkdir()

    ghost_real = root / "unpack-ghost"
    ghost_real.mkdir()

    class _Ghost:
        """Looks like a directory but refuses to stat."""

        name = "unpack-ghost"

        def is_dir(self) -> bool:
            return True

        def stat(self) -> Any:
            raise OSError("vanished")

        def __fspath__(self) -> str:
            return str(ghost_real)

    class _Root:
        def iterdir(self) -> Any:
            return iter([_Ghost(), keep_me])

    prune_jsre_unpack_dirs(cast(Path, _Root()), keep=1)
    assert not ghost_real.exists()
    assert keep_me.exists()


def test_prune_removes_only_the_oldest_extra_trees(tmp_path: Path) -> None:
    import os

    root = tmp_path / "jsre"
    root.mkdir()
    for index in range(4):
        tree = root / f"unpack-{index}"
        tree.mkdir()
        (tree / "module.js").write_text("x", encoding="utf-8")
        stamp = 1_000_000_000 + index
        os.utime(tree, (stamp, stamp))
    # A non-matching sibling must never be collected.
    other = root / "har-export"
    other.mkdir()
    prune_jsre_unpack_dirs(root, keep=2)
    assert not (root / "unpack-0").exists()
    assert not (root / "unpack-1").exists()
    assert (root / "unpack-2").exists()
    assert (root / "unpack-3").exists()
    assert other.exists()
