"""JS/WASM static-analysis service: error mapping and unpack-dir pruning.

These tools run webcrack / wabt over a local file. The live gates skip when the
CLIs are absent (skip != pass), so the envelope mapping and the retention prune
that keeps js.unpack_bundle from filling the artifact root were thin under unit
coverage. These drive them with the CLI clients stubbed.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.core.service_jsre import (
    _MAX_JSRE_UNPACK_DIRS,
    JsReAnalysisMixin,
    prune_jsre_unpack_dirs,
)


class _Service(JsReAnalysisMixin):
    def __init__(self, artifact_root: Path) -> None:
        self.settings = SimpleNamespace(  # type: ignore[assignment]
            artifact_root=artifact_root, webcrack=None, wabt=None
        )


# ----------------------------------------------------------------------
# prune_jsre_unpack_dirs.
# ----------------------------------------------------------------------
def test_prune_keeps_the_newest_unpack_dirs(tmp_path: Path) -> None:
    """js.unpack_bundle never registers its tree, so retention cannot see it.

    The prune is the only thing keeping repeated unpacks from growing the
    artifact root without bound, so it drops the oldest once the cap is passed.
    """
    for index in range(_MAX_JSRE_UNPACK_DIRS + 3):
        made = tmp_path / f"unpack-{index}"
        made.mkdir()
        os.utime(made, (index, index))
    prune_jsre_unpack_dirs(tmp_path)
    remaining = sorted(p.name for p in tmp_path.iterdir())
    assert len(remaining) == _MAX_JSRE_UNPACK_DIRS
    # The three oldest (0, 1, 2) are gone; the newest survive.
    assert "unpack-0" not in remaining
    assert f"unpack-{_MAX_JSRE_UNPACK_DIRS + 2}" in remaining


def test_prune_ignores_non_unpack_entries(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("x")
    (tmp_path / "other-dir").mkdir()
    prune_jsre_unpack_dirs(tmp_path, keep=0)
    # Only unpack- prefixed dirs are candidates; unrelated entries stay.
    assert (tmp_path / "keep.txt").exists()
    assert (tmp_path / "other-dir").exists()


def test_prune_on_a_missing_root_is_a_noop(tmp_path: Path) -> None:
    prune_jsre_unpack_dirs(tmp_path / "does-not-exist")


# ----------------------------------------------------------------------
# js.* / wasm.* error mapping.
# ----------------------------------------------------------------------
def test_js_deobfuscate_maps_success_and_errors(monkeypatch: Any, tmp_path: Path) -> None:
    class _Ok:
        def __init__(self, _cli: Any) -> None:
            pass

        def deobfuscate(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            return {"code": "clean();"}

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _Ok)
    result = _Service(tmp_path).js_deobfuscate("a.js")
    assert result.ok is True
    assert result.data == {"code": "clean();"}

    class _Missing:
        def __init__(self, _cli: Any) -> None:
            pass

        def deobfuscate(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            raise JsReError("capability_unavailable", "webcrack is not installed")

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _Missing)
    result = _Service(tmp_path).js_deobfuscate("a.js")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_js_deobfuscate_reports_an_unexpected_exception(monkeypatch: Any, tmp_path: Path) -> None:
    class _Boom:
        def __init__(self, _cli: Any) -> None:
            pass

        def deobfuscate(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            raise RuntimeError("node segfault")

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _Boom)
    result = _Service(tmp_path).js_deobfuscate("a.js")
    assert result.ok is False
    assert result.error is not None


def test_js_beautify_maps_success_and_errors(monkeypatch: Any, tmp_path: Path) -> None:
    class _Ok:
        def __init__(self, _cli: Any) -> None:
            pass

        def beautify(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            return {"code": "pretty();"}

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _Ok)
    assert _Service(tmp_path).js_beautify("a.js").ok is True

    class _Missing:
        def __init__(self, _cli: Any) -> None:
            pass

        def beautify(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            raise JsReError("capability_unavailable", "webcrack is not installed")

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _Missing)
    result = _Service(tmp_path).js_beautify("a.js")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_js_beautify_reports_an_unexpected_exception(monkeypatch: Any, tmp_path: Path) -> None:
    class _Boom:
        def __init__(self, _cli: Any) -> None:
            pass

        def beautify(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            raise RuntimeError("node crashed")

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _Boom)
    result = _Service(tmp_path).js_beautify("a.js")
    assert result.ok is False
    assert result.error is not None


def test_js_unpack_bundle_prunes_even_when_the_cli_fails(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """The finally-prune must run whether the unpack succeeded or raised."""
    pruned: list[Path] = []

    class _Fail:
        def __init__(self, _cli: Any) -> None:
            pass

        def unpack_bundle(self, path: Path, out_dir: Path, **kwargs: Any) -> dict[str, Any]:
            raise JsReError("capability_unavailable", "webcrack is not installed")

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.JsClient", _Fail)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_jsre.prune_jsre_unpack_dirs",
        lambda root, **kwargs: pruned.append(root),
    )
    result = _Service(tmp_path).js_unpack_bundle("bundle.js")
    assert result.ok is False
    assert pruned  # the finally clause pruned despite the failure


def test_wasm_wat_and_info_map_errors(monkeypatch: Any, tmp_path: Path) -> None:
    class _Ok:
        def __init__(self, _cli: Any) -> None:
            pass

        def wat(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            return {"wat": "(module)"}

        def info(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            raise JsReError("capability_unavailable", "wabt is not installed")

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.WasmClient", _Ok)
    service = _Service(tmp_path)
    assert service.wasm_wat("m.wasm").ok is True
    info = service.wasm_info("m.wasm")
    assert info.ok is False
    assert info.error is not None
    assert info.error.code == "capability_unavailable"


def test_wasm_wat_maps_its_own_error_paths(monkeypatch: Any, tmp_path: Path) -> None:
    class _BadWat:
        def __init__(self, _cli: Any) -> None:
            pass

        def wat(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            raise JsReError("invalid_params", "not a wasm module")

        def info(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            return {"sections": []}

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.WasmClient", _BadWat)
    service = _Service(tmp_path)
    wat = service.wasm_wat("m.wasm")
    assert wat.ok is False
    assert wat.error is not None
    assert wat.error.code == "invalid_params"
    # wasm_info's happy path shares the same wrapper.
    assert service.wasm_info("m.wasm").ok is True


def test_wasm_info_reports_an_unexpected_exception(monkeypatch: Any, tmp_path: Path) -> None:
    class _Boom:
        def __init__(self, _cli: Any) -> None:
            pass

        def info(self, path: Path, timeout: float = 0.0) -> dict[str, Any]:
            raise RuntimeError("wasm2wat died")

    monkeypatch.setattr("headless_re_mcp.core.service_jsre.WasmClient", _Boom)
    result = _Service(tmp_path).wasm_info("m.wasm")
    assert result.ok is False
    assert result.error is not None
