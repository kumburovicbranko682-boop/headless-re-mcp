"""js.unpack_bundle gate: prove webcrack really splits a bundle into modules.

The existing web RE gate proves ``js.deobfuscate`` (unminify one file) and the
WASM tools. ``js.unpack_bundle`` is a distinct capability -- it takes a single
webpack/browserify bundle and reconstructs the *module graph* as separate files
on disk -- and nothing exercised it live. The unit tests around it mock the
subprocess, so "webcrack actually splits a real bundle, and the split preserves
the cross-module call edge" was unproven.

This gate points the service at committed two-module bundles and asserts, from
webcrack's own ``bundle.json`` graph, that:

  * the entry module and its dependency land in *separate* files (the split
    happened, not just a reformat);
  * the entry file keeps the marker string and a ``require`` edge into the
    dependency file (the inter-module reference survived);
  * the dependency file carries its own body.

Both bundler families are covered because webcrack detects them through
different unpackers: webpack (dependency resolved to a numeric ``1.js``) and
browserify (which carries the require-string map, so the dependency resolves
back to its real name ``greet.js``). It also pins the paging contract on the
returned file listing, since callers rely on ``total`` / ``has_more`` rather
than assuming ``files`` is complete.

skip != pass: with Node/webcrack absent the gate skips loudly instead of
quietly passing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUNDLE_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "webpack_bundle.js"
_BROWSERIFY_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "browserify_bundle.js"
_MARKER = "UNPACK_GATE_MARKER"
_BROWSERIFY_MARKER = "BRIFY_GATE_MARKER"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


@pytest.mark.integration
def test_js_unpack_bundle_splits_a_webpack_bundle() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — Unpack Gate not run (skip != pass)")
    assert _BUNDLE_FIXTURE.is_file(), f"fixture missing: {_BUNDLE_FIXTURE}"

    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_BUNDLE_FIXTURE))
        assert result.ok, result.error
        data = result.data

        # A real split writes at least the two module files plus the graph
        # description; a bundle read as one blob would not.
        assert data["file_count"] >= 3, data
        assert data["total"] == data["file_count"], data
        # A clean unpack omits tool_failed entirely; it appears only when
        # webcrack exits non-zero but still wrote something.
        assert data.get("tool_failed") is not True, data

        out_dir = Path(data["output_dir"])
        assert out_dir.is_dir(), out_dir

        listed = set(data["files"])
        assert "bundle.json" in listed, data["files"]

        graph = json.loads(_read(out_dir / "bundle.json"))
        assert graph["type"] == "webpack", graph
        modules = {str(m["id"]): m["path"].lstrip("./") for m in graph["modules"]}
        assert len(modules) >= 2, graph

        entry_id = str(graph["entryId"])
        entry_rel = modules[entry_id]
        # Exactly one dependency in this fixture; take the other module.
        dep_id = next(mid for mid in modules if mid != entry_id)
        dep_rel = modules[dep_id]
        assert entry_rel != dep_rel, modules

        entry_text = _read(out_dir / entry_rel)
        dep_text = _read(out_dir / dep_rel)

        # The entry kept its marker and a require edge naming the dependency
        # file -- the cross-module reference survived the split.
        assert _MARKER in entry_text, entry_text
        assert Path(dep_rel).name in entry_text, (entry_rel, entry_text)
        # The dependency carries its own body, and it is genuinely a different
        # file (the marker did not leak into it).
        assert "hello " in dep_text, dep_text
        assert _MARKER not in dep_text, dep_text
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_splits_a_browserify_bundle() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — Unpack Gate not run (skip != pass)")
    assert _BROWSERIFY_FIXTURE.is_file(), f"fixture missing: {_BROWSERIFY_FIXTURE}"

    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_BROWSERIFY_FIXTURE))
        assert result.ok, result.error
        data = result.data
        assert data["file_count"] >= 3, data
        assert data.get("tool_failed") is not True, data

        out_dir = Path(data["output_dir"])
        assert out_dir.is_dir(), out_dir

        graph = json.loads(_read(out_dir / "bundle.json"))
        # A different unpacker from webpack: prove webcrack took the browserify
        # path, not that it happened to split something.
        assert graph["type"] == "browserify", graph
        modules = {str(m["id"]): m["path"].lstrip("./") for m in graph["modules"]}
        assert len(modules) >= 2, graph

        entry_id = str(graph["entryId"])
        entry_rel = modules[entry_id]
        dep_id = next(mid for mid in modules if mid != entry_id)
        dep_rel = modules[dep_id]
        assert entry_rel != dep_rel, modules
        # Browserify carries the require-string map, so the dependency resolves
        # to its real name rather than a numeric id -- the distinguishing trait
        # of this path.
        assert dep_rel.endswith("greet.js"), modules

        entry_text = _read(out_dir / entry_rel)
        dep_text = _read(out_dir / dep_rel)
        assert _BROWSERIFY_MARKER in entry_text, entry_text
        assert Path(dep_rel).stem in entry_text, (entry_rel, entry_text)
        assert "hi " in dep_text, dep_text
        assert _BROWSERIFY_MARKER not in dep_text, dep_text
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_pages_its_file_listing() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — Unpack Gate not run (skip != pass)")
    assert _BUNDLE_FIXTURE.is_file(), f"fixture missing: {_BUNDLE_FIXTURE}"

    service = AnalysisService()
    try:
        full = service.js_unpack_bundle(str(_BUNDLE_FIXTURE))
        assert full.ok, full.error
        total = full.data["total"]
        assert total >= 3, full.data
        all_names = sorted(full.data["files"])

        first = service.js_unpack_bundle(str(_BUNDLE_FIXTURE), offset=0, limit=2)
        assert first.ok, first.error
        assert first.data["count"] == 2, first.data
        assert first.data["total"] == total, first.data
        assert first.data["offset"] == 0, first.data
        assert first.data["has_more"] is True, first.data
        assert first.data["files"] == all_names[:2], first.data

        second = service.js_unpack_bundle(str(_BUNDLE_FIXTURE), offset=2, limit=2)
        assert second.ok, second.error
        assert second.data["offset"] == 2, second.data
        assert second.data["files"] == all_names[2:4], second.data
        # The two pages together cover the listing without overlap.
        assert set(first.data["files"]).isdisjoint(second.data["files"]), (
            first.data["files"],
            second.data["files"],
        )
    finally:
        service.close_all()
