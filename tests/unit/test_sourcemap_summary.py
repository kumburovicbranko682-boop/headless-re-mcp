"""The stdlib Source Map v3 reader (summarize_sourcemap) and js.sourcemap routing.

js.deobfuscate / js.beautify / js.unpack_bundle drive the webcrack (Node) CLI,
so the JS static surface is capability_unavailable on a host without it. A
source map -- the most valuable Web-RE artifact after the bundle, since it names
the original file tree and often embeds the original source -- is plain JSON and
reads with the stdlib alone, yet nothing here could open one. These tests pin
that reader on a flat map and a v3 index map, the whole-file honesty of its
counts, its measure-not-decode treatment of the VLQ mappings, its resilience to
malformed members, its refusal of a non-map, and the service routing that turns
a bad file into a precise envelope rather than a fault.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.sourcemap import (
    SourceMapParseError,
    summarize_sourcemap,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _flat_map() -> dict:
    return {
        "version": 3,
        "file": "app.min.js",
        "sourceRoot": "webpack://app/",
        "sources": ["src/index.ts", "src/util.ts", "node_modules/lib/x.js"],
        "sourcesContent": ["export const a = 1\n", None, "module.exports = {}"],
        "names": ["a", "b", "c"],
        "mappings": "AAAA,SAASA;;AACT,MAAMC",
        "x_google_ignoreList": [2],
    }


def test_flat_map_summary_carries_analyst_fields() -> None:
    out = summarize_sourcemap(_flat_map())
    assert out["version"] == 3
    assert out["file"] == "app.min.js"
    assert out["source_root"] == "webpack://app/"
    assert out["is_index_map"] is False
    assert out["section_count"] == 0
    assert out["sources_total"] == 3
    assert out["sources_content_embedded"] == 2
    assert out["names_total"] == 3
    assert out["ignore_list"] == [2]
    # mappings are measured, not decoded: two ';' => three generated lines,
    # four comma/semicolon-delimited segments.
    assert out["mappings_size"] == len("AAAA,SAASA;;AACT,MAAMC")
    assert out["generated_lines"] == 3
    assert out["segment_count"] == 4


def test_flat_map_source_detail_flags_embedded_content() -> None:
    out = summarize_sourcemap(_flat_map())
    detail = {d["source"]: d for d in out["sources_detail"]}
    assert detail["src/index.ts"]["has_content"] is True
    assert detail["src/index.ts"]["content_length"] == len("export const a = 1\n")
    assert detail["src/util.ts"]["has_content"] is False
    assert detail["src/util.ts"]["content_length"] is None
    assert detail["node_modules/lib/x.js"]["has_content"] is True


def test_index_map_aggregates_sections() -> None:
    document = {
        "version": 3,
        "file": "bundle.js",
        "sections": [
            {
                "offset": {"line": 0, "column": 0},
                "map": {
                    "version": 3,
                    "sources": ["a.ts"],
                    "sourcesContent": ["x"],
                    "names": [],
                    "mappings": "AAAA",
                },
            },
            {
                "offset": {"line": 10, "column": 0},
                "map": {
                    "version": 3,
                    "sources": ["b.ts", "c.ts"],
                    "sourcesContent": [None, "y"],
                    "names": ["n"],
                    "mappings": "AAAA;AACA",
                },
            },
        ],
    }
    out = summarize_sourcemap(document)
    assert out["is_index_map"] is True
    assert out["section_count"] == 2
    assert out["sources"] == ["a.ts", "b.ts", "c.ts"]
    assert out["sources_total"] == 3
    assert out["sources_content_embedded"] == 2
    assert out["names_total"] == 1
    assert out["generated_lines"] == 3  # 1 + 2 across the two sections
    assert out["segment_count"] == 3


def test_minimal_document_with_only_a_version_is_tolerated() -> None:
    out = summarize_sourcemap({"version": 3})
    assert out["version"] == 3
    assert out["sources_total"] == 0
    assert out["generated_lines"] == 0
    assert out["is_index_map"] is False


def test_wrong_typed_members_do_not_raise() -> None:
    out = summarize_sourcemap(
        {"version": 3, "sources": "nope", "sourcesContent": 1, "mappings": 42, "names": "x"}
    )
    assert out["sources_total"] == 0
    assert out["names_total"] == 0
    assert out["mappings_size"] == 0


def test_long_paths_are_bounded() -> None:
    huge = "d/" * 10000
    out = summarize_sourcemap({"version": 3, "sources": [huge], "mappings": ""})
    assert len(out["sources"][0]) == 4096


def test_a_non_int_version_becomes_none() -> None:
    out = summarize_sourcemap({"version": "3", "mappings": ""})
    assert out["version"] is None


@pytest.mark.parametrize(
    "document",
    ["a string", 123, None, [], {"foo": "bar"}, {"names": []}],
)
def test_non_source_maps_raise(document: object) -> None:
    with pytest.raises(SourceMapParseError):
        summarize_sourcemap(document)


# --- service routing ----------------------------------------------------------


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_reads_a_source_map(tmp_path: Path) -> None:
    smap = tmp_path / "app.js.map"
    smap.write_text(json.dumps(_flat_map()), encoding="utf-8")
    result = _service(tmp_path).js_sourcemap(str(smap))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["sources_total"] == 3
    assert result.data["sources_content_embedded"] == 2


def test_service_refuses_non_json(tmp_path: Path) -> None:
    smap = tmp_path / "bad.map"
    smap.write_text("<<not json>>", encoding="utf-8")
    result = _service(tmp_path).js_sourcemap(str(smap))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_refuses_valid_json_that_is_not_a_map(tmp_path: Path) -> None:
    smap = tmp_path / "obj.map"
    smap.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    result = _service(tmp_path).js_sourcemap(str(smap))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).js_sourcemap(str(tmp_path / "nope.map"))
    assert not result.ok
    assert result.error.code == "not_found"


def test_service_refuses_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.client as client

    monkeypatch.setattr(client, "_MAX_INPUT_BYTES", 8)
    smap = tmp_path / "app.js.map"
    smap.write_text(json.dumps(_flat_map()), encoding="utf-8")
    result = _service(tmp_path).js_sourcemap(str(smap))
    assert not result.ok
    assert result.error.code == "too_large"
