"""js.summary: a node-free one-call roll-up of the five JS scanners.

Where each scanner answers one triage question, this drives all five and folds
their headline results into a single profile. These tests pin the contract on
hand-written JS: the full roll-up (endpoint hosts, import kind split, source-map
flag, capability categories), that each reported total matches the underlying
scanner run directly, an empty source, the scan_capped floor when a detail
roll-up is paged short, and the not_found / too_large guards.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import (
    JsReError,
    scan_js_capabilities,
    scan_js_comments,
    scan_js_endpoints,
    scan_js_imports,
    scan_js_strings,
    scan_js_summary,
)

_SOURCE = """// entry point
//# sourceMappingURL=app.js.map
import React from 'react';
import util from './util.js';
import cfg from '/config';
import cdn from 'https://cdn.example.com/lib.js';
const http = require('http');
const a = 'https://api.example.com/v1/status';
const b = "wss://socket.example.net/ws";
const label = "dashboard-widget";
fetch(a);
eval(payload);
localStorage.setItem("k", v);
"""


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(text, encoding="utf-8")
    return target


def test_summary_rolls_up_every_scanner(tmp_path: Path) -> None:
    payload = scan_js_summary(_write(tmp_path, _SOURCE))
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False
    assert payload["input_bytes"] > 0

    assert payload["endpoints"]["total"] == 3
    assert payload["endpoints"]["hosts"] == [
        "cdn.example.com",
        "api.example.com",
        "socket.example.net",
    ]

    assert payload["imports"] == {
        "total": 5,
        "bare": 2,
        "relative": 1,
        "absolute": 1,
        "url": 1,
    }

    assert payload["comments"]["total"] == 2
    assert payload["comments"]["has_source_map"] is True

    assert payload["capabilities"]["total"] == 3
    assert payload["capabilities"]["categories"] == ["code_execution", "network", "storage"]


def test_totals_match_the_underlying_scanners(tmp_path: Path) -> None:
    path = _write(tmp_path, _SOURCE)
    payload = scan_js_summary(path)
    assert payload["strings"]["total"] == scan_js_strings(path, offset=0, limit=1)["total"]
    assert payload["endpoints"]["total"] == scan_js_endpoints(path)["total"]
    assert payload["imports"]["total"] == scan_js_imports(path)["total"]
    assert payload["comments"]["total"] == scan_js_comments(path)["total"]
    assert payload["capabilities"]["total"] == len(scan_js_capabilities(path)["capabilities"])


def test_benign_source_is_all_zero(tmp_path: Path) -> None:
    payload = scan_js_summary(_write(tmp_path, "const total = items.reduce(sum, 0);\n"))
    assert payload["endpoints"] == {"total": 0, "hosts": []}
    assert payload["imports"] == {"total": 0, "bare": 0, "relative": 0, "absolute": 0, "url": 0}
    assert payload["comments"]["has_source_map"] is False
    assert payload["capabilities"] == {"total": 0, "categories": []}
    assert payload["scan_capped"] is False
    assert payload["truncated"] is False


def test_paged_detail_rollup_sets_scan_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force the endpoint page below the number of URLs: the host roll-up becomes
    # a floor even though the endpoint scanner's own cap is untouched.
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_ENDPOINTS_PAGE", 1)
    payload = scan_js_summary(_write(tmp_path, _SOURCE))
    assert payload["endpoints"]["total"] == 3
    assert len(payload["endpoints"]["hosts"]) == 1
    assert payload["scan_capped"] is True


def test_open_literal_sets_truncated(tmp_path: Path) -> None:
    payload = scan_js_summary(_write(tmp_path, "fetch(x);\nconst s = 'no end\n"))
    assert payload["truncated"] is True
    assert payload["capabilities"]["total"] == 1


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        scan_js_summary(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_oversized_input_is_too_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    with pytest.raises(JsReError) as info:
        scan_js_summary(_write(tmp_path, _SOURCE))
    assert info.value.code == "too_large"
