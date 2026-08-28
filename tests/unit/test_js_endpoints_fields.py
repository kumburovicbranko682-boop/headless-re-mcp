"""js.endpoints maps HTTP/WS request targets from a script's network call sites.

The core is extract_js_endpoints, pure over the source text, so most of this
drives it directly; a few tests wire it through JsClient/AnalysisService.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as client_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_static import extract_js_endpoints
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _by_url(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(e["url"]): e for e in payload["items"]}  # type: ignore[index,union-attr]


def test_fetch_relative_path_defaults_to_get() -> None:
    payload = extract_js_endpoints("fetch('/api/v1/users');")
    ep = _by_url(payload)["/api/v1/users"]
    assert ep["kind"] == "fetch"
    assert ep["method"] == "GET"
    assert ep["absolute"] is False
    assert ep["host"] is None
    assert ep["lines"] == [1]


def test_fetch_reads_method_option() -> None:
    src = "fetch('/api/login', { method: 'POST', body: b });"
    ep = _by_url(extract_js_endpoints(src))["/api/login"]
    assert ep["method"] == "POST"
    assert ep["kind"] == "fetch"


def test_fetch_absolute_url_records_host() -> None:
    ep = _by_url(extract_js_endpoints("fetch('https://api.evil.test/c2')"))[
        "https://api.evil.test/c2"
    ]
    assert ep["absolute"] is True
    assert ep["host"] == "api.evil.test"


def test_axios_method_verbs() -> None:
    src = "axios.post('/a'); axios.delete('/b'); axios('/c');"
    by = _by_url(extract_js_endpoints(src))
    assert by["/a"]["method"] == "POST"
    assert by["/a"]["kind"] == "axios"
    assert by["/b"]["method"] == "DELETE"
    # Bare axios(url) defaults to GET.
    assert by["/c"]["method"] == "GET"


def test_axios_config_object_url_and_method() -> None:
    src = "axios({ url: '/graphql', method: 'PUT', data: x });"
    ep = _by_url(extract_js_endpoints(src))["/graphql"]
    assert ep["method"] == "PUT"
    assert ep["kind"] == "axios"


def test_xhr_open_reads_verb_and_url() -> None:
    src = "var r = new XMLHttpRequest(); r.open('PUT', '/upload');"
    ep = _by_url(extract_js_endpoints(src))["/upload"]
    assert ep["kind"] == "xhr"
    assert ep["method"] == "PUT"


def test_open_with_non_verb_first_arg_is_not_an_endpoint() -> None:
    # IndexedDB-style open(name, version): first arg is not an HTTP verb.
    payload = extract_js_endpoints("db.open('mydb', 2);")
    assert payload["items"] == []
    assert payload["total"] == 0


def test_jquery_helpers_and_ajax_config() -> None:
    src = (
        "$.get('/g'); $.post('/p'); $.getJSON('/j');"
        " $.ajax({ url: '/x', type: 'DELETE' });"
    )
    by = _by_url(extract_js_endpoints(src))
    assert by["/g"]["method"] == "GET"
    assert by["/p"]["method"] == "POST"
    assert by["/j"]["method"] == "GET"
    assert by["/x"]["method"] == "DELETE"


def test_sendbeacon_is_post() -> None:
    ep = _by_url(extract_js_endpoints("navigator.sendBeacon('/track', p);"))["/track"]
    assert ep["kind"] == "beacon"
    assert ep["method"] == "POST"


def test_websocket_and_eventsource_have_null_method() -> None:
    src = "new WebSocket('wss://feed.test/ws'); new EventSource('/sse');"
    by = _by_url(extract_js_endpoints(src))
    assert by["wss://feed.test/ws"]["kind"] == "websocket"
    assert by["wss://feed.test/ws"]["method"] is None
    assert by["/sse"]["kind"] == "eventsource"
    assert by["/sse"]["method"] is None


def test_template_url_is_marked_dynamic() -> None:
    src = "fetch(`/api/user/${id}/profile`);"
    ep = _by_url(extract_js_endpoints(src))["/api/user/${...}/profile"]
    assert ep["dynamic"] is True
    assert ep["method"] == "GET"


def test_fetch_inside_a_string_or_comment_is_not_a_call_site() -> None:
    src = "// fetch('/nope')\nvar s = \"fetch('/also-nope')\"; fetch('/real');"
    by = _by_url(extract_js_endpoints(src))
    assert "/real" in by
    assert "/nope" not in by
    assert "/also-nope" not in by


def test_repeated_call_is_folded_with_sample_lines_and_count() -> None:
    src = "fetch('/api/x');\nfetch('/api/x');\nfetch('/api/x');"
    ep = _by_url(extract_js_endpoints(src))["/api/x"]
    assert ep["count"] == 3
    assert ep["lines"] == [1, 2, 3]


def test_rollups_report_kinds_methods_and_hosts() -> None:
    src = (
        "fetch('https://a.test/1');"
        " axios.post('https://a.test/2');"
        " $.get('/rel');"
    )
    payload = extract_js_endpoints(src)
    assert payload["kinds"] == {"fetch": 1, "axios": 1, "jquery": 1}
    assert payload["methods"]["GET"] == 2
    assert payload["methods"]["POST"] == 1
    hosts = {h["host"]: h["count"] for h in payload["hosts"]}
    assert hosts == {"a.test": 2}
    assert payload["host_count"] == 1


def test_paging_endpoints() -> None:
    src = "\n".join(f"fetch('/api/{i}');" for i in range(5))
    page = extract_js_endpoints(src, offset=0, limit=2)
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True
    tail = extract_js_endpoints(src, offset=4, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False


def test_no_calls_is_empty() -> None:
    payload = extract_js_endpoints("const x = 1 + 2; console.log(x);")
    assert payload["items"] == []
    assert payload["total"] == 0
    assert payload["kinds"] == {}


# --- client + service integration -------------------------------------------


def test_client_endpoints_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text("fetch('/api/ping');", encoding="utf-8")
    payload = JsClient(None).endpoints(js)
    assert _by_url(payload)["/api/ping"]["method"] == "GET"


def test_client_endpoints_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        JsClient(None).endpoints(tmp_path / "nope.js")
    assert caught.value.code == "not_found"


def test_client_endpoints_oversized_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_mod, "_MAX_INPUT_BYTES", 8)
    js = tmp_path / "big.js"
    js.write_text("fetch('/api/ping');" * 4, encoding="utf-8")
    with pytest.raises(JsReError) as caught:
        JsClient(None).endpoints(js)
    assert caught.value.code == "too_large"


def test_service_js_endpoints_dispatch(tmp_path: Path) -> None:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    js = tmp_path / "s.js"
    js.write_text("axios.post('/api/login');", encoding="utf-8")
    result = service.js_endpoints(str(js))
    assert result.ok, result.error
    assert result.data is not None
    assert _by_url(result.data)["/api/login"]["method"] == "POST"


def test_js_endpoints_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_js_wasm_tools(service)}
    assert "js.endpoints" in names


def test_js_endpoints_docstring_names_its_shape() -> None:
    doc = " ".join(_tool_docstring("js.endpoints").split())
    assert "items" in doc
    assert "kinds" in doc
    assert "methods" in doc
    assert "dynamic" in doc
    assert "endpoints_capped" in doc
    assert "too_large" in doc
