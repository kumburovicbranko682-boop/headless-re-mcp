"""Web read tools classify a driver failure instead of leaking it.

script_source / dom_snapshot / screenshot each run one CDP or page call on the
session thread. When that call fails, the raw Playwright/CDP exception must not
reach the service's BaseException arm as an internal_error incident -- a script
whose source CDP cannot return, a page that will not evaluate, a screenshot the
browser refuses are backend outcomes. These pin the classification, and the one
case that must NOT be reclassified: a WebError the runner already raised (a
timeout that wedged the session) has to pass through script_source unchanged,
not be relabelled not_found.

Each drives the real method body on a real _Runner thread with a fake page/cdp,
so no browser is needed.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError, _Runner


@pytest.fixture
def runner() -> Any:
    made = _Runner("test-web-read-errors")
    try:
        yield made
    finally:
        made.shutdown()


def _wire(backend: WebBackend, handle: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)


def test_script_source_cdp_failure_is_not_found(
    tmp_path: Any, runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A script id CDP cannot fetch is not_found, not a raw CDP exception.

    Debugger.getScriptSource raises for an id the page has since discarded; the
    read classifies that as not_found carrying the script id rather than letting
    the CDP error become an internal_error incident.
    """
    def send(method: str, params: Any) -> Any:
        raise RuntimeError("No script for given id")

    backend = WebBackend()
    handle = SimpleNamespace(cdp=SimpleNamespace(send=send), runner=runner)
    _wire(backend, handle, monkeypatch)
    with pytest.raises(WebError) as info:
        backend.script_source("s", "42", tmp_path)
    assert info.value.code == "not_found"
    assert "cannot fetch script source" in info.value.message
    assert info.value.details.get("script_id") == "42"


def test_script_source_on_a_wasm_script_flags_it_instead_of_answering_empty(
    tmp_path: Any, runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WebAssembly script has no text source; say so and point at the bytes.

    wasm.list surfaces WebAssembly scripts, and an agent will reasonably call
    script.source on one. CDP's Debugger.getScriptSource returns an empty
    scriptSource for Wasm and carries the module in a separate base64 bytecode
    field, which this tool does not decode. Answering with a silent empty source
    is a dead end, so the read must flag is_wasm and name the working path
    (web.network.get -> wasm.wat/info). Only the bytecode field distinguishes it
    from a genuinely empty JS source, so that is what must trip the branch.
    """
    def send(method: str, params: Any) -> Any:
        # \x00asm\x01\x00\x00\x00 -> the wasm magic+version, base64-encoded, as
        # CDP delivers a Wasm module's bytecode.
        return {"scriptSource": "", "bytecode": "AGFzbQEAAAA="}

    backend = WebBackend()
    handle = SimpleNamespace(cdp=SimpleNamespace(send=send), runner=runner)
    _wire(backend, handle, monkeypatch)

    result = backend.script_source("s", "42", tmp_path)

    assert result["is_wasm"] is True
    assert result["source"] == "", "a Wasm module has no text source to inline"
    assert "source_path" not in result, "nothing text was spilled"
    assert "web.network.get" in str(result["note"])
    # An ordinary empty JS source (no bytecode) must NOT be mislabelled wasm.
    def send_plain(method: str, params: Any) -> Any:
        return {"scriptSource": ""}

    handle_plain = SimpleNamespace(cdp=SimpleNamespace(send=send_plain), runner=runner)
    _wire(backend, handle_plain, monkeypatch)
    plain = backend.script_source("s", "43", tmp_path)
    assert "is_wasm" not in plain
    assert plain["source"] == ""


def test_script_source_passes_a_web_error_through_unchanged(
    tmp_path: Any, runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WebError from the runner (e.g. a timeout) is not relabelled not_found.

    If the session wedged and the runner raises WebError('timeout'), reporting
    not_found would tell the caller the script does not exist when in truth the
    browser stopped answering. The passthrough arm keeps the real code.
    """
    def send(method: str, params: Any) -> Any:
        raise WebError("timeout", "browser did not respond within 60s")

    backend = WebBackend()
    handle = SimpleNamespace(cdp=SimpleNamespace(send=send), runner=runner)
    _wire(backend, handle, monkeypatch)
    with pytest.raises(WebError) as info:
        backend.script_source("s", "42", tmp_path)
    assert info.value.code == "timeout"


def test_dom_snapshot_evaluate_failure_is_backend_error(
    tmp_path: Any, runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A page that will not evaluate is a backend outcome, not a crash."""
    def evaluate(expression: str, arg: Any = None) -> Any:
        raise RuntimeError("Execution context was destroyed")

    backend = WebBackend()
    page = SimpleNamespace(evaluate=evaluate, url="https://x/", title=lambda: "x")
    handle = SimpleNamespace(page=page, runner=runner)
    _wire(backend, handle, monkeypatch)
    with pytest.raises(WebError) as info:
        backend.dom_snapshot("s", tmp_path)
    assert info.value.code == "backend_error"
    assert "dom snapshot failed" in info.value.message


def test_dom_snapshot_non_string_result_degrades_to_empty_html(
    tmp_path: Any, runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An evaluate that yields no string document reads as an empty page, not a crash.

    A driver hiccup or a navigation mid-evaluate can return a non-string; the
    snapshot coerces that to empty html with truncated False and writes no
    spill, rather than raising or claiming a document it does not have.
    """
    backend = WebBackend()
    page = SimpleNamespace(
        evaluate=lambda expr, arg=None: None, url="https://x/", title=lambda: "x"
    )
    handle = SimpleNamespace(page=page, runner=runner)
    _wire(backend, handle, monkeypatch)
    result = backend.dom_snapshot("s", tmp_path)
    assert result["html"] == ""
    assert result["truncated"] is False
    assert "html_path" not in result


def test_screenshot_failure_is_backend_error(
    tmp_path: Any, runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A browser that refuses to screenshot is a backend outcome, named as such."""
    def screenshot(path: str = "", full_page: bool = False) -> None:
        raise RuntimeError("Unable to capture screenshot")

    backend = WebBackend()
    page = SimpleNamespace(screenshot=screenshot)
    handle = SimpleNamespace(page=page, runner=runner)
    _wire(backend, handle, monkeypatch)
    with pytest.raises(WebError) as info:
        backend.screenshot("s", tmp_path / "shot.png")
    assert info.value.code == "backend_error"
    assert "screenshot failed" in info.value.message
