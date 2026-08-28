"""web.forms lists the page's forms grouped with their input controls.

These mock the browser handle's page.evaluate so the shaping -- action/method/
enctype, the per-field {tag,type,name,value,hidden} record, the hidden flag, the
form and field caps, and a non-dict payload -- is pinned without a live browser.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_FORM_FIELDS, _MAX_FORMS, WebBackend
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _FakePage:
    def __init__(self, payload: Any) -> None:
        self._payload = payload
        self.calls: list[Any] = []

    def evaluate(self, script: str, arg: Any = None) -> Any:
        del script
        self.calls.append(arg)
        return self._payload


class _FormsRunner:
    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()


class _FormsHandle:
    def __init__(self, page: _FakePage) -> None:
        self.page = page
        self.runner = _FormsRunner()


def _backend_with(monkeypatch: Any, page: _FakePage) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FormsHandle(page))
    return backend


def test_web_forms_groups_controls_under_their_form(monkeypatch: Any) -> None:
    payload = {
        "forms": [
            {
                "action": "https://app.example/login",
                "method": "post",
                "enctype": "application/x-www-form-urlencoded",
                "name": "login",
                "id": "loginForm",
                "fields": [
                    {"tag": "input", "type": "text", "name": "user", "value": ""},
                    {"tag": "input", "type": "password", "name": "pass", "value": ""},
                    {"tag": "input", "type": "hidden", "name": "csrf", "value": "tok-123"},
                    {"tag": "button", "type": "submit", "name": "go", "value": "Sign in"},
                ],
                "field_total": 4,
            }
        ],
        "total": 1,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.forms("s")
    assert result["count"] == result["total"] == 1
    assert result["has_more"] is False

    form = result["forms"][0]
    assert form["action"] == "https://app.example/login"
    assert form["method"] == "post"
    assert form["enctype"] == "application/x-www-form-urlencoded"
    assert form["name"] == "login"
    assert form["id"] == "loginForm"
    assert form["field_count"] == form["field_total"] == 4
    assert form["fields_truncated"] is False

    by_name = {f["name"]: f for f in form["fields"]}
    # The hidden CSRF token is the point: it must round-trip with its value and
    # be flagged hidden so it stands out from the visible inputs.
    assert by_name["csrf"]["hidden"] is True
    assert by_name["csrf"]["value"] == "tok-123"
    assert by_name["csrf"]["type"] == "hidden"
    assert by_name["user"]["hidden"] is False
    assert by_name["pass"]["type"] == "password"
    assert by_name["go"]["tag"] == "button"


def test_web_forms_reports_field_overflow(monkeypatch: Any) -> None:
    # A form with more controls than the per-form cap: the browser slices at the
    # cap, and field_total (the real count) drives fields_truncated.
    emitted = [
        {"tag": "input", "type": "text", "name": f"f{i}", "value": ""}
        for i in range(_MAX_FORM_FIELDS)
    ]
    payload = {
        "forms": [
            {
                "action": "https://x/",
                "method": "get",
                "enctype": "",
                "name": "",
                "id": "",
                "fields": emitted,
                "field_total": _MAX_FORM_FIELDS + 25,
            }
        ],
        "total": 1,
    }
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.forms("s")
    form = result["forms"][0]
    assert form["field_count"] == _MAX_FORM_FIELDS
    assert form["field_total"] == _MAX_FORM_FIELDS + 25
    assert form["fields_truncated"] is True


def test_web_forms_reports_form_overflow(monkeypatch: Any) -> None:
    # More forms existed than were emitted: has_more must be true so a capped
    # page is not read as the whole set.
    forms = [
        {
            "action": f"https://x/{i}",
            "method": "get",
            "enctype": "",
            "name": "",
            "id": "",
            "fields": [],
            "field_total": 0,
        }
        for i in range(_MAX_FORMS)
    ]
    payload = {"forms": forms, "total": _MAX_FORMS + 10}
    backend = _backend_with(monkeypatch, _FakePage(payload))
    result = backend.forms("s")
    assert result["count"] == _MAX_FORMS
    assert result["total"] == _MAX_FORMS + 10
    assert result["has_more"] is True


def test_web_forms_reports_a_page_with_no_forms(monkeypatch: Any) -> None:
    backend = _backend_with(monkeypatch, _FakePage({"forms": [], "total": 0}))
    result = backend.forms("s")
    assert result["forms"] == []
    assert result["count"] == result["total"] == 0
    assert result["has_more"] is False


def test_web_forms_survives_a_non_dict_payload(monkeypatch: Any) -> None:
    # A driver that hands back something odd must not crash the call.
    backend = _backend_with(monkeypatch, _FakePage("not-an-object"))
    result = backend.forms("s")
    assert result["forms"] == []
    assert result["count"] == result["total"] == 0


def test_web_forms_passes_the_caps_to_the_page(monkeypatch: Any) -> None:
    page = _FakePage({"forms": [], "total": 0})
    backend = _backend_with(monkeypatch, page)
    backend.forms("s")
    assert page.calls, "the in-page script was never evaluated"
    cfg = page.calls[0]
    assert cfg["maxForms"] == _MAX_FORMS
    assert cfg["maxFields"] == _MAX_FORM_FIELDS
    assert cfg["maxValueChars"] > 0


def test_web_forms_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.forms")
    assert doc, "web.forms is missing its docstring"
    assert "action" in doc
    assert "hidden" in doc
    assert "fields" in doc
    assert "has_more" in doc
