"""web.forms lists the page's forms and their fields, bounded and normalised.

Driven through the _get/_runner seam with a fake page whose evaluate() returns
the shape the in-page script produces. No real browser is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
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


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Page:
    def __init__(self, result: dict[str, Any], url: str) -> None:
        self._result = result
        self.url = url

    def evaluate(self, script: str, cfg: dict[str, Any]) -> dict[str, Any]:
        del script, cfg
        return self._result


def _backend_with(monkeypatch: Any, result: dict[str, Any], url: str) -> WebBackend:
    backend = WebBackend()
    page = _Page(result, url)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _field(type_: str, name: str, value: str, required: bool) -> dict[str, Any]:
    return {
        "tag": "input",
        "type": type_,
        "name": name,
        "value": value,
        "required": required,
    }


def _login_form() -> dict[str, Any]:
    return {
        "name": "login",
        "id": "loginForm",
        "action": "https://example.com/session",
        "method": "post",
        "enctype": "application/x-www-form-urlencoded",
        "field_count": 3,
        "fields_truncated": False,
        "fields": [
            _field("hidden", "csrf", "tok-123", False),
            _field("text", "user", "", True),
            _field("password", "pass", "", True),
        ],
    }


def test_forms_capture_action_method_and_fields(monkeypatch: Any) -> None:
    result = {"forms": [_login_form()], "total": 1}
    payload = _backend_with(monkeypatch, result, "https://example.com/login").forms("s")

    assert payload["count"] == 1
    assert payload["total"] == 1
    assert payload["truncated"] is False

    form = payload["forms"][0]
    assert form["name"] == "login"
    assert form["action"] == "https://example.com/session"
    assert form["method"] == "post"
    assert form["has_password"] is True
    assert form["has_file"] is False
    assert form["field_count"] == 3


def test_forms_capture_hidden_values_but_not_password(monkeypatch: Any) -> None:
    result = {"forms": [_login_form()], "total": 1}
    payload = _backend_with(monkeypatch, result, "https://example.com/login").forms("s")
    fields = {f["name"]: f for f in payload["forms"][0]["fields"]}
    assert fields["csrf"]["value"] == "tok-123"  # hidden value captured
    assert fields["pass"]["value"] == ""  # password value never captured
    assert fields["user"]["required"] is True


def test_forms_flag_a_cross_origin_action(monkeypatch: Any) -> None:
    """An action posting to a different host is flagged action_external."""
    form = _login_form()
    form["action"] = "https://evil.example.net/collect"
    result = {"forms": [form], "total": 1}
    payload = _backend_with(monkeypatch, result, "https://example.com/login").forms("s")
    assert payload["forms"][0]["action_external"] is True


def test_forms_same_host_action_is_not_external(monkeypatch: Any) -> None:
    result = {"forms": [_login_form()], "total": 1}
    payload = _backend_with(monkeypatch, result, "https://example.com/login").forms("s")
    assert payload["forms"][0]["action_external"] is False


def test_forms_report_truncation(monkeypatch: Any) -> None:
    result = {"forms": [_login_form()], "total": 250}
    payload = _backend_with(monkeypatch, result, "https://example.com/login").forms("s")
    assert payload["count"] == 1
    assert payload["total"] == 250
    assert payload["truncated"] is True


def test_web_forms_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.forms")
    assert "action_external" in doc
    assert "has_password" in doc
    assert "fields" in doc
    assert "truncated" in doc
