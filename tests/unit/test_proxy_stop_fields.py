"""proxy.stop must not call a still-live proxy thread a successful stop."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend, _ProxyInstance
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Zombie:
    """A proxy thread that ignores shutdown and never dies."""

    def is_alive(self) -> bool:
        return True

    def join(self, timeout: float | None = None) -> None:
        del timeout


class _Dead:
    def is_alive(self) -> bool:
        return False

    def join(self, timeout: float | None = None) -> None:
        del timeout


def test_a_wedged_proxy_thread_is_not_reported_stopped() -> None:
    """The join deadline can pass with the thread still inside mitmproxy, still
    holding the listening socket. Reporting that as stopped drops a live proxy
    and calls the port free, so the next capture cannot bind it."""
    backend = ProxyBackend()
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._thread = _Zombie()  # type: ignore[assignment]
    backend._instances["s"] = inst

    result = backend.stop("s")

    assert result["stopped"] is False
    assert "did not exit" in str(result.get("note", ""))
    assert result["port"] == 8080
    # Still tracked, so a retry / close_all / a colliding start all see it.
    assert backend._instances.get("s") is inst


def test_a_clean_proxy_stop_reports_stopped_and_drops_the_instance() -> None:
    backend = ProxyBackend()
    inst = _ProxyInstance("127.0.0.1", 8080)
    inst._thread = _Dead()  # type: ignore[assignment]
    backend._instances["s"] = inst

    result = backend.stop("s")

    assert result == {"stopped": True}
    assert "s" not in backend._instances


def test_stop_with_no_proxy_running_says_so() -> None:
    backend = ProxyBackend()
    result = backend.stop("never-started")
    assert result["stopped"] is False
    assert "no proxy" in str(result.get("note", ""))


def test_instance_stop_returns_true_when_there_is_no_thread() -> None:
    inst = _ProxyInstance("127.0.0.1", 8080)
    assert inst.stop() is True


def test_proxy_stop_docstring_names_stopped_and_the_wedged_case() -> None:
    doc = _tool_docstring("proxy.stop")
    assert "Answers with stopped" in doc
    assert "released the port" in doc
    assert "wedged" in doc
