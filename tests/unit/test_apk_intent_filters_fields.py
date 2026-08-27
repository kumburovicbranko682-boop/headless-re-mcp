"""apk.intent_filters must map the intent attack surface honestly."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _FilterApk:
    """A deep-linked activity, a filtered receiver, and unfiltered components."""

    def get_activities(self) -> list[str]:
        return ["c.Main", "a.Deep"]

    def get_services(self) -> list[str]:
        return ["s.Bg"]

    def get_receivers(self) -> list[str]:
        return ["r.Boot"]

    def get_intent_filters(self, itemtype: str, name: str) -> dict[str, object]:
        table: dict[tuple[str, str], dict[str, object]] = {
            ("activity", "a.Deep"): {
                "action": ["android.intent.action.VIEW"],
                "category": ["android.intent.category.BROWSABLE"],
                "data": [{"scheme": "myapp", "host": "pay"}],
            },
            ("receiver", "r.Boot"): {
                "action": ["android.intent.action.BOOT_COMPLETED"],
            },
        }
        return table.get((itemtype, name), {})


class _NoisyApk(_FilterApk):
    """One component's filter walk raises: it must be counted, not silent."""

    def get_intent_filters(self, itemtype: str, name: str) -> dict[str, object]:
        if (itemtype, name) == ("receiver", "r.Boot"):
            raise ValueError("hostile manifest tripped the walk")
        return super().get_intent_filters(itemtype, name)


def test_apk_intent_filters_maps_actions_categories_and_deep_link_data() -> None:
    """The tool surfaces what intents reach each component, sorted and typed.

    Only the filtered components come back: the deep-linked activity (with its
    scheme/host in data) and the boot receiver. The unfiltered activity and
    service are omitted, so the list reads as the reachable set, not the roster.
    """
    client = ApkClient()
    client._apk = lambda _path: _FilterApk()  # type: ignore[method-assign]
    payload = client.intent_filters(Path("dummy.apk"))
    assert payload["total"] == 2
    assert payload["has_more"] is False
    by_component = {entry["component"]: entry for entry in payload["intent_filters"]}
    assert set(by_component) == {"a.Deep", "r.Boot"}
    deep = by_component["a.Deep"]
    assert deep["type"] == "activity"
    assert deep["actions"] == ["android.intent.action.VIEW"]
    assert deep["data"] == [{"scheme": "myapp", "host": "pay"}]
    boot = by_component["r.Boot"]
    assert boot["type"] == "receiver"
    assert boot["categories"] == []
    doc = _tool_docstring("apk.intent_filters")
    assert "intent_filters" in doc
    assert "has_more" in doc


def test_apk_intent_filters_paginates_over_the_filtered_set() -> None:
    """offset/limit page the filtered components and report honest has_more."""
    client = ApkClient()
    client._apk = lambda _path: _FilterApk()  # type: ignore[method-assign]
    payload = client.intent_filters(Path("dummy.apk"), offset=0, limit=1)
    assert payload["count"] == 1
    assert payload["total"] == 2
    assert payload["offset"] == 0
    assert payload["has_more"] is True


def test_apk_intent_filters_counts_a_component_whose_walk_raises() -> None:
    """A filter walk that raises is counted in parse_errors, never dropped.

    The boot receiver's walk raises, so it cannot be listed, but parse_errors
    must flag that a component went unread -- an empty or short page must not
    read as a smaller attack surface than the APK actually has.
    """
    client = ApkClient()
    client._apk = lambda _path: _NoisyApk()  # type: ignore[method-assign]
    payload = client.intent_filters(Path("dummy.apk"))
    assert [entry["component"] for entry in payload["intent_filters"]] == ["a.Deep"]
    assert payload["parse_errors"] == 1


def test_apk_intent_filters_omits_the_error_field_when_every_walk_succeeds() -> None:
    """The signal is additive: a clean scan never carries parse_errors."""
    client = ApkClient()
    client._apk = lambda _path: _FilterApk()  # type: ignore[method-assign]
    payload = client.intent_filters(Path("dummy.apk"))
    assert "parse_errors" not in payload
    assert "names_capped" not in payload
