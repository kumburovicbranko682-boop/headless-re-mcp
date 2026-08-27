"""apk list tools must refuse a negative page offset at the schema."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for


def _offset_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_apk_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["offset"]


def test_apk_list_schema_refuses_a_negative_offset() -> None:
    """The catalog accepted any integer offset, including negatives.

    Measured: apk.classes/methods/strings schema offset has no minimum.
    The client pages with names[offset:offset+limit], so offset=-1 is a
    tail slice (ten names, offset -1, limit 100 -> last name only), not a
    rejection. An overnight pass that undershot zero silently read the
    end of the DEX as page zero and treated has_more as the rest of the
    list.
    """
    names = [f"L{index};" for index in range(10)]
    assert names[-1 : -1 + 100] == ["L9;"]
    for name in ("apk.classes", "apk.methods", "apk.strings"):
        offset = _offset_schema(name)
        assert offset.get("type") == "integer"
        assert offset.get("minimum") == 0
        assert "maximum" not in offset


class _Klass:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_external(self) -> bool:
        return False


class _Parsed:
    def __init__(self, classes: list[_Klass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_Klass]:
        return self._classes


def test_apk_classes_backend_clamps_a_negative_offset_reached_directly(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The schema rejects offset<0, but the backend is what actually pages.

    The web/proxy/jsre/adb backends all clamp offset/limit themselves, so a
    caller that reaches the method directly -- a future binding path, a service
    refactor -- cannot turn offset=-1 into a tail slice. This backend was the
    one sibling that trusted the boundary. Measured: classes(offset=-5,
    limit=3) -> offset 0 and the first three names, not the last of the DEX.
    """
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _Parsed([_Klass(f"L{index:03d};") for index in range(10)]),
    )
    client = ApkClient()
    payload = client.classes(tmp_path / "app.apk", offset=-5, limit=3)
    assert payload["offset"] == 0
    assert payload["classes"] == ["L000;", "L001;", "L002;"]
    assert payload["count"] == 3
    assert payload["total"] == 10
    assert payload["has_more"] is True


@pytest.mark.parametrize("limit", [-1, 0])
def test_apk_classes_backend_clamps_a_nonpositive_limit(
    tmp_path: Path, monkeypatch: Any, limit: int
) -> None:
    """A limit at or below zero would page an empty slice; clamp it to one row."""
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _Parsed([_Klass(f"L{index:03d};") for index in range(10)]),
    )
    client = ApkClient()
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=limit)
    assert payload["count"] == 1
    assert payload["classes"] == ["L000;"]
    assert payload["has_more"] is True
