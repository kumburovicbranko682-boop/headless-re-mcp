"""``apk.classes`` lists the app's own classes, not the framework it references.

androguard's ``Analysis.get_classes()`` returns a node for every class the DEX
*mentions*, which includes the framework and library classes it merely
references -- ``Landroid/app/Activity;``, ``Ljava/lang/Object;``,
``Lkotlin/Unit;`` and hundreds more -- alongside the handful the app actually
defines. ``apk.classes`` is meant to answer "what classes does this app define",
so it skips the referenced-but-external ones:

    for klass in parsed.analysis.get_classes():
        if klass.is_external():
            continue
        ...
        names.append(klass.name)

Drop that ``continue`` and ``apk.classes`` floods with framework classes: an
analyst asking what an APK contains gets ``Landroid/...`` / ``Ljava/...`` drowning
the app's own code, ``total`` counts references rather than definitions, and --
because the list is sorted -- the framework names that sort ahead of the app's
package push the real classes off the first page entirely.

The skip is a no-op in every existing test: ``_FakeClass.is_external()`` in
``test_apk_page_clamp`` returns ``False`` unconditionally and each fixture class
is internal, so the branch never fires and deleting it fails nothing there. These
feed a mix of internal and external classes -- with external names placed to sort
both *before* (``Landroid``) and *after* (``Lzzz``) the app package, so the guard
cannot be mistaken for a head/tail slice -- and pin that only the app's classes
come back, that ``total``/``has_more`` describe the internal-only set, and that
pagination walks that set without the external references inflating it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient


class _Class:
    def __init__(self, name: str, *, external: bool) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _Parsed:
    def __init__(self, classes: list[_Class]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_Class]:
        return self._classes


def _client(monkeypatch: Any, classes: list[_Class]) -> ApkClient:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed(classes))
    return ApkClient()


def _mixed() -> list[_Class]:
    """Three app classes, three external -- external sort to the front and back."""
    return [
        _Class("Landroid/app/Activity;", external=True),  # sorts before every Lcom/*
        _Class("Lcom/app/Beta;", external=False),
        _Class("Ljava/lang/Object;", external=True),  # sorts between the Lcom/* names
        _Class("Lcom/app/Alpha;", external=False),
        _Class("Lzzz/lib/Helper;", external=True),  # sorts after every Lcom/*
        _Class("Lcom/app/Gamma;", external=False),
    ]


def test_external_classes_are_dropped_from_the_listing(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Only the app's own classes appear; total counts definitions, not references.

    ``Landroid/app/Activity;`` sorts ahead of every ``Lcom/*`` name, so if the
    external skip were gone it would be ``classes[0]`` and ``total`` would be 6 --
    this asserts exactly the three internal names and total 3 instead.
    """
    payload = _client(monkeypatch, _mixed()).classes(tmp_path / "app.apk", limit=100)
    assert payload["classes"] == ["Lcom/app/Alpha;", "Lcom/app/Beta;", "Lcom/app/Gamma;"]
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False
    # None of the referenced framework/library classes leak into the listing.
    for external in ("Landroid/app/Activity;", "Ljava/lang/Object;", "Lzzz/lib/Helper;"):
        assert external not in payload["classes"]


def test_pagination_walks_the_internal_set_without_external_inflating_it(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """has_more and total describe the internal-only set, and paging stays on it.

    With the three external references present, a two-row page must still report
    total 3 and hand back the internal classes in order -- the references neither
    fill a slot nor bump has_more.
    """
    client = _client(monkeypatch, _mixed())
    first = client.classes(tmp_path / "app.apk", offset=0, limit=2)
    assert first["classes"] == ["Lcom/app/Alpha;", "Lcom/app/Beta;"]
    assert first["total"] == 3
    assert first["has_more"] is True

    second = client.classes(tmp_path / "app.apk", offset=2, limit=2)
    assert second["classes"] == ["Lcom/app/Gamma;"]
    assert second["has_more"] is False
