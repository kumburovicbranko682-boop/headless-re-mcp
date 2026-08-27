"""Edge coverage for the Address and ModuleSelector value objects.

The construction invariants (require_coordinate, sha256 pattern) are covered by
the wider suite. These pin the resolve() paths and the two ModuleSelector
validator arcs the suite did not reach: the blank-text validator returning None
for an absent path/name, and require_locator refusing a selector with no base,
path, or name.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from headless_re_mcp.core.models import Address, ModuleSelector


def test_resolve_returns_the_virtual_address_directly() -> None:
    assert Address(va=0x1000).resolve() == 0x1000
    # A VA needs no module base, so passing one changes nothing.
    assert Address(va=0x1000).resolve(module_base=0x400000) == 0x1000


def test_resolve_of_an_rva_requires_a_module_base() -> None:
    address = Address(module="app.dll", rva=0x10)
    with pytest.raises(ValueError, match="module_base is required"):
        address.resolve()
    assert address.resolve(module_base=0x400000) == 0x400010


def test_module_selector_accepts_a_base_with_null_text_locators() -> None:
    # path and name are passed as None explicitly, so the blank-text validator
    # runs and returns None for each; require_locator is satisfied by the base.
    selector = ModuleSelector(base=0x400000, path=None, name=None)
    assert selector.path is None
    assert selector.name is None


def test_module_selector_requires_at_least_one_locator() -> None:
    # sha256 identifies a module but does not locate one; with no base, path, or
    # name, construction must fail.
    with pytest.raises(ValidationError, match="requires base, path, or name"):
        ModuleSelector(sha256="ab" * 32)
