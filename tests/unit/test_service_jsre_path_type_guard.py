"""A non-string path to a jsre/wasm service method is a parameter mistake.

Every method in service_jsre is schema-typed to take a string path, but the
agent and OpenAI-bridge transports call handlers straight from model arguments
with no pydantic coercion. ``Path(path)`` on an int/list/null raised TypeError,
which each method's ``except BaseException`` filed as an internal_error
incident -- and js_unpack_bundle had already created an unpack output
directory for a call that could never run.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.core.service_jsre import JsReAnalysisMixin

_METHODS = ("js_deobfuscate", "js_beautify", "js_unpack_bundle", "wasm_wat", "wasm_info")
_BAD_PATHS = (123, 1.5, True, None, ["a.js"], {"path": "a.js"}, b"a.js")


class _Service(JsReAnalysisMixin):
    def __init__(self, artifact_root: Path) -> None:
        self.settings: Any = SimpleNamespace(artifact_root=artifact_root, webcrack=None, wabt=None)


@pytest.fixture
def service(tmp_path: Path) -> _Service:
    return _Service(tmp_path)


@pytest.mark.parametrize("method", _METHODS)
@pytest.mark.parametrize("bad", _BAD_PATHS)
def test_a_non_string_path_is_invalid_params_not_an_incident(
    service: _Service, method: str, bad: Any
) -> None:
    result = getattr(service, method)(bad)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


@pytest.mark.parametrize("method", _METHODS)
def test_a_string_path_still_reaches_the_backend(service: _Service, method: str) -> None:
    """The guard must only stop the shapes the schema forbids.

    With no webcrack/wabt configured the backend answers with its own
    structured unavailability, which is exactly the point: a proper string
    path gets past the guard and earns a backend answer, not invalid_params.
    """
    result = getattr(service, method)("missing.js")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_a_refused_unpack_creates_no_output_directory(service: _Service, tmp_path: Path) -> None:
    """The output tree used to be made before the path was ever looked at."""
    bad_path: Any = 123
    result = service.js_unpack_bundle(bad_path)

    assert result.error is not None and result.error.code == "invalid_params"
    jsre_root = tmp_path / "jsre"
    leftovers = list(jsre_root.iterdir()) if jsre_root.is_dir() else []
    assert leftovers == []
