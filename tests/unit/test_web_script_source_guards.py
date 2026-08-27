"""web.script.source: the small-body, byte-count, and failure paths the fixture skips.

The one existing script.source test drives a source larger than the inline cap,
so it always spills and always carries a source_path. That leaves the small-body
path -- where ``_spill_text`` returns no artifact and the client must *not* attach
a source_path -- inert, along with three others the large-ASCII fixture cannot
reach:

* ``bytes`` is ``len(source.encode("utf-8"))``, not the character count. The
  fixture is pure ASCII, so the two coincide; a multibyte source separates them.
* a CDP ``getScriptSource`` that raises is mapped to not_found, but a WebError
  raised on the way (a wedged runner) must pass through with its own code, not be
  re-wrapped as not_found.
* a payload with no ``scriptSource`` key is an empty body, not a KeyError.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


def _backend(send: Any) -> WebBackend:
    backend = WebBackend()
    cdp = SimpleNamespace(send=send)
    backend._get = lambda session_id: SimpleNamespace(cdp=cdp)  # type: ignore[method-assign]
    backend._runner = lambda handle: _Immediate()  # type: ignore[method-assign]
    return backend


def test_a_small_source_is_inlined_verbatim_with_no_spill_artifact(tmp_path: Path) -> None:
    """A source under the inline cap is returned whole, not truncated, and -- the
    inert part -- carries no source_path and writes nothing to the artifact dir.
    The client only attaches source_path when the spill actually produced a file.
    """
    backend = _backend(lambda method, params: {"scriptSource": "console.log(1)"})

    payload = backend.script_source("s", "1", tmp_path)

    assert payload["source"] == "console.log(1)"
    assert payload["truncated"] is False
    assert "source_path" not in payload
    assert list(tmp_path.iterdir()) == []


def test_bytes_reports_utf8_length_not_character_count(tmp_path: Path) -> None:
    """bytes is the wire size of the source, len(encode("utf-8")). Three euro signs
    are three characters but nine UTF-8 bytes; the field must read nine so a caller
    sizing a fetch against it is not off by the multibyte factor.
    """
    backend = _backend(lambda method, params: {"scriptSource": "\u20ac\u20ac\u20ac"})

    payload = backend.script_source("s", "1", tmp_path)

    assert payload["source"] == "\u20ac\u20ac\u20ac"
    assert payload["bytes"] == 9
    assert payload["bytes"] != len("\u20ac\u20ac\u20ac")


def test_a_cdp_failure_maps_to_not_found(tmp_path: Path) -> None:
    """CDP has no source for an id it never compiled (or one already gone). The
    generic failure becomes not_found naming the script, not an uncaught exception.
    """

    def boom(method: str, params: dict[str, Any]) -> Any:
        raise RuntimeError("no script with given id")

    backend = _backend(boom)

    with pytest.raises(WebError) as caught:
        backend.script_source("s", "42", tmp_path)

    assert caught.value.code == "not_found"


def test_a_weberror_on_the_way_passes_through_with_its_own_code(tmp_path: Path) -> None:
    """A WebError raised while fetching (e.g. a wedged runner reporting
    backend_error) must propagate unchanged. If the WebError re-raise were dropped,
    the generic handler would relabel every such failure as not_found and hide the
    real cause.
    """

    def wedged(method: str, params: dict[str, Any]) -> Any:
        raise WebError("backend_error", "runner thread is wedged")

    backend = _backend(wedged)

    with pytest.raises(WebError) as caught:
        backend.script_source("s", "42", tmp_path)

    assert caught.value.code == "backend_error"
    assert "wedged" in caught.value.message


def test_a_missing_script_source_key_is_an_empty_body_not_a_crash(tmp_path: Path) -> None:
    """Some CDP replies omit scriptSource entirely. That is an empty source with a
    zero byte count and no spill -- the get() default must hold, not a KeyError.
    """
    backend = _backend(lambda method, params: {})

    payload = backend.script_source("s", "1", tmp_path)

    assert payload["source"] == ""
    assert payload["bytes"] == 0
    assert payload["truncated"] is False
    assert "source_path" not in payload
